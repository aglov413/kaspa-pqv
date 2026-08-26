//! Assembling a broadcastable transaction from a signed spend.
//!
//! # Declaring the compute budget
//!
//! An input declares a `compute_budget` in units of 100 grams, and the
//! transaction's compute mass includes `100 * sum(compute_budget)` — so
//! over-declaring is not free, it is paid for in mass and therefore in fee.
//! Under-declaring is worse: the script aborts with
//! `ExceededCommittedScriptUnits` and the one-time key that signed has been
//! spent for nothing.
//!
//! Rather than derive the cost from a formula that would drift as the
//! generator changes, the budget is **measured**: the transaction is dry-run
//! through the same `TxScriptEngine` a node uses, and the engine's own
//! accounting fixes the number.
//!
//! This is safe because the binding digest covers the transaction version, the
//! outpoint, and every output amount and script public key — but *not* the
//! input's `compute_commit`. Adjusting the budget therefore does not invalidate
//! the signature, which is what makes measure-then-rebuild possible at all.

use anyhow::{anyhow, ensure, Context, Result};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{pay_to_script_hash_script, EngineCtx, SigCacheKey, TxScriptEngine};
use lms_script::binding::OutputView;

use crate::spend::{SignedSpend, VaultUtxo};

/// Safety margin added to the measured budget, in compute-budget units.
///
/// Script-unit consumption for a vault spend is deterministic given the same
/// transaction, so in principle zero margin is correct. A small allowance costs
/// 100 grams per unit and guards against an off-by-one in rounding rather than
/// against genuine variance.
pub const BUDGET_MARGIN_UNITS: u16 = 2;

/// The largest budget an input may declare.
pub const MAX_BUDGET_UNITS: u16 = u16::MAX;

/// A transaction ready to broadcast, with what it cost to verify.
#[derive(Clone, Debug)]
pub struct AssembledTransaction {
    pub tx: Transaction,
    /// The UTXO being spent, as the engine needs it for verification.
    pub utxo: UtxoEntry,
    /// Script units the redeem script actually consumed, measured.
    pub measured_script_units: u64,
    /// The budget declared on the input.
    pub declared_budget_units: u16,
}

impl AssembledTransaction {
    /// Compute mass this spend contributes, approximately: transaction bytes at
    /// `mass_per_tx_byte = 1` plus the declared budget in grams.
    pub fn approx_compute_mass(&self) -> u64 {
        let size: u64 = self.tx.inputs.iter().map(|i| i.signature_script.len() as u64).sum::<u64>()
            + self.tx.outputs.iter().map(|o| o.script_public_key.script().len() as u64 + 10).sum::<u64>()
            + 100;
        size + u64::from(self.declared_budget_units) * 100
    }
}

fn to_outputs(views: &[OutputView]) -> Vec<TransactionOutput> {
    views
        .iter()
        .map(|o| {
            TransactionOutput::new(
                o.amount,
                ScriptPublicKey::new(o.spk_version, ScriptVec::from_slice(&o.script)),
            )
        })
        .collect()
}

fn build(
    signed: &SignedSpend,
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &[OutputView],
    budget_units: u16,
) -> (Transaction, UtxoEntry) {
    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&utxo.txid), utxo.index);
    let input = TransactionInput::new_with_compute_budget(
        outpoint,
        signed.signature_script.clone(),
        0,
        budget_units,
    );
    let tx = Transaction::new(
        tx_version,
        vec![input],
        to_outputs(outputs),
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let entry = UtxoEntry::new(
        utxo.amount,
        pay_to_script_hash_script(&signed.redeem_script),
        0,
        false,
        None,
    );
    (tx, entry)
}

/// Run the spend through the consensus script engine and report the units used.
///
/// This is the same verification a node performs, so a spend that fails here
/// would be rejected on-chain — and finding that out *before* broadcasting
/// costs nothing, whereas finding out after has already burned the key.
pub fn verify_and_measure(tx: &Transaction, utxo: &UtxoEntry) -> Result<u64> {
    let reused = SigHashReusedValuesUnsync::new();
    let sig_cache: Cache<SigCacheKey, bool> = Cache::new(0);
    let populated = PopulatedTransaction::new(tx, vec![utxo.clone()]);

    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &populated.tx.inputs[0],
        0,
        utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused),
        Default::default(),
    );

    vm.execute().map_err(|e| anyhow!("the assembled spend does not verify: {e}"))?;
    Ok(vm.used_script_units().0)
}

/// Assemble a broadcastable transaction, measuring the compute budget.
///
/// The spend is built once with the maximum budget to measure it, then rebuilt
/// with the budget it actually needs. The signature is unaffected because the
/// binding digest does not cover `compute_commit`.
pub fn assemble(
    signed: &SignedSpend,
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &[OutputView],
) -> Result<AssembledTransaction> {
    let total_out: u64 = outputs.iter().map(|o| o.amount).sum();
    ensure!(
        total_out <= utxo.amount,
        "outputs total {total_out} exceeds the {} available",
        utxo.amount
    );

    // Measure under a budget that cannot be the binding constraint.
    let (probe_tx, entry) = build(signed, utxo, tx_version, outputs, MAX_BUDGET_UNITS);
    let measured = verify_and_measure(&probe_tx, &entry).context("dry run")?;

    // script units -> grams -> budget units, both divisors being 100.
    let needed = measured.div_ceil(100).div_ceil(100);
    let declared = u16::try_from(needed)
        .map_err(|_| anyhow!("spend needs {needed} budget units, above the per-input maximum"))?
        .saturating_add(BUDGET_MARGIN_UNITS);

    let (tx, utxo_entry) = build(signed, utxo, tx_version, outputs, declared);

    // Re-verify under the real budget: if the declared amount were too small
    // the engine would abort here rather than on-chain.
    verify_and_measure(&tx, &utxo_entry)
        .context("spend does not verify under its declared compute budget")?;

    Ok(AssembledTransaction {
        tx,
        utxo: utxo_entry,
        measured_script_units: measured,
        declared_budget_units: declared,
    })
}
