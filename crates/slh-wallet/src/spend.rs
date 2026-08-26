//! Building, signing and assembling a vault spend.
//!
//! # What is different from the stateful scheme
//!
//! There is no journal, no leaf cursor and no sign-once invariant. An SLH-DSA
//! key can sign any number of messages, so a rejected transaction is simply
//! rebuilt and re-signed. That removes the failure mode the LMS wallet is
//! largely built around — where a fee that turns out to be too low after
//! signing strands the coins at that leaf, because the digest changed and the
//! one-time key cannot sign again.
//!
//! Preflight still runs before signing, because finding out that a spend cannot
//! be mined before paying for it is still the right order, and because the
//! checks catch things a retry would not fix — a non-standard output, or a
//! change output small enough to inflate storage mass past the block limit.
//!
//! # Order of operations
//!
//! 1. Preflight the unsigned shape, using a zero-filled signature script of the
//!    exact final length.
//! 2. Compute the binding digest and sign it.
//! 3. Measure script units by running the assembled spend through the real
//!    engine under an unconstrained budget.
//! 4. Rebuild declaring the budget it actually needs, and re-verify with that
//!    budget **enforced**.
//!
//! Step 4 is safe because the binding digest does not cover `compute_commit`,
//! so changing the declared budget does not invalidate the signature.

use anyhow::{anyhow, ensure, Context, Result};
use fips205::slh_dsa_sha2_128s;
use fips205::traits::Signer;
use kaspa_consensus_core::config::params::Params;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::{ComputeBudget, ScriptUnits};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{
    pay_to_script_hash_script, pay_to_script_hash_signature_script, EngineCtx, SigCacheKey,
    TxScriptEngine,
};
use vault_core::binding::{binding_digest, OutputView, SpendView};
use vault_core::preflight::{estimate, PreflightReport, SpendShape};

use crate::keygen::{Keypair, NoRng};
use crate::vault::{SlhVault, CANONICAL_OUTPUT_COUNT};

/// Compute budget assumed when sizing an *unsigned* spend.
///
/// The exact budget cannot be known before signing — it depends on the
/// Winternitz digits of the signature, which vary by a few percent. That does
/// not matter for the fee, and the reason is worth stating: the fee floor uses
/// `max(compute_mass, normalized_transient_mass)`, and for a spend this large
/// transient mass wins by a wide margin. Compute mass is transaction bytes plus
/// 100 grams per declared budget unit, so the budget would have to exceed
/// roughly a thousand units before it changed the fee at all — an order of
/// magnitude above what a spend actually needs.
///
/// So this is a ceiling used for estimation, not a guess that has to be right.
/// `budget_never_dominates_the_fee_floor` pins both halves of that argument.
pub const PREFLIGHT_BUDGET_UNITS: u16 = 200;

/// Slack added to the measured compute budget.
///
/// Consumption is deterministic for a fixed transaction, so zero would be
/// correct. The allowance costs 100 grams per unit and guards against a
/// rounding off-by-one, not against genuine variance.
pub const BUDGET_MARGIN_UNITS: u16 = 2;

/// A vault UTXO. There is no leaf field: a vault is one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultUtxo {
    pub txid: [u8; 32],
    pub index: u32,
    pub amount: u64,
}

/// A signed spend, verified against the consensus engine and ready to
/// broadcast.
#[derive(Clone, Debug)]
pub struct SignedSpend {
    /// The digest that was signed — what the redeem script reconstructs.
    pub digest: [u8; 32],
    pub tx: Transaction,
    /// The UTXO being spent, as the engine needs it.
    pub utxo: UtxoEntry,
    pub redeem_script: Vec<u8>,
    /// Script units the spend actually consumed, measured by the engine.
    pub measured_script_units: u64,
    /// The budget declared on the input.
    pub declared_budget_units: u16,
    /// Mass, fee and size, from Kaspa's own calculator.
    pub report: PreflightReport,
}

impl SignedSpend {
    pub fn txid(&self) -> String {
        self.tx.id().to_string()
    }
    pub fn size(&self) -> u64 {
        kaspa_consensus_core::mass::transaction_estimated_serialized_size(&self.tx)
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
    signature_script: Vec<u8>,
    redeem_script: &[u8],
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &[OutputView],
    budget_units: u16,
) -> (Transaction, UtxoEntry) {
    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&utxo.txid), utxo.index);
    let input =
        TransactionInput::new_with_compute_budget(outpoint, signature_script, 0, budget_units);
    let tx = Transaction::new(
        tx_version,
        vec![input],
        to_outputs(outputs),
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let entry =
        UtxoEntry::new(utxo.amount, pay_to_script_hash_script(redeem_script), 0, false, None);
    (tx, entry)
}

/// Run a spend through the consensus engine.
///
/// `budget_units` of `None` measures without a limit; `Some(n)` enforces the
/// limit a node would apply to an input declaring `n`.
pub fn verify(tx: &Transaction, utxo: &UtxoEntry, budget_units: Option<u16>) -> Result<u64> {
    let reused = SigHashReusedValuesUnsync::new();
    let sig_cache: Cache<SigCacheKey, bool> = Cache::new(0);
    let populated = PopulatedTransaction::new(tx, vec![utxo.clone()]);
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused);

    let mut vm = match budget_units {
        None => TxScriptEngine::from_transaction_input(
            &populated,
            &populated.tx.inputs[0],
            0,
            utxo,
            ctx,
            Default::default(),
        ),
        Some(units) => {
            let limit: ScriptUnits = ComputeBudget(units).into();
            TxScriptEngine::from_transaction_input_with_script_units_limit(
                &populated,
                &populated.tx.inputs[0],
                0,
                utxo,
                ctx,
                Default::default(),
                limit,
            )
        }
    };

    vm.execute().map_err(|e| anyhow!("the assembled spend does not verify: {e}"))?;
    Ok(vm.used_script_units().0)
}

/// The signature script a spend will produce, at full size but zero-filled.
///
/// The signature is a fixed length for the parameter set and the redeem script
/// is deterministic, so this is byte-for-byte the size of the real thing —
/// which is all the mass calculation needs.
pub fn placeholder_signature_script(vault: &SlhVault) -> Result<Vec<u8>> {
    let redeem_script = vault.redeem_script()?;
    let witness = vault.plan.placeholder_witness()?;
    pay_to_script_hash_signature_script(redeem_script, witness)
        .map_err(|e| anyhow!("signature script assembly failed: {e}"))
}

/// Preflight an unsigned spend: what it will cost and whether it can relay.
pub fn preflight(
    params: &Params,
    vault: &SlhVault,
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &[OutputView],
    budget_units: u16,
) -> Result<PreflightReport> {
    estimate(&SpendShape {
        params,
        signature_script: placeholder_signature_script(vault)?,
        utxo_script_pubkey: pay_to_script_hash_script(&vault.redeem_script()?),
        utxo_amount: utxo.amount,
        outpoint_txid: utxo.txid,
        outpoint_index: utxo.index,
        tx_version,
        outputs,
        expected_output_count: CANONICAL_OUTPUT_COUNT,
        budget_units,
    })
}

/// Build and sign a canonical vault spend.
///
/// Fails before signing if the spend could not be mined. Unlike the LMS path
/// this is a convenience rather than a safety requirement — nothing is
/// consumed by a failed attempt.
pub fn build_spend(
    params: &Params,
    vault: &SlhVault,
    keypair: &Keypair,
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &[OutputView],
) -> Result<SignedSpend> {
    ensure!(
        outputs.len() == CANONICAL_OUTPUT_COUNT,
        "a vault spend must have exactly {CANONICAL_OUTPUT_COUNT} outputs; the redeem \
         script is unrolled to that shape"
    );

    // Size the unsigned spend. The declared budget is not known until the
    // signature exists, but it does not move the fee floor — see
    // `PREFLIGHT_BUDGET_UNITS`. The real budget is checked again below.
    let report = preflight(params, vault, utxo, tx_version, outputs, PREFLIGHT_BUDGET_UNITS)?;
    ensure!(
        report.fee >= report.minimum_fee,
        "fee of {} sompi is below the {} minimum for this spend ({})",
        report.fee,
        report.minimum_fee,
        report.summary()
    );
    ensure!(
        report.normalized_max_mass <= params.block_mass_limits.compute,
        "spend needs {} normalized mass but a block allows {} — it can never be included. \
         Usually caused by a change output small enough to inflate storage mass ({}).",
        report.normalized_max_mass,
        params.block_mass_limits.compute,
        report.storage_mass
    );

    let digest = binding_digest(&SpendView {
        tx_version,
        outpoint_txid: utxo.txid,
        outpoint_index: utxo.index,
        outputs: outputs.to_vec(),
    })
    .context("computing the binding digest")?;

    // Empty context, matching what the emitted script's two zero bytes assume.
    // Deterministic signing, so a rebuild of the same spend is byte-identical.
    let signature: [u8; slh_dsa_sha2_128s::SIG_LEN] = keypair
        .secret
        .try_sign_with_rng(&mut NoRng, &digest, &[], false)
        .map_err(|e| anyhow!("signing failed: {e}"))?;

    let redeem_script = vault.redeem_script()?;
    let signature_script = pay_to_script_hash_signature_script(
        redeem_script.clone(),
        vault.plan.witness_pushes(&signature)?,
    )
    .map_err(|e| anyhow!("signature script assembly failed: {e}"))?;

    // Measure under a budget that cannot bind.
    let (probe, entry) = build(
        signature_script.clone(),
        &redeem_script,
        utxo,
        tx_version,
        outputs,
        u16::MAX,
    );
    let measured = verify(&probe, &entry, None).context("dry run")?;

    // script units -> grams -> budget units, both divisors being 100.
    let needed = measured.div_ceil(100).div_ceil(100);
    let declared = u16::try_from(needed)
        .map_err(|_| anyhow!("spend needs {needed} budget units, above the per-input maximum"))?
        .checked_add(BUDGET_MARGIN_UNITS)
        .ok_or_else(|| anyhow!("compute budget overflows its u16 field"))?;

    let (tx, utxo_entry) =
        build(signature_script, &redeem_script, utxo, tx_version, outputs, declared);

    // The budget is not covered by the binding digest, so declaring it after
    // signing is sound — but it must still be enough, and only the enforcing
    // engine can tell us that.
    verify(&tx, &utxo_entry, Some(declared))?;

    // Re-report with the real budget, since it feeds compute mass.
    let report = preflight(params, vault, utxo, tx_version, outputs, declared)?;
    ensure!(
        report.fee >= report.minimum_fee,
        "fee of {} sompi is below the {} minimum once the compute budget is declared ({})",
        report.fee,
        report.minimum_fee,
        report.summary()
    );

    Ok(SignedSpend {
        digest,
        tx,
        utxo: utxo_entry,
        redeem_script,
        measured_script_units: measured,
        declared_budget_units: declared,
        report,
    })
}
