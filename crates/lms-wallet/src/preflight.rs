//! Checks that must pass **before** a one-time key signs.
//!
//! The sign-once invariant makes ordering load-bearing. If a transaction is
//! rejected after signing — for a low fee, an oversized mass, a non-standard
//! output — the remedy would be to change the transaction, which changes the
//! binding digest, which requires signing again with the same leaf. The journal
//! refuses that, correctly, and the coins are then stranded at that leaf with
//! no way to move them.
//!
//! So everything that can cause a rejection is evaluated here, on an unsigned
//! transaction, using Kaspa's own [`MassCalculator`] and [`ScriptClass`] rather
//! than a local reimplementation that could drift from consensus.
//!
//! The signature script's size is known before signing: an LMS signature is a
//! fixed length for a parameter set, every witness element is 32 bytes, and the
//! redeem script is deterministic. A zero-filled signature therefore produces a
//! byte-identical *size*, which is all the mass calculation needs.

use anyhow::{bail, ensure, Result};
use kaspa_consensus_core::config::params::Params;
use kaspa_consensus_core::constants::{MAX_SCRIPT_PUBLIC_KEY_VERSION, STORAGE_MASS_PARAMETER};
use kaspa_consensus_core::mass::{Mass, MassCalculator, MassCofactors};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::script_class::ScriptClass;
use kaspa_txscript::pay_to_script_hash_script;
use lms_script::binding::OutputView;

use crate::spend::VaultUtxo;
use crate::vault::{Vault, CANONICAL_OUTPUT_COUNT};

/// `DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE` from the mempool config, in
/// sompi per kilogram of mass.
pub const MINIMUM_RELAY_TRANSACTION_FEE: u64 = 100_000;

/// What a spend will cost, and whether it can relay.
#[derive(Clone, Debug)]
pub struct PreflightReport {
    /// Fee implied by the inputs and outputs.
    pub fee: u64,
    /// Minimum fee the mempool will accept for this shape.
    pub minimum_fee: u64,
    /// Estimated serialized size in bytes.
    pub size: u64,
    pub compute_mass: u64,
    pub transient_mass: u64,
    /// Transient mass scaled to the compute-mass axis, which is what the fee
    /// floor and block capacity actually use.
    pub normalized_transient_mass: u64,
    pub storage_mass: u64,
    /// The largest dimension, normalized. This is what consumes block space.
    pub normalized_max_mass: u64,
}

impl PreflightReport {
    /// Roughly how many spends of this shape fit in a block.
    pub fn spends_per_block(&self, compute_limit: u64) -> u64 {
        compute_limit / self.normalized_max_mass.max(1)
    }

    pub fn summary(&self) -> String {
        format!(
            "{} bytes, mass {} (compute {}, transient {} normalized, storage {}), \
             fee {} sompi against a {} minimum",
            self.size,
            self.normalized_max_mass,
            self.compute_mass,
            self.normalized_transient_mass,
            self.storage_mass,
            self.fee,
            self.minimum_fee,
        )
    }
}

/// The fee floor, as `check_transaction_standard_in_context` computes it.
fn minimum_relay_fee(mass: u64) -> u64 {
    let fee = mass.saturating_mul(MINIMUM_RELAY_TRANSACTION_FEE) / 1000;
    if fee == 0 {
        MINIMUM_RELAY_TRANSACTION_FEE
    } else {
        fee
    }
}

/// The signature script a spend of this vault will produce, at full size but
/// filled with zeros.
///
/// Used to size an unsigned transaction. Every witness element is 32 bytes and
/// the redeem script is fixed, so the placeholder is byte-for-byte the same
/// length as the real thing.
pub fn placeholder_signature_script(vault: &Vault, leaf: u32) -> Result<Vec<u8>> {
    let redeem_script = vault.redeem_script(leaf)?;
    let dummy = vec![0u8; crate::vault::PARAMS.signature_len()];
    let witness = crate::spend::witness_pushes(&dummy)?;
    kaspa_txscript::pay_to_script_hash_signature_script(redeem_script, witness)
        .map_err(|e| anyhow::anyhow!("signature script assembly failed: {e}"))
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

/// Compute the report without enforcing it.
///
/// Used to discover the fee floor for a shape before a fee has been chosen —
/// [`preflight`] would reject an underpaid spend, which is unhelpful when the
/// point is to find out what "paid enough" means.
pub fn estimate(
    params: &Params,
    vault: &Vault,
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &[OutputView],
    budget_units: u16,
) -> Result<PreflightReport> {
    report_for(params, vault, utxo, tx_version, outputs, budget_units)
}

/// Evaluate a spend without signing it.
///
/// `budget_units` is the compute budget the input will declare. It contributes
/// directly to compute mass, so it has to be known here rather than measured
/// after signing.
pub fn preflight(
    params: &Params,
    vault: &Vault,
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &[OutputView],
    budget_units: u16,
) -> Result<PreflightReport> {
    let report = report_for(params, vault, utxo, tx_version, outputs, budget_units)?;

    ensure!(
        report.fee >= report.minimum_fee,
        "fee of {} sompi is below the {} minimum for this transaction ({}). Raising it \
         AFTER signing is impossible: the change would alter the binding digest and the \
         one-time key cannot sign twice. Increase the fee now.",
        report.fee,
        report.minimum_fee,
        report.summary()
    );

    ensure!(
        report.normalized_max_mass <= params.block_mass_limits.compute,
        "spend needs {} normalized mass but a block allows {} — it can never be \
         included. Usually caused by a change output small enough to inflate storage \
         mass ({}).",
        report.normalized_max_mass,
        params.block_mass_limits.compute,
        report.storage_mass
    );

    Ok(report)
}

fn report_for(
    params: &Params,
    vault: &Vault,
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &[OutputView],
    budget_units: u16,
) -> Result<PreflightReport> {
    ensure!(
        outputs.len() == CANONICAL_OUTPUT_COUNT,
        "a vault spend must have exactly {CANONICAL_OUTPUT_COUNT} outputs; the redeem \
         script is unrolled to that shape"
    );

    let total_out: u64 = outputs.iter().map(|o| o.amount).sum();
    ensure!(
        total_out <= utxo.amount,
        "outputs total {total_out} exceeds the {} available",
        utxo.amount
    );
    let fee = utxo.amount - total_out;

    // Outputs must be scripts a mempool will relay. A vault spend paying to a
    // script nobody recognises would verify in the engine and be dropped before
    // it ever reached a block.
    let built_outputs = to_outputs(outputs);
    for (i, output) in built_outputs.iter().enumerate() {
        if output.script_public_key.version() > MAX_SCRIPT_PUBLIC_KEY_VERSION {
            bail!(
                "output {i} has script public key version {} but standard relay allows at \
                 most {MAX_SCRIPT_PUBLIC_KEY_VERSION}",
                output.script_public_key.version(),
            );
        }
        if ScriptClass::from_script(&output.script_public_key) == ScriptClass::NonStandard {
            bail!(
                "output {i} is not a standard script type (expected pay-to-pubkey or \
                 pay-to-script-hash); a mempool will reject this transaction"
            );
        }
    }

    // Size the unsigned transaction using a placeholder of the exact length the
    // real signature script will occupy.
    let signature_script = placeholder_signature_script(vault, utxo.leaf)?;
    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&utxo.txid), utxo.index);
    let input =
        TransactionInput::new_with_compute_budget(outpoint, signature_script, 0, budget_units);
    let tx = Transaction::new(
        tx_version,
        vec![input],
        built_outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    let calculator = MassCalculator::new(
        params.mass_per_tx_byte,
        params.mass_per_script_pub_key_byte,
        STORAGE_MASS_PARAMETER,
    );
    let non_contextual = calculator.calc_non_contextual_masses(&tx);

    let utxo_entry = UtxoEntry::new(
        utxo.amount,
        pay_to_script_hash_script(&vault.redeem_script(utxo.leaf)?),
        0,
        false,
        None,
    );
    let populated = PopulatedTransaction::new(&tx, vec![utxo_entry]);
    let contextual = calculator
        .calc_contextual_masses(&populated)
        .ok_or_else(|| anyhow::anyhow!("storage mass overflowed; an output amount is too small"))?;

    let cofactors = MassCofactors::new(&params.block_mass_limits);
    let normalized_transient = non_contextual.normalized_transient(&cofactors);
    let normalized_max = Mass::new(non_contextual, contextual).normalized_max(&cofactors);

    // The fee floor uses the larger of compute and normalized transient. For a
    // vault spend transient usually wins, because the script is large but cheap
    // to verify.
    let fee_mass = non_contextual.compute_mass.max(normalized_transient);
    let minimum_fee = minimum_relay_fee(fee_mass);

    Ok(PreflightReport {
        fee,
        minimum_fee,
        size: kaspa_consensus_core::mass::transaction_estimated_serialized_size(&tx),
        compute_mass: non_contextual.compute_mass,
        transient_mass: non_contextual.transient_mass,
        normalized_transient_mass: normalized_transient,
        storage_mass: contextual.storage_mass,
        normalized_max_mass: normalized_max,
    })
}
