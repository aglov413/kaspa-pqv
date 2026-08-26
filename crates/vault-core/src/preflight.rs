//! Checks that must pass **before** a vault transaction is broadcast.
//!
//! Everything that can cause a rejection is evaluated on an *unsigned*
//! transaction, using Kaspa's own [`MassCalculator`] and [`ScriptClass`] rather
//! than a local reimplementation that could drift from consensus.
//!
//! # Why the ordering matters, and how much
//!
//! For a stateful scheme it is critical: a rejected LMS transaction cannot be
//! repaired, because changing the fee changes the binding digest and the
//! one-time key cannot sign twice, so the coins are stranded at that leaf.
//! Preflight is what stands between a fee mistake and unspendable funds.
//!
//! For SLH-DSA the stakes are lower — a rejected transaction can simply be
//! re-signed — but the checks are the same ones, and finding out that a spend
//! is unmineable *before* paying for a signature is still the right order.
//!
//! # Sizing an unsigned transaction
//!
//! Both schemes produce a fixed-length signature for their parameter set and a
//! deterministic redeem script, so a zero-filled placeholder is byte-for-byte
//! the same *size* as the real signature script — which is all the mass
//! calculation needs.

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

use crate::binding::OutputView;

/// `DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE` from the mempool config, in sompi
/// per kilogram of mass.
pub const MINIMUM_RELAY_TRANSACTION_FEE: u64 = 100_000;

/// Smallest value any output may carry, in sompi (0.02 KAS).
///
/// There are two separate limits on how small an output can be, and confusing
/// them produces a spend that fails for a reason the error does not explain:
///
/// - **This one is absolute.** Storage mass (KIP-9) scales with the inverse of
///   an output's value, so below roughly 0.019 KAS the mass explodes past the
///   standard limit no matter what else the transaction looks like. 0.02 KAS is
///   the floor wallets and libraries settle on to stay clear of the penalty
///   zone, and it is checked here by value so the rejection names the cause.
/// - **The other is relative**, and is not a constant: change that is small
///   *compared to the input being consumed* also inflates storage mass. That
///   one has no fixed threshold — it depends on the UTXO — so it is caught by
///   the mass calculation below rather than by a comparison.
///
/// A vault spend can hit either. Both are checked before signing.
pub const DUST_THRESHOLD: u64 = 2_000_000;

/// A spend to evaluate, with nothing scheme-specific in it.
pub struct SpendShape<'a> {
    pub params: &'a Params,
    /// The signature script this spend will carry, at its exact final length.
    /// Contents are irrelevant; only the length is used.
    pub signature_script: Vec<u8>,
    /// The script public key of the UTXO being spent.
    pub utxo_script_pubkey: ScriptPublicKey,
    pub utxo_amount: u64,
    pub outpoint_txid: [u8; 32],
    pub outpoint_index: u32,
    pub tx_version: u16,
    pub outputs: &'a [OutputView],
    /// Output count the redeem script is unrolled to. A spend of a different
    /// shape cannot satisfy the script at all.
    pub expected_output_count: usize,
    /// Compute budget the input will declare. It contributes directly to
    /// compute mass, so it has to be known here rather than measured after
    /// signing.
    pub budget_units: u16,
}

/// What a spend will cost, and whether it can relay.
#[derive(Clone, Debug)]
pub struct PreflightReport {
    pub fee: u64,
    /// Minimum fee the mempool will accept for this shape.
    pub minimum_fee: u64,
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
pub fn minimum_relay_fee(mass: u64) -> u64 {
    let fee = mass.saturating_mul(MINIMUM_RELAY_TRANSACTION_FEE) / 1000;
    if fee == 0 {
        MINIMUM_RELAY_TRANSACTION_FEE
    } else {
        fee
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

/// Compute the report without enforcing it.
///
/// Used to discover the fee floor for a shape before a fee has been chosen —
/// [`enforce`] would reject an underpaid spend, which is unhelpful when the
/// point is to find out what "paid enough" means.
pub fn estimate(shape: &SpendShape<'_>) -> Result<PreflightReport> {
    ensure!(
        shape.outputs.len() == shape.expected_output_count,
        "a vault spend must have exactly {} outputs; the redeem script is unrolled to that shape",
        shape.expected_output_count
    );

    let total_out: u64 = shape.outputs.iter().map(|o| o.amount).sum();
    ensure!(
        total_out <= shape.utxo_amount,
        "outputs total {total_out} exceeds the {} available",
        shape.utxo_amount
    );
    let fee = shape.utxo_amount - total_out;

    for (i, output) in shape.outputs.iter().enumerate() {
        ensure!(
            output.amount >= DUST_THRESHOLD,
            "output {i} carries {} sompi, below the {DUST_THRESHOLD} sompi ({:.2} KAS) dust \
             floor. Storage mass scales with the inverse of an output's value, so anything \
             smaller is rejected however the rest of the transaction is shaped. Raise the \
             amount, or drop the output and let the value go to fee.",
            output.amount,
            DUST_THRESHOLD as f64 / 100_000_000.0,
        );
    }

    // Outputs must be scripts a mempool will relay. A vault spend paying to a
    // script nobody recognises would verify in the engine and be dropped before
    // it ever reached a block.
    let built_outputs = to_outputs(shape.outputs);
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

    let outpoint =
        TransactionOutpoint::new(TransactionId::from_slice(&shape.outpoint_txid), shape.outpoint_index);
    let input = TransactionInput::new_with_compute_budget(
        outpoint,
        shape.signature_script.clone(),
        0,
        shape.budget_units,
    );
    let tx = Transaction::new(
        shape.tx_version,
        vec![input],
        built_outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    let calculator = MassCalculator::new(
        shape.params.mass_per_tx_byte,
        shape.params.mass_per_script_pub_key_byte,
        STORAGE_MASS_PARAMETER,
    );
    let non_contextual = calculator.calc_non_contextual_masses(&tx);

    let utxo_entry =
        UtxoEntry::new(shape.utxo_amount, shape.utxo_script_pubkey.clone(), 0, false, None);
    let populated = PopulatedTransaction::new(&tx, vec![utxo_entry]);
    let contextual = calculator
        .calc_contextual_masses(&populated)
        .ok_or_else(|| anyhow::anyhow!("storage mass overflowed; an output amount is too small"))?;

    let cofactors = MassCofactors::new(&shape.params.block_mass_limits);
    let normalized_transient = non_contextual.normalized_transient(&cofactors);
    let normalized_max = Mass::new(non_contextual, contextual).normalized_max(&cofactors);

    // The fee floor uses the larger of compute and normalized transient. For a
    // vault spend transient usually wins, because the script is large but cheap
    // to verify.
    let fee_mass = non_contextual.compute_mass.max(normalized_transient);

    Ok(PreflightReport {
        fee,
        minimum_fee: minimum_relay_fee(fee_mass),
        size: kaspa_consensus_core::mass::transaction_estimated_serialized_size(&tx),
        compute_mass: non_contextual.compute_mass,
        transient_mass: non_contextual.transient_mass,
        normalized_transient_mass: normalized_transient,
        storage_mass: contextual.storage_mass,
        normalized_max_mass: normalized_max,
    })
}

/// Evaluate a spend and refuse it if it cannot relay or cannot be mined.
pub fn enforce(shape: &SpendShape<'_>) -> Result<PreflightReport> {
    let report = estimate(shape)?;

    ensure!(
        report.fee >= report.minimum_fee,
        "fee of {} sompi is below the {} minimum for this transaction ({})",
        report.fee,
        report.minimum_fee,
        report.summary()
    );

    ensure!(
        report.normalized_max_mass <= shape.params.block_mass_limits.compute,
        "spend needs {} normalized mass but a block allows {} — it can never be \
         included. Usually caused by a change output small enough to inflate storage \
         mass ({}).",
        report.normalized_max_mass,
        shape.params.block_mass_limits.compute,
        report.storage_mass
    );

    Ok(report)
}
