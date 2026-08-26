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

use anyhow::Result;
use kaspa_consensus_core::config::params::Params;
use kaspa_txscript::pay_to_script_hash_script;
use vault_core::binding::OutputView;
use vault_core::preflight::SpendShape;

pub use vault_core::preflight::{
    minimum_relay_fee, PreflightReport, MINIMUM_RELAY_TRANSACTION_FEE,
};

use crate::spend::VaultUtxo;
use crate::vault::{Vault, CANONICAL_OUTPUT_COUNT};

/// The signature script a spend of this vault will produce, at full size but
/// filled with zeros.
///
/// Every LMS witness element is 32 bytes and the redeem script is fixed, so the
/// placeholder is byte-for-byte the same length as the real thing.
pub fn placeholder_signature_script(vault: &Vault, leaf: u32) -> Result<Vec<u8>> {
    let redeem_script = vault.redeem_script(leaf)?;
    let dummy = vec![0u8; crate::vault::PARAMS.signature_len()];
    let witness = crate::spend::witness_pushes(&dummy)?;
    kaspa_txscript::pay_to_script_hash_signature_script(redeem_script, witness)
        .map_err(|e| anyhow::anyhow!("signature script assembly failed: {e}"))
}

fn shape<'a>(
    params: &'a Params,
    vault: &Vault,
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &'a [OutputView],
    budget_units: u16,
) -> Result<SpendShape<'a>> {
    Ok(SpendShape {
        params,
        signature_script: placeholder_signature_script(vault, utxo.leaf)?,
        utxo_script_pubkey: pay_to_script_hash_script(&vault.redeem_script(utxo.leaf)?),
        utxo_amount: utxo.amount,
        outpoint_txid: utxo.txid,
        outpoint_index: utxo.index,
        tx_version,
        outputs,
        expected_output_count: CANONICAL_OUTPUT_COUNT,
        budget_units,
    })
}

/// Compute the report without enforcing it.
pub fn estimate(
    params: &Params,
    vault: &Vault,
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &[OutputView],
    budget_units: u16,
) -> Result<PreflightReport> {
    vault_core::preflight::estimate(&shape(params, vault, utxo, tx_version, outputs, budget_units)?)
}

/// Evaluate a spend without signing it.
///
/// The failure message is LMS-specific on purpose: for a one-time key, a fee
/// that is too low after signing is unrecoverable, and the user needs to be
/// told that rather than told a number.
pub fn preflight(
    params: &Params,
    vault: &Vault,
    utxo: &VaultUtxo,
    tx_version: u16,
    outputs: &[OutputView],
    budget_units: u16,
) -> Result<PreflightReport> {
    vault_core::preflight::enforce(&shape(params, vault, utxo, tx_version, outputs, budget_units)?)
        .map_err(|e| {
            anyhow::anyhow!(
                "{e}\n\nRaising the fee AFTER signing is impossible: the change would alter \
                 the binding digest and the one-time key cannot sign twice. Fix it now."
            )
        })
}
