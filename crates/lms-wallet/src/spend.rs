//! Building and signing a vault spend.
//!
//! Every signature goes through [`crate::journal::sign_once`], so a leaf cannot
//! sign two different transactions by any route this module exposes.

use anyhow::{ensure, Result};
use kaspa_txscript::pay_to_script_hash_signature_script;
use lms_script::binding::{binding_digest, OutputView, SpendView};
use lms_script::params::N;
use lms_script::ScriptWriter;
use oxicrypt_lms::lms_sha256_m32_h15_w2 as lms;

use crate::journal::{sign_once, LeafId, SignOutcome, SpendJournal};
use crate::preflight::{preflight, PreflightReport};
use crate::vault::{ChangeTarget, LeafBudget, Vault, CANONICAL_OUTPUT_COUNT, PARAMS};
use kaspa_consensus_core::config::params::Params;

/// The UTXO a vault leaf is spending.
#[derive(Clone, Debug)]
pub struct VaultUtxo {
    pub txid: [u8; 32],
    pub index: u32,
    pub amount: u64,
    /// Which leaf's address holds it.
    pub leaf: u32,
}

/// A signed, ready-to-broadcast spend.
#[derive(Clone, Debug)]
pub struct SignedSpend {
    /// The digest that was signed — what the redeem script will reconstruct.
    pub digest: [u8; 32],
    /// P2SH signature script: witness pushes followed by the redeem script.
    pub signature_script: Vec<u8>,
    /// The redeem script, for reference and for computing the address.
    pub redeem_script: Vec<u8>,
    /// Whether this came from a fresh signature or a stored one.
    pub reused_stored_signature: bool,
    /// One-time keys left in this vault after the spend. Surfaced so the user
    /// learns the number is falling before it runs out.
    pub budget: LeafBudget,
    /// Where the change output should be sent for the vault to advance.
    /// A migration target means this vault is out of leaves.
    pub change_target: ChangeTarget,
    /// What the spend will cost, computed before the signature existed.
    pub preflight: PreflightReport,
}

/// Assemble the P2SH witness: `path[h-1] … path[0], y[p-1] … y[0], C`.
///
/// The signed message is deliberately absent — the redeem script rebuilds it
/// from introspection. Including it would let anyone holding a signature
/// redirect the spend.
pub(crate) fn witness_pushes(signature: &[u8]) -> Result<Vec<u8>> {
    ensure!(signature.len() == PARAMS.signature_len(), "unexpected signature length");

    let c = &signature[8..40];
    let y_end = 40 + PARAMS.p * N;
    let y: Vec<&[u8]> = signature[40..y_end].chunks_exact(N).collect();
    let path: Vec<&[u8]> = signature[y_end + 4..].chunks_exact(N).collect();

    let mut w = ScriptWriter::new();
    for node in path.iter().rev() {
        w.data(node)?;
    }
    for yi in y.iter().rev() {
        w.data(yi)?;
    }
    w.data(c)?;
    Ok(w.build())
}

/// Build and sign a canonical vault spend.
///
/// `signing_key` must be positioned at `utxo.leaf`; the caller is responsible
/// for advancing it, because how a wallet reconstructs one-time-key state is
/// its own concern. The journal is what prevents that going wrong.
///
/// Re-invoking with identical outputs returns the stored signature rather than
/// producing a second one, so retrying a broadcast is safe. Invoking with
/// *different* outputs for a leaf that has already signed fails.
pub fn build_spend<J: SpendJournal + ?Sized>(
    journal: &mut J,
    vault: &Vault,
    signing_key: &mut lms::LmsSigningKey,
    utxo: &VaultUtxo,
    key_index: u32,
    tx_version: u16,
    outputs: &[OutputView],
    params: &Params,
    budget_units: u16,
) -> Result<SignedSpend> {
    ensure!(
        outputs.len() == CANONICAL_OUTPUT_COUNT,
        "a vault spend must have exactly {CANONICAL_OUTPUT_COUNT} outputs \
         (destination and change); the redeem script is unrolled to that shape \
         and a different count is a different address"
    );
    ensure!(utxo.leaf < vault.leaf_count(), "leaf {} out of range", utxo.leaf);

    // Everything that could get the transaction rejected is checked BEFORE the
    // one-time key signs. After signing there is no remedy: changing the fee or
    // the outputs changes the binding digest, and the leaf cannot sign twice.
    let report = preflight(params, vault, utxo, tx_version, outputs, budget_units)?;

    let view = SpendView {
        tx_version,
        outpoint_txid: utxo.txid,
        outpoint_index: utxo.index,
        outputs: outputs.to_vec(),
    };
    let digest = binding_digest(&view)?;

    let leaf_id = LeafId::new(vault.public_key.id, utxo.leaf);
    let outcome = sign_once(journal, leaf_id, digest, || {
        ensure!(
            signing_key.leaf_index() == utxo.leaf,
            "signing key is at leaf {} but the UTXO is at leaf {}",
            signing_key.leaf_index(),
            utxo.leaf
        );
        signing_key
            .sign_internal(&digest)
            .map(|sig| sig.to_vec())
            .ok_or_else(|| anyhow::anyhow!("signing key is exhausted"))
    })?;

    let redeem_script = vault.redeem_script(utxo.leaf)?;
    let signature_script =
        pay_to_script_hash_signature_script(redeem_script.clone(), witness_pushes(outcome.signature())?)
            .map_err(|e| anyhow::anyhow!("signature script assembly failed: {e}"))?;

    Ok(SignedSpend {
        digest,
        signature_script,
        redeem_script,
        reused_stored_signature: matches!(outcome, SignOutcome::AlreadySigned(_)),
        budget: vault.budget_after(utxo.leaf),
        change_target: vault.change_target(key_index, utxo.leaf),
        preflight: report,
    })
}

/// A migration: move a vault's remaining balance into the next key index.
///
/// This is not a special transaction type — it is an ordinary spend whose
/// change output happens to be the next vault's leaf 0 rather than this
/// vault's next leaf. Which makes it available at *any* point, not only at
/// exhaustion: a user who wants a fresh vault early can take one.
///
/// The destination output is where the funds actually go; `change_address_spk`
/// is the next vault's leaf 0 script public key, which the caller derives
/// because doing so needs the seed.
pub struct MigrationPlan {
    /// The vault the funds are leaving.
    pub from_key_index: u32,
    /// The vault they are entering.
    pub to_key_index: u32,
    /// Leaf being spent.
    pub leaf: u32,
    /// Amount that will land in the new vault, after the fee.
    pub amount: u64,
}

/// Plan a migration of `utxo` into the next key index.
///
/// The whole balance moves, minus `fee`. Both outputs are required because the
/// redeem script is unrolled to the canonical two-output shape, so the
/// destination carries the funds and the change output carries the dust
/// minimum — a vault cannot emit a one-output transaction without being a
/// different address entirely.
pub fn plan_migration(
    vault: &Vault,
    key_index: u32,
    utxo: &VaultUtxo,
    fee: u64,
) -> Result<MigrationPlan> {
    ensure!(fee < utxo.amount, "fee {fee} exceeds the {} available", utxo.amount);
    let target = vault.change_target(key_index, utxo.leaf);
    Ok(MigrationPlan {
        from_key_index: key_index,
        to_key_index: target.key_index(),
        leaf: utxo.leaf,
        amount: utxo.amount - fee,
    })
}
