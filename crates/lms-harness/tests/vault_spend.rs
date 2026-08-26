//! A full vault spend, executed by the consensus engine.
//!
//! Derives a vault from a mnemonic, funds a leaf address, builds a canonical
//! two-output spend, computes the binding digest off-chain, signs it with the
//! reference LMS implementation, and spends the P2SH output.
//!
//! This is the first test where every piece is load-bearing at once: the
//! derivation, the redeem script, the in-script digest reconstruction, and the
//! unrolled LMS verifier. If it passes, a vault is spendable.

use kaspa_bip32::{Language, Mnemonic};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use kaspa_txscript::{pay_to_script_hash_script, pay_to_script_hash_signature_script};
use lms_harness::execute_with_tx;
use lms_script::binding::{binding_digest, OutputView, SpendView};
use lms_script::params::N;
use lms_script::ScriptWriter;
use kaspa_consensus_core::config::params::{Params, TESTNET_PARAMS};
use lms_wallet::derivation::{derive_xi, Scheme};
use lms_wallet::vault::{Vault, CANONICAL_OUTPUT_COUNT, PARAMS};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const FUNDING_TXID: [u8; 32] = [0x77; 32];
const FUNDING_INDEX: u32 = 0;
const FUNDING_AMOUNT: u64 = 1_000_000_000;

static TN_PARAMS: Params = TESTNET_PARAMS;

fn seed() -> Vec<u8> {
    let m = Mnemonic::new(TEST_MNEMONIC, Language::English).unwrap();
    hex::decode(m.create_seed(None)).unwrap()
}

/// The canonical spend shape: destination plus change.
/// A standard pay-to-script-hash output. Preflight rejects non-standard script
/// types, as a mempool would, so test outputs must be real scripts.
fn p2sh_output(amount: u64, tag: u8) -> OutputView {
    let spk = kaspa_txscript::pay_to_script_hash_script(&[tag; 40]);
    OutputView { amount, spk_version: spk.version(), script: spk.script().to_vec() }
}

fn spend_outputs() -> Vec<OutputView> {
    vec![
        p2sh_output(900_000_000, 0xaa),
        p2sh_output(90_000_000, 0xbb),
    ]
}

/// Build the witness: `path[h-1] … path[0], y[p-1] … y[0], C`.
///
/// The signed message is deliberately absent — the script rebuilds it.
fn witness(sig: &[u8]) -> Vec<u8> {
    assert_eq!(sig.len(), PARAMS.signature_len());
    let c: [u8; N] = sig[8..40].try_into().unwrap();
    let y_end = 40 + PARAMS.p * N;
    let y: Vec<&[u8]> = sig[40..y_end].chunks_exact(N).collect();
    let path: Vec<&[u8]> = sig[y_end + 4..].chunks_exact(N).collect();

    let mut w = ScriptWriter::new();
    for node in path.iter().rev() {
        w.data(node).unwrap();
    }
    for yi in y.iter().rev() {
        w.data(yi).unwrap();
    }
    w.data(&c).unwrap();
    w.build()
}

struct Spend {
    tx: Transaction,
    utxos: Vec<UtxoEntry>,
    redeem_script: Vec<u8>,
}

/// Assemble a complete spend of `leaf`, signing whatever digest the given
/// outputs produce.
fn build_spend(leaf: u32, outputs: Vec<OutputView>, tamper: impl FnOnce(&mut Vec<OutputView>)) -> Spend {
    let xi = derive_xi(&seed(), Scheme::LmsSha256, 0, 0).unwrap();
    let (vault, mut signing_key) = Vault::from_xi(&xi);

    // Burn leaves until the signing key is positioned at the one we want,
    // mirroring how a real wallet advances through its one-time keys.
    for _ in 0..leaf {
        signing_key.sign_internal(&[0u8; 32]).expect("leaf available");
    }

    let redeem_script = vault.redeem_script(leaf).expect("redeem script");
    let funding_spk = pay_to_script_hash_script(&redeem_script);

    // The digest is computed over the outputs as they will appear on-chain.
    let view = SpendView {
        tx_version: 1,
        outpoint_txid: FUNDING_TXID,
        outpoint_index: FUNDING_INDEX,
        outputs: outputs.clone(),
    };
    let digest = binding_digest(&view).expect("binding digest");
    let sig = signing_key.sign_internal(&digest).expect("sign");

    // Tampering happens *after* signing, so the signature covers the original.
    let mut broadcast_outputs = outputs;
    tamper(&mut broadcast_outputs);

    let signature_script =
        pay_to_script_hash_signature_script(redeem_script.clone(), witness(&sig)).expect("sig script");

    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&FUNDING_TXID), FUNDING_INDEX);
    let input = TransactionInput::new_with_compute_budget(outpoint, signature_script, 0, 2000);
    let tx = Transaction::new(
        1,
        vec![input],
        broadcast_outputs
            .iter()
            .map(|o| {
                TransactionOutput::new(
                    o.amount,
                    ScriptPublicKey::new(o.spk_version, ScriptVec::from_slice(&o.script)),
                )
            })
            .collect(),
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let utxo = UtxoEntry::new(FUNDING_AMOUNT, funding_spk, 0, false, None);

    Spend { tx, utxos: vec![utxo], redeem_script }
}

fn run(spend: &Spend) -> anyhow::Result<lms_harness::Cost> {
    execute_with_tx(&spend.redeem_script, &spend.tx, spend.utxos.clone(), 0)
}

/// The headline: a vault spend verifies.
#[test]
fn vault_spend_verifies() {
    let spend = build_spend(0, spend_outputs(), |_| {});
    let cost = run(&spend).expect("vault spend was rejected");

    let sig_script_len = spend.tx.inputs[0].signature_script.len();
    println!(
        "vault spend: redeem {} B, signature script {} B, total input witness {} B",
        spend.redeem_script.len(),
        sig_script_len,
        sig_script_len
    );
    println!(
        "  {} script units = {} grams, {} compute-budget units",
        cost.script_units,
        cost.grams(),
        cost.compute_budget_units()
    );

    let tx_bytes = sig_script_len + spend.tx.outputs.iter().map(|o| o.script_public_key.script().len() + 10).sum::<usize>() + 100;
    let compute_mass = tx_bytes as u64 + cost.grams();
    println!(
        "  approx tx {tx_bytes} B -> ~{compute_mass} compute mass, \
         ~{} spends/block, fee floor ~{:.4} KAS",
        500_000 / compute_mass.max(1),
        (compute_mass * 100) as f64 / 100_000_000.0
    );
}

/// Several leaves, since each is a distinct script and address.
#[test]
fn multiple_leaves_spend() {
    for leaf in [0u32, 1, 7, 31] {
        let spend = build_spend(leaf, spend_outputs(), |_| {});
        run(&spend).unwrap_or_else(|e| panic!("leaf {leaf} rejected: {e}"));
    }
}

/// Redirecting an output after signing must fail. This is the property the
/// whole binding-digest construction exists to provide — without it, anyone
/// holding a valid signature could reroute the funds.
#[test]
fn redirecting_an_output_is_rejected() {
    let spend = build_spend(0, spend_outputs(), |outputs| {
        outputs[0].script = vec![0xcc; 34]; // attacker's script
    });
    assert!(run(&spend).is_err(), "a redirected output was accepted");
}

/// Changing an amount after signing must fail.
#[test]
fn changing_an_amount_is_rejected() {
    let spend = build_spend(0, spend_outputs(), |outputs| {
        outputs[0].amount += 1;
        outputs[1].amount -= 1;
    });
    assert!(run(&spend).is_err(), "an altered amount was accepted");
}

/// Dropping the change output must fail: the count is part of the digest and
/// the script is unrolled to a fixed shape.
#[test]
fn changing_the_output_count_is_rejected() {
    let spend = build_spend(0, spend_outputs(), |outputs| {
        outputs.truncate(1);
    });
    assert!(run(&spend).is_err(), "a different output count was accepted");
}

/// A signature made for one leaf must not spend another leaf's UTXO.
#[test]
fn a_signature_does_not_transfer_between_leaves() {
    let xi = derive_xi(&seed(), Scheme::LmsSha256, 0, 0).unwrap();
    let (vault, mut sk) = Vault::from_xi(&xi);

    let view = SpendView {
        tx_version: 1,
        outpoint_txid: FUNDING_TXID,
        outpoint_index: FUNDING_INDEX,
        outputs: spend_outputs(),
    };
    let sig = sk.sign_internal(&binding_digest(&view).unwrap()).unwrap(); // leaf 0

    // Present it against leaf 1's script.
    let redeem_script = vault.redeem_script(1).unwrap();
    let signature_script =
        pay_to_script_hash_signature_script(redeem_script.clone(), witness(&sig)).unwrap();
    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&FUNDING_TXID), FUNDING_INDEX);
    let input = TransactionInput::new_with_compute_budget(outpoint, signature_script, 0, 2000);
    let tx = Transaction::new(
        1,
        vec![input],
        spend_outputs()
            .iter()
            .map(|o| {
                TransactionOutput::new(
                    o.amount,
                    ScriptPublicKey::new(o.spk_version, ScriptVec::from_slice(&o.script)),
                )
            })
            .collect(),
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let utxo =
        UtxoEntry::new(FUNDING_AMOUNT, pay_to_script_hash_script(&redeem_script), 0, false, None);

    assert!(
        execute_with_tx(&redeem_script, &tx, vec![utxo], 0).is_err(),
        "a leaf-0 signature spent leaf 1"
    );
}

/// The canonical shape is what `redeem_script` produces.
#[test]
fn canonical_shape_is_two_outputs() {
    assert_eq!(CANONICAL_OUTPUT_COUNT, 2);
    let xi = derive_xi(&seed(), Scheme::LmsSha256, 0, 0).unwrap();
    let (vault, _) = Vault::from_xi(&xi);
    assert_eq!(
        vault.redeem_script(0).unwrap(),
        vault.redeem_script_for_shape(0, CANONICAL_OUTPUT_COUNT).unwrap()
    );
    assert_ne!(
        vault.redeem_script(0).unwrap(),
        vault.redeem_script_for_shape(0, 1).unwrap(),
        "a different output count must be a different script"
    );
}

/// The wallet's own output spends under the consensus engine.
///
/// The tests above build the signature script by hand. This one goes through
/// `lms_wallet::build_spend` — journal, sign-once check, witness assembly and
/// all — and feeds the result to the engine. Without it, the wallet could
/// produce well-formed bytes that no node would accept.
#[test]
fn wallet_built_spend_verifies() {
    use lms_script::binding::OutputView;
    use lms_wallet::journal::MemoryJournal;
    use lms_wallet::spend::{build_spend, VaultUtxo};

    let xi = derive_xi(&seed(), Scheme::LmsSha256, 0, 0).unwrap();
    let (vault, mut sk) = Vault::from_xi(&xi);
    let mut journal = MemoryJournal::default();

    let outputs: Vec<OutputView> = spend_outputs();
    let utxo = VaultUtxo { txid: FUNDING_TXID, index: FUNDING_INDEX, amount: FUNDING_AMOUNT, leaf: 0 };

    let signed = build_spend(&mut journal, &vault, &mut sk, &utxo, 0, 1, &outputs, &TN_PARAMS, 60).expect("build_spend");
    assert!(!signed.reused_stored_signature);

    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&FUNDING_TXID), FUNDING_INDEX);
    let input = TransactionInput::new_with_compute_budget(outpoint, signed.signature_script.clone(), 0, 2000);
    let tx = Transaction::new(
        1,
        vec![input],
        outputs
            .iter()
            .map(|o| {
                TransactionOutput::new(
                    o.amount,
                    ScriptPublicKey::new(o.spk_version, ScriptVec::from_slice(&o.script)),
                )
            })
            .collect(),
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let utxo_entry = UtxoEntry::new(
        FUNDING_AMOUNT,
        pay_to_script_hash_script(&signed.redeem_script),
        0,
        false,
        None,
    );

    execute_with_tx(&signed.redeem_script, &tx, vec![utxo_entry], 0)
        .expect("a wallet-built spend was rejected by the engine");

    // And the stored signature, replayed for a rebroadcast, still spends.
    let replayed = build_spend(&mut journal, &vault, &mut sk, &utxo, 0, 1, &outputs, &TN_PARAMS, 60).unwrap();
    assert!(replayed.reused_stored_signature);
    assert_eq!(replayed.signature_script, signed.signature_script);
}
