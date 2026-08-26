//! Transaction assembly: does a signed spend become something a node accepts,
//! and is the declared compute budget right?

use kaspa_bip32::{Language, Mnemonic};
use kaspa_consensus_core::config::params::{Params, TESTNET_PARAMS};
use lms_script::binding::OutputView;
use lms_wallet::derivation::{derive_xi, Scheme};
use lms_wallet::journal::MemoryJournal;
use lms_wallet::spend::{build_spend, VaultUtxo};
use lms_wallet::tx::{assemble, verify_and_measure, BUDGET_MARGIN_UNITS};
use lms_wallet::vault::Vault;

static TN_PARAMS: Params = TESTNET_PARAMS;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn xi() -> &'static [u8; 32] {
    static XI: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    XI.get_or_init(|| {
        let m = Mnemonic::new(TEST_MNEMONIC, Language::English).unwrap();
        let seed = hex::decode(m.create_seed(None)).unwrap();
        derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap()
    })
}

/// A standard pay-to-script-hash output. Preflight rejects non-standard script
/// types, as a mempool would, so test outputs must be real scripts.
fn p2sh_output(amount: u64, tag: u8) -> OutputView {
    let spk = kaspa_txscript::pay_to_script_hash_script(&[tag; 40]);
    OutputView { amount, spk_version: spk.version(), script: spk.script().to_vec() }
}

fn outputs() -> Vec<OutputView> {
    vec![
        p2sh_output(900_000_000, 0xaa),
        p2sh_output(90_000_000, 0xbb),
    ]
}

fn utxo() -> VaultUtxo {
    VaultUtxo { txid: [0x77; 32], index: 0, amount: 1_000_000_000, leaf: 0 }
}

/// The whole path: derive, sign, assemble, verify.
#[test]
fn a_signed_spend_assembles_into_a_verifying_transaction() {
    let (vault, mut sk) = Vault::from_xi(xi());
    let mut journal = MemoryJournal::default();

    let signed =
        build_spend(&mut journal, &vault, &mut sk, &utxo(), 0, 1, &outputs(), &TN_PARAMS, 60).expect("sign");
    let assembled = assemble(&signed, &utxo(), 1, &outputs()).expect("assemble");

    println!(
        "assembled spend: {} script units, {} compute-budget units declared, \
         ~{} compute mass",
        assembled.measured_script_units,
        assembled.declared_budget_units,
        assembled.approx_compute_mass()
    );

    assert_eq!(assembled.tx.inputs.len(), 1);
    assert_eq!(assembled.tx.outputs.len(), 2);
    assert!(assembled.measured_script_units > 0);
}

/// The declared budget must cover the measured cost, with the margin on top —
/// under-declaring aborts the script and burns the one-time key for nothing.
#[test]
fn the_declared_budget_covers_the_measured_cost() {
    let (vault, mut sk) = Vault::from_xi(xi());
    let mut journal = MemoryJournal::default();

    let signed = build_spend(&mut journal, &vault, &mut sk, &utxo(), 0, 1, &outputs(), &TN_PARAMS, 60).unwrap();
    let assembled = assemble(&signed, &utxo(), 1, &outputs()).unwrap();

    let declared_units = u64::from(assembled.declared_budget_units) * 100 * 100;
    assert!(
        declared_units >= assembled.measured_script_units,
        "declared {declared_units} script units but the spend consumed {}",
        assembled.measured_script_units
    );

    // And not wastefully loose: over-declaring is paid for in mass.
    let needed = assembled.measured_script_units.div_ceil(100).div_ceil(100);
    assert_eq!(
        u64::from(assembled.declared_budget_units),
        needed + u64::from(BUDGET_MARGIN_UNITS),
        "budget should be the measured requirement plus the margin, nothing more"
    );
}

/// Assembly re-verifies under the real budget, so a spend that a node would
/// reject fails here instead — before the key is spent.
#[test]
fn assembly_verifies_under_the_declared_budget() {
    let (vault, mut sk) = Vault::from_xi(xi());
    let mut journal = MemoryJournal::default();

    let signed = build_spend(&mut journal, &vault, &mut sk, &utxo(), 0, 1, &outputs(), &TN_PARAMS, 60).unwrap();
    let assembled = assemble(&signed, &utxo(), 1, &outputs()).unwrap();

    verify_and_measure(&assembled.tx, &assembled.utxo)
        .expect("assembled transaction must verify as a node would verify it");
}

/// Outputs that differ from the ones signed must not assemble — the binding
/// digest would not match and the node would reject.
#[test]
fn assembling_with_different_outputs_fails() {
    let (vault, mut sk) = Vault::from_xi(xi());
    let mut journal = MemoryJournal::default();

    let signed = build_spend(&mut journal, &vault, &mut sk, &utxo(), 0, 1, &outputs(), &TN_PARAMS, 60).unwrap();

    let mut redirected = outputs();
    redirected[0].script = vec![0xcc; 34];
    assert!(
        assemble(&signed, &utxo(), 1, &redirected).is_err(),
        "a redirected output assembled into a transaction"
    );
}

/// Spending more than the UTXO holds is refused at assembly.
#[test]
fn overspending_is_refused_at_assembly() {
    let (vault, mut sk) = Vault::from_xi(xi());
    let mut journal = MemoryJournal::default();

    let signed = build_spend(&mut journal, &vault, &mut sk, &utxo(), 0, 1, &outputs(), &TN_PARAMS, 60).unwrap();

    let mut too_much = outputs();
    too_much[0].amount = 2_000_000_000;
    assert!(assemble(&signed, &utxo(), 1, &too_much).is_err());
}
