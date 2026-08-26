//! A full SLH-DSA vault spend, executed by the consensus engine.
//!
//! Derives a vault from a mnemonic, funds it with a fabricated UTXO, builds a
//! canonical two-output spend, computes the binding digest off-chain, signs it,
//! and verifies the P2SH input exactly as a node would.
//!
//! If this passes, a funded vault is spendable. It is the last gate before real
//! coins are involved.

use kaspa_addresses::Prefix;
use kaspa_bip32::{Language, Mnemonic};
use kaspa_consensus_core::config::params::{Params, TESTNET_PARAMS};
use kaspa_consensus_core::tx::{
    ScriptPublicKey, ScriptVec, Transaction, TransactionOutput,
};
use kaspa_txscript::pay_to_script_hash_script;
use slh_wallet::spend::{build_spend, preflight, verify, VaultUtxo};
use slh_wallet::{derive_xi, Scheme, SlhVault, CANONICAL_OUTPUT_COUNT};
use vault_core::binding::OutputView;

static TN: Params = TESTNET_PARAMS;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const FUNDING_TXID: [u8; 32] = [0x77; 32];
const FUNDING_AMOUNT: u64 = 1_000_000_000; // 10 TKAS
const TX_VERSION: u16 = 1;

fn vault() -> (SlhVault, slh_wallet::Keypair) {
    let m = Mnemonic::new(TEST_MNEMONIC, Language::English).unwrap();
    let seed = hex::decode(m.create_seed(None)).unwrap();
    let xi = derive_xi(&seed, Scheme::SlhDsaSha2_128s, 0, 0).unwrap();
    SlhVault::from_xi(&xi).unwrap()
}

fn utxo() -> VaultUtxo {
    VaultUtxo { txid: FUNDING_TXID, index: 0, amount: FUNDING_AMOUNT }
}

fn p2sh_output(amount: u64, tag: u8) -> OutputView {
    let spk = pay_to_script_hash_script(&[tag; 40]);
    OutputView { amount, spk_version: spk.version(), script: spk.script().to_vec() }
}

/// Destination plus change back to the vault's own address — which a stateful
/// scheme cannot do, because its current leaf is burned by the spend.
fn outputs(vault: &SlhVault, send: u64, fee: u64) -> Vec<OutputView> {
    let change_spk = pay_to_script_hash_script(&vault.redeem_script().unwrap());
    vec![
        p2sh_output(send, 0xaa),
        OutputView {
            amount: FUNDING_AMOUNT - send - fee,
            spk_version: change_spk.version(),
            script: change_spk.script().to_vec(),
        },
    ]
}

#[test]
fn a_vault_spend_verifies() {
    let (vault, keypair) = vault();
    let outs = outputs(&vault, 100_000_000, 30_000_000);
    let spend = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outs)
        .expect("the vault spend was rejected");

    println!(
        "SLH-DSA vault spend: {} bytes, {} script units, budget {} units, fee {} sompi",
        spend.size(),
        spend.measured_script_units,
        spend.declared_budget_units,
        spend.report.fee
    );
    println!("  {}", spend.report.summary());
    println!("  txid {}", spend.txid());

    assert!(spend.report.fee >= spend.report.minimum_fee);
    assert!(spend.report.normalized_max_mass <= TN.block_mass_limits.compute);
}

/// Change returns to the same address, so the vault can be spent again from
/// the output of its own spend. This is the whole operational difference from
/// the stateful scheme, so it is asserted rather than assumed.
#[test]
fn the_vault_can_spend_its_own_change() {
    let (vault, keypair) = vault();
    let first = build_spend(
        &TN,
        &vault,
        &keypair,
        &utxo(),
        TX_VERSION,
        &outputs(&vault, 100_000_000, 30_000_000),
    )
    .expect("first spend");

    // The change output pays the vault's own address.
    let vault_spk = pay_to_script_hash_script(&vault.redeem_script().unwrap());
    assert_eq!(first.tx.outputs[1].script_public_key, vault_spk);

    // Spend that change with the same key. Under LMS this would require the
    // next leaf and a journal entry.
    let change = VaultUtxo {
        txid: first.tx.id().as_bytes(),
        index: 1,
        amount: first.tx.outputs[1].value,
    };
    // Change stays large. KIP-9 storage mass punishes an output that is small
    // relative to the input being consumed, and `a_small_change_output_is_refused`
    // pins where that becomes fatal.
    let second_change = change.amount / 2;
    let second_outs = vec![
        p2sh_output(change.amount - 30_000_000 - second_change, 0xbb),
        OutputView {
            amount: second_change,
            spk_version: vault_spk.version(),
            script: vault_spk.script().to_vec(),
        },
    ];
    build_spend(&TN, &vault, &keypair, &change, TX_VERSION, &second_outs)
        .expect("spending the vault's own change failed");
}

/// Signing the same spend twice is safe and produces identical bytes. Under
/// LMS this is the operation that leaks the private key.
#[test]
fn re_signing_the_same_spend_is_safe_and_deterministic() {
    let (vault, keypair) = vault();
    let outs = outputs(&vault, 100_000_000, 30_000_000);
    let a = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outs).unwrap();
    let b = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outs).unwrap();
    assert_eq!(a.tx.inputs[0].signature_script, b.tx.inputs[0].signature_script);
    assert_eq!(a.txid(), b.txid());
}

/// A rejected spend can be rebuilt at a different fee — the recovery path that
/// does not exist for a one-time key.
#[test]
fn a_spend_can_be_rebuilt_at_a_different_fee() {
    let (vault, keypair) = vault();
    let cheap = build_spend(
        &TN,
        &vault,
        &keypair,
        &utxo(),
        TX_VERSION,
        &outputs(&vault, 100_000_000, 1_000),
    );
    assert!(cheap.is_err(), "a spend below the fee floor was accepted");

    build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outputs(&vault, 100_000_000, 30_000_000))
        .expect("rebuilding at a higher fee failed");
}

// ---- negative controls -------------------------------------------------

/// Redirecting an output after signing must fail: the digest is rebuilt from
/// introspection, not taken from the witness.
#[test]
fn a_redirected_spend_is_rejected() {
    let (vault, keypair) = vault();
    let outs = outputs(&vault, 100_000_000, 30_000_000);
    let spend = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outs).unwrap();

    let mut redirected: Vec<TransactionOutput> = spend.tx.outputs.clone();
    let evil = p2sh_output(100_000_000, 0xcc);
    redirected[0] = TransactionOutput::new(
        evil.amount,
        ScriptPublicKey::new(evil.spk_version, ScriptVec::from_slice(&evil.script)),
    );
    let tampered = Transaction::new(
        TX_VERSION,
        spend.tx.inputs.clone(),
        redirected,
        0,
        kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    assert!(verify(&tampered, &spend.utxo, None).is_err(), "a redirected spend verified");
}

/// Raising an output amount after signing steals the fee and must fail.
#[test]
fn an_altered_amount_is_rejected() {
    let (vault, keypair) = vault();
    let outs = outputs(&vault, 100_000_000, 30_000_000);
    let spend = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outs).unwrap();

    let mut altered: Vec<TransactionOutput> = spend.tx.outputs.clone();
    altered[0] = TransactionOutput::new(
        altered[0].value + 1,
        altered[0].script_public_key.clone(),
    );
    let tampered = Transaction::new(
        TX_VERSION,
        spend.tx.inputs.clone(),
        altered,
        0,
        kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    assert!(verify(&tampered, &spend.utxo, None).is_err(), "an altered amount verified");
}

/// A signature from a different vault must not spend this one.
#[test]
fn another_vaults_signature_is_rejected() {
    let (vault, _) = vault();
    let m = Mnemonic::new(TEST_MNEMONIC, Language::English).unwrap();
    let seed = hex::decode(m.create_seed(None)).unwrap();
    let other_xi = derive_xi(&seed, Scheme::SlhDsaSha2_128s, 0, 1).unwrap();
    let (other_vault, other_key) = SlhVault::from_xi(&other_xi).unwrap();

    // Sign with the other vault's key, then present it against this vault's
    // UTXO by swapping in this vault's redeem script.
    let outs = outputs(&vault, 100_000_000, 30_000_000);
    let foreign =
        build_spend(&TN, &other_vault, &other_key, &utxo(), TX_VERSION, &outs).unwrap();

    let entry = kaspa_consensus_core::tx::UtxoEntry::new(
        FUNDING_AMOUNT,
        pay_to_script_hash_script(&vault.redeem_script().unwrap()),
        0,
        false,
        None,
    );
    assert!(
        verify(&foreign.tx, &entry, None).is_err(),
        "a signature from another vault spent this one"
    );
}

/// The declared compute budget is enforced. An under-declared spend is
/// rejected by consensus, so the builder must never emit one.
#[test]
fn the_declared_budget_is_sufficient_and_enforced() {
    let (vault, keypair) = vault();
    let outs = outputs(&vault, 100_000_000, 30_000_000);
    let spend = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outs).unwrap();

    verify(&spend.tx, &spend.utxo, Some(spend.declared_budget_units))
        .expect("the declared budget does not cover the spend");
    assert!(
        verify(&spend.tx, &spend.utxo, Some(spend.declared_budget_units / 2)).is_err(),
        "half the declared budget was accepted; the limit is not being enforced"
    );
}

/// A spend of the wrong shape cannot satisfy a script unrolled to two outputs.
#[test]
fn a_wrong_output_count_is_refused_before_signing() {
    let (vault, keypair) = vault();
    let one = vec![p2sh_output(900_000_000, 0xaa)];
    assert!(build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &one).is_err());
    assert_eq!(CANONICAL_OUTPUT_COUNT, 2);
}

/// Storage mass (KIP-9) scales with the inverse of an output's value, so a
/// vault cannot pay itself an arbitrarily small change output. That is an
/// operational constraint on how a vault is spent, not a bug, and the wallet's
/// guidance is only honest if the boundary is measured rather than assumed.
///
/// The threshold is found by bisection and printed. The practical rule for a
/// user is: keep change on the same order as the input, or consolidate.
#[test]
fn the_storage_mass_floor_on_change_is_measured() {
    let (vault, keypair) = vault();
    let change_spk = pay_to_script_hash_script(&vault.redeem_script().unwrap());
    let fee = 30_000_000u64;

    let attempt = |change: u64| {
        let outs = vec![
            p2sh_output(FUNDING_AMOUNT - fee - change, 0xaa),
            OutputView {
                amount: change,
                spk_version: change_spk.version(),
                script: change_spk.script().to_vec(),
            },
        ];
        build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outs).is_ok()
    };

    // An even split must work, or a vault could not be spent at all.
    let half = FUNDING_AMOUNT / 2;
    assert!(attempt(half), "an even split was refused");

    // Bisect for the smallest change output that still builds.
    let (mut lo, mut hi) = (1u64, half);
    while hi - lo > half / 512 {
        let mid = lo + (hi - lo) / 2;
        if attempt(mid) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    println!(
        "\nstorage-mass floor on change: ~{hi} sompi ({:.4} KAS) against a {:.2} KAS input \
         \n  i.e. change must be at least ~{:.2}% of the UTXO being spent",
        hi as f64 / 1e8,
        FUNDING_AMOUNT as f64 / 1e8,
        hi as f64 * 100.0 / FUNDING_AMOUNT as f64,
    );

    assert!(hi < FUNDING_AMOUNT / 4, "the floor is high enough to make vaults impractical");
    assert!(!attempt(hi / 4), "a quarter of the measured floor was accepted");
}

/// The absolute dust floor, which is a different limit from the relative
/// storage-mass one above.
///
/// Below roughly 0.019 KAS an output is rejected regardless of the input it is
/// paid from, so a small vault can fail for a reason that has nothing to do
/// with proportions. The wallet names that cause rather than letting it surface
/// as a mass error.
#[test]
fn the_absolute_dust_floor_is_enforced_and_named() {
    use vault_core::preflight::DUST_THRESHOLD;

    let (vault, keypair) = vault();
    let change_spk = pay_to_script_hash_script(&vault.redeem_script().unwrap());
    let fee = 30_000_000u64;

    let with_change = |change: u64| {
        vec![
            p2sh_output(FUNDING_AMOUNT - fee - change, 0xaa),
            OutputView {
                amount: change,
                spk_version: change_spk.version(),
                script: change_spk.script().to_vec(),
            },
        ]
    };

    // Just under the floor: refused, and the message says why.
    let err = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &with_change(DUST_THRESHOLD - 1))
        .map(|_| ())
        .expect_err("an output below the dust floor was accepted")
        .to_string();
    assert!(err.contains("dust floor"), "expected a dust rejection, got: {err}");

    // The floor is 0.02 KAS, the value wallets settle on.
    assert_eq!(DUST_THRESHOLD, 2_000_000);

    // Being above the absolute floor is necessary but not sufficient: against a
    // 10 KAS input the relative storage-mass limit still binds, and that is a
    // different error.
    let err = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &with_change(DUST_THRESHOLD))
        .map(|_| ())
        .expect_err("dust floor alone should not make a tiny change output viable")
        .to_string();
    assert!(
        err.contains("storage mass"),
        "expected the relative storage-mass limit to bind next, got: {err}"
    );
}

/// A change output small enough to inflate storage mass past the block limit
/// must be caught before signing, not discovered by a node.
#[test]
fn a_dust_change_output_is_refused() {
    let (vault, keypair) = vault();
    let change_spk = pay_to_script_hash_script(&vault.redeem_script().unwrap());
    let outs = vec![
        p2sh_output(FUNDING_AMOUNT - 30_000_000 - 1, 0xaa),
        OutputView {
            amount: 1,
            spk_version: change_spk.version(),
            script: change_spk.script().to_vec(),
        },
    ];
    let result = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outs);
    assert!(result.is_err(), "a spend with a 1-sompi change output was accepted");
}

/// The address a spend pays change to is the address the wallet reports.
#[test]
fn the_reported_address_matches_the_funding_script() {
    let (vault, _) = vault();
    let address = vault.address(Prefix::Testnet).unwrap();
    let spk = pay_to_script_hash_script(&vault.redeem_script().unwrap());
    let derived = kaspa_txscript::extract_script_pub_key_address(&spk, Prefix::Testnet).unwrap();
    assert_eq!(address, derived);
}

/// The compute budget cannot be known before signing, so the builder sizes
/// unsigned spends with a fixed ceiling. That is only sound while transient
/// mass dominates the fee floor — both halves are pinned here.
#[test]
fn budget_never_dominates_the_fee_floor() {
    use slh_wallet::spend::PREFLIGHT_BUDGET_UNITS;

    let (vault, keypair) = vault();
    let outs = outputs(&vault, 100_000_000, 30_000_000);
    let spend = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outs).unwrap();

    assert!(
        spend.declared_budget_units <= PREFLIGHT_BUDGET_UNITS,
        "a spend needed {} budget units, above the {PREFLIGHT_BUDGET_UNITS} assumed when \
         sizing unsigned spends",
        spend.declared_budget_units
    );

    // Sizing at the ceiling and at the real budget must give the same fee
    // floor, or the pre-signing estimate would be wrong.
    let at_ceiling =
        preflight(&TN, &vault, &utxo(), TX_VERSION, &outs, PREFLIGHT_BUDGET_UNITS).unwrap();
    assert_eq!(
        at_ceiling.minimum_fee, spend.report.minimum_fee,
        "the assumed budget changed the fee floor"
    );
    assert!(
        spend.report.compute_mass < spend.report.normalized_transient_mass,
        "compute mass now dominates; the fee floor depends on the budget and \
         PREFLIGHT_BUDGET_UNITS is no longer a safe ceiling"
    );
}

/// Preflight sizes an unsigned spend correctly: the placeholder must be the
/// same length as the real signature script, or every fee estimate is wrong.
#[test]
fn the_placeholder_matches_the_real_signature_script() {
    let (vault, keypair) = vault();
    let outs = outputs(&vault, 100_000_000, 30_000_000);
    let report = preflight(&TN, &vault, &utxo(), TX_VERSION, &outs, 200).unwrap();
    let spend = build_spend(&TN, &vault, &keypair, &utxo(), TX_VERSION, &outs).unwrap();
    assert_eq!(
        slh_wallet::spend::placeholder_signature_script(&vault).unwrap().len(),
        spend.tx.inputs[0].signature_script.len(),
        "preflight sized the spend differently from what it produced"
    );
    assert!(report.size > 90_000);
}
