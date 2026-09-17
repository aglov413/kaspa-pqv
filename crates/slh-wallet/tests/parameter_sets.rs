//! A complete wallet-level spend under **every** SLH-DSA parameter set.
//!
//! The rest of this crate's tests run on `128s` and are about wallet mechanics
//! — fee floors, storage mass, rebuilding at a different fee — which do not
//! depend on the parameter set. This file is about the part that does: that a
//! vault derived under each set produces an address, signs the binding digest
//! its own script reconstructs, and verifies under the real engine with the
//! compute budget enforced.
//!
//! `SLH-DSA-SHA2-128-24` is here too, behind `#[ignore]`, because its key
//! generation is 4,194,304 WOTS+ public keys — about a hundred seconds, and
//! then twenty seconds per signature. That is a property of `d = 1` worth
//! measuring rather than hiding, and it is stated in the test's name:
//!
//! ```text
//! cargo test --release -p slh-wallet --test parameter_sets -- --ignored --nocapture
//! ```

use kaspa_bip32::{Language, Mnemonic};
use kaspa_consensus_core::config::params::{Params, TESTNET_PARAMS};
use kaspa_txscript::pay_to_script_hash_script;
use slh_script::params::{Params as SlhParams, SHA2_128_24};
use slh_wallet::spend::{build_spend, verify, VaultUtxo};
use slh_wallet::{derive_xi, params_for, SlhVault, SLH_SCHEMES};
use vault_core::binding::OutputView;

static TN: Params = TESTNET_PARAMS;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const FUNDING_TXID: [u8; 32] = [0x77; 32];
const FUNDING_AMOUNT: u64 = 1_000_000_000; // 10 TKAS
const TX_VERSION: u16 = 1;

fn seed() -> Vec<u8> {
    let m = Mnemonic::new(TEST_MNEMONIC, Language::English).unwrap();
    hex::decode(m.create_seed(None)).unwrap()
}

/// Build, sign and verify one spend, returning what it cost.
fn spend_under(set: &'static SlhParams) -> (usize, u64, u64, u64) {
    let (scheme, _) = SLH_SCHEMES
        .iter()
        .find(|(s, p)| params_for(*s).is_some() && p.name == set.name)
        .expect("every set has a scheme");

    let xi = derive_xi(&seed(), *scheme, 0, 0).unwrap();
    let (vault, keypair) = SlhVault::from_xi(set, &xi).unwrap();

    let change_spk = pay_to_script_hash_script(&vault.redeem_script().unwrap());
    let send = 500_000_000u64;
    let fee = 50_000_000u64;
    let outputs = vec![
        OutputView {
            amount: send,
            spk_version: pay_to_script_hash_script(&[0xaa; 40]).version(),
            script: pay_to_script_hash_script(&[0xaa; 40]).script().to_vec(),
        },
        OutputView {
            amount: FUNDING_AMOUNT - send - fee,
            spk_version: change_spk.version(),
            script: change_spk.script().to_vec(),
        },
    ];

    let redeem = vault.redeem_script().unwrap();
    let utxo = VaultUtxo { txid: FUNDING_TXID, index: 0, amount: FUNDING_AMOUNT };
    let spend = build_spend(&TN, &vault, &keypair, &utxo, TX_VERSION, &outputs)
        .unwrap_or_else(|e| panic!("{}: building the spend failed: {e}", set.name));

    // `build_spend` already ran this, but running it again here is what makes
    // the assertion belong to this test rather than to a call it made.
    verify(&spend.tx, &spend.utxo, Some(spend.declared_budget_units))
        .unwrap_or_else(|e| panic!("{}: the spend does not verify under its budget: {e}", set.name));

    assert!(
        spend.report.normalized_max_mass <= TN.block_mass_limits.compute,
        "{}: a spend needing {} normalized mass can never be mined",
        set.name,
        spend.report.normalized_max_mass
    );

    // The signature script is the witness followed by a push of the redeem
    // script — which is the one place a mixed-up parameter set would show as a
    // size rather than as a verification failure. The push header is 3 or 5
    // bytes depending on the script's length, so the sizes are checked by
    // containment rather than by an arithmetic identity that would encode which
    // opcode this set happens to need.
    let sig_script = &spend.tx.inputs[0].signature_script;
    let witness = vault.plan.placeholder_witness().unwrap();
    assert!(sig_script.ends_with(&redeem), "{}: the redeem script is not at the end", set.name);
    assert!(
        (3..=5).contains(&(sig_script.len() - redeem.len() - witness.len())),
        "{}: signature script is not the witness plus one push of the redeem script",
        set.name
    );

    println!(
        "  {:<24} redeem {:>7} B   tx {:>7} B   units {:>9}   budget {:>4}   fee floor {:.4} TKAS",
        set.name,
        spend.redeem_script.len(),
        spend.size(),
        spend.measured_script_units,
        spend.declared_budget_units,
        spend.report.minimum_fee as f64 / 100_000_000.0
    );

    (spend.redeem_script.len(), spend.size(), spend.measured_script_units, spend.report.minimum_fee)
}

/// Every set whose key generation is not minutes of hashing.
#[test]
fn a_vault_spend_verifies_under_every_fast_set() {
    println!("\n=== wallet-level spend, one input, two outputs ===");
    let mut rows = Vec::new();
    for (_, set) in SLH_SCHEMES.iter().filter(|(_, p)| p.hp < 16) {
        rows.push((set.name, spend_under(set)));
    }
    assert_eq!(rows.len(), 2, "expected two fast sets; the roster changed");
}

/// The set the fast path leaves out, so nothing about it is taken on trust.
///
/// `128s` is measured alongside it in the same process rather than compared
/// against numbers written down here, so the comparison cannot go stale.
#[test]
#[ignore = "SLH-DSA-SHA2-128-24 key generation is 2^22 WOTS+ public keys; run explicitly"]
fn a_vault_spend_verifies_under_the_d1_set() {
    println!("\n=== wallet-level spend, one input, two outputs ===");
    let baseline = spend_under(params_for(slh_wallet::Scheme::SlhDsaSha2_128s).unwrap());

    let started = std::time::Instant::now();
    let d1 = spend_under(&SHA2_128_24);
    println!(
        "  keygen, signing and verification took {:?} — the cost of d=1 on the signer",
        started.elapsed()
    );

    // The claim this set exists to make, as an assertion rather than a note:
    // its spend is smaller and cheaper than the standardised one.
    let (redeem, tx_size, units, fee) = d1;
    assert!(redeem < baseline.0, "128-24's redeem script is not smaller ({redeem} B)");
    assert!(tx_size < baseline.1, "128-24's transaction is not smaller ({tx_size} B)");
    assert!(units < baseline.2, "128-24 is not cheaper to verify ({units} units)");
    assert!(fee < baseline.3, "128-24's fee floor is not lower ({fee} sompi)");
    println!(
        "\n  128-24 is {:.2}x the transaction bytes and {:.2}x the fee floor of 128s.",
        tx_size as f64 / baseline.1 as f64,
        fee as f64 / baseline.3 as f64
    );
}
