//! LMS against every SLH-DSA parameter set, measured the same way in the same
//! process.
//!
//! The point of this file is that the numbers are comparable. Every spend has
//! the same shape — one input, two standard outputs, the same funding amount —
//! all are executed by the same engine, and all are massed by the same
//! `MassCalculator` with the same network parameters. Nothing is quoted from a
//! previous session.
//!
//! The default run covers LMS, `128s` and `128-24d2`.
//! `every_scheme_measured_side_by_side` adds `SLH-DSA-SHA2-128-24`, whose key
//! generation is a hypertree of four million leaves, and is `#[ignore]`d for
//! that reason alone.

use kaspa_bip32::{Language, Mnemonic};
use kaspa_consensus_core::config::params::{Params, TESTNET_PARAMS};
use kaspa_consensus_core::constants::STORAGE_MASS_PARAMETER;
use kaspa_consensus_core::mass::{Mass, MassCalculator, MassCofactors};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::{pay_to_script_hash_script, pay_to_script_hash_signature_script};

use vault_harness::execute_with_tx;
use slh_script::params::{Params as SlhParams, ALL, SHA2_128S, SHA2_128_24_D2};
use slh_script::witness::BlobPlan;
use slh_script::{build_vault_script, SecretSeeds, SigningKey};
use vault_core::binding::{binding_digest, OutputView, SpendView};

static TN: Params = TESTNET_PARAMS;

const FUNDING_TXID: [u8; 32] = [0x77; 32];
const FUNDING_INDEX: u32 = 0;
const FUNDING_AMOUNT: u64 = 1_000_000_000;
const TX_VERSION: u16 = 1;
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn p2sh_output(amount: u64, tag: u8) -> OutputView {
    let spk = pay_to_script_hash_script(&[tag; 40]);
    OutputView { amount, spk_version: spk.version(), script: spk.script().to_vec() }
}

fn outputs() -> Vec<OutputView> {
    vec![p2sh_output(900_000_000, 0xaa), p2sh_output(90_000_000, 0xbb)]
}

fn digest_for() -> [u8; 32] {
    binding_digest(&SpendView {
        tx_version: TX_VERSION,
        outpoint_txid: FUNDING_TXID,
        outpoint_index: FUNDING_INDEX,
        outputs: outputs(),
    })
    .expect("binding digest")
}

fn assemble(redeem_script: Vec<u8>, witness: Vec<u8>, budget: u16) -> (Transaction, Vec<UtxoEntry>) {
    let funding_spk = pay_to_script_hash_script(&redeem_script);
    let signature_script =
        pay_to_script_hash_signature_script(redeem_script, witness).expect("signature script");
    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&FUNDING_TXID), FUNDING_INDEX);
    let input = TransactionInput::new_with_compute_budget(outpoint, signature_script, 0, budget);
    let tx = Transaction::new(
        TX_VERSION,
        vec![input],
        outputs()
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
    (tx, vec![UtxoEntry::new(FUNDING_AMOUNT, funding_spk, 0, false, None)])
}

struct Row {
    name: &'static str,
    stateful: bool,
    /// Signatures one key may make. LMS counts leaves; SLH-DSA counts the
    /// limit its parameter set was sized for.
    signature_limit: String,
    redeem: usize,
    sig_script: usize,
    tx_size: u64,
    units: u64,
    compute_mass: u64,
    normalized_transient: u64,
    normalized_max: u64,
    fee: u64,
}

fn mass_row(
    name: &'static str,
    stateful: bool,
    signature_limit: String,
    redeem: &[u8],
    tx: &Transaction,
    utxos: &[UtxoEntry],
    units: u64,
) -> Row {
    let calc = MassCalculator::new(TN.mass_per_tx_byte, TN.mass_per_script_pub_key_byte, STORAGE_MASS_PARAMETER);
    let non_contextual = calc.calc_non_contextual_masses(tx);
    let populated = PopulatedTransaction::new(tx, utxos.to_vec());
    let contextual = calc.calc_contextual_masses(&populated).expect("storage mass");
    let cofactors = MassCofactors::new(&TN.block_mass_limits);
    let normalized_transient = non_contextual.normalized_transient(&cofactors);
    let normalized_max = Mass::new(non_contextual, contextual).normalized_max(&cofactors);
    let fee_mass = non_contextual.compute_mass.max(normalized_transient);
    Row {
        name,
        stateful,
        signature_limit,
        redeem: redeem.len(),
        sig_script: tx.inputs[0].signature_script.len(),
        tx_size: kaspa_consensus_core::mass::transaction_estimated_serialized_size(tx),
        units,
        compute_mass: non_contextual.compute_mass,
        normalized_transient,
        normalized_max,
        fee: (fee_mass.saturating_mul(100_000) / 1000).max(100_000),
    }
}

/// Compute-budget units an input must declare to afford `units` script units.
///
/// Over-declaring is not free: the declared budget is multiplied into compute
/// mass whether or not the script uses it.
fn budget_for(units: u64) -> u16 {
    u16::try_from((units / 100).div_ceil(100)).expect("budget fits its u16 field")
}

fn lms_row() -> Row {
    use lms_wallet::derivation::{derive_xi, Scheme};
    use lms_wallet::vault::{Vault, PARAMS};
    use lms_script::params::N as LMS_N;

    let m = Mnemonic::new(TEST_MNEMONIC, Language::English).unwrap();
    let seed = hex::decode(m.create_seed(None)).unwrap();
    let xi = derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap();
    let (vault, mut key) = Vault::from_xi(&xi);

    let redeem = vault.redeem_script(0).expect("redeem script");
    let sig = key.sign_internal(&digest_for()).expect("sign");

    // The LMS witness: path, then chain values, then C. The message is absent.
    let c = &sig[8..40];
    let y_end = 40 + PARAMS.p * LMS_N;
    let mut w = vault_core::ScriptWriter::new();
    for node in sig[y_end + 4..].chunks_exact(LMS_N).rev() {
        w.data(node).unwrap();
    }
    for yi in sig[40..y_end].chunks_exact(LMS_N).rev() {
        w.data(yi).unwrap();
    }
    w.data(c).unwrap();

    let witness = w.build();
    let (tx, utxos) = assemble(redeem.clone(), witness.clone(), 60_000);
    let units = execute_with_tx(&redeem, &tx, utxos.clone(), 0).expect("LMS spend must verify").script_units;

    // Declare the budget this spend actually needs. An over-declared budget is
    // charged in full as compute mass, so leaving it at a round number would
    // make the comparison meaningless.
    let (tx, utxos) = assemble(redeem.clone(), witness, budget_for(units));
    mass_row("LMS h=15 w=2", true, "2^15".to_string(), &redeem, &tx, &utxos, units)
}

/// The signature limit each set was sized for, as a column rather than a
/// footnote: it is the only axis on which `128s` beats the other two, and a
/// table that omitted it would make them look strictly better.
///
/// Read from the set, not inferred from `h` — `h` is the hypertree height and
/// the two differ by a factor each set's analysis chooses.
fn signature_limit(set: &SlhParams) -> String {
    format!("2^{}", set.sig_limit_log2)
}

fn slh_row(set: &'static SlhParams) -> Row {
    let plan = BlobPlan::for_params(set);
    let seeds = SecretSeeds { sk_seed: [0x11; 16], sk_prf: [0x22; 16], pk_seed: [0x33; 16] };
    let key = SigningKey::generate(set, seeds);
    let pk = key.public_key();
    let redeem = build_vault_script(&pk, &plan, outputs().len()).expect("emit").script;
    let sig = key.sign(&digest_for());

    let (tx, utxos) = assemble(redeem.clone(), plan.witness_pushes(&sig).unwrap(), 60_000);
    let units = execute_with_tx(&redeem, &tx, utxos.clone(), 0)
        .unwrap_or_else(|e| panic!("{} spend must verify: {e}", set.name))
        .script_units;

    // Re-assemble declaring the budget this spend actually needs, which is what
    // the mass figures must reflect.
    let (tx, utxos) = assemble(redeem.clone(), plan.witness_pushes(&sig).unwrap(), budget_for(units));
    mass_row(set.name, false, signature_limit(set), &redeem, &tx, &utxos, units)
}

fn print_rows(rows: &[Row]) {
    println!("\n=== Same spend shape, same engine, same mass parameters ===");
    println!(
        "  {:<24} {:>8} {:>16} {:>9} {:>10} {:>10} {:>11} {:>10} {:>8} {:>8}",
        "scheme", "stateful", "signatures", "redeem B", "sigscript", "tx bytes", "units",
        "norm mass", "per blk", "fee KAS"
    );
    for r in rows {
        println!(
            "  {:<24} {:>8} {:>16} {:>9} {:>10} {:>10} {:>11} {:>10} {:>8} {:>8.4}",
            r.name,
            if r.stateful { "yes" } else { "no" },
            r.signature_limit,
            r.redeem,
            r.sig_script,
            r.tx_size,
            r.units,
            r.normalized_max,
            TN.block_mass_limits.compute / r.normalized_max.max(1),
            r.fee as f64 / 100_000_000.0,
        );
    }
}

fn check(rows: &[Row]) {
    let lms = &rows[0];
    for r in &rows[1..] {
        println!(
            "  {:<24} {:>6.2}x the bytes and {:>6.2}x the fee of LMS, and needs no state.",
            r.name,
            r.tx_size as f64 / lms.tx_size as f64,
            r.fee as f64 / lms.fee as f64,
        );
    }

    // Every row must be mineable at all, which is the only hard constraint here.
    for r in rows {
        assert!(
            r.normalized_max <= TN.block_mass_limits.compute,
            "{} needs {} normalized mass, over the block limit",
            r.name,
            r.normalized_max
        );
    }
}

#[test]
fn lms_versus_slh_dsa_measured_side_by_side() {
    let rows = [lms_row(), slh_row(&SHA2_128S), slh_row(&SHA2_128_24_D2)];
    print_rows(&rows);
    println!();
    check(&rows);
    println!(
        "\n  Mass axes — LMS compute {} vs normalized transient {}; {} {} vs {}.",
        rows[0].compute_mass,
        rows[0].normalized_transient,
        rows[1].name,
        rows[1].compute_mass,
        rows[1].normalized_transient
    );
}

/// Every scheme in the workspace, including the one that costs a minute of
/// hashing to hold a key for.
///
/// ```text
/// cargo test --release -p slh-script --test comparison -- --ignored --nocapture
/// ```
#[test]
#[ignore = "SLH-DSA-SHA2-128-24 key generation is ~2^22 WOTS+ public keys; run explicitly"]
fn every_scheme_measured_side_by_side() {
    let mut rows = vec![lms_row()];
    rows.extend(ALL.iter().map(|s| slh_row(s)));
    print_rows(&rows);
    println!();
    check(&rows);

    // The 2^24 sets exist to be cheaper than `128s`. If they are not, the
    // signature limit they accept buys nothing on this chain.
    let baseline = rows.iter().find(|r| r.name == SHA2_128S.name).expect("128s row");
    for r in rows.iter().filter(|r| !r.stateful && r.name != SHA2_128S.name) {
        assert!(
            r.tx_size < baseline.tx_size,
            "{} is not smaller than {}",
            r.name,
            baseline.name
        );
    }
}
