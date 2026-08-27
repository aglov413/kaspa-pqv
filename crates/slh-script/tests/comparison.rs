//! LMS against SLH-DSA, measured the same way in the same process.
//!
//! The point of this file is that the two numbers are comparable. Both spends
//! have the same shape — one input, two standard outputs, the same funding
//! amount — both are executed by the same engine, and both are massed by the
//! same `MassCalculator` with the same network parameters. Nothing is quoted
//! from a previous session.

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

use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Signer};
use vault_harness::execute_with_tx;
use slh_script::witness::BlobPlan;
use slh_script::{build_vault_script, PublicKey};
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
    mass_row("LMS h=15 w=2", true, &redeem, &tx, &utxos, units)
}

fn slh_row() -> Row {
    let plan = BlobPlan::default();
    let (fips_pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("keygen");
    let pk = PublicKey::from_bytes(&fips_pk.into_bytes()).expect("pk");
    let redeem = build_vault_script(&pk, &plan, outputs().len()).expect("emit").script;
    let sig = sk.try_sign(&digest_for(), &[], false).expect("sign");

    let (tx, utxos) = assemble(redeem.clone(), plan.witness_pushes(&sig).unwrap(), 60_000);
    let units = execute_with_tx(&redeem, &tx, utxos.clone(), 0).expect("SLH spend must verify").script_units;

    // Re-assemble declaring the budget this spend actually needs, which is what
    // the mass figures must reflect.
    let (tx, utxos) = assemble(redeem.clone(), plan.witness_pushes(&sig).unwrap(), budget_for(units));
    mass_row("SLH-DSA-SHA2-128s", false, &redeem, &tx, &utxos, units)
}

#[test]
fn lms_versus_slh_dsa_measured_side_by_side() {
    let rows = [lms_row(), slh_row()];

    println!("\n=== Same spend shape, same engine, same mass parameters ===");
    println!(
        "  {:<20} {:>8} {:>10} {:>10} {:>10} {:>11} {:>10} {:>9} {:>7}",
        "scheme", "stateful", "redeem B", "sigscript", "tx bytes", "units", "norm mass", "per blk", "fee KAS"
    );
    for r in &rows {
        println!(
            "  {:<20} {:>8} {:>10} {:>10} {:>10} {:>11} {:>10} {:>9} {:>7.4}",
            r.name,
            if r.stateful { "yes" } else { "no" },
            r.redeem,
            r.sig_script,
            r.tx_size,
            r.units,
            r.normalized_max,
            TN.block_mass_limits.compute / r.normalized_max.max(1),
            r.fee as f64 / 100_000_000.0,
        );
    }
    let (lms, slh) = (&rows[0], &rows[1]);
    println!(
        "\n  SLH-DSA costs {:.1}x the bytes and {:.1}x the fee of LMS, and needs no state.",
        slh.tx_size as f64 / lms.tx_size as f64,
        slh.fee as f64 / lms.fee as f64,
    );
    println!(
        "  Mass axes — LMS compute {} vs normalized transient {}; SLH {} vs {}.",
        lms.compute_mass, lms.normalized_transient, slh.compute_mass, slh.normalized_transient
    );

    // Both must be mineable at all, which is the only hard constraint here.
    for r in &rows {
        assert!(
            r.normalized_max <= TN.block_mass_limits.compute,
            "{} needs {} normalized mass, over the block limit",
            r.name,
            r.normalized_max
        );
    }
}
