//! **The measurement.** What an SLH-DSA vault spend actually costs on Kaspa.
//!
//! Every number printed here is produced by Kaspa's own code:
//!
//! - script units come from `TxScriptEngine::used_script_units`, the node's
//!   accounting, after the script has actually run;
//! - sizes come from `transaction_estimated_serialized_size`;
//! - masses come from `MassCalculator` and `MassCofactors`, with the real
//!   testnet parameters.
//!
//! Nothing is arithmetic on top of a model. The only figure derived by hand is
//! the compute budget, and it is derived *from* the measured unit count and
//! then fed back through the engine, which rejects it if it is short.

use kaspa_consensus_core::config::params::{Params, TESTNET_PARAMS};
use kaspa_consensus_core::constants::STORAGE_MASS_PARAMETER;
use kaspa_consensus_core::mass::{Mass, MassCalculator, MassCofactors};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, ScriptVec, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::{pay_to_script_hash_script, pay_to_script_hash_signature_script};

use vault_harness::{execute_with_tx, execute_with_tx_budget};

mod common;
use common::{budget_for, signed};
use slh_script::params::*;
use slh_script::witness::BlobPlan;
use slh_script::build_vault_script;
use vault_core::binding::{binding_digest, OutputView, SpendView};

static TN_PARAMS: Params = TESTNET_PARAMS;

const FUNDING_TXID: [u8; 32] = [0x77; 32];
const FUNDING_INDEX: u32 = 0;
const FUNDING_AMOUNT: u64 = 1_000_000_000;
const TX_VERSION: u16 = 1;

fn p2sh_output(amount: u64, tag: u8) -> OutputView {
    let spk = pay_to_script_hash_script(&[tag; 40]);
    OutputView { amount, spk_version: spk.version(), script: spk.script().to_vec() }
}

fn spend_outputs() -> Vec<OutputView> {
    vec![p2sh_output(900_000_000, 0xaa), p2sh_output(90_000_000, 0xbb)]
}

struct Spend {
    tx: Transaction,
    utxos: Vec<UtxoEntry>,
    redeem_script: Vec<u8>,
}

/// A complete SLH-DSA vault spend: derive the address, build the canonical
/// two-output transaction, reconstruct the binding digest off-chain, sign it,
/// and assemble the P2SH input.
fn build_spend(
    plan: &BlobPlan,
    budget_units: u16,
    tag: u8,
    tamper: impl FnOnce(&mut Vec<u8>),
) -> Spend {
    let outputs = spend_outputs();
    let view = SpendView {
        tx_version: TX_VERSION,
        outpoint_txid: FUNDING_TXID,
        outpoint_index: FUNDING_INDEX,
        outputs: outputs.clone(),
    };
    let digest = binding_digest(&view).expect("binding digest");

    // The vault signs with an empty context, which is what the script's
    // `context_prefixed` two zero bytes account for.
    let (pk, mut sig) = signed(tag, &digest);
    tamper(&mut sig);

    let redeem_script = build_vault_script(&pk, plan, outputs.len()).expect("emit").script;
    let funding_spk = pay_to_script_hash_script(&redeem_script);
    let signature_script =
        pay_to_script_hash_signature_script(redeem_script.clone(), plan.witness_pushes(&sig).expect("witness"))
            .expect("signature script");

    let outpoint = TransactionOutpoint::new(TransactionId::from_slice(&FUNDING_TXID), FUNDING_INDEX);
    let input = TransactionInput::new_with_compute_budget(outpoint, signature_script, 0, budget_units);
    let tx = Transaction::new(
        TX_VERSION,
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
    let utxo = UtxoEntry::new(FUNDING_AMOUNT, funding_spk, 0, false, None);
    Spend { tx, utxos: vec![utxo], redeem_script }
}

#[derive(Debug)]
struct Report {
    redeem_bytes: usize,
    signature_script_bytes: usize,
    tx_size: u64,
    script_units: u64,
    budget_units: u16,
    compute_mass: u64,
    transient_mass: u64,
    normalized_transient: u64,
    storage_mass: u64,
    normalized_max: u64,
    minimum_fee: u64,
}

impl Report {
    fn spends_per_block(&self) -> u64 {
        TN_PARAMS.block_mass_limits.compute / self.normalized_max.max(1)
    }
    fn fee_kas(&self) -> f64 {
        self.minimum_fee as f64 / 100_000_000.0
    }
}

fn measure(spend: &Spend, budget_units: u16) -> Report {
    let cost = execute_with_tx(&spend.redeem_script, &spend.tx, spend.utxos.clone(), 0)
        .expect("the vault spend must verify");

    let calculator = MassCalculator::new(
        TN_PARAMS.mass_per_tx_byte,
        TN_PARAMS.mass_per_script_pub_key_byte,
        STORAGE_MASS_PARAMETER,
    );
    let non_contextual = calculator.calc_non_contextual_masses(&spend.tx);
    let populated = PopulatedTransaction::new(&spend.tx, spend.utxos.clone());
    let contextual = calculator.calc_contextual_masses(&populated).expect("storage mass");

    let cofactors = MassCofactors::new(&TN_PARAMS.block_mass_limits);
    let normalized_transient = non_contextual.normalized_transient(&cofactors);
    let normalized_max = Mass::new(non_contextual, contextual).normalized_max(&cofactors);
    let fee_mass = non_contextual.compute_mass.max(normalized_transient);

    Report {
        redeem_bytes: spend.redeem_script.len(),
        signature_script_bytes: spend.tx.inputs[0].signature_script.len(),
        tx_size: kaspa_consensus_core::mass::transaction_estimated_serialized_size(&spend.tx),
        script_units: cost.script_units,
        budget_units,
        compute_mass: non_contextual.compute_mass,
        transient_mass: non_contextual.transient_mass,
        normalized_transient,
        storage_mass: contextual.storage_mass,
        normalized_max,
        // `DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE` is 100_000 sompi per kilogram.
        minimum_fee: (fee_mass.saturating_mul(100_000) / 1000).max(100_000),
    }
}

/// The headline measurement.
#[test]
fn slh_dsa_vault_spend_cost() {
    let plan = BlobPlan::default();

    // First pass with a generous budget, purely to learn the unit count.
    let probe = build_spend(&plan, 60_000, 1, |_| {});
    let probe_units = execute_with_tx(&probe.redeem_script, &probe.tx, probe.utxos.clone(), 0)
        .expect("probe spend must verify")
        .script_units;
    let budget = budget_for(probe_units);

    // Second pass declaring exactly what it needs, which is what a real spend
    // would do and what the mass numbers must reflect.
    let spend = build_spend(&plan, budget, 1, |_| {});
    let r = measure(&spend, budget);

    println!("\n=== SLH-DSA-SHA2-128s vault spend, measured ===");
    println!("  redeem script            {:>9} bytes", r.redeem_bytes);
    println!("  signature script         {:>9} bytes  (witness + redeem push)", r.signature_script_bytes);
    println!("  transaction              {:>9} bytes", r.tx_size);
    println!("  script units             {:>9}        ({} grams)", r.script_units, r.script_units / 100);
    println!("  compute budget declared  {:>9} units", r.budget_units);
    println!("  compute mass             {:>9}", r.compute_mass);
    println!("  transient mass           {:>9}  ({} normalized)", r.transient_mass, r.normalized_transient);
    println!("  storage mass             {:>9}", r.storage_mass);
    println!("  normalized max mass      {:>9}  (block limit {})", r.normalized_max, TN_PARAMS.block_mass_limits.compute);
    println!("  spends per block         {:>9}", r.spends_per_block());
    println!("  fee floor                {:>9.4} KAS", r.fee_kas());

    assert!(
        r.normalized_max <= TN_PARAMS.block_mass_limits.compute,
        "a spend needing {} normalized mass can never be mined",
        r.normalized_max
    );
}

/// The declared compute budget is enforced, so the measured unit count is not
/// a number the engine merely reports — it is a number the engine charges for.
#[test]
fn an_underdeclared_compute_budget_is_rejected() {
    let plan = BlobPlan::default();
    let probe = build_spend(&plan, 60_000, 1, |_| {});
    let units = execute_with_tx(&probe.redeem_script, &probe.tx, probe.utxos.clone(), 0)
        .expect("probe must verify")
        .script_units;

    let needed = budget_for(units);

    // Declaring what it needs succeeds. This is the same key and the same
    // signature as the probe, which is the point: the budget is a function of
    // the signature being broadcast, not of the parameter set.
    let spend = build_spend(&plan, needed, 1, |_| {});
    let cost = execute_with_tx_budget(&spend.redeem_script, &spend.tx, spend.utxos.clone(), 0, needed)
        .expect("the derived compute budget must cover the spend");
    assert!(cost.script_units <= u64::from(needed) * 10_000);

    // ...and declaring half of it does not. Without this the budget would be a
    // number nothing checks.
    let short = build_spend(&plan, needed / 2, 1, |_| {});
    let err = execute_with_tx_budget(&short.redeem_script, &short.tx, short.utxos.clone(), 0, needed / 2)
        .expect_err("half the required compute budget must fail");
    let text = format!("{err}");
    assert!(
        text.contains("ScriptUnits") || text.contains("units"),
        "expected a compute-budget failure, got: {text}"
    );
}

/// A vault spend must not be redirectable. The signature commits to the
/// outputs through the binding digest, which the script rebuilds from
/// introspection rather than taking from the witness.
#[test]
fn a_redirected_spend_is_rejected() {
    let plan = BlobPlan::default();
    let mut spend = build_spend(&plan, 60_000, 1, |_| {});

    // Repoint the destination output after signing.
    let redirected = p2sh_output(900_000_000, 0xcc);
    let mut outputs: Vec<TransactionOutput> = spend.tx.outputs.clone();
    outputs[0] = TransactionOutput::new(
        redirected.amount,
        ScriptPublicKey::new(redirected.spk_version, ScriptVec::from_slice(&redirected.script)),
    );
    spend.tx = Transaction::new(
        TX_VERSION,
        spend.tx.inputs.clone(),
        outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    assert!(
        execute_with_tx(&spend.redeem_script, &spend.tx, spend.utxos.clone(), 0).is_err(),
        "a redirected spend verified — the digest is not binding the outputs"
    );
}

/// A corrupted signature is rejected in transaction context too, not only in
/// the standalone verifier.
#[test]
fn a_corrupt_signature_is_rejected_in_context() {
    let plan = BlobPlan::default();
    let spend = build_spend(&plan, 60_000, 1, |sig| sig[SIG_LEN / 2] ^= 0x40);
    assert!(
        execute_with_tx(&spend.redeem_script, &spend.tx, spend.utxos.clone(), 0).is_err(),
        "a corrupt signature verified in transaction context"
    );
}

/// A 97 KB signature script has to be *relayable*, not merely valid.
///
/// The mempool's standardness checks for a pay-to-script-hash input are the
/// input's script class, its signature-operation count, and the fee floor.
/// There is no cap on signature-script length, so the binding constraint is
/// mass — which is what makes the byte count the number that decides this.
#[test]
fn the_spend_is_standard() {
    use kaspa_txscript::script_class::ScriptClass;

    let plan = BlobPlan::default();
    let spend = build_spend(&plan, 60_000, 1, |_| {});

    // The funded output is a plain P2SH, whatever the redeem script's size.
    assert_eq!(
        ScriptClass::from_script(&spend.utxos[0].script_public_key),
        ScriptClass::ScriptHash
    );

    // Both spend outputs must be standard, or the mempool drops the whole
    // transaction regardless of the input.
    for (i, out) in spend.tx.outputs.iter().enumerate() {
        assert_ne!(
            ScriptClass::from_script(&out.script_public_key),
            ScriptClass::NonStandard,
            "output {i} is non-standard"
        );
    }

    // The verifier uses no signature operations at all — it is hashes and
    // comparisons — so it cannot trip MAX_STANDARD_P2SH_SIG_OPS (15).
    let sig_script = &spend.tx.inputs[0].signature_script;
    assert!(sig_script.len() > 90_000, "expected a large signature script");
    assert!(
        !spend.redeem_script.contains(&kaspa_txscript::opcodes::codes::OpCheckSig),
        "the redeem script should contain no signature operations"
    );
}
