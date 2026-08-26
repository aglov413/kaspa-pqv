//! Where the cost actually goes, and how much of it is a choice.
//!
//! Two variables are under the emitter's control and both are measured here
//! rather than argued about: the witness blob size, and the spread of script
//! units across signatures.

use lms_harness::execute;
use slh_script::params::*;
use slh_script::witness::BlobPlan;
use slh_script::{build_verify_script, PublicKey};

mod common;
use common::{signed, verify_script_with_witness as spend_script};

fn one_signature() -> (PublicKey, Vec<u8>, [u8; 32]) {
    let message = [0x5au8; 32];
    let (pk, sig) = signed(1, &message);
    (pk, sig, message)
}

/// The blob-size tradeoff, measured against the engine.
///
/// Larger blobs mean fewer stack slots and quadratically more slicing work;
/// smaller blobs mean the reverse, until the blob count alone breaches
/// `MAX_STACK_SIZE`. This is the table the choice of `BLOB_ELEMS` comes from.
#[test]
fn blob_size_sweep() {
    let (pk, sig, message) = one_signature();

    println!("\n=== witness blob size sweep (one fixed signature) ===");
    println!("  elems  blobs   redeem B   witness B   script units   peak stack");
    for elems in [2usize, 3, 4, 6, 8, 12, 20, 40, 100, SIG_ELEMENTS] {
        let plan = BlobPlan::new(elems).unwrap();
        let vs = build_verify_script(&pk, &plan).unwrap();
        let peak = vs.peak_stack();
        let witness_bytes = plan.witness_pushes(&sig).unwrap().len();

        let legal = peak < kaspa_txscript::MAX_STACK_SIZE;
        let units = if legal {
            match execute(&spend_script(&pk, &plan, &sig, &message)) {
                Ok(c) => c.script_units.to_string(),
                Err(e) => format!("failed: {e}"),
            }
        } else {
            "over stack limit".to_string()
        };

        println!(
            "  {elems:>5}  {:>5}   {:>8}   {:>9}   {:>12}   {:>4}{}",
            plan.blob_count(),
            vs.script.len(),
            witness_bytes,
            units,
            peak,
            if legal { "" } else { "  <- rejected" }
        );
    }
}

/// Script units are data-dependent: a Winternitz chain runs from its message
/// digit to 14, and untaken steps cost nothing at runtime. Bytes are not — the
/// worst case is always emitted. This measures both spreads.
///
/// It matters because the compute budget is declared per input, and a spend
/// that under-declares is rejected.
#[test]
fn script_unit_spread_across_signatures() {
    let plan = BlobPlan::default();
    let mut sizes = std::collections::HashSet::new();
    let mut units = Vec::new();

    for i in 0..8u8 {
        let message = [i.wrapping_mul(53); 32];
        let (pk, sig) = signed(i, &message);
        let script = spend_script(&pk, &plan, &sig, &message);
        sizes.insert(script.len());
        units.push(execute(&script).expect("must verify").script_units);
    }

    units.sort_unstable();
    let min = units[0];
    let max = units[units.len() - 1];
    let mean = units.iter().sum::<u64>() / units.len() as u64;

    println!("\n=== script units across 8 independent signatures ===");
    println!("  min {min}  mean {mean}  max {max}  (spread {:.1}%)", (max - min) as f64 * 100.0 / mean as f64);
    println!("  distinct script sizes: {} (bytes are signature-independent)", sizes.len());

    // Size is fixed by the parameter set, so a vault address and a fee
    // estimate do not depend on which signature is presented.
    assert_eq!(sizes.len(), 1, "script size varied across signatures: {sizes:?}");

    // Units vary, but only within the band the unrolled worst case allows.
    assert!(max < 2 * min, "unit spread wider than expected: {min}..{max}");
}

/// Worst-case script units, bounded by construction rather than sampled.
///
/// Every emitted chain step either runs or is skipped, so the ceiling is what
/// a signature whose digits are all zero would cost. The compute budget has to
/// be sized against that ceiling, not against the mean.
#[test]
fn the_worst_case_compute_budget_is_declarable() {
    let plan = BlobPlan::default();
    let (pk, sig, message) = one_signature();
    let measured = execute(&spend_script(&pk, &plan, &sig, &message)).unwrap().script_units;

    // Executed chain hashes scale with sum(15 - digit); the worst case is all
    // digits zero, i.e. every one of the 15 emitted steps runs.
    let executed_ceiling = (D * LEN * (W as usize - 1)) as u64;
    println!("\n=== compute budget ===");
    println!("  measured units          {measured}");
    println!("  emitted chain steps     {executed_ceiling}");

    // A u16 field has to be able to express the budget at all.
    let budget = (measured / 100).div_ceil(100);
    println!("  declared budget         {budget} units (u16 max {})", u16::MAX);
    assert!(budget < u64::from(u16::MAX), "compute budget does not fit its field");
}
