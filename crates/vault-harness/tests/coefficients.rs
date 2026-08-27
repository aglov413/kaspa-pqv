//! Differential test: the emitted coefficient-extraction script against the
//! RFC 8554 reference, for every chain index, executed by Kaspa's engine.
//!
//! Coefficient extraction is where an in-script Winternitz verifier is most
//! likely to be subtly wrong — byte indexing, bit shifts, and Kaspa's
//! sign-magnitude numbers all have to line up. A single wrong coefficient
//! either bricks the vault or, worse, lets a forged signature through.

use kaspa_txscript::opcodes::codes::*;
use vault_harness::execute;
use lms_script::ots::{coef, emit_coefficient};
use lms_script::{LmsParams, ScriptWriter};

/// Deterministic pseudo-random bytes, so failures are reproducible.
fn pseudo_random(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Run the extraction script for one chain index and assert it equals `expected`.
fn check_one(params: &LmsParams, v: &[u8], i: usize, expected: u32) {
    let mut w = ScriptWriter::new();
    w.data(v).unwrap(); // [V]
    emit_coefficient(&mut w, params, i).unwrap(); // [V, a_i]
    w.num(i64::from(expected)).unwrap(); // [V, a_i, expected]
    w.op(OpNumEqual).unwrap(); // [V, bool]
    w.op(OpSwap).unwrap(); // [bool, V]
    w.op(OpDrop).unwrap(); // [bool]

    execute(&w.build()).unwrap_or_else(|e| {
        panic!(
            "coefficient {i} of V={}: script disagrees with reference (expected {expected}): {e}",
            hex::encode(v)
        )
    });
}

/// Every chain index, over adversarial and random `V` values.
#[test]
fn every_coefficient_matches_the_reference() {
    let params = LmsParams::SHA256_H5_W2;

    let mut cases: Vec<Vec<u8>> = vec![
        vec![0x00; 34],
        vec![0xff; 34], // every byte has the high bit set — the sign-magnitude trap
        vec![0x80; 34], // every byte is exactly negative zero if unpadded
        vec![0x7f; 34],
        vec![0x55; 34],
        vec![0xaa; 34],
    ];
    for seed in 0..8u64 {
        cases.push(pseudo_random(seed, 34));
    }

    for v in &cases {
        for i in 0..params.p {
            check_one(&params, v, i, coef(v, i, params.w));
        }
    }
}

/// Same, for w = 4, where coefficients straddle nibbles rather than pairs.
#[test]
fn every_coefficient_matches_the_reference_w4() {
    let params = LmsParams::SHA256_H5_W4;
    for seed in 0..4u64 {
        let v = pseudo_random(seed + 100, 34);
        for i in 0..params.p {
            check_one(&params, &v, i, coef(&v, i, params.w));
        }
    }
}

/// The negative control: if the script were returning a constant, or the
/// reference and script agreed only by luck, this would fail to fail.
#[test]
fn a_wrong_expected_coefficient_is_rejected() {
    let params = LmsParams::SHA256_H5_W2;
    let v = pseudo_random(42, 34);

    let mut rejected = 0;
    for i in 0..params.p {
        let actual = coef(&v, i, params.w);
        let wrong = (actual + 1) % (1 << params.w);

        let mut w = ScriptWriter::new();
        w.data(&v).unwrap();
        emit_coefficient(&mut w, &params, i).unwrap();
        w.num(i64::from(wrong)).unwrap();
        w.op(OpNumEqual).unwrap();
        w.op(OpSwap).unwrap();
        w.op(OpDrop).unwrap();

        assert!(execute(&w.build()).is_err(), "chain {i}: wrong coefficient was accepted");
        rejected += 1;
    }
    assert_eq!(rejected, params.p);
}

/// What extraction costs, so the total budget is built from measurements.
#[test]
fn report_extraction_cost() {
    let params = LmsParams::SHA256_H5_W2;
    let v = pseudo_random(7, 34);

    let mut w = ScriptWriter::new();
    w.data(&v).unwrap();
    for i in 0..params.p {
        emit_coefficient(&mut w, &params, i).unwrap();
        w.op(OpDrop).unwrap(); // discard, we only want the cost
    }
    w.op(OpDrop).unwrap(); // drop V
    w.num(1).unwrap();

    let cost = execute(&w.build()).expect("extraction should run");
    println!(
        "all {} coefficients: {} script bytes, {} script units ({:.1} units/coefficient)",
        params.p,
        cost.script_bytes,
        cost.script_units,
        cost.script_units as f64 / params.p as f64
    );
}
