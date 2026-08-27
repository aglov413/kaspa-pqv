//! How much does a deeper Merkle tree cost?
//!
//! Proving time is no longer a constraint — transaction mass is. Merkle depth
//! is the cheapest axis available: each extra level adds one hash to the
//! signature path and one unrolled step to the script, while multiplying the
//! number of one-time keys by two. This measures the actual slope, including
//! keygen, which is the cost that does *not* stay cheap.

use vault_harness::execute;
use lms_script::params::{LmsParams, N};
use lms_script::verify::{emit_verify, LmsPublicKey};
use lms_script::ScriptWriter;
use std::time::Instant;

struct Row {
    label: &'static str,
    leaves: u64,
    script_bytes: usize,
    sig_bytes: usize,
    script_units: u64,
    keygen_ms: u128,
}

macro_rules! measure_height {
    ($label:literal, $params:expr, $module:path) => {{
        use $module as lms;
        let params: LmsParams = $params;
        let xi = [0x11u8; 32];

        let t0 = Instant::now();
        let (mut sk, pk) = lms::LmsSigningKey::new_internal(&xi);
        let keygen_ms = t0.elapsed().as_millis();

        let key = LmsPublicKey {
            id: pk[8..24].try_into().unwrap(),
            root: pk[24..56].try_into().unwrap(),
        };

        let message = [0xabu8; 32];
        let sig = sk.sign_internal(&message).expect("sign");
        assert_eq!(sig.len(), params.signature_len(), "{} signature length", $label);

        let q = u32::from_be_bytes(sig[0..4].try_into().unwrap());
        let c: [u8; N] = sig[8..40].try_into().unwrap();
        let y_end = 40 + params.p * N;
        let y: Vec<[u8; N]> =
            sig[40..y_end].chunks_exact(N).map(|c| <[u8; N]>::try_from(c).unwrap()).collect();
        let path: Vec<[u8; N]> =
            sig[y_end + 4..].chunks_exact(N).map(|c| <[u8; N]>::try_from(c).unwrap()).collect();

        let mut w = ScriptWriter::new();
        for node in path.iter().rev() {
            w.data(node).unwrap();
        }
        for yi in y.iter().rev() {
            w.data(yi).unwrap();
        }
        w.data(&c).unwrap();
        w.data(&message).unwrap();
        emit_verify(&mut w, &params, &key, q).unwrap();

        let cost = execute(&w.build())
            .unwrap_or_else(|e| panic!("{} rejected a valid signature: {e}", $label));

        Row {
            label: $label,
            leaves: 1u64 << params.h,
            script_bytes: cost.script_bytes,
            sig_bytes: sig.len(),
            script_units: cost.script_units,
            keygen_ms,
        }
    }};
}

/// Compute mass a spend costs: transaction bytes at `mass_per_tx_byte = 1`,
/// plus the script's runtime grams.
fn compute_mass(row: &Row) -> u64 {
    (row.script_bytes + row.sig_bytes) as u64 + row.script_units / 100
}

#[test]
fn sweep_tree_height() {
    let rows = vec![
        measure_height!("h=5", LmsParams::SHA256_H5_W2, oxicrypt_lms::lms_sha256_m32_h5_w2),
        measure_height!("h=10", LmsParams::SHA256_H10_W2, oxicrypt_lms::lms_sha256_m32_h10_w2),
        measure_height!("h=15", LmsParams::SHA256_H15_W2, oxicrypt_lms::lms_sha256_m32_h15_w2),
        measure_height!("h=20", LmsParams::SHA256_H20_W2, oxicrypt_lms::lms_sha256_m32_h20_w2),
    ];

    let baseline = compute_mass(&rows[0]);

    println!();
    println!(
        "{:<6} {:>12} {:>12} {:>10} {:>13} {:>10} {:>12}",
        "h", "leaves", "script B", "sig B", "compute mass", "vs h=5", "keygen"
    );
    for row in &rows {
        let mass = compute_mass(row);
        println!(
            "{:<6} {:>12} {:>12} {:>10} {:>13} {:>9.1}% {:>10} ms",
            row.label,
            row.leaves,
            row.script_bytes,
            row.sig_bytes,
            mass,
            (mass as f64 / baseline as f64 - 1.0) * 100.0,
            row.keygen_ms,
        );
    }
    println!();
    for row in &rows {
        let mass = compute_mass(row);
        println!(
            "  {:<6} -> ~{} spends/block, fee floor ~{:.4} KAS",
            row.label,
            500_000 / mass.max(1),
            (mass * 100) as f64 / 100_000_000.0,
        );
    }

    // Depth must be cheap in mass, or the whole premise is wrong.
    let deepest = compute_mass(rows.last().unwrap());
    assert!(
        deepest < baseline * 11 / 10,
        "h=20 costs more than 10% over h=5 ({deepest} vs {baseline})"
    );
}
