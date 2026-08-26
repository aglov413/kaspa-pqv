//! Measures the `w` tradeoff end to end.
//!
//! Larger `w` means fewer, longer hash chains: a smaller signature but a much
//! larger unrolled script. Both land in the same transaction, so the quantity
//! to minimise is script bytes + signature bytes, not either alone.
//!
//! Every number here is produced by executing generated script under the
//! consensus engine against a signature from the reference implementation.

use lms_harness::{execute, Cost};
use lms_script::params::{LmsParams, N};
use lms_script::verify::{emit_verify, LmsPublicKey};
use lms_script::ScriptWriter;

#[allow(dead_code)]
struct Measurement {
    label: &'static str,
    params: LmsParams,
    cost: Cost,
    signature_bytes: usize,
}

impl Measurement {
    /// Compute mass a spend of this shape costs: transaction bytes at
    /// `mass_per_tx_byte = 1`, plus the script's runtime grams.
    fn approx_compute_mass(&self) -> u64 {
        (self.cost.script_bytes + self.signature_bytes) as u64 + self.cost.grams()
    }
}

/// Generic over the reference module, since each parameter pair is its own type.
macro_rules! measure {
    ($label:literal, $params:expr, $module:path, $seed:expr) => {{
        use $module as lms;
        let params: LmsParams = $params;
        let xi = [$seed; 32];
        let (mut sk, pk) = lms::LmsSigningKey::new_internal(&xi);
        let key = LmsPublicKey {
            id: pk[8..24].try_into().unwrap(),
            root: pk[24..56].try_into().unwrap(),
        };

        let message = [0xabu8; 32];
        let sig = sk.sign_internal(&message).expect("sign");
        assert_eq!(sig.len(), params.signature_len(), "{} length", $label);

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

        let outcome = execute(&w.build());
        (Measurement { label: $label, params, cost: Cost { script_bytes: 0, script_units: 0 }, signature_bytes: sig.len() }, outcome)
    }};
}

/// Kaspa's `MAX_STACK_SIZE` is 244 *items*, counting the data and alt stacks
/// together. The witness must present all `p` chain values at once, so the
/// stack limit puts a hard ceiling on `p` — and therefore a hard floor on `w`.
///
/// `w = 1` needs `p = 265` and cannot run at all. Bundling the chain values
/// into one blob and slicing them out with `OpSubstr` does not rescue it:
/// every slice needs a copy of the remaining blob, which is O(p^2) in bytes
/// pushed and costs over a million script units.
#[test]
fn w1_exceeds_the_stack_limit() {
    let (m, outcome) =
        measure!("w=1", LmsParams::SHA256_H5_W1, oxicrypt_lms::lms_sha256_m32_h5_w1, 0x11);
    let err = outcome.expect_err("w=1 should not fit on the stack").to_string();
    assert!(
        err.contains("stack size"),
        "expected a stack-size failure for p = {}, got: {err}",
        m.params.p
    );
    println!("w=1 (p={}): rejected -- {err}", m.params.p);
}

#[test]
fn sweep_winternitz_parameter() {
    let results: Vec<Measurement> = [
        measure!("h=5,w=2", LmsParams::SHA256_H5_W2, oxicrypt_lms::lms_sha256_m32_h5_w2, 0x11),
        measure!("h=10,w=2", LmsParams::SHA256_H10_W2, oxicrypt_lms::lms_sha256_m32_h10_w2, 0x11),
        measure!("h=5,w=4", LmsParams::SHA256_H5_W4, oxicrypt_lms::lms_sha256_m32_h5_w4, 0x11),
    ]
    .into_iter()
    .map(|(mut m, outcome)| {
        m.cost = outcome.unwrap_or_else(|e| panic!("{} rejected a valid signature: {e}", m.label));
        m
    })
    .collect();

    println!();
    println!(
        "{:<10} {:>7} {:>12} {:>11} {:>10} {:>12} {:>13}",
        "params", "leaves", "script bytes", "sig bytes", "total B", "script units", "compute mass"
    );
    for m in &results {
        println!(
            "{:<10} {:>7} {:>12} {:>11} {:>10} {:>12} {:>13}",
            m.label,
            m.params.leaf_count(),
            m.cost.script_bytes,
            m.signature_bytes,
            m.cost.script_bytes + m.signature_bytes,
            m.cost.script_units,
            m.approx_compute_mass(),
        );
    }
    println!();

    let best = results
        .iter()
        .min_by_key(|m| m.approx_compute_mass())
        .expect("at least one measurement");
    println!("lowest compute mass: {} ({} mass)", best.label, best.approx_compute_mass());
    println!(
        "  -> ~{} spends per 500,000 compute-mass block, fee floor ~{:.4} KAS",
        500_000 / best.approx_compute_mass(),
        (best.approx_compute_mass() * 100) as f64 / 100_000_000.0
    );

    // The tradeoff must actually be a tradeoff, or the sweep is measuring noise.
    let w2 = &results[0];
    let w4 = &results[2];
    assert!(w2.signature_bytes > w4.signature_bytes, "w=2 should have the larger signature");
    assert!(w2.cost.script_bytes < w4.cost.script_bytes, "w=2 should have the smaller script");
}
