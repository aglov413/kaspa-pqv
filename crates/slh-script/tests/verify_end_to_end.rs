//! The emitted verifier, executed by Kaspa's real `TxScriptEngine` against
//! signatures produced by `fips205`.
//!
//! Nothing here reimplements script semantics: a script that passes here passes
//! for the same reasons it would on a node, and the reported cost is the
//! engine's own accounting.

use vault_harness::execute;
use slh_script::params::*;
use slh_script::witness::BlobPlan;

mod common;
use common::{signed, verify_script_with_witness as spend_script};

#[test]
fn a_valid_signature_verifies_in_the_engine() {
    let plan = BlobPlan::default();
    let message = [0x5au8; 32];
    let (pk, sig) = signed(1, &message);

    let script = spend_script(&pk, &plan, &sig, &message);
    let cost = execute(&script).expect("a valid signature must verify");
    println!(
        "SLH-DSA-SHA2-128s verify: {} script bytes, {} script units, {} grams",
        cost.script_bytes,
        cost.script_units,
        cost.grams()
    );
}

/// Negative controls. Every one of these must fail, and a scheme that accepted
/// any of them would still pass the test above.
#[test]
fn corrupted_inputs_are_rejected() {
    let plan = BlobPlan::default();
    let message = [0x5au8; 32];
    let (pk, sig) = signed(1, &message);

    // A different message under the same signature.
    let mut other = message;
    other[0] ^= 0x01;
    assert!(
        execute(&spend_script(&pk, &plan, &sig, &other)).is_err(),
        "verifier accepted a signature over a different message"
    );

    // A different key.
    let (other_pk, _) = signed(2, &message);
    assert!(
        execute(&spend_script(&other_pk, &plan, &sig, &message)).is_err(),
        "verifier accepted a signature under the wrong key"
    );

    // One flipped bit in each region of the signature: randomiser, a FORS
    // secret value, a FORS auth node, a WOTS+ chain value in the bottom layer,
    // an auth node, and a chain value in the top layer.
    let fors_start = N;
    let ht_start = N + K * (1 + A) * N;
    let top_layer = ht_start + 6 * (LEN + HP) * N;
    for (label, pos) in [
        ("randomiser", 0),
        ("fors sk", fors_start),
        ("fors auth", fors_start + N + N),
        ("wots layer 0", ht_start + 3 * N),
        ("xmss auth layer 0", ht_start + LEN * N),
        ("wots layer 6", top_layer + 3 * N),
        ("xmss auth layer 6", top_layer + LEN * N),
        ("last byte", SIG_LEN - 1),
    ] {
        let mut bad = sig.clone();
        bad[pos] ^= 0x01;
        assert!(
            execute(&spend_script(&pk, &plan, &bad, &message)).is_err(),
            "verifier accepted a signature corrupted at {label} (byte {pos})"
        );
    }
}

/// Two elements swapped inside the signature keeps the length and the byte
/// multiset identical, so it catches an emitter that consumes the witness in
/// the wrong order — which a random bit-flip would not.
#[test]
fn transposed_signature_elements_are_rejected() {
    let plan = BlobPlan::default();
    let message = [0x11u8; 32];
    let (pk, sig) = signed(1, &message);
    let ht_start = N + K * (1 + A) * N;

    for (a, b) in [(0usize, N), (ht_start, ht_start + N), (ht_start + LEN * N, ht_start + (LEN + 1) * N)] {
        let mut swapped = sig.clone();
        for k in 0..N {
            swapped.swap(a + k, b + k);
        }
        assert!(
            execute(&spend_script(&pk, &plan, &swapped, &message)).is_err(),
            "verifier accepted a signature with elements at {a} and {b} transposed"
        );
    }
}
