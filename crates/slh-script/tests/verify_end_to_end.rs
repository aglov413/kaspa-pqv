//! The emitted verifier, executed by Kaspa's real `TxScriptEngine` against
//! real signatures.
//!
//! Nothing here reimplements script semantics: a script that passes here passes
//! for the same reasons it would on a node, and the reported cost is the
//! engine's own accounting.

use vault_harness::execute;
use slh_script::witness::BlobPlan;

mod common;
use common::{signed, verify_script_with_witness as spend_script, FAST_SETS};

#[test]
fn a_valid_signature_verifies_in_the_engine() {
    for set in FAST_SETS {
        let plan = BlobPlan::for_params(set);
        let message = [0x5au8; 32];
        let (pk, sig) = signed(set, 1, &message);

        let script = spend_script(&pk, &plan, &sig, &message);
        let cost = execute(&script).expect("a valid signature must verify");
        println!(
            "{:<24} verify: {:>7} script bytes, {:>9} script units, {:>7} grams",
            set.name,
            cost.script_bytes,
            cost.script_units,
            cost.grams()
        );
    }
}

/// Negative controls. Every one of these must fail, and a scheme that accepted
/// any of them would still pass the test above.
#[test]
fn corrupted_inputs_are_rejected() {
    for set in FAST_SETS {
        let (n, plan) = (set.n, BlobPlan::for_params(set));
        let message = [0x5au8; 32];
        let (pk, sig) = signed(set, 1, &message);

        // A different message under the same signature.
        let mut other = message;
        other[0] ^= 0x01;
        assert!(
            execute(&spend_script(&pk, &plan, &sig, &other)).is_err(),
            "{}: verifier accepted a signature over a different message",
            set.name
        );

        // A different key.
        let (other_pk, _) = signed(set, 2, &message);
        assert!(
            execute(&spend_script(&other_pk, &plan, &sig, &message)).is_err(),
            "{}: verifier accepted a signature under the wrong key",
            set.name
        );

        // One flipped bit in each region of the signature: randomiser, a FORS
        // secret value, a FORS auth node, a WOTS+ chain value and an auth node
        // in the bottom layer, and the same two in the top layer — which is
        // the same layer when `d = 1`.
        let fors_start = n;
        let ht_start = n + set.k * (1 + set.a) * n;
        let layer_stride = (set.len() + set.hp) * n;
        let top_layer = ht_start + (set.d - 1) * layer_stride;
        for (label, pos) in [
            ("randomiser", 0),
            ("fors sk", fors_start),
            ("fors auth", fors_start + 2 * n),
            ("wots bottom layer", ht_start + 3 * n),
            ("xmss auth bottom layer", ht_start + set.len() * n),
            ("wots top layer", top_layer + 3 * n),
            ("xmss auth top layer", top_layer + set.len() * n),
            ("last byte", set.sig_len() - 1),
        ] {
            let mut bad = sig.clone();
            bad[pos] ^= 0x01;
            assert!(
                execute(&spend_script(&pk, &plan, &bad, &message)).is_err(),
                "{}: verifier accepted a signature corrupted at {label} (byte {pos})",
                set.name
            );
        }
    }
}

/// Two elements swapped inside the signature keeps the length and the byte
/// multiset identical, so it catches an emitter that consumes the witness in
/// the wrong order — which a random bit-flip would not.
#[test]
fn transposed_signature_elements_are_rejected() {
    for set in FAST_SETS {
        let (n, plan) = (set.n, BlobPlan::for_params(set));
        let message = [0x11u8; 32];
        let (pk, sig) = signed(set, 1, &message);
        let ht_start = n + set.k * (1 + set.a) * n;
        let auth_start = ht_start + set.len() * n;

        for (a, b) in [
            (0usize, n),
            (ht_start, ht_start + n),
            (auth_start, auth_start + n),
        ] {
            let mut swapped = sig.clone();
            for k in 0..n {
                swapped.swap(a + k, b + k);
            }
            assert!(
                execute(&spend_script(&pk, &plan, &swapped, &message)).is_err(),
                "{}: verifier accepted elements at {a} and {b} transposed",
                set.name
            );
        }
    }
}
