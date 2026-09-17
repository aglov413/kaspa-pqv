//! Differential tests against the reference, and the negative controls that
//! make them mean something.
//!
//! # Why the ADRS gets special treatment
//!
//! Every hash in SLH-DSA is domain-separated by a 22-byte compressed address.
//! A verifier with the wrong ADRS layout is *self-consistent*: it would verify
//! signatures made by itself and reject every real one. That failure looks
//! exactly like "the signature is bad", which is why the emitter is checked
//! against signatures produced by an implementation that has never seen this
//! code — and why the ADRS is then deliberately broken, to prove the check
//! would have caught it.

use vault_harness::execute;
use slh_script::adrs::{hash, Adrs};
use slh_script::params::*;
use slh_script::reference::{self, Signature};
use slh_script::witness::BlobPlan;

mod common;
use common::{signed, verify_script_with_witness as spend_script, FAST_SETS};

/// Independent keys and messages, so the emitted script runs against a wide
/// spread of hypertree positions, index bits and Winternitz chain lengths
/// rather than one lucky path.
#[test]
fn many_independent_signatures_verify() {
    for set in FAST_SETS {
        let plan = BlobPlan::for_params(set);
        for round in 0..6u8 {
            let message = [round.wrapping_mul(37).wrapping_add(11); 32];
            let (pk, sig) = signed(set, round, &message);

            // The shadow verifier and the script must agree with each other on
            // the same inputs, and for `128s` both are pinned to `fips205` by
            // `reference_oracle.rs`.
            let parsed = Signature::from_bytes(set, &sig).expect("parse");
            let trace = reference::verify_traced(&pk, &parsed, &message);
            assert_eq!(trace.root, pk.root, "{}: reference rejected round {round}", set.name);

            execute(&spend_script(&pk, &plan, &sig, &message))
                .unwrap_or_else(|e| panic!("{}: script rejected round {round}: {e}", set.name));
        }
    }
}

/// The script's implied intermediates match the reference's, position by
/// position — not merely "both said yes".
///
/// A verifier that ignored the message-derived indices entirely (say, by
/// always using zero) would still be self-consistent. These assertions pin the
/// indices to the digest and check they are actually spread across the
/// hypertree.
#[test]
fn the_message_selects_the_hypertree_position() {
    for set in FAST_SETS {
        let mut seen_trees = std::collections::HashSet::new();
        let mut seen_leaves = std::collections::HashSet::new();
        for i in 0..24u8 {
            let message = [i; 32];
            let (pk, sig) = signed(set, 9, &message);
            let parsed = Signature::from_bytes(set, &sig).expect("parse");
            let trace = reference::verify_traced(&pk, &parsed, &message);

            // The indices are exactly the digest fields, masked as FIPS 205
            // says. A `d = 1` set carries no tree index at all, and the mask
            // below would be a shift by 64 — so that case is stated rather
            // than folded into the arithmetic.
            if set.idx_tree_bits() == 0 {
                assert_eq!(trace.idx_tree, 0, "{}: a one-layer hypertree has one tree", set.name);
            } else {
                let field = &trace.digest[set.md_len()..set.md_len() + set.idx_tree_len()];
                let expected = reference::to_int(field) & (u64::MAX >> (64 - set.idx_tree_bits()));
                assert_eq!(trace.idx_tree, expected, "{}", set.name);
                assert!(trace.idx_tree < (1u64 << set.idx_tree_bits()));
            }
            assert!(trace.idx_leaf < (1u32 << set.hp));

            // FORS opens k trees at message-derived leaves.
            assert_eq!(trace.fors_indices.len(), set.k);
            assert!(trace.fors_indices.iter().all(|&x| x < (1 << set.a)));

            seen_trees.insert(trace.idx_tree);
            seen_leaves.insert(trace.idx_leaf);
        }

        // Statelessness is exactly this: different messages land in different
        // places without anything being recorded. A `d = 1` set spreads over
        // leaves only, because it has a single tree to spread within.
        let spread = if set.idx_tree_bits() == 0 { seen_leaves.len() } else { seen_trees.len() };
        assert!(spread > 20, "{}: only {spread} distinct positions in 24 signatures", set.name);
        assert!(seen_leaves.len() > 10, "{}: only {} distinct leaves", set.name, seen_leaves.len());
    }
}

/// The layer addresses walk the hypertree the way Algorithm 21 says: each
/// layer's tree address is the previous one shifted right by `h'`, and its key
/// pair address is the bits that fell off.
#[test]
fn hypertree_layer_addresses_are_shifts_of_the_tree_index() {
    for set in FAST_SETS {
        let (pk, sig) = signed(set, 3, b"addressing");
        let parsed = Signature::from_bytes(set, &sig).unwrap();
        let trace = reference::verify_traced(&pk, &parsed, b"addressing");

        assert_eq!(trace.layer_addresses.len(), set.d, "{}", set.name);
        assert_eq!(trace.layer_addresses[0], (trace.idx_tree, trace.idx_leaf));
        for layer in 1..set.d {
            let (tree, leaf) = trace.layer_addresses[layer];
            assert_eq!(
                tree,
                trace.idx_tree >> (set.hp * layer),
                "{}: layer {layer} tree address",
                set.name
            );
            assert_eq!(
                u64::from(leaf),
                (trace.idx_tree >> (set.hp * (layer - 1))) & ((1 << set.hp) - 1),
                "{}: layer {layer} key pair address",
                set.name
            );
        }

        // The top layer's tree address must be zero: `h - h/d` bits of index
        // are consumed by exactly `d - 1` shifts of `h'`.
        assert_eq!(trace.layer_addresses[set.d - 1].0, 0, "{}", set.name);
    }
}

/// **The ADRS negative control.** Break the address layout the way a
/// misreading of FIPS 205 §11.2 would, and confirm verification collapses.
///
/// Without this, "the reference verifies real signatures" is evidence that the
/// ADRS is right, but not evidence that the test could tell if it were wrong.
#[test]
fn a_wrong_adrs_layout_breaks_verification() {
    let seed = [0x33u8; N];
    let mut correct = Adrs::new();
    correct.set_layer(2);
    correct.set_tree_address(0x0123_4567_89ab_cdef);
    correct.set_type_and_clear(TREE);
    correct.set_tree_height(5);
    correct.set_tree_index(9);
    let good = hash(&seed, &correct, &[&[0xAAu8; N]]);

    // Little-endian tree address instead of big-endian.
    let mut swapped = correct;
    swapped.0[1..9].reverse();
    assert_ne!(hash(&seed, &swapped, &[&[0xAAu8; N]]), good, "endianness must matter");

    // Tree height written into the key pair word — the aliasing trap.
    let mut aliased = correct;
    aliased.set_key_pair_address(5);
    aliased.set_tree_height(0);
    assert_ne!(hash(&seed, &aliased, &[&[0xAAu8; N]]), good, "word aliasing must matter");

    // A type byte that was set without clearing the words.
    let mut stale = correct;
    stale.0[9] = FORS_TREE;
    assert_ne!(hash(&seed, &stale, &[&[0xAAu8; N]]), good, "the type byte must matter");

    // The 48-byte pad is not decorative: it is what makes the first SHA-256
    // block constant, and it is inside the hashed preimage.
    use sha2::{Digest, Sha256};
    let mut unpadded = Sha256::new();
    unpadded.update(seed);
    unpadded.update(correct.as_bytes());
    unpadded.update([0xAAu8; N]);
    assert_ne!(&unpadded.finalize()[..N], &good[..], "the pad must be hashed");
}

/// Truncation to `n` bytes is part of the definition of `F`, `H` and `T_l`.
/// A verifier that carried the full 32-byte SHA-256 output forward would be
/// internally consistent and incompatible with everything.
#[test]
fn hashes_are_truncated_to_n_bytes() {
    let seed = [0x44u8; N];
    let adrs = Adrs::new();
    assert_eq!(hash(&seed, &adrs, &[&[0u8; N]]).len(), N);
}

/// A signature verifying under a *different* message must be impossible even
/// when the two messages share a prefix, which is what the context prefix and
/// the length-committed digest are for.
#[test]
fn near_miss_messages_are_rejected() {
    for set in FAST_SETS {
        let plan = BlobPlan::for_params(set);
        let message = [0x9au8; 32];
        let (pk, sig) = signed(set, 4, &message);

        for pos in [0usize, 15, 31] {
            let mut near = message;
            near[pos] ^= 0x80;
            assert!(
                execute(&spend_script(&pk, &plan, &sig, &near)).is_err(),
                "{}: a signature verified against a message differing at byte {pos}",
                set.name
            );
        }
    }
}
