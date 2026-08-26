//! The shadow verifier is checked against `fips205` before anything is built
//! on top of it.
//!
//! Everything downstream — the emitted script, every differential test — is
//! compared against `reference::verify_traced`. If that is wrong, the whole
//! measurement is wrong in a way no amount of script testing would reveal, so
//! it is pinned against an independent implementation with NIST ACVP vectors
//! in-crate, and against its negative cases too.

use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Signer, Verifier};
use slh_script::params::*;
use slh_script::reference::{self, PublicKey, Signature};

fn keypair() -> (slh_dsa_sha2_128s::PublicKey, slh_dsa_sha2_128s::PrivateKey) {
    slh_dsa_sha2_128s::try_keygen().expect("keygen")
}

#[test]
fn shadow_verifier_agrees_with_fips205_on_valid_signatures() {
    let (pk, sk) = keypair();
    for i in 0..4u8 {
        let message = [i; 48];
        // Deterministic (non-hedged) signing keeps failures reproducible.
        let sig = sk.try_sign(&message, &[], false).expect("sign");
        assert!(pk.verify(&message, &sig, &[]), "fips205 rejected its own signature");

        let our_pk = PublicKey::from_bytes(&pk.clone().into_bytes()).expect("pk parse");
        let our_sig = Signature::from_bytes(&sig).expect("sig parse");
        assert!(
            reference::verify(&our_pk, &our_sig, &message),
            "shadow verifier rejected a signature fips205 accepts (message {i})"
        );
    }
}

/// Negative control: agreement on acceptance is meaningless without agreement
/// on rejection. A verifier that returns `true` unconditionally would pass the
/// test above.
#[test]
fn shadow_verifier_agrees_with_fips205_on_rejection() {
    let (pk, sk) = keypair();
    let message = [7u8; 48];
    let sig = sk.try_sign(&message, &[], false).expect("sign");
    let our_pk = PublicKey::from_bytes(&pk.clone().into_bytes()).expect("pk parse");

    // Wrong message.
    let other = [8u8; 48];
    assert!(!pk.verify(&other, &sig, &[]));
    assert!(!reference::verify(&our_pk, &Signature::from_bytes(&sig).unwrap(), &other));

    // Corrupted signature, one element at a time across every region.
    for &pos in &[0usize, N, N * 5, N * 100, N * 200, N * 400, SIG_LEN - 1] {
        let mut bad = sig;
        bad[pos] ^= 0x01;
        assert!(!pk.verify(&message, &bad, &[]), "fips205 accepted a corrupt sig at {pos}");
        assert!(
            !reference::verify(&our_pk, &Signature::from_bytes(&bad).unwrap(), &message),
            "shadow verifier accepted a corrupt sig at byte {pos}"
        );
    }

    // Wrong key.
    let (other_pk, _) = keypair();
    let other_pk = PublicKey::from_bytes(&other_pk.into_bytes()).expect("pk parse");
    assert!(!reference::verify(&other_pk, &Signature::from_bytes(&sig).unwrap(), &message));
}

/// The context prefix is invisible in a self-consistent implementation: sign
/// and verify both omitting it still agree. It is pinned against `fips205`,
/// which applies it, so that the vault cannot drift into a private scheme.
#[test]
fn empty_context_prefix_is_applied() {
    assert_eq!(reference::context_prefixed(b"abc"), b"\x00\x00abc");

    let (pk, sk) = keypair();
    let message = [3u8; 32];
    let sig = sk.try_sign(&message, &[], false).expect("sign");
    let our_pk = PublicKey::from_bytes(&pk.into_bytes()).expect("pk parse");
    let our_sig = Signature::from_bytes(&sig).expect("sig parse");

    let trace = reference::verify_traced(&our_pk, &our_sig, &message);
    assert_eq!(trace.root, our_pk.root);

    // Without the prefix the digest differs, so verification must fail. This is
    // what makes the assertion above load-bearing rather than tautological.
    let unprefixed = reference::h_msg(&our_sig.randomness, &our_pk, &message);
    assert_ne!(
        unprefixed,
        reference::h_msg(&our_sig.randomness, &our_pk, &reference::context_prefixed(&message))
    );
}

/// The signature splits into the element groups the script consumes, in order.
#[test]
fn signature_element_layout_is_addressable() {
    let (_, sk) = keypair();
    let sig_bytes = sk.try_sign(b"layout", &[], false).expect("sign");
    let sig = Signature::from_bytes(&sig_bytes).expect("sig parse");

    assert_eq!(sig.fors.len(), K * (1 + A));
    assert_eq!(sig.ht.len(), D * (LEN + HP));
    assert_eq!(1 + sig.fors.len() + sig.ht.len(), SIG_ELEMENTS);

    // Group accessors must index the same bytes the flat signature holds.
    let (sk_val, auth) = sig.fors_group(3);
    let base = N + 3 * (1 + A) * N;
    assert_eq!(&sk_val[..], &sig_bytes[base..base + N]);
    assert_eq!(auth.len(), A);
    assert_eq!(&auth[0][..], &sig_bytes[base + N..base + 2 * N]);

    let (wots, path) = sig.ht_layer(2);
    let base = N + K * (1 + A) * N + 2 * (LEN + HP) * N;
    assert_eq!(wots.len(), LEN);
    assert_eq!(path.len(), HP);
    assert_eq!(&wots[0][..], &sig_bytes[base..base + N]);
    assert_eq!(&path[0][..], &sig_bytes[base + LEN * N..base + (LEN + 1) * N]);
}

/// `base_2b` against the worked shapes the algorithm relies on.
#[test]
fn base_2b_extracts_big_endian_fields() {
    assert_eq!(reference::base_2b(&[0x12, 0x34], 4, 4), vec![1, 2, 3, 4]);
    // 12-bit fields, as FORS uses over `md`.
    assert_eq!(reference::base_2b(&[0xab, 0xcd, 0xef], 12, 2), vec![0xabc, 0xdef]);
    assert_eq!(reference::to_int(&[0x01, 0x02]), 0x0102);
}
