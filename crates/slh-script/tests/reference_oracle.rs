//! The shadow verifier **and the signer** are checked against `fips205` before
//! anything is built on top of them.
//!
//! Everything downstream — the emitted script, every differential test, all
//! three parameter sets — is compared against `reference::verify_traced` and
//! signed by `slh_script::signer`. If either is wrong, the whole measurement is
//! wrong in a way no amount of script testing would reveal, so both are pinned
//! against an independent implementation with NIST ACVP vectors in-crate, and
//! against its negative cases too.
//!
//! Only `128s` can be pinned this way, because it is the only one of the three
//! that anybody else implements. What that buys for the other two is this: the
//! code is the same code. `signer.rs` and `reference.rs` read their constants
//! from [`Params`] and have no per-set branches, so a `128s` instantiation that
//! agrees with `fips205` byte for byte is evidence about the algorithm, not
//! about one table of numbers.

use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Signer, Verifier};
use slh_script::params::*;
use slh_script::reference::{self, PublicKey, Signature};
use slh_script::{SecretSeeds, SigningKey};

const P: &Params = &SHA2_128S;

fn keypair() -> (slh_dsa_sha2_128s::PublicKey, slh_dsa_sha2_128s::PrivateKey) {
    slh_dsa_sha2_128s::try_keygen().expect("keygen")
}

/// **The signer's pin.** Our `slh_keygen_internal` and `slh_sign_internal` must
/// reproduce `fips205` exactly, not merely produce something it accepts.
///
/// `fips205` will not take the three secrets directly — that is the whole
/// reason this signer exists — so the comparison runs the other way: it
/// generates a key, recovers the three seeds from the private key's serialised
/// form, regenerates from those, and requires the public keys and the
/// signatures to match.
#[test]
fn the_signer_reproduces_fips205() {
    let (fips_pk, fips_sk) = keypair();
    let sk_bytes = fips_sk.clone().into_bytes();

    // FIPS 205 §9.1: a private key serialises as SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root.
    let mut seeds = SecretSeeds { sk_seed: [0; N], sk_prf: [0; N], pk_seed: [0; N] };
    seeds.sk_seed.copy_from_slice(&sk_bytes[..N]);
    seeds.sk_prf.copy_from_slice(&sk_bytes[N..2 * N]);
    seeds.pk_seed.copy_from_slice(&sk_bytes[2 * N..3 * N]);

    let ours = SigningKey::generate(P, seeds);
    let theirs = PublicKey::from_bytes(&fips_pk.clone().into_bytes()).expect("pk parse");
    assert_eq!(
        ours.public_key(),
        theirs,
        "keygen diverged from fips205: the hypertree root differs"
    );

    for i in 0..3u8 {
        let message = [i; 32];
        let ours_sig = ours.sign(&message);
        let theirs_sig = fips_sk.try_sign(&message, &[], false).expect("sign");
        assert_eq!(
            ours_sig,
            theirs_sig.to_vec(),
            "signing diverged from fips205 on message {i}"
        );
        assert!(fips_pk.verify(&message, &theirs_sig, &[]), "fips205 rejected its own signature");
    }
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
        let our_sig = Signature::from_bytes(P, &sig).expect("sig parse");
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
    assert!(!reference::verify(&our_pk, &Signature::from_bytes(P, &sig).unwrap(), &other));

    // Corrupted signature, one element at a time across every region.
    for &pos in &[0usize, N, N * 5, N * 100, N * 200, N * 400, P.sig_len() - 1] {
        let mut bad = sig;
        bad[pos] ^= 0x01;
        assert!(!pk.verify(&message, &bad, &[]), "fips205 accepted a corrupt sig at {pos}");
        assert!(
            !reference::verify(&our_pk, &Signature::from_bytes(P, &bad).unwrap(), &message),
            "shadow verifier accepted a corrupt sig at byte {pos}"
        );
    }

    // Wrong key.
    let (other_pk, _) = keypair();
    let other_pk = PublicKey::from_bytes(&other_pk.into_bytes()).expect("pk parse");
    assert!(!reference::verify(&other_pk, &Signature::from_bytes(P, &sig).unwrap(), &message));
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
    let our_sig = Signature::from_bytes(P, &sig).expect("sig parse");

    let trace = reference::verify_traced(&our_pk, &our_sig, &message);
    assert_eq!(trace.root, our_pk.root);

    // Without the prefix the digest differs, so verification must fail. This is
    // what makes the assertion above load-bearing rather than tautological.
    let unprefixed = reference::h_msg(P, &our_sig.randomness, &our_pk, &message);
    assert_ne!(
        unprefixed,
        reference::h_msg(P, &our_sig.randomness, &our_pk, &reference::context_prefixed(&message))
    );
}

/// The signature splits into the element groups the script consumes, in order.
#[test]
fn signature_element_layout_is_addressable() {
    let (_, sk) = keypair();
    let sig_bytes = sk.try_sign(b"layout", &[], false).expect("sign");
    let sig = Signature::from_bytes(P, &sig_bytes).expect("sig parse");

    let (k, a, d, len, hp) = (P.k, P.a, P.d, P.len(), P.hp);
    assert_eq!(sig.fors.len(), k * (1 + a));
    assert_eq!(sig.ht.len(), d * (len + hp));
    assert_eq!(1 + sig.fors.len() + sig.ht.len(), P.sig_elements());

    // Group accessors must index the same bytes the flat signature holds.
    let (sk_val, auth) = sig.fors_group(3);
    let base = N + 3 * (1 + a) * N;
    assert_eq!(&sk_val[..], &sig_bytes[base..base + N]);
    assert_eq!(auth.len(), a);
    assert_eq!(&auth[0][..], &sig_bytes[base + N..base + 2 * N]);

    let (wots, path) = sig.ht_layer(2);
    let base = N + k * (1 + a) * N + 2 * (len + hp) * N;
    assert_eq!(wots.len(), len);
    assert_eq!(path.len(), hp);
    assert_eq!(&wots[0][..], &sig_bytes[base..base + N]);
    assert_eq!(&path[0][..], &sig_bytes[base + len * N..base + (len + 1) * N]);
}

/// `base_2b` against the worked shapes the algorithm relies on.
#[test]
fn base_2b_extracts_big_endian_fields() {
    assert_eq!(reference::base_2b(&[0x12, 0x34], 4, 4), vec![1, 2, 3, 4]);
    // 12-bit fields, as FORS uses over `md`.
    assert_eq!(reference::base_2b(&[0xab, 0xcd, 0xef], 12, 2), vec![0xabc, 0xdef]);
    // 2-bit fields, as the `lg(w) = 2` sets use over a WOTS+ message.
    assert_eq!(reference::base_2b(&[0b1101_1000], 2, 4), vec![3, 1, 2, 0]);
    // 14-bit and 24-bit FORS fields, the two the 2^24 sets need.
    assert_eq!(reference::base_2b(&[0xff, 0xff, 0xff], 24, 1), vec![0xff_ffff]);
    assert_eq!(reference::base_2b(&[0b1111_1111, 0b1111_1100], 14, 1), vec![0x3fff]);
    assert_eq!(reference::to_int(&[0x01, 0x02]), 0x0102);
}

/// The WOTS+ checksum digits must match FIPS 205's shift-and-`base_2b`
/// construction for every set, including the `lg(w) = 2` sets whose checksum
/// is byte-aligned and whose digits are therefore *not* nibbles.
#[test]
fn wots_checksum_digits_follow_the_standard() {
    for set in ALL {
        let m = [0x5au8; N];
        let msg = reference::wots_message(set, &m);
        assert_eq!(msg.len(), set.len(), "{}", set.name);
        assert!(msg.iter().all(|&d| d < set.w()), "{}: a digit exceeded w-1", set.name);

        let csum: u32 = msg[..set.len1()].iter().map(|d| set.w() - 1 - d).sum();
        for (j, &digit) in msg[set.len1()..].iter().enumerate() {
            let shift = set.csum_bits() - set.lgw * (j as u32 + 1);
            assert_eq!(
                digit,
                (csum >> shift) & (set.w() - 1),
                "{}: checksum digit {j}",
                set.name
            );
        }
    }
}
