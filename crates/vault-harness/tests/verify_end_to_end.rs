//! The test that decides the design: a real LMS signature, produced by the
//! reference implementation, verified by generated Kaspa script running under
//! the consensus engine.
//!
//! Signatures come from `oxicrypt-lms`, which carries NIST ACVP vectors for
//! this exact parameter pair. If the generated script accepts precisely what
//! the reference accepts — and rejects what it rejects — the verifier is
//! correct for the reasons that matter.

use vault_harness::execute;
use lms_script::params::{LmsParams, N};
use lms_script::verify::{emit_verify, LmsPublicKey};
use lms_script::ScriptWriter;
use oxicrypt_lms::lms_sha256_m32_h5_w2 as lms;

const PARAMS: LmsParams = LmsParams::SHA256_H5_W2;

/// RFC 8554 §5.4 signature layout.
struct ParsedSignature {
    q: u32,
    c: [u8; N],
    y: Vec<[u8; N]>,
    path: Vec<[u8; N]>,
}

fn parse_signature(sig: &[u8]) -> ParsedSignature {
    assert_eq!(sig.len(), PARAMS.signature_len(), "unexpected signature length");

    let q = u32::from_be_bytes(sig[0..4].try_into().unwrap());
    let c: [u8; N] = sig[8..40].try_into().unwrap();

    let y_end = 40 + PARAMS.p * N;
    let y = sig[40..y_end].chunks_exact(N).map(|c| <[u8; N]>::try_from(c).unwrap()).collect();

    let path_start = y_end + 4;
    let path =
        sig[path_start..].chunks_exact(N).map(|c| <[u8; N]>::try_from(c).unwrap()).collect();

    ParsedSignature { q, c, y, path }
}

/// RFC 8554 §5.3 public key layout.
fn parse_public_key(pk: &[u8]) -> LmsPublicKey {
    assert_eq!(pk.len(), PARAMS.public_key_len());
    LmsPublicKey {
        id: pk[8..24].try_into().unwrap(),
        root: pk[24..56].try_into().unwrap(),
    }
}

/// Build the signature script: witness pushes, bottom first.
fn emit_witness(w: &mut ScriptWriter, sig: &ParsedSignature, message: &[u8]) {
    for node in sig.path.iter().rev() {
        w.data(node).unwrap();
    }
    for y in sig.y.iter().rev() {
        w.data(y).unwrap();
    }
    w.data(&sig.c).unwrap();
    w.data(message).unwrap();
}

fn build_script(key: &LmsPublicKey, sig: &ParsedSignature, message: &[u8]) -> Vec<u8> {
    let mut w = ScriptWriter::new();
    emit_witness(&mut w, sig, message);
    emit_verify(&mut w, &PARAMS, key, sig.q).unwrap();
    w.build()
}

fn signing_key(seed: u8) -> (lms::LmsSigningKey, LmsPublicKey) {
    let xi = [seed; 32];
    let (sk, pk) = lms::LmsSigningKey::new_internal(&xi);
    (sk, parse_public_key(&pk))
}

/// A genuine signature verifies.
#[test]
fn valid_signature_verifies_in_script() {
    let (mut sk, key) = signing_key(0x11);
    let message = [0xabu8; 32];

    let sig_bytes = sk.sign_internal(&message).expect("signing should succeed");
    let sig = parse_signature(&sig_bytes);
    assert_eq!(sig.q, 0, "first signature should use leaf 0");

    let cost = execute(&build_script(&key, &sig, &message))
        .expect("generated script rejected a valid signature");

    println!(
        "LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W2 verify: {} script bytes, {} script units \
         ({} grams, {} compute-budget units)",
        cost.script_bytes,
        cost.script_units,
        cost.grams(),
        cost.compute_budget_units()
    );
}

/// Every leaf index works, and each produces a distinct script.
#[test]
fn every_leaf_index_verifies() {
    let (mut sk, key) = signing_key(0x22);
    let mut seen_scripts = Vec::new();

    for expected_q in 0..PARAMS.leaf_count() {
        let message = [expected_q as u8; 32];
        let sig_bytes = sk.sign_internal(&message).expect("signing should succeed");
        let sig = parse_signature(&sig_bytes);
        assert_eq!(sig.q, expected_q);

        let script = build_script(&key, &sig, &message);
        execute(&script).unwrap_or_else(|e| panic!("leaf {expected_q} rejected: {e}"));
        seen_scripts.push(script);
    }

    assert!(sk.is_exhausted(), "h = 5 should give exactly 32 signatures");

    // Pinned q means each leaf is a different script, hence a different address.
    for i in 1..seen_scripts.len() {
        assert_ne!(seen_scripts[i], seen_scripts[i - 1], "leaf scripts must differ");
    }
}

/// A tampered chain value must be rejected.
#[test]
fn corrupted_chain_value_is_rejected() {
    let (mut sk, key) = signing_key(0x33);
    let message = [0x5au8; 32];
    let sig_bytes = sk.sign_internal(&message).unwrap();

    for idx in [0usize, 1, 64, PARAMS.p - 1] {
        let mut sig = parse_signature(&sig_bytes);
        sig.y[idx][0] ^= 0x01;
        assert!(
            execute(&build_script(&key, &sig, &message)).is_err(),
            "corrupted y[{idx}] was accepted"
        );
    }
}

/// A different message must be rejected — this is the property that binds a
/// signature to one transaction.
#[test]
fn different_message_is_rejected() {
    let (mut sk, key) = signing_key(0x44);
    let message = [0x5au8; 32];
    let sig_bytes = sk.sign_internal(&message).unwrap();
    let sig = parse_signature(&sig_bytes);

    let mut other = message;
    other[31] ^= 0x01;
    assert!(
        execute(&build_script(&key, &sig, &other)).is_err(),
        "signature verified against the wrong message"
    );
}

/// A signature for one leaf must not verify under another leaf's script.
/// This is what makes the pinned-q address model safe.
#[test]
fn signature_does_not_verify_under_a_different_leaf() {
    let (mut sk, key) = signing_key(0x55);
    let message = [0x77u8; 32];
    let sig = parse_signature(&sk.sign_internal(&message).unwrap());
    assert_eq!(sig.q, 0);

    let mut w = ScriptWriter::new();
    emit_witness(&mut w, &sig, &message);
    emit_verify(&mut w, &PARAMS, &key, 1).unwrap(); // wrong leaf
    assert!(execute(&w.build()).is_err(), "leaf-0 signature verified under leaf 1");
}

/// Tampering with the Merkle path must be rejected.
#[test]
fn corrupted_merkle_path_is_rejected() {
    let (mut sk, key) = signing_key(0x66);
    let message = [0x99u8; 32];
    let sig_bytes = sk.sign_internal(&message).unwrap();

    for level in 0..PARAMS.h as usize {
        let mut sig = parse_signature(&sig_bytes);
        sig.path[level][0] ^= 0x01;
        assert!(
            execute(&build_script(&key, &sig, &message)).is_err(),
            "corrupted path[{level}] was accepted"
        );
    }
}

/// A signature under a different key must not verify.
#[test]
fn signature_from_another_key_is_rejected() {
    let (mut sk_a, _key_a) = signing_key(0x77);
    let (_sk_b, key_b) = signing_key(0x88);
    let message = [0x12u8; 32];

    let sig = parse_signature(&sk_a.sign_internal(&message).unwrap());
    assert!(
        execute(&build_script(&key_b, &sig, &message)).is_err(),
        "signature verified under the wrong public key"
    );
}
