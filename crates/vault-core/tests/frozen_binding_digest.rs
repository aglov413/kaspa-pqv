//! The binding digest, frozen byte for byte.
//!
//! # Why differential testing is not enough here
//!
//! Every other test of the binding digest checks that the **in-script**
//! reconstruction and the **off-chain** serializer agree with each other. That
//! catches the two drifting apart, which is the failure that bricks a UTXO
//! mid-flight.
//!
//! It does not catch them drifting *together*. Change the field order, widen a
//! length prefix, or swap an endianness in `binding_preimage`, and the emitter
//! is usually changed to match in the same edit — at which point every
//! differential test still passes, and every address funded under the old
//! construction becomes unspendable, silently, with no failing test anywhere.
//!
//! So the bytes themselves are pinned. A diff to this file is a compatibility
//! break: coins at existing vault addresses can no longer be spent by this
//! code. There is no version negotiation and no migration path — the digest is
//! what a signature committed to, and a one-time key cannot re-issue one.
//!
//! Regenerate **only** when the break is intended:
//!
//! ```text
//! cargo test -p vault-core --test frozen_binding_digest -- --ignored regenerate --nocapture
//! ```

use vault_core::binding::{binding_digest, binding_preimage, OutputView, SpendView};

/// The canonical vault spend: one input, destination plus change.
///
/// The values are arbitrary but fixed. The point is that they never change,
/// not that they are realistic.
fn canonical_view() -> SpendView {
    SpendView {
        tx_version: 1,
        outpoint_txid: core::array::from_fn(|i| i as u8),
        outpoint_index: 0,
        outputs: vec![
            OutputView { amount: 100_000_000, spk_version: 0, script: vec![0xaa; 35] },
            OutputView { amount: 899_000_000, spk_version: 0, script: vec![0xbb; 35] },
        ],
    }
}

/// A spend exercising the fields the canonical one leaves at zero: a non-zero
/// outpoint index, a non-zero SPK version, and asymmetric script lengths.
///
/// SPK version 0 is endian-symmetric and standardness rejects anything higher,
/// so without this a byte-order mistake in the version prefix would be
/// invisible in every realistic test.
fn edge_view() -> SpendView {
    SpendView {
        tx_version: 0x0102,
        outpoint_txid: core::array::from_fn(|i| (0xff - i) as u8),
        outpoint_index: 0x0000_1234,
        outputs: vec![
            OutputView { amount: 1, spk_version: 0x0304, script: vec![0x11; 1] },
            OutputView { amount: u64::from(u32::MAX), spk_version: 0, script: vec![0x22; 64] },
        ],
    }
}

#[test]
fn the_canonical_binding_digest_is_frozen() {
    let view = canonical_view();
    assert_eq!(
        hex::encode(binding_preimage(&view).expect("preimage")),
        CANONICAL_PREIMAGE,
        "the binding preimage changed -- every funded vault address is now unspendable"
    );
    assert_eq!(
        hex::encode(binding_digest(&view).expect("digest")),
        CANONICAL_DIGEST,
        "the binding digest changed -- every funded vault address is now unspendable"
    );
}

#[test]
fn the_edge_case_binding_digest_is_frozen() {
    assert_eq!(
        hex::encode(binding_digest(&edge_view()).expect("digest")),
        EDGE_DIGEST,
        "the binding digest changed on non-zero versions and indices"
    );
}

/// The digest must depend on every field it claims to cover. A construction
/// that silently dropped one would still be self-consistent, and would let a
/// spend be redirected.
#[test]
fn every_covered_field_changes_the_digest() {
    let base = binding_digest(&canonical_view()).expect("digest");

    let mut v = canonical_view();
    v.tx_version += 1;
    assert_ne!(binding_digest(&v).unwrap(), base, "tx_version is not covered");

    let mut v = canonical_view();
    v.outpoint_txid[31] ^= 1;
    assert_ne!(binding_digest(&v).unwrap(), base, "outpoint txid is not covered");

    let mut v = canonical_view();
    v.outpoint_index += 1;
    assert_ne!(binding_digest(&v).unwrap(), base, "outpoint index is not covered");

    let mut v = canonical_view();
    v.outputs[0].amount += 1;
    assert_ne!(binding_digest(&v).unwrap(), base, "output amount is not covered");

    let mut v = canonical_view();
    v.outputs[0].script[0] ^= 1;
    assert_ne!(binding_digest(&v).unwrap(), base, "output script is not covered");

    let mut v = canonical_view();
    v.outputs[0].spk_version += 1;
    assert_ne!(binding_digest(&v).unwrap(), base, "output spk version is not covered");

    let mut v = canonical_view();
    v.outputs.swap(0, 1);
    assert_ne!(binding_digest(&v).unwrap(), base, "output order is not covered");

    let mut v = canonical_view();
    v.outputs.pop();
    assert_ne!(binding_digest(&v).unwrap(), base, "output count is not covered");
}

/// Length prefixes are what stop two different output sets colliding. Without
/// them `[script "0102", script "03"]` and `[script "01", script "0203"]`
/// would serialize identically.
#[test]
fn length_prefixes_prevent_collisions() {
    let mut a = canonical_view();
    a.outputs[0].script = vec![0x01, 0x02];
    a.outputs[1].script = vec![0x03];

    let mut b = canonical_view();
    b.outputs[0].script = vec![0x01];
    b.outputs[1].script = vec![0x02, 0x03];

    assert_ne!(binding_digest(&a).unwrap(), binding_digest(&b).unwrap());
}

#[test]
#[ignore = "regeneration helper; a diff here is a compatibility break"]
fn regenerate() {
    println!("CANONICAL_PREIMAGE {}", hex::encode(binding_preimage(&canonical_view()).unwrap()));
    println!("CANONICAL_DIGEST {}", hex::encode(binding_digest(&canonical_view()).unwrap()));
    println!("EDGE_DIGEST {}", hex::encode(binding_digest(&edge_view()).unwrap()));
}

const CANONICAL_PREIMAGE: &str = "0100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000000200e1f5050000000025000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac0a695350000000025000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CANONICAL_DIGEST: &str = "a9c47f7c925c11286be8e565d24834447af4368bd4db40014b5f749285be056f";
const EDGE_DIGEST: &str = "621b10ab9ee4621a122399f00f08a6ea647b0a4a94976fe1c931555ce3a23815";
