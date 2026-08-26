//! The binding digest `D`: what a vault signature actually commits to.
//!
//! Kaspa has no sighash opcode and the introspection range provides no
//! equivalent, so the digest is reconstructed inside the redeem script from
//! introspection primitives. The same bytes are produced off-chain by
//! [`binding_preimage`] when building the transaction to sign.
//!
//! **These two constructions must agree byte for byte.** They do not fail
//! loudly when they diverge — the signature simply verifies against a message
//! nobody will ever reconstruct, and the UTXO becomes unspendable with no error
//! anywhere. That is why there is one serializer, and why the in-script
//! emission is property-tested against it rather than eyeballed.
//!
//! # What it covers, and why
//!
//! Covering the outpoint stops a receipt or signature being replayed against a
//! different UTXO sharing the same script. Covering every output amount and
//! script public key stops the spend being redirected. Neither is optional.
//!
//! # Canonical preimage
//!
//! All integers little-endian at fixed width, matching `OpNum2Bin`. Variable
//! length fields are length-prefixed; without the prefix two distinct output
//! sets can collide.
//!
//! ```text
//! version        u16 LE   (2)
//! outpoint_txid  32 bytes
//! outpoint_index u32 LE   (4)
//! output_count   u8       (1)
//! per output i:
//!   amount       u64 LE   (8)
//!   spk_len      u16 LE   (2)
//!   spk          spk_len bytes
//! ```
//!
//! # The SPK endianness trap
//!
//! `spk` is the wire encoding `OpTxOutputSpk` pushes, which is
//! `version.to_be_bytes() || script` — the SPK version is **big**-endian while
//! every other integer here is little-endian. `OpTxOutputSpkLen` measures that
//! same encoding, so `spk_len == script.len() + 2`.
//!
//! Version 0 is endian-symmetric, and standardness currently rejects any output
//! whose SPK version exceeds 0, so a byte-order mistake here is invisible in
//! every test that uses realistic outputs. [`spk_wire_bytes`] exists so the
//! encoding is written once, and the property tests deliberately include
//! non-zero versions.

use anyhow::{ensure, Result};
use kaspa_txscript::opcodes::codes::*;
use sha2::{Digest, Sha256};

use crate::builder::ScriptWriter;

/// Maximum SPK length the 2-byte length prefix can express.
///
/// `OpNum2Bin` emits little-endian *sign-magnitude*, so two bytes carry
/// magnitudes only up to `0x7FFF`. Every standard output type is far below
/// this; widen the prefix to four bytes if a vault ever needs to pay a large
/// script.
pub const MAX_SPK_LEN: usize = 0x7FFF;

/// Maximum amount the 8-byte field can express, for the same reason.
/// Kaspa's total supply (~2.87e18 sompi) is comfortably below it.
pub const MAX_AMOUNT: u64 = i64::MAX as u64;

/// Maximum transaction version the 2-byte field can express.
///
/// `OpNum2Bin` is sign-magnitude, so two bytes reach only `0x7FFF` — a
/// transaction version above that cannot be encoded in script at all, and the
/// off-chain serializer must refuse it rather than produce a digest the script
/// can never reproduce.
pub const MAX_TX_VERSION: u16 = 0x7FFF;

/// Maximum outpoint index the 4-byte field can express.
pub const MAX_OUTPOINT_INDEX: u32 = i32::MAX as u32;

/// Maximum number of outputs the 1-byte count field can express.
pub const MAX_OUTPUT_COUNT: usize = 0x7F;

/// One output, as the digest sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputView {
    pub amount: u64,
    /// SPK version. Big-endian on the wire — see the module docs.
    pub spk_version: u16,
    /// The script itself, without the version prefix.
    pub script: Vec<u8>,
}

/// The transaction fields the digest commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendView {
    pub tx_version: u16,
    pub outpoint_txid: [u8; 32],
    pub outpoint_index: u32,
    pub outputs: Vec<OutputView>,
}

/// The wire encoding `OpTxOutputSpk` pushes: `u16 big-endian version || script`.
///
/// Mirrors the private `SpkEncoding` trait in `kaspa-txscript`. Reimplemented
/// here because that trait is not exported; `binding_digest_matches_opcodes`
/// in the harness is what proves the two agree.
pub fn spk_wire_bytes(version: u16, script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + script.len());
    out.extend_from_slice(&version.to_be_bytes()); // BIG-endian, deliberately
    out.extend_from_slice(script);
    out
}

/// Build the canonical preimage.
pub fn binding_preimage(view: &SpendView) -> Result<Vec<u8>> {
    ensure!(!view.outputs.is_empty(), "a spend must have at least one output");
    // Every bound below comes from OpNum2Bin's little-endian sign-magnitude
    // encoding: an n-byte field carries magnitudes only up to 2^(8n-1) - 1.
    // Exceeding one is refused here rather than encoded, because the script
    // cannot reproduce it and the UTXO would be unspendable.
    ensure!(
        view.outputs.len() <= MAX_OUTPUT_COUNT,
        "output count {} exceeds {MAX_OUTPUT_COUNT}",
        view.outputs.len()
    );
    ensure!(
        view.tx_version <= MAX_TX_VERSION,
        "tx version {} exceeds {MAX_TX_VERSION}",
        view.tx_version
    );
    ensure!(
        view.outpoint_index <= MAX_OUTPOINT_INDEX,
        "outpoint index {} exceeds {MAX_OUTPOINT_INDEX}",
        view.outpoint_index
    );

    let mut out = Vec::new();
    out.extend_from_slice(&view.tx_version.to_le_bytes());
    out.extend_from_slice(&view.outpoint_txid);
    out.extend_from_slice(&view.outpoint_index.to_le_bytes());
    out.push(u8::try_from(view.outputs.len()).expect("checked above"));

    for output in &view.outputs {
        ensure!(output.amount <= MAX_AMOUNT, "amount {} exceeds 2^63-1", output.amount);
        let spk = spk_wire_bytes(output.spk_version, &output.script);
        ensure!(spk.len() <= MAX_SPK_LEN, "spk of {} bytes exceeds the 2-byte prefix", spk.len());

        out.extend_from_slice(&output.amount.to_le_bytes());
        out.extend_from_slice(&u16::try_from(spk.len()).expect("checked above").to_le_bytes());
        out.extend_from_slice(&spk);
    }
    Ok(out)
}

/// `D = SHA-256(preimage)`.
///
/// The original PQV draft specified BLAKE3 here, because its zkVM journal was
/// already BLAKE3. This design has no journal and verifies LMS, which is
/// SHA-256 throughout, so using SHA-256 leaves the whole vault resting on a
/// single hash primitive rather than two. `OpSHA256` and `OpBlake3` are both
/// priced at 1 script unit per byte, so the choice costs nothing either way.
pub fn binding_digest(view: &SpendView) -> Result<[u8; 32]> {
    Ok(Sha256::digest(binding_preimage(view)?).into())
}

/// Emit the in-script reconstruction of `D`.
///
/// Kaspa script has no loops, so output iteration is unrolled and the script
/// commits to one specific output count. A vault therefore defines a canonical
/// spend shape — destination plus change — and enforces it. A different shape
/// needs its own `OpIf` branch with its own unrolled digest.
///
/// Leaves `D` on the stack.
pub fn emit_binding_digest(w: &mut ScriptWriter, output_count: usize) -> Result<()> {
    ensure!(output_count > 0, "a spend must have at least one output");
    ensure!(output_count <= MAX_OUTPUT_COUNT, "output count must fit the 1-byte field");

    w.op(OpTxVersion)?;
    w.num(2)?;
    w.op(OpNum2Bin)?;

    // `OpOutpointTxId` and `OpOutpointIndex` both POP an input index. The PQV
    // draft's redeem script writes them as bare opcodes, which would consume
    // the accumulator as an index and fail. `OpTxInputIndex` supplies the
    // index of the input currently being verified, which is also the binding
    // we want: the digest commits to *this* input's outpoint.
    w.op(OpTxInputIndex)?;
    w.op(OpOutpointTxId)?;
    w.op(OpCat)?;

    w.op(OpTxInputIndex)?;
    w.op(OpOutpointIndex)?;
    w.num(4)?;
    w.op(OpNum2Bin)?;
    w.op(OpCat)?;

    w.op(OpTxOutputCount)?;
    w.num(1)?;
    w.op(OpNum2Bin)?;
    w.op(OpCat)?;

    for i in 0..output_count {
        let idx = i64::try_from(i).expect("output count is small");

        w.num(idx)?;
        w.op(OpTxOutputAmount)?;
        w.num(8)?;
        w.op(OpNum2Bin)?;
        w.op(OpCat)?;

        w.num(idx)?;
        w.op(OpTxOutputSpkLen)?;
        w.num(2)?;
        w.op(OpNum2Bin)?;
        w.op(OpCat)?;

        w.num(idx)?;
        w.op(OpTxOutputSpk)?;
        w.op(OpCat)?;
    }

    w.op(OpSHA256)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SpendView {
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

    /// Layout for a canonical two-output spend with 35-byte scripts.
    ///
    /// This comes to **133** bytes, not the 129 in the PQV draft's test vector.
    /// The draft's prose is right — "`OpTxOutputSpkLen` measures this same
    /// encoding, so `spk_len` is `len(script) + 2`" — but its worked vector
    /// contradicts it, encoding `spk_len = 0x0023 = 35` and 35 SPK bytes, i.e.
    /// the bare script with no version prefix. Each output is therefore 2 bytes
    /// short.
    ///
    /// `binding_digest_matches_the_engine` in `lms-harness` settles which is
    /// correct by running the real introspection opcodes.
    #[test]
    fn preimage_has_the_documented_layout() {
        let preimage = binding_preimage(&sample()).unwrap();
        assert_eq!(preimage.len(), 2 + 32 + 4 + 1 + 2 * (8 + 2 + 37), "unexpected preimage length");
        assert_eq!(preimage.len(), 133);

        assert_eq!(&preimage[0..2], &1u16.to_le_bytes());
        assert_eq!(&preimage[34..38], &0u32.to_le_bytes());
        assert_eq!(preimage[38], 2, "output count");
    }

    /// The length prefix is what stops two different output sets colliding.
    #[test]
    fn length_prefix_prevents_ambiguity() {
        let mut a = sample();
        a.outputs[0].script = vec![0xcc; 40];
        a.outputs[1].script = vec![0xdd; 30];

        let mut b = sample();
        b.outputs[0].script = vec![0xcc; 30];
        b.outputs[1].script = vec![0xdd; 40];

        assert_ne!(binding_digest(&a).unwrap(), binding_digest(&b).unwrap());
    }

    /// Every covered field must actually change the digest.
    #[test]
    fn every_field_binds() {
        let base = binding_digest(&sample()).unwrap();

        let mut v = sample();
        v.tx_version = 2;
        assert_ne!(base, binding_digest(&v).unwrap(), "tx version");

        let mut v = sample();
        v.outpoint_txid[0] ^= 1;
        assert_ne!(base, binding_digest(&v).unwrap(), "outpoint txid -- replay protection");

        let mut v = sample();
        v.outpoint_index = 1;
        assert_ne!(base, binding_digest(&v).unwrap(), "outpoint index -- replay protection");

        let mut v = sample();
        v.outputs[0].amount += 1;
        assert_ne!(base, binding_digest(&v).unwrap(), "amount -- redirection");

        let mut v = sample();
        v.outputs[1].script[0] ^= 1;
        assert_ne!(base, binding_digest(&v).unwrap(), "spk -- redirection");

        let mut v = sample();
        v.outputs.pop();
        assert_ne!(base, binding_digest(&v).unwrap(), "output count");
    }

    /// The SPK version is big-endian, so 0x0100 and 0x0001 must differ. With a
    /// version of 0 this is invisible, which is exactly the trap.
    #[test]
    fn spk_version_is_big_endian() {
        assert_eq!(spk_wire_bytes(1, &[0xff]), vec![0x00, 0x01, 0xff]);
        assert_eq!(spk_wire_bytes(0x0100, &[0xff]), vec![0x01, 0x00, 0xff]);

        let mut a = sample();
        a.outputs[0].spk_version = 1;
        let mut b = sample();
        b.outputs[0].spk_version = 0x0100;
        assert_ne!(
            binding_digest(&a).unwrap(),
            binding_digest(&b).unwrap(),
            "byte-swapped SPK versions must not collide"
        );
    }

    /// Field widths are rejected rather than silently truncated.
    #[test]
    fn out_of_range_fields_are_rejected() {
        let mut v = sample();
        v.outputs[0].amount = MAX_AMOUNT + 1;
        assert!(binding_digest(&v).is_err(), "amount above 2^63-1 must be rejected");

        let mut v = sample();
        v.outputs[0].script = vec![0u8; MAX_SPK_LEN];
        assert!(binding_digest(&v).is_err(), "spk above the 2-byte prefix must be rejected");

        let mut v = sample();
        v.tx_version = MAX_TX_VERSION + 1;
        assert!(binding_digest(&v).is_err(), "tx version above 0x7FFF must be rejected");

        let mut v = sample();
        v.outpoint_index = MAX_OUTPOINT_INDEX + 1;
        assert!(binding_digest(&v).is_err(), "outpoint index above 2^31-1 must be rejected");

        let mut v = sample();
        v.outputs = (0..MAX_OUTPUT_COUNT + 1)
            .map(|_| OutputView { amount: 1, spk_version: 0, script: vec![] })
            .collect();
        assert!(binding_digest(&v).is_err(), "more than 127 outputs must be rejected");
    }
}
