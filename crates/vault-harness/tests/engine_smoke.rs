//! Validates the rig itself: that a generated script executes under Kaspa's
//! consensus engine, and that the engine's own script-unit accounting is
//! readable. Everything downstream is measured through this path, so if these
//! assumptions are wrong every later number is wrong too.

use kaspa_txscript::opcodes::codes::*;
use vault_harness::execute;
use lms_script::ScriptWriter;
use sha2::{Digest, Sha256};

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `OpSHA256` computes what the reference SHA-256 computes.
#[test]
fn op_sha256_agrees_with_the_reference() {
    let msg = b"abc";
    let mut w = ScriptWriter::new();
    w.data(msg).unwrap();
    w.op(OpSHA256).unwrap();
    w.data(&sha256(msg)).unwrap();
    w.op(OpEqual).unwrap();

    let cost = execute(&w.build()).expect("script should verify");
    assert!(cost.script_units > 0, "engine reported no cost");
}

/// A wrong digest must fail, or the test above proves nothing.
#[test]
fn op_sha256_rejects_a_wrong_digest() {
    let mut bad = sha256(b"abc");
    bad[0] ^= 0x01;

    let mut w = ScriptWriter::new();
    w.data(b"abc").unwrap();
    w.op(OpSHA256).unwrap();
    w.data(&bad).unwrap();
    w.op(OpEqual).unwrap();

    assert!(execute(&w.build()).is_err(), "a flipped digest bit must be rejected");
}

/// The engine's actual accounting, measured rather than assumed.
///
/// Literal data pushes in the script body are **free** at runtime — they are
/// already paid for as transaction mass, so charging them again would double
/// count. What costs units is (a) bytes hashed, at 1 unit/byte, and (b) bytes
/// an *opcode* pushes onto the stack. `OpCat` therefore costs the length of its
/// result, and `OpSHA256` costs the input length plus 32 for the digest it
/// pushes.
///
/// This drives two generator decisions: script constants are free, and
/// concatenation must be done as a balanced tree rather than linearly.
#[test]
fn cost_is_bytes_hashed_plus_bytes_pushed_by_opcodes() {
    let cost_of = |len: usize| {
        let msg = vec![0x5au8; len];
        let mut w = ScriptWriter::new();
        w.data(&msg).unwrap();
        w.op(OpSHA256).unwrap();
        w.data(&sha256(&msg)).unwrap();
        w.op(OpEqual).unwrap();
        execute(&w.build()).unwrap().script_units
    };

    // Only the extra 100 bytes hashed are charged; the larger literal push is
    // free. The two 32-byte digest pushes cancel out.
    assert_eq!(cost_of(200) - cost_of(100), 100, "expected 1 unit per byte hashed, pushes free");
}

/// One LM-OTS chain step: `tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)`.
///
/// The prefix is constant for a given `(I, q, i, j)`, so a step is a 23-byte
/// push, a swap, a concat and a hash. This is the primitive the whole verifier
/// is built from — 399 of them for `w = 2`.
#[test]
fn one_ots_chain_step_matches_the_reference() {
    let i_id = [0xa1u8; 16];
    let q: u32 = 7;
    let chain: u16 = 3;
    let j: u8 = 1;
    let tmp = [0x42u8; 32];

    let mut prefix = Vec::new();
    prefix.extend_from_slice(&i_id);
    prefix.extend_from_slice(&q.to_be_bytes());
    prefix.extend_from_slice(&chain.to_be_bytes());
    prefix.push(j);
    assert_eq!(prefix.len(), 23);

    let mut expected_input = prefix.clone();
    expected_input.extend_from_slice(&tmp);
    let expected = sha256(&expected_input);

    let mut w = ScriptWriter::new();
    w.data(&tmp).unwrap(); // witness supplies tmp
    w.data(&prefix).unwrap(); // script constant
    w.op(OpSwap).unwrap(); // prefix, tmp -> tmp, prefix ... put prefix first
    w.op(OpCat).unwrap(); // prefix || tmp
    w.op(OpSHA256).unwrap();
    w.data(&expected).unwrap();
    w.op(OpEqual).unwrap();

    let cost = execute(&w.build()).expect("chain step should verify");
    println!(
        "one chain step: {} script bytes, {} script units",
        cost.script_bytes, cost.script_units
    );
}
