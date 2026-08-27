//! Pins operand order and edge-case behaviour for the opcodes the LM-OTS
//! verifier depends on.
//!
//! Kaspa enables `OpSubstr`, `OpDiv` and `OpMod`, which Bitcoin disables, so
//! there is no folklore to fall back on and the source alone does not make
//! operand order obvious. Every assumption the generator makes is asserted
//! here against the real engine.

use kaspa_txscript::opcodes::codes::*;
use vault_harness::execute;
use lms_script::ScriptWriter;

/// Assert a script leaves exactly `expected` (as a number) on the stack.
fn assert_num(build: impl FnOnce(&mut ScriptWriter), expected: i64, what: &str) {
    let mut w = ScriptWriter::new();
    build(&mut w);
    w.num(expected).unwrap();
    w.op(OpNumEqual).unwrap();
    execute(&w.build()).unwrap_or_else(|e| panic!("{what}: expected {expected}, {e}"));
}

/// Assert a script leaves exactly `expected` (as bytes) on the stack.
fn assert_bytes(build: impl FnOnce(&mut ScriptWriter), expected: &[u8], what: &str) {
    let mut w = ScriptWriter::new();
    build(&mut w);
    w.data(expected).unwrap();
    w.op(OpEqual).unwrap();
    execute(&w.build())
        .unwrap_or_else(|e| panic!("{what}: expected {}, {e}", hex::encode(expected)));
}

/// `OpSubstr` takes `data start end` and returns the half-open range.
#[test]
fn substr_is_data_start_end_half_open() {
    let data = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55];

    assert_bytes(
        |w| {
            w.data(&data).unwrap();
            w.num(2).unwrap();
            w.num(4).unwrap();
            w.op(OpSubstr).unwrap();
        },
        &[0x22, 0x33],
        "substr(2,4)",
    );

    // Single byte, which is what coefficient extraction actually needs.
    assert_bytes(
        |w| {
            w.data(&data).unwrap();
            w.num(5).unwrap();
            w.num(6).unwrap();
            w.op(OpSubstr).unwrap();
        },
        &[0x55],
        "substr(5,6)",
    );
}

/// `OpDiv` and `OpMod` take `a b` and compute `a / b`, `a % b`.
#[test]
fn div_and_mod_are_a_op_b() {
    assert_num(
        |w| {
            w.num(200).unwrap();
            w.num(8).unwrap();
            w.op(OpDiv).unwrap();
        },
        25,
        "200 / 8",
    );
    assert_num(
        |w| {
            w.num(203).unwrap();
            w.num(8).unwrap();
            w.op(OpMod).unwrap();
        },
        3,
        "203 % 8",
    );
}

/// `OpGreaterThanOrEqual` takes `a b` and yields `a >= b`.
#[test]
fn greater_than_or_equal_is_a_ge_b() {
    for (a, b, expect) in [(3i64, 2i64, 1i64), (2, 2, 1), (1, 2, 0)] {
        assert_num(
            |w| {
                w.num(a).unwrap();
                w.num(b).unwrap();
                w.op(OpGreaterThanOrEqual).unwrap();
            },
            expect,
            &format!("{a} >= {b}"),
        );
    }
}

/// A single byte pulled out by `OpSubstr` converts to a number with
/// `OpBin2Num`. Kaspa numbers are sign-magnitude, so the high bit of a byte
/// would read as a sign — check the whole 0..=255 range behaves as expected
/// once masked through div/mod, which is how the generator uses it.
#[test]
fn bin2num_on_a_single_byte_and_the_sign_bit_trap() {
    // 0x7f is unambiguous.
    assert_num(
        |w| {
            w.data(&[0x7fu8]).unwrap();
            w.op(OpBin2Num).unwrap();
        },
        127,
        "bin2num(0x7f)",
    );

    // 0x80 is *negative zero* in sign-magnitude, not 128. This is exactly the
    // kind of trap that silently corrupts coefficient extraction, so it is
    // pinned rather than discovered later.
    assert_num(
        |w| {
            w.data(&[0x80u8]).unwrap();
            w.op(OpBin2Num).unwrap();
        },
        0,
        "bin2num(0x80) is negative zero",
    );

    // Appending a zero byte clears the sign and gives the true value.
    assert_num(
        |w| {
            w.data(&[0x80u8, 0x00]).unwrap();
            w.op(OpBin2Num).unwrap();
        },
        128,
        "bin2num(0x80 0x00)",
    );
    assert_num(
        |w| {
            w.data(&[0xffu8, 0x00]).unwrap();
            w.op(OpBin2Num).unwrap();
        },
        255,
        "bin2num(0xff 0x00)",
    );
}
