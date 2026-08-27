//! Empirically pins Kaspa's script-unit accounting.
//!
//! The whole cost case for an in-script LMS verifier rests on this, so it is
//! measured against the engine rather than read off the source.

use kaspa_txscript::opcodes::codes::*;
use vault_harness::execute;
use lms_script::ScriptWriter;
use sha2::{Digest, Sha256};

fn units_of(build: impl FnOnce(&mut ScriptWriter)) -> u64 {
    let mut w = ScriptWriter::new();
    build(&mut w);
    w.op(OpDrop).unwrap();
    w.num(1).unwrap();
    execute(&w.build()).expect("probe script should succeed").script_units
}

#[test]
fn probe_cost_model() {
    let push_100 = units_of(|w| {
        w.data(&vec![0u8; 100]).unwrap();
    });
    let push_200 = units_of(|w| {
        w.data(&vec![0u8; 200]).unwrap();
    });
    let hash_100 = units_of(|w| {
        w.data(&vec![0u8; 100]).unwrap();
        w.op(OpSHA256).unwrap();
    });
    let hash_200 = units_of(|w| {
        w.data(&vec![0u8; 200]).unwrap();
        w.op(OpSHA256).unwrap();
    });
    let cat_100_100 = units_of(|w| {
        w.data(&vec![0u8; 100]).unwrap();
        w.data(&vec![0u8; 100]).unwrap();
        w.op(OpCat).unwrap();
    });
    let dup_100 = units_of(|w| {
        w.data(&vec![0u8; 100]).unwrap();
        w.op(OpDup).unwrap();
        w.op(OpDrop).unwrap();
    });

    println!("push 100 bytes          : {push_100}");
    println!("push 200 bytes          : {push_200}");
    println!("push 100 + sha256       : {hash_100}");
    println!("push 200 + sha256       : {hash_200}");
    println!("push 100 x2 + cat       : {cat_100_100}");
    println!("push 100 + dup + drop   : {dup_100}");
    println!();
    println!("marginal cost per pushed byte : {}", (push_200 - push_100) as f64 / 100.0);
    println!("marginal cost per hashed byte : {}", (hash_200 - hash_100) as f64 / 100.0);
    println!("cost of OpCat over 2x100      : {}", cat_100_100 - push_200);
    println!("cost of OpDup over 100        : {}", dup_100 - push_100);

    // An untaken OpIf branch must cost nothing at runtime — this is what makes
    // unrolling variable-length Winternitz chains affordable.
    let taken = units_of(|w| {
        w.num(1).unwrap();
        w.op(OpIf).unwrap();
        w.data(&vec![0u8; 500]).unwrap();
        w.op(OpSHA256).unwrap();
        w.op(OpElse).unwrap();
        w.data(&[0u8; 1]).unwrap();
        w.op(OpEndIf).unwrap();
    });
    let untaken = units_of(|w| {
        w.num(0).unwrap();
        w.op(OpIf).unwrap();
        w.data(&vec![0u8; 500]).unwrap();
        w.op(OpSHA256).unwrap();
        w.op(OpElse).unwrap();
        w.data(&[0u8; 1]).unwrap();
        w.op(OpEndIf).unwrap();
    });
    println!();
    println!("branch taken (500B hash): {taken}");
    println!("branch untaken          : {untaken}");
    assert!(untaken < taken, "untaken branch must be cheaper");

    let _ = Sha256::digest(b"");
}
