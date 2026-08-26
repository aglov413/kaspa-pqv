//! The script generates at all, and the emitter's own bookkeeping holds.
//!
//! These run before anything is executed. A generator that miscounts a stack
//! depth produces a script that runs and hashes the wrong bytes, so the
//! cheapest place to catch it is at generation time — which is what the frame
//! is for.

use slh_script::params::*;
use slh_script::{build_vault_script, BlobPlan, PublicKey};

fn key() -> PublicKey {
    PublicKey { seed: [0x11; N], root: [0x22; N] }
}

#[test]
fn the_verifier_generates_and_balances_its_own_stack() {
    let plan = BlobPlan::default();
    let vs = build_vault_script(&key(), &plan, 2).expect("emitter should balance");
    assert!(vs.script.len() > 10_000, "suspiciously small: {} bytes", vs.script.len());
    println!(
        "redeem script {} bytes, peak data-stack frame {}, peak combined {}",
        vs.script.len(),
        vs.peak_frame,
        vs.peak_stack()
    );
}

/// The emitter's peak frame plus the blob queue must fit the consensus limit.
#[test]
fn the_peak_stack_fits_the_consensus_limit() {
    let plan = BlobPlan::default();
    let vs = build_vault_script(&key(), &plan, 2).unwrap();
    assert!(
        vs.peak_stack() < kaspa_txscript::MAX_STACK_SIZE,
        "peak {} exceeds MAX_STACK_SIZE {}",
        vs.peak_stack(),
        kaspa_txscript::MAX_STACK_SIZE
    );
}

/// The script is a pure function of the public key, the blob plan and the
/// spend shape. A vault address is the hash of this script, so any drift here
/// changes an address that may already hold coins.
#[test]
fn generation_is_deterministic() {
    let plan = BlobPlan::default();
    let a = build_vault_script(&key(), &plan, 2).unwrap();
    let b = build_vault_script(&key(), &plan, 2).unwrap();
    assert_eq!(a.script, b.script);

    let other = PublicKey { seed: [0x11; N], root: [0x23; N] };
    assert_ne!(build_vault_script(&other, &plan, 2).unwrap().script, a.script);
}
