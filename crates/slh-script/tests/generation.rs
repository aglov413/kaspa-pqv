//! The script generates at all, and the emitter's own bookkeeping holds.
//!
//! These run before anything is executed. A generator that miscounts a stack
//! depth produces a script that runs and hashes the wrong bytes, so the
//! cheapest place to catch it is at generation time — which is what the frame
//! is for.

use slh_script::params::{Params, ALL, N};
use slh_script::{build_vault_script, BlobPlan, PublicKey};

fn key() -> PublicKey {
    PublicKey { seed: [0x11; N], root: [0x22; N] }
}

/// Generation needs no signature, so every set is covered here — including the
/// one whose key generation is a minute of hashing.
fn plan(set: &'static Params) -> BlobPlan {
    BlobPlan::for_params(set)
}

#[test]
fn the_verifier_generates_and_balances_its_own_stack() {
    for set in ALL {
        let vs = build_vault_script(&key(), &plan(set), 2).expect("emitter should balance");
        assert!(vs.script.len() > 5_000, "{}: suspiciously small: {} bytes", set.name, vs.script.len());
        println!(
            "{:<24} redeem script {:>7} bytes, peak data-stack frame {:>3}, peak combined {:>4}",
            set.name,
            vs.script.len(),
            vs.peak_frame,
            vs.peak_stack()
        );
    }
}

/// The emitter's peak frame plus the blob queue must fit the consensus limit.
#[test]
fn the_peak_stack_fits_the_consensus_limit() {
    for set in ALL {
        let vs = build_vault_script(&key(), &plan(set), 2).unwrap();
        assert!(
            vs.peak_stack() < kaspa_txscript::MAX_STACK_SIZE,
            "{}: peak {} exceeds MAX_STACK_SIZE {}",
            set.name,
            vs.peak_stack(),
            kaspa_txscript::MAX_STACK_SIZE
        );
    }
}

/// The script is a pure function of the parameter set, the public key, the blob
/// plan and the spend shape. A vault address is the hash of this script, so any
/// drift here changes an address that may already hold coins.
#[test]
fn generation_is_deterministic() {
    for set in ALL {
        let a = build_vault_script(&key(), &plan(set), 2).unwrap();
        let b = build_vault_script(&key(), &plan(set), 2).unwrap();
        assert_eq!(a.script, b.script, "{}", set.name);

        let other = PublicKey { seed: [0x11; N], root: [0x23; N] };
        assert_ne!(build_vault_script(&other, &plan(set), 2).unwrap().script, a.script);
    }

    // And the sets must not emit one another's script, which is what makes
    // the parameter set part of the address rather than a label on it.
    let scripts: Vec<Vec<u8>> =
        ALL.iter().map(|s| build_vault_script(&key(), &plan(s), 2).unwrap().script).collect();
    for (i, a) in scripts.iter().enumerate() {
        for b in &scripts[i + 1..] {
            assert_ne!(a, b, "two parameter sets emitted the same script");
        }
    }
}
