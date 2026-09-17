#![allow(dead_code)] // each integration test binary uses a different subset

//! Shared test fixtures.
//!
//! Keys are derived from a tag rather than from the OS RNG. That is not about
//! secrecy — it is because script units are **data-dependent**: a Winternitz
//! chain runs from its message digit to `w - 1`, so a different signature
//! executes a different number of hashes. A test that generated a fresh key for
//! its probe and another for its measurement would compare two different
//! numbers, and a compute budget derived that way under-declares.

use slh_script::params::{Params, N, SHA2_128_24};
use slh_script::witness::BlobPlan;
use slh_script::{build_verify_script, PublicKey, SecretSeeds, SigningKey};
use vault_core::ScriptWriter;

/// Three independent seeds from one tag, so a test can name a key with a byte.
pub fn seeds(tag: u8) -> SecretSeeds {
    let field = |label: &[u8]| {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"slh-script test key");
        h.update(label);
        h.update([tag]);
        let full = h.finalize();
        let mut out = [0u8; N];
        out.copy_from_slice(&full[..N]);
        out
    };
    SecretSeeds { sk_seed: field(b"sk"), sk_prf: field(b"prf"), pk_seed: field(b"pk") }
}

/// A reproducible key for `set`, cached for the lifetime of the test binary.
///
/// `SLH-DSA-SHA2-128-24` generates a hypertree of four million leaves, which
/// is about a hundred seconds of hashing — once per key per process, and every test in
/// a binary that asks for the same tag shares it.
pub fn key(set: &'static Params, tag: u8) -> std::sync::Arc<SigningKey> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};

    type Keys = Mutex<HashMap<(&'static str, u8), Arc<SigningKey>>>;
    static CACHE: OnceLock<Keys> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    // The lock is released before generating, so two tests asking for
    // different keys do not serialise behind each other. Generating the same
    // key twice is wasteful but correct, and the threaded test harness makes
    // it unlikely enough not to be worth a per-key lock.
    if let Some(found) = cache.lock().expect("key cache").get(&(set.name, tag)) {
        return Arc::clone(found);
    }
    let generated = Arc::new(SigningKey::generate(set, seeds(tag)));
    cache.lock().expect("key cache").insert((set.name, tag), Arc::clone(&generated));
    generated
}

/// A reproducible key pair and its signature over `message`.
///
/// Signing is deterministic, so the same set, tag and message always produce
/// the same signature and therefore the same script units.
pub fn signed(set: &'static Params, tag: u8, message: &[u8]) -> (PublicKey, Vec<u8>) {
    let key = key(set, tag);
    (key.public_key(), key.sign(message))
}

/// The sets a test may run without paying for a four-million-leaf hypertree.
///
/// `SLH-DSA-SHA2-128-24` is excluded and covered by `#[ignore]`d tests that
/// name it explicitly — `measurement::the_2_24_sets_are_measured_against_128s`
/// and `comparison::every_scheme_measured_side_by_side` — so a default
/// `cargo test` stays in seconds rather than minutes. Excluding it from the
/// *fast* set is a scheduling decision, not a coverage one.
pub const FAST_SETS: &[&Params] =
    &[&slh_script::params::SHA2_128S, &slh_script::params::SHA2_128_24_D2];

/// Whether a set is the slow one, for tests that want to say so in a message.
pub fn is_slow(set: &Params) -> bool {
    set.name == SHA2_128_24.name
}

/// A bare verifier plus its witness, concatenated into one executable script.
///
/// The bare verifier takes its message from the witness, so this is a test
/// harness and not a vault — see `emit_verify`.
pub fn verify_script_with_witness(
    pk: &PublicKey,
    plan: &BlobPlan,
    sig: &[u8],
    message: &[u8],
) -> Vec<u8> {
    let mut w = ScriptWriter::new();
    w.data(message).expect("message push");
    let mut script = w.build();
    script.extend_from_slice(&plan.witness_pushes(sig).expect("witness"));
    script.extend_from_slice(&build_verify_script(pk, plan).expect("emit").script);
    script
}

/// Compute-budget units an input must declare to afford `units` script units.
///
/// Over-declaring is charged in full as compute mass, and under-declaring is
/// rejected outright, so this has to be computed from the signature that will
/// actually be broadcast.
pub fn budget_for(units: u64) -> u16 {
    u16::try_from((units / 100).div_ceil(100)).expect("budget fits its u16 field")
}
