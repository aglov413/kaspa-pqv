#![allow(dead_code)] // each integration test binary uses a different subset

//! Shared test fixtures.
//!
//! Keys are generated from a seeded RNG rather than the OS one. That is not
//! about secrecy — it is because script units are **data-dependent**: a
//! Winternitz chain runs from its message digit to 14, so a different signature
//! executes a different number of hashes. A test that generated a fresh key for
//! its probe and another for its measurement would compare two different
//! numbers, and a compute budget derived that way under-declares.

use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Signer};
use rand_core::{CryptoRng, RngCore};
use slh_script::witness::BlobPlan;
use slh_script::{build_verify_script, PublicKey};
use vault_core::ScriptWriter;

/// A counter-mode SHA-256 stream. Deterministic, and only ever used to make
/// test keys reproducible.
pub struct SeededRng {
    seed: [u8; 32],
    counter: u64,
    buffer: Vec<u8>,
}

impl SeededRng {
    pub fn new(tag: u8) -> Self {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        Self { seed, counter: 0, buffer: Vec::new() }
    }

    fn refill(&mut self) {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.seed);
        h.update(self.counter.to_le_bytes());
        self.counter += 1;
        self.buffer.extend_from_slice(&h.finalize());
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            if self.buffer.is_empty() {
                self.refill();
            }
            let take = (dest.len() - written).min(self.buffer.len());
            dest[written..written + take].copy_from_slice(&self.buffer[..take]);
            self.buffer.drain(..take);
            written += take;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SeededRng {}

/// A reproducible key pair and its signature over `message`.
///
/// Signing is deterministic (`hedged = false`), so the same tag and message
/// always produce the same signature and therefore the same script units.
pub fn signed(tag: u8, message: &[u8]) -> (PublicKey, Vec<u8>) {
    let mut rng = SeededRng::new(tag);
    let (fips_pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng).expect("keygen");
    let sig = sk.try_sign(message, &[], false).expect("sign");
    (PublicKey::from_bytes(&fips_pk.into_bytes()).expect("pk"), sig.to_vec())
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
