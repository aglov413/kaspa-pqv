//! Deterministic SLH-DSA key generation from a derived seed.
//!
//! # Why this is not simply a call into `fips205`
//!
//! FIPS 205 defines `slh_keygen_internal(SK.seed, SK.prf, PK.seed)`, which
//! takes its three secrets as arguments. `fips205` keeps that function
//! `pub(crate)` and exposes only `try_keygen_with_rng`, which *draws* the three
//! values from an RNG. A vault key must be reproducible from a mnemonic a
//! decade later, so the only route is to supply an RNG that returns exactly the
//! bytes we derived.
//!
//! That makes the vault address depend on an implementation detail: that
//! `slh_keygen_with_rng` fills `SK.seed`, then `SK.prf`, then `PK.seed`, each
//! `n` bytes, and asks for nothing else. Three things guard it:
//!
//! 1. `fips205` is pinned to `=0.4.1` in the workspace manifest.
//! 2. [`SeedRng`] hands out a **fixed 48-byte budget and then fails**. If a
//!    future version draws in a different order the key changes silently, but
//!    if it draws a different *amount* keygen fails loudly instead of
//!    producing a vault nobody can restore.
//! 3. The frozen derivation vector pins `xi` to a finished address, so any
//!    drift at all is a failing test.
//!
//! # The key derivation itself
//!
//! ```text
//! SK.seed = SHA-256(DOMAIN || "sk.seed" || xi)[0..16]
//! SK.prf  = SHA-256(DOMAIN || "sk.prf"  || xi)[0..16]
//! PK.seed = SHA-256(DOMAIN || "pk.seed" || xi)[0..16]
//! ```
//!
//! Three independent hashes rather than one 48-byte stream, so that a change to
//! how one field is derived cannot shift the others.

use anyhow::{anyhow, Context, Result};
use fips205::slh_dsa_sha2_128s;
use fips205::traits::SerDes;
use sha2::{Digest, Sha256};
use slh_script::params::N;
use slh_script::PublicKey;

/// Domain separator for SLH-DSA key derivation. Versioned, so a future change
/// to the construction is a different tag rather than a silent divergence.
pub const KEY_DOMAIN: &[u8] = b"KaspaPQV-SLH-DSA-SHA2-128s-v1";

/// Bytes `slh_keygen_with_rng` is expected to draw: `SK.seed`, `SK.prf` and
/// `PK.seed`, `n` bytes each.
pub const KEYGEN_BYTES: usize = 3 * N;

/// The three secrets FIPS 205 Algorithm 21 draws, derived from `xi`.
#[derive(Clone)]
pub struct KeySeeds {
    pub sk_seed: [u8; N],
    pub sk_prf: [u8; N],
    pub pk_seed: [u8; N],
}

fn field(xi: &[u8; 32], label: &[u8]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(KEY_DOMAIN);
    h.update(label);
    h.update(xi);
    let full = h.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

impl KeySeeds {
    pub fn from_xi(xi: &[u8; 32]) -> Self {
        Self {
            sk_seed: field(xi, b"sk.seed"),
            sk_prf: field(xi, b"sk.prf"),
            pk_seed: field(xi, b"pk.seed"),
        }
    }

    /// The bytes in the order `slh_keygen_with_rng` consumes them.
    pub fn as_stream(&self) -> [u8; KEYGEN_BYTES] {
        let mut out = [0u8; KEYGEN_BYTES];
        out[..N].copy_from_slice(&self.sk_seed);
        out[N..2 * N].copy_from_slice(&self.sk_prf);
        out[2 * N..].copy_from_slice(&self.pk_seed);
        out
    }
}

/// An RNG that returns a fixed byte string and then refuses.
///
/// Not a random number generator, and deliberately not usable as one: the
/// budget is exhaustible so that a change in how much entropy `fips205` asks
/// for surfaces as an error rather than as an unrecoverable vault.
pub struct SeedRng {
    bytes: [u8; KEYGEN_BYTES],
    used: usize,
}

impl SeedRng {
    pub fn new(seeds: &KeySeeds) -> Self {
        Self { bytes: seeds.as_stream(), used: 0 }
    }

    /// Bytes not yet handed out. Zero after a correct keygen.
    pub fn remaining(&self) -> usize {
        KEYGEN_BYTES - self.used
    }
}

impl rand_core::RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        rand_core::RngCore::fill_bytes(self, &mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        rand_core::RngCore::fill_bytes(self, &mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).expect("SeedRng budget exhausted");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        if dest.len() > self.remaining() {
            // Non-zero and otherwise unused, so the cause is identifiable if it
            // ever escapes through fips205's opaque `&'static str` errors.
            return Err(rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START + 205)
                    .expect("non-zero"),
            ));
        }
        dest.copy_from_slice(&self.bytes[self.used..self.used + dest.len()]);
        self.used += dest.len();
        Ok(())
    }
}

impl rand_core::CryptoRng for SeedRng {}

/// An RNG that refuses every request.
///
/// FIPS 205 signing takes an RNG but only draws from it for the *hedged*
/// variant; the deterministic variant sets `opt_rand = PK.seed` and never
/// touches it. A vault signs deterministically, so that this crate does not
/// link an operating-system RNG into a cold-storage signing path at all — and
/// so that flipping to hedged fails loudly rather than quietly depending on
/// entropy an air-gapped machine may not have.
pub struct NoRng;

impl rand_core::RngCore for NoRng {
    fn next_u32(&mut self) -> u32 {
        panic!("deterministic signing must not draw randomness")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("deterministic signing must not draw randomness")
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!("deterministic signing must not draw randomness")
    }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Err(rand_core::Error::from(
            core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START + 206).expect("non-zero"),
        ))
    }
}

impl rand_core::CryptoRng for NoRng {}

/// A vault's SLH-DSA key pair, reproducible from `xi`.
pub struct Keypair {
    pub public: PublicKey,
    pub secret: slh_dsa_sha2_128s::PrivateKey,
}

/// Derive the vault key pair from a derived seed.
///
/// Deterministic: the same `xi` always yields the same address.
pub fn keypair_from_xi(xi: &[u8; 32]) -> Result<Keypair> {
    let seeds = KeySeeds::from_xi(xi);
    let mut rng = SeedRng::new(&seeds);

    let (public, secret) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng).map_err(|e| {
        anyhow!(
            "SLH-DSA keygen failed ({e}). If this says the rng failed, `fips205` has changed \
             how much entropy it draws and the pinned version no longer matches this \
             derivation — do not fund any address it produces."
        )
    })?;

    // Keygen must have consumed exactly the budget. A short draw would mean
    // PK.seed came from somewhere other than where this module thinks.
    if rng.remaining() != 0 {
        return Err(anyhow!(
            "SLH-DSA keygen consumed {} of {KEYGEN_BYTES} seed bytes; the derivation this \
             wallet implements no longer matches `fips205`",
            KEYGEN_BYTES - rng.remaining()
        ));
    }

    let public = PublicKey::from_bytes(&public.into_bytes()).context("parsing the public key")?;

    // PK.seed is derived, not drawn, so it is checkable against the derivation
    // independently of the RNG contract above.
    if public.seed != seeds.pk_seed {
        return Err(anyhow!(
            "SLH-DSA keygen did not use the derived PK.seed; `fips205` draws its key material \
             in a different order than this wallet assumes"
        ));
    }

    Ok(Keypair { public, secret })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn derivation_is_deterministic_and_index_dependent() {
        let a = keypair_from_xi(&[0x11; 32]).unwrap();
        let b = keypair_from_xi(&[0x11; 32]).unwrap();
        let c = keypair_from_xi(&[0x12; 32]).unwrap();
        assert_eq!(a.public, b.public, "same xi gave two different vaults");
        assert_ne!(a.public, c.public, "different xi gave the same vault");
    }

    /// The three fields must be independent. Deriving them by slicing one hash
    /// would tie them together, so that a change to one moves all three.
    #[test]
    fn the_three_seeds_are_independent() {
        let s = KeySeeds::from_xi(&[0x5a; 32]);
        assert_ne!(s.sk_seed, s.sk_prf);
        assert_ne!(s.sk_seed, s.pk_seed);
        assert_ne!(s.sk_prf, s.pk_seed);
        assert_eq!(s.as_stream().len(), KEYGEN_BYTES);
    }

    /// The budget is what turns a `fips205` change from a silent
    /// unrecoverable-vault bug into an error.
    #[test]
    fn the_seed_rng_refuses_to_exceed_its_budget() {
        let mut rng = SeedRng::new(&KeySeeds::from_xi(&[0u8; 32]));
        let mut buf = [0u8; KEYGEN_BYTES];
        assert!(rng.try_fill_bytes(&mut buf).is_ok());
        assert_eq!(rng.remaining(), 0);
        assert!(rng.try_fill_bytes(&mut [0u8; 1]).is_err(), "budget was not enforced");
    }

    /// Deterministic signing must not touch the RNG. If `fips205` ever draws
    /// for the unhedged path, this fails rather than silently depending on
    /// entropy a cold signer may not have.
    #[test]
    fn deterministic_signing_draws_no_randomness() {
        use fips205::traits::Signer;
        let kp = keypair_from_xi(&[0x31; 32]).unwrap();
        let sig = kp.secret.try_sign_with_rng(&mut NoRng, b"message", &[], false);
        assert!(sig.is_ok(), "deterministic signing drew from the RNG");

        // And it is genuinely deterministic, so a rebuilt spend is identical.
        let again = kp.secret.try_sign_with_rng(&mut NoRng, b"message", &[], false).unwrap();
        assert_eq!(sig.unwrap(), again);
    }

    /// Keygen consumes the whole budget, in order. This is the assumption the
    /// pinned `fips205` version is holding up.
    #[test]
    fn keygen_consumes_exactly_the_expected_entropy() {
        let seeds = KeySeeds::from_xi(&[0x77; 32]);
        let mut rng = SeedRng::new(&seeds);
        let (pk, _) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng).unwrap();
        assert_eq!(rng.remaining(), 0, "fips205 drew a different amount of entropy");

        // And the public key carries the derived PK.seed verbatim, which pins
        // the draw *order*, not just the total.
        let parsed = PublicKey::from_bytes(&pk.into_bytes()).unwrap();
        assert_eq!(parsed.seed, seeds.pk_seed, "PK.seed was drawn out of order");
    }
}
