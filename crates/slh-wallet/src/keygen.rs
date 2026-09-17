//! Deterministic SLH-DSA key generation from a derived seed.
//!
//! # The key derivation
//!
//! ```text
//! SK.seed = SHA-256(DOMAIN || "sk.seed" || xi)[0..16]
//! SK.prf  = SHA-256(DOMAIN || "sk.prf"  || xi)[0..16]
//! PK.seed = SHA-256(DOMAIN || "pk.seed" || xi)[0..16]
//! ```
//!
//! Three independent hashes rather than one 48-byte stream, so that a change to
//! how one field is derived cannot shift the others.
//!
//! `DOMAIN` names the parameter set, so one `xi` cannot produce two vaults that
//! share key material. That is belt and braces — the `scheme'` level of the
//! BIP32 path already gives each set a different `xi` — but the two guards fail
//! differently, and key material shared across parameter sets is the kind of
//! thing that is obvious only after it has cost someone their coins.
//!
//! # Why this is no longer a call into `fips205`
//!
//! It used to be, and the shape of that call is worth recording because the
//! replacement is what removed it. FIPS 205 defines
//! `slh_keygen_internal(SK.seed, SK.prf, PK.seed)`, which takes its three
//! secrets as arguments; `fips205` keeps that function private and exposes only
//! `try_keygen_with_rng`, which *draws* them. A reproducible vault therefore had
//! to feed it an RNG returning exactly the derived bytes, which made every vault
//! address depend on an implementation detail: the order and size of that
//! function's three random draws. A patch release that reordered them would
//! silently move every funded address.
//!
//! [`slh_script::SigningKey`] implements `slh_keygen_internal` directly, so the
//! address now depends on the seeds and the parameter set and nothing else.
//! This crate no longer depends on `fips205` at all; it survives as a
//! dev-dependency of `slh-script`, where `reference_oracle.rs` holds the `128s`
//! instantiation against it key-for-key and signature-for-signature. That is a
//! better job for it — an oracle that can only disagree in a test, rather than
//! a dependency that can only disagree in production.

use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use slh_script::params::{Params, N};
use slh_script::{PublicKey, SecretSeeds, SigningKey};

/// Domain separator for SLH-DSA key derivation under one parameter set.
///
/// Versioned, so a future change to the construction is a different tag rather
/// than a silent divergence. `SLH-DSA-SHA2-128s` reproduces the tag this
/// wallet used when it was the only set, which is why funded `128s` addresses
/// did not move when the other two arrived.
pub fn key_domain(p: &Params) -> String {
    format!("KaspaPQV-{}-v1", p.name)
}

/// The three secrets FIPS 205 Algorithm 18 takes, derived from `xi`.
pub fn seeds_from_xi(p: &Params, xi: &[u8; 32]) -> SecretSeeds {
    let domain = key_domain(p);
    let field = |label: &[u8]| {
        let mut h = Sha256::new();
        h.update(domain.as_bytes());
        h.update(label);
        h.update(xi);
        let full = h.finalize();
        let mut out = [0u8; N];
        out.copy_from_slice(&full[..N]);
        out
    };
    SecretSeeds {
        sk_seed: field(b"sk.seed"),
        sk_prf: field(b"sk.prf"),
        pk_seed: field(b"pk.seed"),
    }
}

/// A vault's SLH-DSA key pair, reproducible from `xi`.
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SigningKey,
}

/// Derive the vault key pair from a derived seed.
///
/// Deterministic: the same `xi` and parameter set always yield the same
/// address. Under `SLH-DSA-SHA2-128-24` this builds a hypertree of four
/// million leaves and takes about a hundred seconds; the other two are instant.
pub fn keypair_from_xi(p: &'static Params, xi: &[u8; 32]) -> Result<Keypair> {
    let seeds = seeds_from_xi(p, xi);
    let secret = SigningKey::generate(p, seeds);
    let public = secret.public_key();

    // PK.seed is derived rather than generated, so it is checkable against the
    // derivation independently of everything keygen did with it.
    ensure!(
        public.seed == seeds.pk_seed,
        "keygen did not carry the derived PK.seed; the key material this wallet derives no \
         longer matches what {} generates",
        p.name
    );

    Ok(Keypair { public, secret })
}

/// Parse a public key, for a watch-only vault reconstructed from a record
/// rather than from key material.
pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_bytes(bytes).context("parsing the SLH-DSA public key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use slh_script::params::{SHA2_128S, SHA2_128_24_D2};

    #[test]
    fn derivation_is_deterministic_and_index_dependent() {
        let a = keypair_from_xi(&SHA2_128S, &[0x11; 32]).unwrap();
        let b = keypair_from_xi(&SHA2_128S, &[0x11; 32]).unwrap();
        let c = keypair_from_xi(&SHA2_128S, &[0x12; 32]).unwrap();
        assert_eq!(a.public, b.public, "same xi gave two different vaults");
        assert_ne!(a.public, c.public, "different xi gave the same vault");
    }

    /// The three fields must be independent. Deriving them by slicing one hash
    /// would tie them together, so that a change to one moves all three.
    #[test]
    fn the_three_seeds_are_independent() {
        let s = seeds_from_xi(&SHA2_128S, &[0x5a; 32]);
        assert_ne!(s.sk_seed, s.sk_prf);
        assert_ne!(s.sk_seed, s.pk_seed);
        assert_ne!(s.sk_prf, s.pk_seed);
    }

    /// One `xi` must not produce shared key material across parameter sets.
    /// The BIP32 path already separates them; this is the second guard, and it
    /// is the one that holds if a caller ever derives two sets from one seed
    /// directly.
    #[test]
    fn parameter_sets_do_not_share_key_material() {
        let a = seeds_from_xi(&SHA2_128S, &[0x77; 32]);
        let b = seeds_from_xi(&SHA2_128_24_D2, &[0x77; 32]);
        assert_ne!(a.sk_seed, b.sk_seed);
        assert_ne!(a.sk_prf, b.sk_prf);
        assert_ne!(a.pk_seed, b.pk_seed);
    }

    /// The `128s` domain tag is the one funded addresses were derived under.
    /// It is a literal here rather than a formatted string, because "the
    /// format happens to still produce this" is exactly what a test should be
    /// checking rather than restating.
    #[test]
    fn the_128s_domain_tag_is_unchanged() {
        assert_eq!(key_domain(&SHA2_128S), "KaspaPQV-SLH-DSA-SHA2-128s-v1");
    }

    /// Signing is deterministic, so a spend rebuilt to declare a different
    /// compute budget carries the same signature it was measured with.
    #[test]
    fn signing_is_deterministic() {
        let kp = keypair_from_xi(&SHA2_128_24_D2, &[0x31; 32]).unwrap();
        assert_eq!(kp.secret.sign(b"message"), kp.secret.sign(b"message"));
    }
}
