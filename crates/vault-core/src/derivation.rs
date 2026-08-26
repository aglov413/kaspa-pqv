//! BIP32 derivation for post-quantum vaults.
//!
//! ```text
//! m / 111111' / 111111' / scheme' / account' / key_index'   ->  xi (32 bytes)
//!      purpose   coin      1' = LMS
//! ```
//!
//! # Every level is hardened, and that is load-bearing
//!
//! Kaspa's standard path is `m/44'/111111'/{account}'/{change}/{index}`, which
//! is *non-hardened* below the account. Kaspa's default address type is bare
//! pay-to-pubkey, so every receiving address publishes a Schnorr public key in
//! the clear. That gives a quantum adversary a route:
//!
//! 1. Shor an on-chain public key at `.../0/n` to get that index's private key.
//! 2. BIP32's known weakness — parent xpub plus any *non-hardened* child
//!    private key yields the parent private key. Account xpubs leak routinely
//!    through watch-only wallets and accounting integrations.
//! 3. From the account private key every descendant derives, hardened ones
//!    included, because hardening only blocks derivation from an xpub, not from
//!    a parent private key.
//!
//! A vault hanging anywhere beneath the classical account is therefore
//! reachable by exactly the attack it exists to survive. Putting it under a
//! distinct hardened purpose severs that chain: climbing from an account key
//! back to the master is hardened in both directions.
//!
//! Recovering non-hardened derivation in the post-quantum setting is an open
//! research problem, so hardened-only is not a conservative choice — it is the
//! only sound one currently available.
//!
//! **Never export an xpub for any ancestor of the vault branch.**

use anyhow::{Context, Result};
use kaspa_bip32::{ChildNumber, ExtendedPrivateKey, PrivateKey, SecretKey};
use sha2::{Digest, Sha256};

/// BIP43 purpose.
///
/// `101110` read as binary is 46 — the number after Kaspa's existing `44'`
/// (standard) and `45'` (multisig), without occupying `46'` itself, which a
/// future BIP could claim as a purpose.
///
/// No BIP43 purpose is registered for post-quantum keys and no chain has
/// standardised one, so this is chosen rather than inherited. Collision is not
/// really a risk in either direction: the `coin_type'` level already namespaces
/// the subtree to Kaspa, so the only requirement is uniqueness among Kaspa's
/// own purposes (`44'`, `45'`, and the deprecated non-hardened `972`).
///
/// If a KIP later assigns an official number, changing this constant and
/// regenerating the frozen vector is the whole migration — and [`Derivation`]
/// exists so both branches can be scanned during it.
pub const PURPOSE: u32 = 101_110;

/// Kaspa's SLIP-0044 coin type.
pub const COIN_TYPE: u32 = 111_111;

/// Domain separator for the seed derivation. Versioned so a future change to
/// the construction is a different tag rather than a silent divergence.
///
/// The tag names LMS for historical reasons and is **deliberately not changed**
/// for SLH-DSA. It separates *constructions*, not schemes: the `scheme'` level
/// is already inside the BIP32 path, so two schemes derived from one mnemonic
/// reach this point with different child keys and therefore different `xi`.
/// Renaming it would move every LMS address that has ever been funded.
pub const XI_DOMAIN: &[u8] = b"KaspaPQV-LMS-v1";

/// Signature scheme occupying the `scheme'` level.
///
/// Present so a future post-quantum scheme does not need a second purpose
/// number and another round of coordination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Scheme {
    /// LMS over SHA-256, RFC 8554 / NIST SP 800-208. Stateful: each leaf is a
    /// one-time key and signing twice under one leaf leaks it.
    LmsSha256 = 1,
    /// SLH-DSA-SHA2-128s, FIPS 205. Stateless: the hypertree position is
    /// derived from the message, so nothing has to be remembered between
    /// signatures — including signatures the chain never sees.
    SlhDsaSha2_128s = 2,
}

impl Scheme {
    pub const fn index(self) -> u32 {
        self as u32
    }
}

/// A derivation scheme: which purpose, coin type and signature scheme a vault
/// branch lives under.
///
/// Exists as a value rather than as bare constants so that a wallet can scan
/// more than one at a time. If a KIP later assigns an official purpose number,
/// migration means scanning both the old and the new branch until funds have
/// moved — which needs two [`Derivation`]s alive in the same process.
/// [`Derivation::DEFAULT`] is the canonical one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Derivation {
    /// BIP43 purpose. The one value here that is genuinely a free choice.
    pub purpose: u32,
    /// SLIP-0044 coin type. Fixed by Kaspa; changing it means a different chain.
    pub coin_type: u32,
    /// Signature scheme occupying the `scheme'` level.
    pub scheme: Scheme,
}

impl Default for Derivation {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Derivation {
    /// The canonical derivation. Every address in the frozen test vector comes
    /// from this.
    pub const DEFAULT: Self =
        Self { purpose: PURPOSE, coin_type: COIN_TYPE, scheme: Scheme::LmsSha256 };

    /// The five hardened levels, in order.
    pub const fn levels(&self, account: u32, key_index: u32) -> [u32; 5] {
        [self.purpose, self.coin_type, self.scheme.index(), account, key_index]
    }

    /// Human-readable path, for display and for test vectors.
    pub fn path(&self, account: u32, key_index: u32) -> String {
        let [a, b, c, d, e] = self.levels(account, key_index);
        format!("m/{a}'/{b}'/{c}'/{d}'/{e}'")
    }

    /// Derive the LMS keygen seed from any supported key material.
    ///
    /// A bare private key has no chain code, so BIP32 derivation is impossible
    /// and it is hashed directly with a distinct domain separator and the
    /// account/key indices folded in. That still yields independent vaults per
    /// index, but it provides none of the isolation the hardened path does —
    /// see [`crate::key_material`].
    pub fn xi_from(
        &self,
        material: &crate::key_material::KeyMaterial,
        account: u32,
        key_index: u32,
    ) -> Result<[u8; 32]> {
        use crate::key_material::{KeyMaterial, XI_DOMAIN_RAW};

        match material {
            KeyMaterial::Bip39Seed(seed) => self.xi(seed, account, key_index),
            KeyMaterial::Extended(xprv) => self.xi_from_node(xprv.as_ref().clone(), account, key_index),
            KeyMaterial::Raw(key) => {
                let mut hasher = Sha256::new();
                hasher.update(XI_DOMAIN_RAW);
                hasher.update(account.to_le_bytes());
                hasher.update(key_index.to_le_bytes());
                hasher.update(key);
                Ok(hasher.finalize().into())
            }
        }
    }

    /// Derive from an already-constructed BIP32 node.
    pub fn xi_from_node(
        &self,
        node: ExtendedPrivateKey<SecretKey>,
        account: u32,
        key_index: u32,
    ) -> Result<[u8; 32]> {
        let mut key = node;
        for index in self.levels(account, key_index) {
            let child = ChildNumber::new(index, /* hardened */ true)
                .map_err(|e| anyhow::anyhow!("bad child index {index}: {e}"))?;
            key = key.derive_child(child).context("hardened derivation failed")?;
        }

        let mut hasher = Sha256::new();
        hasher.update(XI_DOMAIN);
        hasher.update(key.private_key().to_bytes());
        Ok(hasher.finalize().into())
    }

    /// Derive the LMS keygen seed. See [`derive_xi`].
    pub fn xi(&self, seed: &[u8], account: u32, key_index: u32) -> Result<[u8; 32]> {
        let root = ExtendedPrivateKey::<SecretKey>::new(seed)
            .map_err(|e| anyhow::anyhow!("invalid BIP39 seed: {e}"))?;

        let mut key = root;
        for index in self.levels(account, key_index) {
            let child = ChildNumber::new(index, /* hardened */ true)
                .map_err(|e| anyhow::anyhow!("bad child index {index}: {e}"))?;
            key = key.derive_child(child).context("hardened derivation failed")?;
        }

        let mut hasher = Sha256::new();
        hasher.update(XI_DOMAIN);
        hasher.update(key.private_key().to_bytes());
        Ok(hasher.finalize().into())
    }
}

/// Human-readable derivation path under [`Derivation::DEFAULT`].
pub fn vault_path(scheme: Scheme, account: u32, key_index: u32) -> String {
    Derivation { scheme, ..Derivation::DEFAULT }.path(account, key_index)
}

/// Derive the LMS keygen seed from a BIP39 seed.
///
/// `xi = SHA-256(XI_DOMAIN || ser256(k_child))`
///
/// The child private key is hashed rather than used directly for two reasons.
/// A BIP32 private key is an integer mod the secp256k1 group order, so it is
/// not uniform over 32 bytes, while LMS keygen expects a uniform seed. And
/// hashing with a domain separator removes any ambiguity about *which* 32
/// bytes are meant — key or chain code, and in which byte order — which is
/// precisely the kind of disagreement that silently produces a different vault
/// from the same mnemonic.
pub fn derive_xi(seed: &[u8], scheme: Scheme, account: u32, key_index: u32) -> Result<[u8; 32]> {
    Derivation { scheme, ..Derivation::DEFAULT }.xi(seed, account, key_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_renders_all_levels_hardened() {
        let path = vault_path(Scheme::LmsSha256, 0, 0);
        assert_eq!(path, "m/101110'/111111'/1'/0'/0'");
        assert_eq!(path.matches('\'').count(), 5, "every level must be hardened");

        let slh = vault_path(Scheme::SlhDsaSha2_128s, 0, 0);
        assert_eq!(slh, "m/101110'/111111'/2'/0'/0'");
    }

    /// The `scheme'` level is the only thing keeping two schemes derived from
    /// one mnemonic apart, since they share `XI_DOMAIN`. If this ever collided
    /// the two vaults would be the same key material under different
    /// algorithms.
    ///
    /// On-chain testing deliberately uses a *separate* mnemonic per scheme, so
    /// nothing else in the test suite exercises the shared-seed case — which is
    /// the case every real user will be in. This is that coverage.
    #[test]
    fn schemes_derive_independent_seeds_from_one_mnemonic() {
        let seed = [0x42u8; 64];
        let lms = derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap();
        let slh = derive_xi(&seed, Scheme::SlhDsaSha2_128s, 0, 0).unwrap();
        assert_ne!(lms, slh, "two schemes shared a keygen seed");
        assert_ne!(Scheme::LmsSha256.index(), Scheme::SlhDsaSha2_128s.index());

        // Independence has to hold across every account and key index, not
        // just the first, or a wallet holding several vaults could collide.
        for account in 0..3 {
            for index in 0..3 {
                let a = derive_xi(&seed, Scheme::LmsSha256, account, index).unwrap();
                let b = derive_xi(&seed, Scheme::SlhDsaSha2_128s, account, index).unwrap();
                assert_ne!(a, b, "collision at account {account}, index {index}");
            }
        }
    }

    #[test]
    fn distinct_indices_give_distinct_seeds() {
        let seed = [0x42u8; 64];
        let base = derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap();
        assert_ne!(base, derive_xi(&seed, Scheme::LmsSha256, 0, 1).unwrap());
        assert_ne!(base, derive_xi(&seed, Scheme::LmsSha256, 1, 0).unwrap());
        assert_ne!(base, derive_xi(&[0x43u8; 64], Scheme::LmsSha256, 0, 0).unwrap());
    }

    #[test]
    fn derivation_is_deterministic() {
        let seed = [0x7fu8; 64];
        assert_eq!(
            derive_xi(&seed, Scheme::LmsSha256, 3, 9).unwrap(),
            derive_xi(&seed, Scheme::LmsSha256, 3, 9).unwrap()
        );
    }

    /// xi must not be the raw child key — that is the ambiguity the domain
    /// separation exists to remove.
    #[test]
    fn xi_is_not_the_raw_child_private_key() {
        let seed = [0x11u8; 64];
        let root = ExtendedPrivateKey::<SecretKey>::new(seed).unwrap();
        let mut key = root;
        for index in [PURPOSE, COIN_TYPE, 1, 0, 0] {
            key = key.derive_child(ChildNumber::new(index, true).unwrap()).unwrap();
        }
        let raw = key.private_key().to_bytes();
        let xi = derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap();
        assert_ne!(xi, raw);
    }
}
