//! Where a vault's key material comes from.
//!
//! A vault can be derived from a mnemonic, from a BIP39 seed, from an extended
//! private key, or from a bare 32-byte private key. These are **not**
//! equivalent — one of them can silently void the post-quantum guarantee, so
//! the distinction is a type rather than a comment.
//!
//! # The bare-key hazard
//!
//! A 32-byte private key has no chain code, so BIP32 derivation is impossible
//! and the key can only be used as raw material. That is fine if it is
//! dedicated key material generated for this purpose. It is **catastrophic** if
//! it is a live Kaspa spending key:
//!
//! Kaspa's default address type is bare pay-to-pubkey, so a spending key's
//! public key is published on-chain the first time it receives. A quantum
//! adversary recovers the private key from that public key with Shor, computes
//! the same domain-separated hash this module does, and derives the vault's LMS
//! key. The vault is then exactly as quantum-vulnerable as the key it came
//! from — which is to say, not post-quantum at all.
//!
//! [`KeyMaterial::is_quantum_isolated`] reports whether a given source keeps
//! the vault behind hardened derivation from material that has never been
//! published. Callers should surface a negative answer prominently.

use anyhow::{bail, Context, Result};
use kaspa_bip32::{ExtendedPrivateKey, Language, Mnemonic, SecretKey};

/// Domain separator for vaults derived from a bare private key.
///
/// Deliberately distinct from [`crate::derivation::XI_DOMAIN`] so the two
/// constructions can never produce the same vault from related inputs.
pub const XI_DOMAIN_RAW: &[u8] = b"KaspaPQV-LMS-v1-rawkey";

/// A source of vault key material.
pub enum KeyMaterial {
    /// A BIP39 seed, from a mnemonic or supplied directly as hex.
    ///
    /// The full hardened path applies, so the vault is isolated from any
    /// classical account under the same seed.
    Bip39Seed(Vec<u8>),

    /// An extended private key, with its chain code.
    ///
    /// Hardened derivation continues from this node. Isolation is only as good
    /// as the node: an account-level `xprv` whose matching `xpub` has been
    /// shared is recoverable by a quantum adversary, and everything beneath it
    /// with it. A master key that has never been exported is safe.
    Extended(Box<ExtendedPrivateKey<SecretKey>>),

    /// A bare 32-byte private key. No chain code, so no BIP32 derivation.
    ///
    /// See the module documentation. Only safe for key material generated for
    /// this purpose and never used as a spending key.
    Raw([u8; 32]),
}

impl KeyMaterial {
    /// Parse a mnemonic phrase.
    pub fn from_mnemonic(phrase: &str) -> Result<Self> {
        let mnemonic = Mnemonic::new(phrase.trim(), Language::English)
            .map_err(|e| anyhow::anyhow!("invalid mnemonic: {e}"))?;
        let seed = hex_decode(&mnemonic.create_seed(None)).context("deriving BIP39 seed")?;
        Ok(Self::Bip39Seed(seed))
    }

    /// Parse a key from its textual form, detecting which of the three it is.
    ///
    /// - `xprv…` / `kprv…` and friends — an extended private key
    /// - 128 hex characters — a 64-byte BIP39 seed
    /// - 64 hex characters — a bare 32-byte private key
    pub fn parse(input: &str) -> Result<Self> {
        let text = input.trim();

        if text.len() > 4 && text.chars().all(|c| c.is_ascii_alphanumeric()) && !is_hex(text) {
            let xprv: ExtendedPrivateKey<SecretKey> =
                text.parse().map_err(|e| anyhow::anyhow!("not a valid extended private key: {e}"))?;
            return Ok(Self::Extended(Box::new(xprv)));
        }

        match text.len() {
            128 => Ok(Self::Bip39Seed(hex_decode(text).context("seed is not valid hex")?)),
            64 => {
                let bytes = hex_decode(text).context("key is not valid hex")?;
                Ok(Self::Raw(bytes.try_into().expect("64 hex chars is 32 bytes")))
            }
            other => bail!(
                "unrecognised key format ({other} characters). Expected an extended \
                 private key (xprv…/kprv…), a 128-character BIP39 seed, or a \
                 64-character private key."
            ),
        }
    }

    /// Whether this source keeps the vault isolated from classical keys.
    ///
    /// `false` means a quantum adversary who breaks the source key also gets
    /// the vault. See the module documentation.
    pub fn is_quantum_isolated(&self) -> bool {
        !matches!(self, Self::Raw(_))
    }

    /// A short description for display.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Bip39Seed(_) => "BIP39 seed",
            Self::Extended(_) => "extended private key",
            Self::Raw(_) => "bare private key",
        }
    }

    /// The warning to show a user, if any.
    pub fn warning(&self) -> Option<&'static str> {
        match self {
            Self::Raw(_) => Some(
                "This vault is derived from a bare private key, which cannot be \
                 hardened-isolated. If that key is or ever was a Kaspa spending key, its \
                 public key is on-chain, and a quantum adversary who recovers it can \
                 derive this vault too — the vault would provide no post-quantum \
                 protection at all. Only use a key generated solely for this purpose.",
            ),
            Self::Extended(_) => Some(
                "Derivation continues from the supplied extended private key. If the \
                 matching extended *public* key has ever been shared — with a watch-only \
                 wallet, an exchange, or accounting software — a quantum adversary can \
                 recover this branch. A master key that has never been exported is safe.",
            ),
            Self::Bip39Seed(_) => None,
        }
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        bail!("hex string has an odd length");
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16).context("invalid hex digit")
        })
        .collect()
}
