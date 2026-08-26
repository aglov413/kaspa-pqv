//! A vault: one LMS key, and the P2SH addresses its leaves unlock.
//!
//! One derived seed gives one LMS key, which gives `2^h` one-time leaves. Each
//! leaf has its own redeem script — `q` is pinned into the script — and
//! therefore its own address. Coins move from leaf `q` to leaf `q+1` as they
//! are spent, so **the live leaf is whichever address holds the UTXO**. That is
//! what keeps one-time-key state out of a counter file that has to survive a
//! decade and a mnemonic restore.
//!
//! It does not make reuse safe. Signing two *different* transactions from one
//! address exposes the one-time key: QRL's published figures for the same
//! construction put recovery at roughly 2^34 hashes from two signatures, which
//! is hours on a consumer GPU. Sign once, persist the signed transaction, and
//! rebroadcast those bytes rather than re-signing.

use anyhow::{ensure, Result};
use kaspa_addresses::{Address, Prefix};
use kaspa_txscript::pay_to_script_hash_script;
use lms_script::params::{LmsParams, N};
use lms_script::verify::{emit_vault_script, LmsPublicKey};
use lms_script::ScriptWriter;
use oxicrypt_lms::lms_sha256_m32_h15_w2 as lms;

/// The `LMS_SHA256_M32_H15 / LMOTS_SHA256_N32_W2` vault.
///
/// Both parameters were chosen by measurement, not taste.
///
/// `w = 2`: `w = 1` cannot run at all — its 265 chain values exceed Kaspa's
/// 244-item stack limit — and `w = 4` costs 39% more compute mass because its
/// unrolled script is larger.
///
/// `h = 15`: Merkle depth is nearly free in mass. Going from 32 leaves to
/// 32,768 costs 3% (+305 script bytes, +160 signature bytes), and every height
/// still yields ~15 spends per block. What is *not* free is keygen, which is
/// O(2^h): 5 ms at h=5, 5.6 s at h=15, 178 s at h=20. h=15 is the last height
/// where key generation stays interactive.
pub const PARAMS: LmsParams = LmsParams::SHA256_H15_W2;

/// Leaves consumed before the wallet starts warning.
///
/// A vault holds 32,768 one-time keys and each spend burns exactly one, so
/// exhaustion is remote — but it is also *terminal*: leaf 32,767 has no
/// successor, and its UTXO can only move by rolling to the next vault. The
/// warning exists so that roll is a planned action rather than a discovery.
pub const LEAF_WARNING_THRESHOLD: u32 = 30_000;

/// Leaves remaining at which the warning becomes urgent.
pub const LEAF_CRITICAL_REMAINING: u32 = 100;

/// The canonical vault spend shape: destination plus change.
///
/// Kaspa script has no loops, so output iteration is unrolled and the redeem
/// script commits to one specific count. A single-output sweep would be a
/// second branch with its own unrolled digest, and therefore a different
/// address.
pub const CANONICAL_OUTPUT_COUNT: usize = 2;

/// A vault's public material. Everything here is safe to persist and to scan
/// with; none of it is secret.
#[derive(Clone, Debug)]
pub struct Vault {
    /// RFC 8554 `I` and `T[1]`, pinned into every leaf's redeem script.
    pub public_key: LmsPublicKey,
}

impl Vault {
    /// Build a vault and its signing key from a derived seed.
    ///
    /// The signing key carries the one-time-key state, so it is returned
    /// separately and should be held only for as long as a signature takes.
    pub fn from_xi(xi: &[u8; 32]) -> (Self, lms::LmsSigningKey) {
        let (signing_key, encoded) = lms::LmsSigningKey::new_internal(xi);
        (Self { public_key: parse_public_key(&encoded) }, signing_key)
    }

    /// Number of one-time leaves, and therefore of addresses.
    pub fn leaf_count(&self) -> u32 {
        PARAMS.leaf_count()
    }

    /// The budget after spending `leaf`.
    pub fn budget_after(&self, leaf: u32) -> LeafBudget {
        LeafBudget {
            leaf,
            total: self.leaf_count(),
            remaining: self.leaf_count().saturating_sub(leaf + 1),
        }
    }

    /// Where change from spending `leaf` should go.
    pub fn change_target(&self, key_index: u32, leaf: u32) -> ChangeTarget {
        change_target(key_index, leaf, self.leaf_count())
    }

    /// The redeem script for one leaf.
    ///
    /// Reconstructs the binding digest `D` from introspection and requires an
    /// LMS signature over it, so the signature commits to this transaction's
    /// outpoint and outputs. The spender chooses nothing that the digest does
    /// not cover.
    pub fn redeem_script(&self, leaf: u32) -> Result<Vec<u8>> {
        self.redeem_script_for_shape(leaf, CANONICAL_OUTPUT_COUNT)
    }

    /// The redeem script for a non-canonical output count.
    ///
    /// A different count is a different script and therefore a different
    /// address, so this is not a spend-time choice — it is a decision made when
    /// the vault is created.
    pub fn redeem_script_for_shape(&self, leaf: u32, output_count: usize) -> Result<Vec<u8>> {
        ensure!(leaf < self.leaf_count(), "leaf {leaf} out of range");
        let mut w = ScriptWriter::new();
        emit_vault_script(&mut w, &PARAMS, &self.public_key, leaf, output_count)?;
        Ok(w.build())
    }

    /// The P2SH address for one leaf.
    ///
    /// Kaspa has only three address versions — `PubKey`, `PubKeyECDSA` and
    /// `ScriptHash` — so a vault address is indistinguishable on-chain from any
    /// other P2SH address. The "this is a vault" marker lives in the wallet's
    /// own records, not in the address.
    pub fn address(&self, prefix: Prefix, leaf: u32) -> Result<Address> {
        let script = self.redeem_script(leaf)?;
        let spk = pay_to_script_hash_script(&script);
        Ok(kaspa_txscript::extract_script_pub_key_address(&spk, prefix)
            .map_err(|e| anyhow::anyhow!("address extraction failed: {e}"))?)
    }

    /// Every leaf address, in order. Scanning these is how a restored wallet
    /// finds which leaf is live.
    pub fn addresses(&self, prefix: Prefix) -> Result<Vec<Address>> {
        (0..self.leaf_count()).map(|leaf| self.address(prefix, leaf)).collect()
    }
}

/// How much of a vault's one-time key supply is left.
///
/// Reported after every spend, because the number only ever goes down and the
/// user is the only one who can act on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafBudget {
    /// The leaf just used, or about to be used.
    pub leaf: u32,
    /// Total leaves in the vault.
    pub total: u32,
    /// Leaves still available after this one.
    pub remaining: u32,
}

/// Whether a vault needs attention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetStatus {
    /// Plenty of leaves left.
    Healthy,
    /// Past [`LEAF_WARNING_THRESHOLD`]. Time to plan a migration.
    Approaching,
    /// Fewer than [`LEAF_CRITICAL_REMAINING`] leaves left. Migrate now.
    Critical,
    /// No leaves left. Funds at this vault can no longer be spent from a
    /// fresh key — only via signatures already issued.
    Exhausted,
}

impl LeafBudget {
    pub fn status(&self) -> BudgetStatus {
        if self.remaining == 0 {
            BudgetStatus::Exhausted
        } else if self.remaining <= LEAF_CRITICAL_REMAINING {
            BudgetStatus::Critical
        } else if self.leaf >= LEAF_WARNING_THRESHOLD {
            BudgetStatus::Approaching
        } else {
            BudgetStatus::Healthy
        }
    }

    /// True when the wallet should prompt the user to migrate.
    pub fn should_prompt_migration(&self) -> bool {
        !matches!(self.status(), BudgetStatus::Healthy)
    }

    /// A line suitable for showing after a spend.
    pub fn summary(&self) -> String {
        match self.status() {
            BudgetStatus::Healthy => {
                format!("{} of {} one-time keys remaining", self.remaining, self.total)
            }
            BudgetStatus::Approaching => format!(
                "{} of {} one-time keys remaining. Consider migrating this vault to the \
                 next key index; the wallet can move the balance for you.",
                self.remaining, self.total
            ),
            BudgetStatus::Critical => format!(
                "Only {} one-time keys remaining. Migrate to the next key index now — \
                 when the last leaf is spent, any balance left here can no longer be moved.",
                self.remaining
            ),
            BudgetStatus::Exhausted => {
                "This vault is exhausted. No further spends are possible from it.".to_string()
            }
        }
    }
}

/// Which vault a change output belongs to.
///
/// A vault spend sends its change to the *next* one-time key, which is what
/// advances the vault and keeps its state in the UTXO set. When the current
/// vault has no next leaf, the change has to start a new vault instead — that
/// is a migration, and it is the same transaction shape, just a different
/// change address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeTarget {
    /// Ordinary advance: same vault, next leaf.
    NextLeaf { key_index: u32, leaf: u32 },
    /// Migration: the current vault is exhausted, so change starts the next
    /// vault at leaf 0.
    NextVault { key_index: u32, leaf: u32 },
}

impl ChangeTarget {
    pub fn key_index(&self) -> u32 {
        match self {
            Self::NextLeaf { key_index, .. } | Self::NextVault { key_index, .. } => *key_index,
        }
    }

    pub fn leaf(&self) -> u32 {
        match self {
            Self::NextLeaf { leaf, .. } | Self::NextVault { leaf, .. } => *leaf,
        }
    }

    pub fn is_migration(&self) -> bool {
        matches!(self, Self::NextVault { .. })
    }
}

/// Where change from spending `leaf` of `key_index` should go.
///
/// Pure index arithmetic — no keys involved — so the seed stays at the edge of
/// the wallet rather than being threaded through spend construction.
pub fn change_target(key_index: u32, leaf: u32, leaf_count: u32) -> ChangeTarget {
    if leaf + 1 < leaf_count {
        ChangeTarget::NextLeaf { key_index, leaf: leaf + 1 }
    } else {
        ChangeTarget::NextVault { key_index: key_index + 1, leaf: 0 }
    }
}

/// Run the LMS implementation's known-answer tests, once per process.
///
/// The KAT is a keygen / sign / verify round-trip for this exact parameter set,
/// plus a negative check that a wrong message fails to verify. Running it here
/// means the signing implementation is validated on this machine, with this
/// binary, immediately before an operation that consumes a one-time key and
/// cannot be undone — which a test suite run at some earlier time does not
/// establish.
///
/// The vectors are invoked directly rather than through
/// `oxicrypt_module::initialize_with_tests`. That entry point also demands a
/// module *integrity* self-test — an HMAC over the module's own object code,
/// requiring build-time support we do not have — and without one it latches
/// `IntegrityUnverified` and refuses every gated call. Since this project makes
/// no FIPS validation claim, supplying a hollow integrity test to satisfy the
/// state machine would assert something untrue. Running the vectors and
/// reporting the result plainly is the honest version of the same check.
///
/// Idempotent: the result is computed once and cached.
pub fn run_self_tests() -> Result<()> {
    static RESULT: std::sync::OnceLock<std::result::Result<(), String>> =
        std::sync::OnceLock::new();

    RESULT
        .get_or_init(|| {
            for kat in lms::KATS {
                (kat.run)().map_err(|_| kat.name.to_string())?;
            }
            Ok(())
        })
        .clone()
        .map_err(|name| {
            anyhow::anyhow!(
                "LMS known-answer test {name:?} FAILED. Refusing to sign: the signing \
                 implementation on this machine does not reproduce its published \
                 vectors, so any signature it produced could be wrong — and a vault \
                 signature cannot be retried."
            )
        })
}

/// Build a signing key positioned at `leaf`.
///
/// A freshly generated key sits at leaf 0, and advancing it by signing throwaway
/// messages would burn one-time keys — the exact thing the design exists to
/// avoid. The private key encodes its own leaf index (`seed || I || q`, with `q`
/// big-endian in the last four bytes), so the position is set directly instead.
///
/// Costs one Merkle tree construction, the same as key generation.
pub fn signing_key_at(xi: &[u8; 32], leaf: u32) -> Result<lms::LmsSigningKey> {
    ensure!(leaf < PARAMS.leaf_count(), "leaf {leaf} out of range");

    run_self_tests()?;

    let (private_key, _public_key) = lms::keygen_internal(xi);
    let mut bytes = private_key.to_bytes();

    const INDEX_OFFSET: usize = N + 16;
    bytes[INDEX_OFFSET..INDEX_OFFSET + 4].copy_from_slice(&leaf.to_be_bytes());

    let positioned = lms::LmsPrivateKey::from_bytes(&bytes)
        .ok_or_else(|| anyhow::anyhow!("could not rebuild the private key at leaf {leaf}"))?;
    // `from_private_key_internal`, not the gated `from_private_key`: every
    // other call site here uses oxicrypt's `_internal` entry points, and the
    // gate requires a FIPS module state this project does not claim. The
    // known-answer tests above are what actually validates the implementation.
    let key = lms::LmsSigningKey::from_private_key_internal(positioned);

    ensure!(key.leaf_index() == leaf, "signing key did not land on leaf {leaf}");
    Ok(key)
}

/// RFC 8554 §5.3: `u32str(lms_type) || u32str(lmots_type) || I || T[1]`.
fn parse_public_key(encoded: &[u8]) -> LmsPublicKey {
    debug_assert_eq!(encoded.len(), PARAMS.public_key_len());
    LmsPublicKey {
        id: encoded[8..24].try_into().expect("I is 16 bytes"),
        root: encoded[24..56].try_into().expect("T[1] is 32 bytes"),
    }
}
