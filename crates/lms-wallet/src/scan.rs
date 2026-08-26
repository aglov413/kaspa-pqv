//! Finding the live leaf.
//!
//! A vault's one-time-key state is the UTXO set: leaf `q` can only ever spend
//! the UTXO at address `q`, so "which index have I burned" is answered by
//! looking at which address holds coins. That is what removes the counter file
//! a stateful scheme would otherwise need to survive a decade and a mnemonic
//! restore.
//!
//! This module is deliberately free of I/O. A caller supplies balances through
//! [`UtxoSource`], which a node client implements and a test implements with a
//! map.

use anyhow::Result;
use kaspa_addresses::{Address, Prefix};

use crate::vault::Vault;

/// Where address balances come from. Implemented by a node client in
/// production and by a fixture in tests.
pub trait UtxoSource {
    /// Total value held at `address`, in sompi. Zero if unfunded.
    fn balance(&self, address: &Address) -> Result<u64>;
}

/// One leaf and what it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafBalance {
    pub leaf: u32,
    pub address: Address,
    pub amount: u64,
}

/// What a scan found.
#[derive(Clone, Debug, Default)]
pub struct ScanResult {
    /// Leaves currently holding funds, in leaf order.
    pub funded: Vec<LeafBalance>,
}

impl ScanResult {
    /// The leaf a spend should come from: the lowest-numbered funded leaf.
    ///
    /// Spending advances a vault from leaf `q` to `q+1`, so under normal use
    /// exactly one leaf is funded. More than one means either a partial spend
    /// or an inbound payment to an already-advanced address — see
    /// [`Self::is_ambiguous`].
    pub fn live_leaf(&self) -> Option<&LeafBalance> {
        self.funded.first()
    }

    /// True if more than one leaf holds funds.
    ///
    /// Worth surfacing rather than resolving silently: it usually means someone
    /// paid into an address the vault has already moved past, and the funds
    /// there can only be recovered with that leaf's one-time key — which may
    /// already have signed.
    pub fn is_ambiguous(&self) -> bool {
        self.funded.len() > 1
    }

    pub fn total(&self) -> u64 {
        self.funded.iter().map(|b| b.amount).sum()
    }
}

/// How many leaves past the hint to check by default.
///
/// A vault advances one leaf per spend, so the live leaf is normally exactly
/// one past the highest that has signed. The window absorbs leaves burned by a
/// spend that was signed but never confirmed.
pub const DEFAULT_SCAN_WINDOW: u32 = 64;

/// Scan a bounded range of leaves. This is the operation a wallet should use.
///
/// `to` is exclusive and clamped to the vault's leaf count.
pub fn scan_range<S: UtxoSource + ?Sized>(
    source: &S,
    vault: &Vault,
    prefix: Prefix,
    from: u32,
    to: u32,
) -> Result<ScanResult> {
    let mut funded = Vec::new();
    for leaf in from..to.min(vault.leaf_count()) {
        let address = vault.address(prefix, leaf)?;
        let amount = source.balance(&address)?;
        if amount > 0 {
            funded.push(LeafBalance { leaf, address, amount });
        }
    }
    Ok(ScanResult { funded })
}

/// Scan forward from a hint — normally the highest leaf the spend journal
/// records as having signed.
///
/// Balance alone cannot distinguish "already spent" from "never used": both
/// read as zero. So the live leaf is not findable by binary search, and a
/// wallet needs *some* starting point. The journal supplies it, since it
/// already knows which leaves have signed, and this checks a short window
/// beyond in case a signed-but-unconfirmed spend burned one.
pub fn scan_from_hint<S: UtxoSource + ?Sized>(
    source: &S,
    vault: &Vault,
    prefix: Prefix,
    hint: u32,
    window: u32,
) -> Result<ScanResult> {
    scan_range(source, vault, prefix, hint, hint.saturating_add(window))
}

/// Scan every leaf of one vault.
///
/// **Recovery only.** At h=15 this builds 32,768 redeem scripts of ~24 KB each
/// and takes tens of seconds. It is the right thing to do exactly once, when a
/// wallet is restored from a mnemonic with no journal and has to rediscover
/// where the vault is. Routine operation should use [`scan_from_hint`].
pub fn scan_vault<S: UtxoSource + ?Sized>(
    source: &S,
    vault: &Vault,
    prefix: Prefix,
) -> Result<ScanResult> {
    scan_range(source, vault, prefix, 0, vault.leaf_count())
}

/// How many consecutive empty vaults to check before concluding there are no
/// more.
///
/// Vaults are used in order, so a gap only appears if a user created one and
/// never funded it. Five is generous for a storage wallet, where creating a
/// vault costs a multi-second key generation and is therefore deliberate.
pub const DEFAULT_VAULT_GAP_LIMIT: u32 = 5;

/// A vault found under a seed.
#[derive(Clone, Debug)]
pub struct DiscoveredVault {
    pub key_index: u32,
    pub scan: ScanResult,
}

/// Walk key indices until `gap_limit` consecutive vaults come back empty.
///
/// `derive` builds the vault for a key index — the caller supplies it because
/// doing so needs the seed, which this crate deliberately keeps at the edges.
///
/// Each vault costs an h=15 key generation (seconds), so the gap limit is the
/// difference between a fast startup and a slow one. Callers that already know
/// how many vaults exist should scan them directly instead.
pub fn discover_vaults<S, D>(
    source: &S,
    prefix: Prefix,
    gap_limit: u32,
    leaf_window: u32,
    mut derive: D,
) -> Result<Vec<DiscoveredVault>>
where
    S: UtxoSource + ?Sized,
    D: FnMut(u32) -> Result<Vault>,
{
    let mut found = Vec::new();
    let mut consecutive_empty = 0;
    let mut key_index = 0u32;

    while consecutive_empty < gap_limit {
        let vault = derive(key_index)?;
        let scan = scan_range(source, &vault, prefix, 0, leaf_window)?;

        if scan.funded.is_empty() {
            consecutive_empty += 1;
        } else {
            consecutive_empty = 0;
            found.push(DiscoveredVault { key_index, scan });
        }
        key_index += 1;
    }
    Ok(found)
}
