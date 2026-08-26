//! The sign-once invariant, enforced structurally.
//!
//! A one-time key signs once. Signing two *different* messages under one LM-OTS
//! key reveals enough of the private key to forge a third: QRL, which has run
//! the same construction in production since 2018, publishes recovery at
//! roughly 2^34 hashes from two signatures, 2^23 from three, 2^18 from four.
//! 2^34 is hours on a consumer GPU. This is not a degradation to manage, it is
//! a loss of funds.
//!
//! Kaspa cannot help here. QRL rejects index reuse at consensus; Kaspa has no
//! such rule and adding one would need the consensus change this design exists
//! to avoid. So the invariant lives in the wallet, and it has to be structural
//! rather than advisory — the tempting moment is a stuck transaction, which is
//! exactly when a user is most inclined to click through a warning.
//!
//! The rule this module enforces:
//!
//! - A leaf that has never signed may sign once. The record is persisted
//!   **before** the signature is returned, so a crash mid-spend cannot lose the
//!   fact that a signature exists.
//! - A leaf asked to sign the *same* digest again returns the stored signature.
//!   Retrying a broadcast is safe and idempotent.
//! - A leaf asked to sign a *different* digest is refused.
//!
//! That last case is the fee bump. The answer is not to re-sign — it is to
//! rebroadcast the stored transaction, or to accept that the leaf is spent and
//! that its UTXO can only ever move via the signature already issued.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Identifies one one-time key: which vault, which leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LeafId {
    /// RFC 8554 `I`, the LMS key identifier.
    pub vault_id: [u8; 16],
    pub leaf: u32,
}

impl LeafId {
    pub fn new(vault_id: [u8; 16], leaf: u32) -> Self {
        Self { vault_id, leaf }
    }
}

/// Proof that a leaf has signed, and what it signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendRecord {
    pub leaf: LeafId,
    /// The binding digest that was signed.
    pub digest: [u8; 32],
    /// The signature itself. Not secret — publishing it is what spending does.
    pub signature: Vec<u8>,
}

/// Durable record of which leaves have signed.
///
/// Implementations must make [`put`](SpendJournal::put) durable before
/// returning. A journal that buffers in memory and flushes later defeats the
/// entire purpose: the window between issuing a signature and recording it is
/// precisely where a crash produces an untracked one-time key.
pub trait SpendJournal {
    fn get(&self, leaf: &LeafId) -> Option<SpendRecord>;
    fn put(&mut self, record: SpendRecord) -> Result<()>;
}

/// What happened when a leaf was asked to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignOutcome {
    /// First use of this leaf. The record is already durable.
    Signed(SpendRecord),
    /// This leaf already signed this exact digest; the stored signature is
    /// returned unchanged. Safe to rebroadcast.
    AlreadySigned(SpendRecord),
}

impl SignOutcome {
    pub fn record(&self) -> &SpendRecord {
        match self {
            Self::Signed(r) | Self::AlreadySigned(r) => r,
        }
    }

    pub fn signature(&self) -> &[u8] {
        &self.record().signature
    }
}

/// Sign `digest` with `leaf`, refusing to reuse the key for anything else.
///
/// `sign` is only invoked when the leaf has no prior record, and the record is
/// persisted before the signature reaches the caller.
pub fn sign_once<J, F>(
    journal: &mut J,
    leaf: LeafId,
    digest: [u8; 32],
    sign: F,
) -> Result<SignOutcome>
where
    J: SpendJournal + ?Sized,
    F: FnOnce() -> Result<Vec<u8>>,
{
    if let Some(existing) = journal.get(&leaf) {
        if existing.digest == digest {
            return Ok(SignOutcome::AlreadySigned(existing));
        }
        bail!(
            "leaf {} of vault {} has already signed a different digest ({}). \
             Signing again would expose the one-time key and allow an attacker to \
             forge a spend of this UTXO. Rebroadcast the stored transaction instead; \
             if it can never confirm, the funds at this leaf can only move via the \
             signature already issued.",
            leaf.leaf,
            hex_16(&leaf.vault_id),
            hex_32(&existing.digest),
        );
    }

    let signature = sign()?;
    let record = SpendRecord { leaf, digest, signature };
    journal.put(record.clone())?; // durable before the signature escapes
    Ok(SignOutcome::Signed(record))
}

/// In-memory journal. For tests, and for callers that persist by other means.
#[derive(Debug, Default)]
pub struct MemoryJournal {
    entries: HashMap<LeafId, SpendRecord>,
}

impl SpendJournal for MemoryJournal {
    fn get(&self, leaf: &LeafId) -> Option<SpendRecord> {
        self.entries.get(leaf).cloned()
    }

    fn put(&mut self, record: SpendRecord) -> Result<()> {
        self.entries.insert(record.leaf, record);
        Ok(())
    }
}

/// Append-only file journal.
///
/// One record per line, `vault_id:leaf:digest:signature` in hex. Append-only
/// and fsynced on write, so a crash can lose at most the record currently being
/// written — and a truncated final line is discarded on load, which is the safe
/// direction: an unreadable record reads as "this leaf may have signed", and
/// [`sign_once`] then refuses rather than issuing a second signature.
#[derive(Debug)]
pub struct FileJournal {
    path: PathBuf,
    entries: HashMap<LeafId, SpendRecord>,
}

impl FileJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut entries = HashMap::new();

        if path.exists() {
            let text = fs::read_to_string(&path)?;
            for line in text.lines() {
                match parse_line(line) {
                    Some(record) => {
                        entries.insert(record.leaf, record);
                    }
                    // A malformed trailing line means a torn write. Skipping it
                    // is safe only because a *missing* record is the dangerous
                    // direction, so we warn loudly rather than silently drop it.
                    None if line.trim().is_empty() => {}
                    None => bail!(
                        "spend journal {} contains an unreadable record; refusing to \
                         continue, because treating it as absent could allow a \
                         one-time key to sign twice: {line:?}",
                        path.display()
                    ),
                }
            }
        }

        Ok(Self { path, entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl SpendJournal for FileJournal {
    fn get(&self, leaf: &LeafId) -> Option<SpendRecord> {
        self.entries.get(leaf).cloned()
    }

    fn put(&mut self, record: SpendRecord) -> Result<()> {
        use std::io::Write;

        let line = format!(
            "{}:{}:{}:{}\n",
            hex_16(&record.leaf.vault_id),
            record.leaf.leaf,
            hex_32(&record.digest),
            to_hex(&record.signature),
        );

        let mut file = fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?; // durable before we report success

        self.entries.insert(record.leaf, record);
        Ok(())
    }
}

fn parse_line(line: &str) -> Option<SpendRecord> {
    let mut parts = line.trim().split(':');
    let vault_id = from_hex(parts.next()?)?;
    let leaf: u32 = parts.next()?.parse().ok()?;
    let digest = from_hex(parts.next()?)?;
    let signature = from_hex(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some(SpendRecord {
        leaf: LeafId { vault_id: vault_id.try_into().ok()?, leaf },
        digest: digest.try_into().ok()?,
        signature,
    })
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_16(bytes: &[u8; 16]) -> String {
    to_hex(bytes)
}

fn hex_32(bytes: &[u8; 32]) -> String {
    to_hex(bytes)
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || s.is_empty() {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}
