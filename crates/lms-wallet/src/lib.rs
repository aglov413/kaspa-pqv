//! Vault key derivation and address generation.
//!
//! Turns an existing BIP39 mnemonic into a post-quantum vault: a set of P2SH
//! addresses whose spend condition is an LMS signature verified in script.
//!
//! Nothing here is reachable from an xpub — see [`derivation`] for why that is
//! a requirement rather than a preference.

pub mod journal;
pub mod preflight;
pub mod scan;
pub mod spend;
pub mod tx;
pub mod vault;


pub use journal::{sign_once, FileJournal, LeafId, MemoryJournal, SignOutcome, SpendJournal, SpendRecord};
pub use scan::{
    discover_vaults, scan_from_hint, scan_range, scan_vault, DiscoveredVault, LeafBalance,
    ScanResult, UtxoSource, DEFAULT_SCAN_WINDOW, DEFAULT_VAULT_GAP_LIMIT,
};
pub use spend::{build_spend, plan_migration, MigrationPlan, SignedSpend, VaultUtxo};
pub use preflight::{estimate, preflight, PreflightReport};
pub use tx::{assemble, verify_under_budget, AssembledTransaction};

pub use vault::{change_target, run_self_tests, signing_key_at, BudgetStatus, ChangeTarget, LeafBudget, Vault};

// `derivation` and `key_material` moved to `vault-core` when the SLH-DSA
// scheme was added: the `scheme'` path level only separates two schemes if
// both read it from one table. Re-exported so existing call sites are
// unchanged.
pub use vault_core::{derivation, key_material};
pub use vault_core::{
    derive_xi, vault_path, Derivation, KeyMaterial, Scheme, COIN_TYPE, PURPOSE, XI_DOMAIN,
};
