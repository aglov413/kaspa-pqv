//! Key derivation, addresses and spending for SLH-DSA post-quantum vaults.
//!
//! # What statelessness deletes
//!
//! The LMS wallet needs a journal, a leaf cursor, exhaustion warnings, a gap
//! limit, a migration path at leaf 32,767, and a scan over 32,768 addresses
//! that cannot distinguish "spent" from "never used". None of that exists here.
//! An SLH-DSA vault is **one address**, signed as many times as you like,
//! including for messages the chain never sees.
//!
//! That is the whole argument for the scheme, and it is why this crate is a
//! fraction of the size of `lms-wallet` despite doing the same job.
//!
//! # What replaces it
//!
//! One thing, and it is load-bearing: the address is a pure function of the
//! derived seed, the emitted redeem script, and the witness blob plan. All
//! three must be reproducible a decade from now. See [`keygen`] for the
//! `fips205` pin that makes the first reproducible, and the frozen derivation
//! vector in `tests/` for the assertion that covers all three at once.

pub mod keygen;
pub mod spend;
pub mod vault;

pub use keygen::{keypair_from_xi, KeySeeds, Keypair, NoRng, KEY_DOMAIN};
pub use spend::{build_spend, preflight, verify, SignedSpend, VaultUtxo};
pub use vault::{SlhVault, CANONICAL_OUTPUT_COUNT};

// Derivation is shared with the LMS scheme: the `scheme'` path level is what
// separates the two branches, and that only works if both read one table.
pub use vault_core::{derive_xi, vault_path, Derivation, KeyMaterial, Scheme};
