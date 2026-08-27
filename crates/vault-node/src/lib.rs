//! Kaspa node connectivity for LMS vaults.
//!
//! Two operations are needed from a node: look up what a vault address holds,
//! and broadcast a spend. Everything else — derivation, script construction,
//! signing, the sign-once journal — is offline and lives in `lms-wallet`.
//!
//! Connection goes through the **Public Node Network (PNN)** by default, using
//! `kaspa-wrpc-client`'s [`Resolver`], which asks the Kaspa Resolver
//! load-balancer for a public node with the fewest active connections. That
//! makes a testnet-10 spend possible without running a node, though the PNN is
//! documented as being for development and testing rather than production
//! load — so a vault holding real value should point at its own node via
//! [`NodeClient::connect_to_url`].

pub mod client;

pub use client::{NodeClient, VaultUtxoEntry};
