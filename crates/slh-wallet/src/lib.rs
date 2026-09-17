//! Key derivation, addresses and spending for SLH-DSA post-quantum vaults.
//!
//! # What statelessness deletes
//!
//! The LMS wallet needs a journal, a leaf cursor, exhaustion warnings, a gap
//! limit, a migration path at leaf 32,767, and a scan over 32,768 addresses
//! that cannot distinguish "spent" from "never used". None of that exists here.
//! An SLH-DSA vault is **one address**, signed as many times as you like,
//! including for messages the chain never sees — up to 2^24 times under the
//! two limited sets, which no vault will reach, and without limit under
//! `128s`.
//!
//! That is the whole argument for the scheme, and it is why this crate is a
//! fraction of the size of `lms-wallet` despite doing the same job.
//!
//! # What replaces it
//!
//! One thing, and it is load-bearing: the address is a pure function of the
//! parameter set, the derived seed, the emitted redeem script, and the witness
//! blob plan. All four must be reproducible a decade from now. See [`keygen`]
//! for why the first two no longer depend on a third-party crate's internals,
//! and the frozen derivation vectors in `tests/` for the assertion that covers
//! all four at once, per set.
//!
//! # Three parameter sets, one code path
//!
//! `SLH-DSA-SHA2-128s` is the standardised set. `SLH-DSA-SHA2-128-24` and
//! `SLH-DSA-SHA2-128-24d2` trade a 2^24 signature limit for roughly half the
//! signature — a limit a vault cannot plausibly reach. They are separate
//! `scheme'` levels in the derivation path and separate addresses, and nothing
//! about a vault's parameter set can be inferred from its key or its address.

pub mod keygen;
pub mod spend;
pub mod vault;

use slh_script::params::{Params, SHA2_128S, SHA2_128_24, SHA2_128_24_D2};

/// The parameter set a derivation `scheme'` level names.
///
/// `None` for [`Scheme::LmsSha256`], which is not an SLH-DSA scheme at all.
/// This is the one place the two tables are tied together, so that adding a
/// set means adding it here rather than discovering later that some code path
/// still maps it to the old default.
pub const fn params_for(scheme: Scheme) -> Option<&'static Params> {
    match scheme {
        Scheme::LmsSha256 => None,
        Scheme::SlhDsaSha2_128s => Some(&SHA2_128S),
        Scheme::SlhDsaSha2_128_24 => Some(&SHA2_128_24),
        Scheme::SlhDsaSha2_128_24D2 => Some(&SHA2_128_24_D2),
    }
}

/// Every SLH-DSA scheme and the set it derives, in report order.
pub const SLH_SCHEMES: &[(Scheme, &Params)] = &[
    (Scheme::SlhDsaSha2_128s, &SHA2_128S),
    (Scheme::SlhDsaSha2_128_24, &SHA2_128_24),
    (Scheme::SlhDsaSha2_128_24D2, &SHA2_128_24_D2),
];

pub use keygen::{key_domain, keypair_from_xi, seeds_from_xi, Keypair};
pub use spend::{build_spend, preflight, verify, SignedSpend, VaultUtxo};
pub use vault::{SlhVault, CANONICAL_OUTPUT_COUNT};

// Derivation is shared with the LMS scheme: the `scheme'` path level is what
// separates the two branches, and that only works if both read one table.
pub use vault_core::{derive_xi, vault_path, Derivation, KeyMaterial, Scheme};

#[cfg(test)]
mod tests {
    use super::*;

    /// The scheme-to-parameter-set map must be a bijection over the SLH-DSA
    /// schemes. A scheme mapped to the wrong set derives a real key at a real
    /// address that the wallet will then look for somewhere else.
    #[test]
    fn every_slh_scheme_maps_to_its_own_set() {
        let mapped: Vec<_> = Scheme::ALL.iter().filter_map(|s| params_for(*s)).collect();
        assert_eq!(mapped.len(), SLH_SCHEMES.len(), "a scheme is missing from the map");
        for (i, a) in mapped.iter().enumerate() {
            for b in &mapped[i + 1..] {
                assert_ne!(a.name, b.name, "two schemes share a parameter set");
            }
        }
        for (scheme, expected) in SLH_SCHEMES {
            assert_eq!(params_for(*scheme).map(|p| p.name), Some(expected.name));
        }
        assert!(params_for(Scheme::LmsSha256).is_none(), "LMS is not an SLH-DSA scheme");
    }
}
