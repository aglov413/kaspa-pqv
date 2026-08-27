//! Freezes `mnemonic -> xi -> LMS key -> address`.
//!
//! This is the fixture that stops two implementations producing different
//! vaults from the same seed. Nothing about that failure is loud: the wallet
//! shows an empty balance and the coins are simply unreachable. If any value
//! here changes, existing vaults become underivable, so a diff to this file is
//! a compatibility break and must be treated as one.
//!
//! The mnemonic is the BIP39 all-`abandon` test phrase. Do not fund it.

use kaspa_addresses::Prefix;
use kaspa_bip32::{Language, Mnemonic};
use lms_wallet::derivation::{
    derive_xi, vault_path, Derivation, Scheme, COIN_TYPE, PURPOSE, XI_DOMAIN,
};
use lms_wallet::vault::{Vault, PARAMS};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// ---------------------------------------------------------------------------
// FROZEN VECTOR.
//
// Derived from TEST_MNEMONIC at m/101110'/111111'/1'/0'/0'. Regenerate with
// `cargo test -p lms-wallet --test derivation_vector -- --ignored --nocapture`
// and paste the output here. A diff to any value below is a compatibility
// break: existing vaults become underivable and the wallet shows an empty
// balance rather than an error.
// ---------------------------------------------------------------------------
const VECTOR_PATH: &str = "m/101110'/111111'/1'/0'/0'";
const VECTOR_XI: &str = "8cb91439205eac77aef51edf93480e6bd8f40e0d41ea9c9e49a166fa3eadaa06";
const VECTOR_I: &str = "4703661b8595616f65a81f43d5ca0442";
const VECTOR_ROOT: &str = "d19da4e6a20ec028ef002bfa2a69917871a864186c4f711bf277be7d95cdd0f9";
const VECTOR_LEAF_0: &str =
    "kaspa:pqtjrau4yfjdg48hvucw76tmvwluz208huvlhrqrylr22j3wwat4wgenq8hjh";
const VECTOR_LEAF_LAST: &str =
    "kaspa:pr495exzslhdc02540x8w669xl8p4epwekwyyu4plvscsqvcg7z76dlhps6df";

fn test_seed() -> Vec<u8> {
    let mnemonic = Mnemonic::new(TEST_MNEMONIC, Language::English).expect("valid mnemonic");
    let seed_hex = mnemonic.create_seed(None);
    hex::decode(seed_hex).expect("seed is hex")
}

/// The constants themselves, so a change to any of them fails here first.
#[test]
fn derivation_constants_are_pinned() {
    assert_eq!(PURPOSE, 101_110, "BIP43 purpose (0b101110 = 46, after Kaspa's 44/45)");
    assert_eq!(COIN_TYPE, 111_111, "SLIP-0044 coin type");
    assert_eq!(Scheme::LmsSha256.index(), 1, "scheme index");
    assert_eq!(XI_DOMAIN, b"KaspaPQV-v1", "xi domain separator");
    assert_eq!(vault_path(Scheme::LmsSha256, 0, 0), "m/101110'/111111'/1'/0'/0'");
}

/// The frozen vector: every derived value asserted against a fixed expectation.
///
/// Without these assertions the surrounding tests only prove the derivation is
/// *self-consistent*, which a silently changed hash construction would also be.
#[test]
fn frozen_vector_still_derives() {
    let seed = test_seed();
    let xi = derive_xi(&seed, Scheme::LmsSha256, 0, 0).expect("derivation");
    let (vault, _sk) = Vault::from_xi(&xi);

    assert_eq!(vault_path(Scheme::LmsSha256, 0, 0), VECTOR_PATH, "derivation path changed");
    assert_eq!(hex::encode(xi), VECTOR_XI, "xi changed -- existing vaults are now underivable");
    assert_eq!(hex::encode(vault.public_key.id), VECTOR_I, "LMS key identifier changed");
    assert_eq!(hex::encode(vault.public_key.root), VECTOR_ROOT, "LMS Merkle root changed");

    let addresses = vault.addresses(Prefix::Mainnet).expect("addresses");
    assert_eq!(addresses[0].to_string(), VECTOR_LEAF_0, "leaf 0 address changed");
    assert_eq!(addresses.last().unwrap().to_string(), VECTOR_LEAF_LAST, "last leaf address changed");
}

/// Prints a paste-ready vector. Run with `--ignored --nocapture` after an
/// intentional change to the derivation or the script generator.
#[test]
#[ignore = "regeneration helper, not a check"]
fn regenerate_vector() {
    let seed = test_seed();
    let xi = derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap();
    let (vault, _) = Vault::from_xi(&xi);
    let addresses = vault.addresses(Prefix::Mainnet).unwrap();

    println!("const VECTOR_PATH: &str = \"{}\";", vault_path(Scheme::LmsSha256, 0, 0));
    println!("const VECTOR_XI: &str = \"{}\";", hex::encode(xi));
    println!("const VECTOR_I: &str = \"{}\";", hex::encode(vault.public_key.id));
    println!("const VECTOR_ROOT: &str = \"{}\";", hex::encode(vault.public_key.root));
    println!("const VECTOR_LEAF_0: &str =\n    \"{}\";", addresses[0]);
    println!("const VECTOR_LEAF_LAST: &str =\n    \"{}\";", addresses.last().unwrap());
}

/// The purpose number is a free choice, and changing it must change the vault.
///
/// This is what makes a future KIP-assigned number a one-line migration rather
/// than an archaeology exercise.
#[test]
fn purpose_is_configurable_and_changes_the_vault() {
    let seed = test_seed();

    let canonical = Derivation::DEFAULT;
    let alternate = Derivation { purpose: 8554, ..Derivation::DEFAULT };

    assert_eq!(canonical.path(0, 0), VECTOR_PATH);
    assert_eq!(alternate.path(0, 0), "m/8554'/111111'/1'/0'/0'");

    let xi_a = canonical.xi(&seed, 0, 0).unwrap();
    let xi_b = alternate.xi(&seed, 0, 0).unwrap();
    assert_ne!(xi_a, xi_b, "a different purpose must yield a different vault");

    // Both are usable in the same process, which is what a migration needs:
    // scan the old branch and the new one until funds have moved.
    let (vault_a, _) = Vault::from_xi(&xi_a);
    let (vault_b, _) = Vault::from_xi(&xi_b);
    assert_ne!(
        vault_a.address(Prefix::Mainnet, 0).unwrap(),
        vault_b.address(Prefix::Mainnet, 0).unwrap()
    );
}

/// The full chain, end to end.
#[test]
fn mnemonic_to_addresses_is_stable() {
    let seed = test_seed();
    let xi = derive_xi(&seed, Scheme::LmsSha256, 0, 0).expect("derivation");
    let (vault, _sk) = Vault::from_xi(&xi);

    let addresses = vault.addresses(Prefix::Mainnet).expect("addresses");
    assert_eq!(addresses.len(), PARAMS.leaf_count() as usize, "one address per leaf");

    // Every leaf is a distinct address, which is what makes the live leaf
    // discoverable by scanning.
    let mut sorted: Vec<String> = addresses.iter().map(ToString::to_string).collect();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), addresses.len(), "leaf addresses must be distinct");

    // Determinism across a fresh derivation.
    let xi_again = derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap();
    let (vault_again, _) = Vault::from_xi(&xi_again);
    assert_eq!(
        vault_again.addresses(Prefix::Mainnet).unwrap(),
        addresses,
        "same mnemonic must give the same vault"
    );
}

/// Distinct key indices give unrelated vaults.
#[test]
fn key_indices_give_independent_vaults() {
    let seed = test_seed();
    let (v0, _) = Vault::from_xi(&derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap());
    let (v1, _) = Vault::from_xi(&derive_xi(&seed, Scheme::LmsSha256, 0, 1).unwrap());

    assert_ne!(v0.public_key.id, v1.public_key.id);
    assert_ne!(v0.public_key.root, v1.public_key.root);
    assert_ne!(
        v0.address(Prefix::Mainnet, 0).unwrap(),
        v1.address(Prefix::Mainnet, 0).unwrap()
    );
}

/// Addresses are P2SH, and carry no marker distinguishing them from any other
/// P2SH address. Pinned so the UX consequence is not forgotten.
#[test]
fn vault_addresses_are_indistinguishable_p2sh() {
    let seed = test_seed();
    let (vault, _) = Vault::from_xi(&derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap());
    let addr = vault.address(Prefix::Mainnet, 0).unwrap();

    assert_eq!(addr.version, kaspa_addresses::Version::ScriptHash);
    assert!(addr.to_string().starts_with("kaspa:"));
}

/// A vault must expose exactly `2^h` leaves, and refuse beyond that.
#[test]
fn leaf_range_is_bounded_by_tree_height() {
    let seed = test_seed();
    let (vault, _) = Vault::from_xi(&derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap());

    assert_eq!(vault.leaf_count(), 32_768, "h = 15 gives 2^15 one-time keys");
    assert!(vault.address(Prefix::Mainnet, 32_767).is_ok());
    assert!(
        vault.address(Prefix::Mainnet, 32_768).is_err(),
        "leaf 32768 is out of range for h = 15"
    );
}
