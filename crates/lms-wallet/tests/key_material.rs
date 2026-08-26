//! The three ways to supply vault key material, and what distinguishes them.

use lms_wallet::derivation::{derive_xi, Derivation, Scheme};
use lms_wallet::key_material::KeyMaterial;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The BIP39 seed for TEST_MNEMONIC with no passphrase.
const TEST_SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

fn xi_of(material: &KeyMaterial, key_index: u32) -> [u8; 32] {
    Derivation::DEFAULT.xi_from(material, 0, key_index).unwrap()
}

/// A mnemonic and its seed are the same key material, so they must give the
/// same vault. Otherwise importing a wallet by seed would silently produce an
/// empty one.
#[test]
fn a_mnemonic_and_its_seed_give_the_same_vault() {
    let from_words = KeyMaterial::from_mnemonic(TEST_MNEMONIC).unwrap();
    let from_seed = KeyMaterial::parse(TEST_SEED_HEX).unwrap();

    assert_eq!(xi_of(&from_words, 0), xi_of(&from_seed, 0));
    assert_eq!(xi_of(&from_words, 5), xi_of(&from_seed, 5));
}

/// And both agree with the plain seed-based helper.
#[test]
fn parsing_agrees_with_direct_derivation() {
    let seed = hex::decode(TEST_SEED_HEX).unwrap();
    let expected = derive_xi(&seed, Scheme::LmsSha256, 0, 0).unwrap();
    assert_eq!(xi_of(&KeyMaterial::parse(TEST_SEED_HEX).unwrap(), 0), expected);
}

/// Formats are told apart by shape.
#[test]
fn key_formats_are_detected() {
    assert!(matches!(KeyMaterial::parse(TEST_SEED_HEX).unwrap(), KeyMaterial::Bip39Seed(_)));
    assert!(matches!(KeyMaterial::parse(&"11".repeat(32)).unwrap(), KeyMaterial::Raw(_)));

    // Wrong lengths are rejected rather than silently reinterpreted.
    assert!(KeyMaterial::parse("deadbeef").is_err());
    assert!(KeyMaterial::parse("").is_err());
    assert!(KeyMaterial::parse(&"11".repeat(31)).is_err());
}

/// A bare key produces a vault, but a different one from any seed — the domain
/// separators guarantee the two constructions cannot collide.
#[test]
fn a_bare_key_is_a_distinct_construction() {
    let raw = KeyMaterial::parse(&"11".repeat(32)).unwrap();
    let seed = KeyMaterial::parse(TEST_SEED_HEX).unwrap();
    assert_ne!(xi_of(&raw, 0), xi_of(&seed, 0));

    // Indices still give independent vaults.
    assert_ne!(xi_of(&raw, 0), xi_of(&raw, 1));
}

/// The isolation property is what the warning is about, so it is asserted
/// rather than left to prose.
#[test]
fn only_a_bare_key_loses_quantum_isolation() {
    assert!(KeyMaterial::from_mnemonic(TEST_MNEMONIC).unwrap().is_quantum_isolated());
    assert!(KeyMaterial::parse(TEST_SEED_HEX).unwrap().is_quantum_isolated());
    assert!(!KeyMaterial::parse(&"11".repeat(32)).unwrap().is_quantum_isolated());
}

/// A user must be told when isolation is lost, and the warning must say why.
#[test]
fn the_bare_key_warning_explains_the_risk() {
    let raw = KeyMaterial::parse(&"11".repeat(32)).unwrap();
    let warning = raw.warning().expect("a bare key must warn");
    assert!(warning.contains("on-chain"), "{warning}");
    assert!(warning.contains("quantum"), "{warning}");

    // A mnemonic needs no warning.
    assert!(KeyMaterial::from_mnemonic(TEST_MNEMONIC).unwrap().warning().is_none());
}

/// Nonsense input fails rather than producing a plausible-looking vault.
#[test]
fn invalid_input_is_rejected() {
    assert!(KeyMaterial::from_mnemonic("not a real mnemonic phrase at all").is_err());
    assert!(KeyMaterial::parse("xprvNotARealExtendedKey").is_err());
    assert!(KeyMaterial::parse(&"zz".repeat(32)).is_err());
}
