//! The frozen derivation vector.
//!
//! **This is the test that makes it safe to fund an address.**
//!
//! A vault address is a pure function of four things, and every one of them can
//! move without anyone noticing:
//!
//! 1. the BIP32 path and the `xi` construction (`vault-core::derivation`);
//! 2. how `xi` becomes SLH-DSA key material — which depends on `fips205`
//!    drawing three 16-byte values in a fixed order, an implementation detail
//!    of a `pub(crate)` function;
//! 3. the emitted redeem script, tens of thousands of opcodes of generator
//!    output;
//! 4. the witness blob plan, which sets how many slice sequences that script
//!    contains.
//!
//! If any of them drifts, coins at the old address become unspendable by the
//! new code and there is no error anywhere — the wallet simply generates a
//! different address and reports a zero balance. So the chain is pinned end to
//! end, from a published mnemonic to a finished bech32 string.
//!
//! Regenerate with:
//!
//! ```text
//! cargo test -p slh-wallet --release -- --ignored print_derivation_vector --nocapture
//! ```
//!
//! Only correct when the change is *intended*. If this fails and you did not
//! mean to move every address, the fix is in the code, not here.

use kaspa_addresses::Prefix;
use kaspa_bip32::{Language, Mnemonic};
use sha2::{Digest, Sha256};
use slh_wallet::{derive_xi, vault_path, Scheme, SlhVault};

/// The BIP39 test vector everyone publishes. Deliberately worthless, and
/// deliberately not the mnemonic any real vault uses.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> Vec<u8> {
    let m = Mnemonic::new(TEST_MNEMONIC, Language::English).expect("valid mnemonic");
    hex::decode(m.create_seed(None)).expect("seed hex")
}

fn vault_at(account: u32, key_index: u32) -> ([u8; 32], SlhVault) {
    let xi =
        derive_xi(&seed(), Scheme::SlhDsaSha2_128s, account, key_index).expect("derivation");
    let (vault, _) = SlhVault::from_xi(&xi).expect("keygen");
    (xi, vault)
}

fn script_hash(vault: &SlhVault) -> String {
    let mut h = Sha256::new();
    h.update(vault.redeem_script().expect("redeem script"));
    hex::encode(h.finalize())
}

#[test]
fn the_derivation_path_is_frozen() {
    assert_eq!(vault_path(Scheme::SlhDsaSha2_128s, 0, 0), "m/101110'/111111'/2'/0'/0'");
}

#[test]
fn the_derived_seed_is_frozen() {
    let (xi, _) = vault_at(0, 0);
    assert_eq!(hex::encode(xi), "6fc0d827b40bd8467fabcf8e1267846e5bbff29b9061b5f240ea40de2664471f", "xi moved: the BIP32 path or the xi construction changed");
}

#[test]
fn the_public_key_is_frozen() {
    let (_, vault) = vault_at(0, 0);
    assert_eq!(
        hex::encode(vault.public_key.seed),
        "9aa2853c75b20987add78868dd57e58b",
        "PK.seed moved: the key derivation changed"
    );
    assert_eq!(
        hex::encode(vault.public_key.root),
        "17dfcc757d3acd953c32e4a018f972ab",
        "PK.root moved: fips205 keygen changed, or it draws its seeds differently now"
    );
}

#[test]
fn the_redeem_script_is_frozen() {
    let (_, vault) = vault_at(0, 0);
    assert_eq!(vault.plan.blob_count(), 123, "the witness blob plan is part of the address");
    assert_eq!(vault.redeem_script().expect("script").len(), 89235, "the script changed size");
    assert_eq!(script_hash(&vault), "1be135f2b5662ca16464af9fea870cc3848cb3950c5294be00e2da1c66c46376", "the emitted script changed");
}

#[test]
fn the_address_is_frozen() {
    let (_, vault) = vault_at(0, 0);
    assert_eq!(vault.address(Prefix::Testnet).expect("address").to_string(), "kaspatest:ppqqpksxdapwp5kc48pn6s88prgwlsh8sn76y63ma9mg76sdcjh269nc5wpy7");
    assert_eq!(vault.address(Prefix::Mainnet).expect("address").to_string(), "kaspa:ppqqpksxdapwp5kc48pn6s88prgwlsh8sn76y63ma9mg76sdcjh26y470pl46");
}

/// Neighbouring indices, so an off-by-one in the path produces a failing test
/// rather than a valid-looking address from the wrong branch.
#[test]
fn neighbouring_indices_are_frozen() {
    for (account, index, expected) in [(0u32, 1u32, "kaspatest:pqakc5rlwdurn2j89npqzlnpe5n6xqqtqnwwj4ls25rj0vvu7qs427ecpdqpn"), (1, 0, "kaspatest:pz6zvzufdmpkly2hmfaq87t0t0t3x8cn9lplan27fdummvq37syeqgnugdd38")] {
        let (_, vault) = vault_at(account, index);
        assert_eq!(
            vault.address(Prefix::Testnet).expect("address").to_string(),
            expected,
            "address at account {account}, index {index}"
        );
    }
}

/// A restored wallet reaches the same address from the mnemonic alone, with
/// nothing carried over from the process that created it.
#[test]
fn the_address_survives_a_cold_restore() {
    let (_, first) = vault_at(0, 0);
    let expected = first.address(Prefix::Testnet).unwrap();
    drop(first);

    let m = Mnemonic::new(TEST_MNEMONIC, Language::English).unwrap();
    let restored_seed = hex::decode(m.create_seed(None)).unwrap();
    let xi = derive_xi(&restored_seed, Scheme::SlhDsaSha2_128s, 0, 0).unwrap();
    let (restored, _) = SlhVault::from_xi(&xi).unwrap();

    assert_eq!(restored.address(Prefix::Testnet).unwrap(), expected);
}

/// The LMS vault under the same mnemonic must be a different address, or the
/// `scheme'` level is not doing its job and one backup phrase would not in fact
/// carry two independent vaults.
#[test]
fn the_two_schemes_do_not_collide_under_one_mnemonic() {
    let slh = derive_xi(&seed(), Scheme::SlhDsaSha2_128s, 0, 0).unwrap();
    let lms = derive_xi(&seed(), Scheme::LmsSha256, 0, 0).unwrap();
    assert_ne!(slh, lms);
}

#[test]
#[ignore = "regeneration helper; run explicitly and only when a change is intended"]
fn print_derivation_vector() {
    let (xi, vault) = vault_at(0, 0);
    println!("XI {}", hex::encode(xi));
    println!("PKSEED {}", hex::encode(vault.public_key.seed));
    println!("PKROOT {}", hex::encode(vault.public_key.root));
    println!("SCRIPTLEN {}", vault.redeem_script().unwrap().len());
    println!("BLOBS {}", vault.plan.blob_count());
    println!("SCRIPTHASH {}", script_hash(&vault));
    println!("TN {}", vault.address(Prefix::Testnet).unwrap());
    println!("MN {}", vault.address(Prefix::Mainnet).unwrap());
    let (_, a01) = vault_at(0, 1);
    println!("A01 {}", a01.address(Prefix::Testnet).unwrap());
    let (_, a10) = vault_at(1, 0);
    println!("A10 {}", a10.address(Prefix::Testnet).unwrap());
}
