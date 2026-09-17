//! Frozen derivation vectors for the two 2^24-limited SLH-DSA sets.
//!
//! **This is the test that makes it safe to fund an address** under
//! `SLH-DSA-SHA2-128-24` or `SLH-DSA-SHA2-128-24d2`. The reasoning is the same
//! as `derivation_vector.rs`'s and is not repeated here; what differs is what
//! each set is pinned *against*.
//!
//! `128s` has `fips205` behind it: its key material is reproduced by an
//! independent implementation, and `reference_oracle::the_signer_reproduces_fips205`
//! holds the two together. Neither set here has that, because nobody ships
//! SP 800-230 yet. So these vectors are pinning **this implementation's** output
//! and nothing more. They catch drift; they cannot catch a misreading of the
//! draft that was wrong from the first commit.
//!
//! That is a real difference in what the two files are worth, and it is the
//! reason `128s` remains the only set these docs suggest holding anything in.
//!
//! Regenerate with:
//!
//! ```text
//! cargo test -p slh-wallet --release -- --ignored print_2_24_vectors --nocapture
//! ```
//!
//! Only correct when the change is *intended*.

use kaspa_addresses::Prefix;
use kaspa_bip32::{Language, Mnemonic};
use sha2::{Digest, Sha256};
use slh_script::params::{Params as SlhParams, SHA2_128_24, SHA2_128_24_D2};
use slh_wallet::{derive_xi, vault_path, Scheme, SlhVault};

/// The BIP39 test vector everyone publishes. Deliberately worthless, and
/// deliberately not the mnemonic any real vault uses.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> Vec<u8> {
    let m = Mnemonic::new(TEST_MNEMONIC, Language::English).expect("valid mnemonic");
    hex::decode(m.create_seed(None)).expect("seed hex")
}

fn vault_at(
    scheme: Scheme,
    set: &'static SlhParams,
    account: u32,
    key_index: u32,
) -> ([u8; 32], SlhVault) {
    let xi = derive_xi(&seed(), scheme, account, key_index).expect("derivation");
    let (vault, _) = SlhVault::from_xi(set, &xi).expect("keygen");
    (xi, vault)
}

fn script_hash(vault: &SlhVault) -> String {
    let mut h = Sha256::new();
    h.update(vault.redeem_script().expect("redeem script"));
    hex::encode(h.finalize())
}

/// Everything one set's address depends on, in one assertion block.
struct Frozen {
    xi: &'static str,
    pk_seed: &'static str,
    pk_root: &'static str,
    script_len: usize,
    blobs: usize,
    script_hash: &'static str,
    testnet: &'static str,
    mainnet: &'static str,
    /// Addresses at `(0, 1)` and `(1, 0)`, so an off-by-one in the path is a
    /// failing test rather than a valid-looking address from the wrong branch.
    neighbours: [&'static str; 2],
}

fn check(scheme: Scheme, set: &'static SlhParams, path: &str, f: &Frozen) {
    assert_eq!(vault_path(scheme, 0, 0), path, "{}: derivation path moved", set.name);

    let (xi, vault) = vault_at(scheme, set, 0, 0);
    assert_eq!(
        hex::encode(xi),
        f.xi,
        "{}: xi moved — the BIP32 path or the xi construction changed",
        set.name
    );
    assert_eq!(
        hex::encode(vault.public_key.seed),
        f.pk_seed,
        "{}: PK.seed moved — the key derivation changed",
        set.name
    );
    assert_eq!(
        hex::encode(vault.public_key.root),
        f.pk_root,
        "{}: PK.root moved — keygen changed, or the parameter set did",
        set.name
    );
    assert_eq!(
        vault.plan.blob_count(),
        f.blobs,
        "{}: the witness blob plan is part of the address",
        set.name
    );
    assert_eq!(
        vault.redeem_script().expect("script").len(),
        f.script_len,
        "{}: the script changed size",
        set.name
    );
    assert_eq!(script_hash(&vault), f.script_hash, "{}: the emitted script changed", set.name);
    assert_eq!(
        vault.address(Prefix::Testnet).expect("address").to_string(),
        f.testnet,
        "{}",
        set.name
    );
    assert_eq!(
        vault.address(Prefix::Mainnet).expect("address").to_string(),
        f.mainnet,
        "{}",
        set.name
    );

    for ((account, index), expected) in [(0u32, 1u32), (1, 0)].into_iter().zip(f.neighbours) {
        let (_, neighbour) = vault_at(scheme, set, account, index);
        assert_eq!(
            neighbour.address(Prefix::Testnet).expect("address").to_string(),
            expected,
            "{}: address at account {account}, index {index}",
            set.name
        );
    }
}

const D2: Frozen = Frozen {
    xi: "c441d0b0ac818c7f75c7f711339a4d29070a4b591bd99813a8ae49fa7b2ceb7c",
    pk_seed: "98e47af8ecf1933318939f6c50d61ea2",
    pk_root: "02e319df89979b953add083a06adeb1e",
    script_len: 29_197,
    blobs: 82,
    script_hash: "768c79ffa0c48e33022842cd0be29261a64fd7f00161e5c198ca976483a2a103",
    testnet: "kaspatest:pqzcsvunare2zxyj4s7esz3apuwfkddycyt3z86al3y60gnkxtaz7c6scd2yk",
    mainnet: "kaspa:pqzcsvunare2zxyj4s7esz3apuwfkddycyt3z86al3y60gnkxtaz7eukrz54j",
    neighbours: [
        "kaspatest:pzx3uvf7zhs3zuhxsttlahrunkaqgvd4wfk6flge6c9kjmhvumxnv0tts2aar",
        "kaspatest:pz3cllytpuj5ual44mxe2lxzrv3z4gxkgzsr0ffwpx3sxjqrrteagyzfhr87v",
    ],
};

const D1: Frozen = Frozen {
    xi: "e2095a76dffa0b0f36701e03540c73e75b82710567f92c945af40342b9f5bfc7",
    pk_seed: "021262d373be68ca87e2f64310675bcb",
    pk_root: "06368ea04376b54a13af6265dcfcf656",
    script_len: 21_752,
    blobs: 61,
    script_hash: "115a1771b3c7c66ce9dfba33fc57a6c04efdb820ce0fa5412261d0439e78030d",
    testnet: "kaspatest:pr5j7ee2l04g7eq64yh3fzfzzzq2k27zvv9psuu9nzwddcxrudrqwl7kterl4",
    mainnet: "kaspa:pr5j7ee2l04g7eq64yh3fzfzzzq2k27zvv9psuu9nzwddcxrudrqw7csskaw3",
    neighbours: [
        "kaspatest:prun5fu7juvps0m7c0zhu47dqgvm5g7xlhkspj0n576msj6hfw6qywxdgrqxq",
        "kaspatest:pr306j7aqseepljjq4s6a8zely6qy2p99qslpqwwzkjy5a8msnpr68t9zvqkk",
    ],
};

#[test]
fn the_d2_vault_is_frozen() {
    check(Scheme::SlhDsaSha2_128_24D2, &SHA2_128_24_D2, "m/101110'/111111'/4'/0'/0'", &D2);
}

/// Three vaults at about a hundred seconds of hashing each. The cost is `d = 1` and nothing
/// else, so it is named rather than worked around.
#[test]
#[ignore = "three SLH-DSA-SHA2-128-24 keys at 2^22 WOTS+ public keys each; run explicitly"]
fn the_d1_vault_is_frozen() {
    check(Scheme::SlhDsaSha2_128_24, &SHA2_128_24, "m/101110'/111111'/3'/0'/0'", &D1);
}

/// The emitted script does not depend on the key, so `128-24`'s script — the
/// expensive half of its vector — is checkable without generating a key at all.
///
/// This is what keeps the `#[ignore]`d test above from being the only coverage
/// of the set most likely to drift: a change to the emitter fails here, in
/// milliseconds, on every run.
#[test]
fn the_d1_script_is_frozen_without_its_key() {
    use slh_script::{build_vault_script, BlobPlan, PublicKey};

    let pk = PublicKey::from_bytes(
        &hex::decode("021262d373be68ca87e2f64310675bcb06368ea04376b54a13af6265dcfcf656").unwrap(),
    )
    .unwrap();
    let plan = BlobPlan::for_params(&SHA2_128_24);
    let script = build_vault_script(&pk, &plan, 2).expect("emit").script;

    let mut h = Sha256::new();
    h.update(&script);
    assert_eq!(plan.blob_count(), D1.blobs);
    assert_eq!(script.len(), D1.script_len, "the 128-24 script changed size");
    assert_eq!(hex::encode(h.finalize()), D1.script_hash, "the 128-24 script changed");
}

/// Three SLH-DSA sets from one mnemonic must reach three different addresses.
/// They share a signature algorithm and differ only in constants, so a
/// collision here would be genuinely reused key material rather than merely two
/// keys from one secret.
#[test]
fn the_sets_do_not_collide_under_one_mnemonic() {
    let seeds: Vec<[u8; 32]> = Scheme::ALL
        .iter()
        .map(|s| derive_xi(&seed(), *s, 0, 0).unwrap())
        .collect();
    for (i, a) in seeds.iter().enumerate() {
        for b in &seeds[i + 1..] {
            assert_ne!(a, b, "two schemes shared a keygen seed");
        }
    }
}

#[test]
#[ignore = "regeneration helper; run explicitly and only when a change is intended"]
fn print_2_24_vectors() {
    for (scheme, set) in [
        (Scheme::SlhDsaSha2_128_24, &SHA2_128_24),
        (Scheme::SlhDsaSha2_128_24D2, &SHA2_128_24_D2),
    ] {
        let (xi, vault) = vault_at(scheme, set, 0, 0);
        println!("--- {}", set.name);
        println!("XI {}", hex::encode(xi));
        println!("PKSEED {}", hex::encode(vault.public_key.seed));
        println!("PKROOT {}", hex::encode(vault.public_key.root));
        println!("SCRIPTLEN {}", vault.redeem_script().unwrap().len());
        println!("BLOBS {}", vault.plan.blob_count());
        println!("SCRIPTHASH {}", script_hash(&vault));
        println!("TN {}", vault.address(Prefix::Testnet).unwrap());
        println!("MN {}", vault.address(Prefix::Mainnet).unwrap());
        for (account, index) in [(0u32, 1u32), (1, 0)] {
            let (_, v) = vault_at(scheme, set, account, index);
            println!("A{account}{index} {}", v.address(Prefix::Testnet).unwrap());
        }
    }
}
