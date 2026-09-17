//! `kaspa-vault artifacts` — every value a vault address depends on.
//!
//! A vault address is the BLAKE2b hash of a redeem script this workspace
//! *compiles*. Nothing in the binary announces which construction produced it,
//! so an independent build that differs by one byte derives a different address
//! from the same mnemonic — and anyone who funds it from that build loses the
//! coins, with no error anywhere.
//!
//! The frozen vectors in the test suite catch drift **within one tree**. This
//! command is what lets a third party check that *their* tree matches: derive
//! everything from a published, worthless mnemonic and print it. Same output,
//! same addresses.
//!
//! It takes no key material and touches no network.

use anyhow::Result;
use kaspa_addresses::Prefix;
use sha2::{Digest, Sha256};
use vault_core::binding::{binding_digest, OutputView, SpendView};
use vault_core::{Derivation, Scheme, COIN_TYPE, PURPOSE, XI_DOMAIN};

/// `PK.seed || PK.root` for `SLH-DSA-SHA2-128-24` at `m/…/3'/0'/0'` under the
/// published test mnemonic.
///
/// Written down rather than derived, because deriving it means 4,194,304
/// WOTS+ public keys. It is not trusted: `slh-wallet`'s
/// `derivation_vector_2_24::the_d1_vault_is_frozen` regenerates it from the
/// mnemonic and fails if it has moved. What it buys here is that the *emitter*
/// — the part a rebuild can change — is checked for this set at no cost.
const FROZEN_128_24_PK: &str =
    "021262d373be68ca87e2f64310675bcb06368ea04376b54a13af6265dcfcf656";

/// The BIP39 test vector everyone publishes. Deliberately worthless, and
/// deliberately not any mnemonic that holds funds.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// The same canonical spend the frozen binding-digest vector pins.
fn canonical_spend() -> SpendView {
    SpendView {
        tx_version: 1,
        outpoint_txid: core::array::from_fn(|i| i as u8),
        outpoint_index: 0,
        outputs: vec![
            OutputView { amount: 100_000_000, spk_version: 0, script: vec![0xaa; 35] },
            OutputView { amount: 899_000_000, spk_version: 0, script: vec![0xbb; 35] },
        ],
    }
}

pub fn cmd_artifacts() -> Result<()> {
    let m = kaspa_bip32::Mnemonic::new(TEST_MNEMONIC, kaspa_bip32::Language::English)
        .map_err(|e| anyhow::anyhow!("test mnemonic: {e}"))?;
    let seed = hex::decode(m.create_seed(None))?;

    println!("kaspa-vault canonical artifacts");
    println!();
    println!("Derived from the published BIP39 test mnemonic (\"abandon x11 about\"),");
    println!("so this output is reproducible by anyone. If your build prints something");
    println!("different, do not fund an address it generates.");
    println!();
    println!("These are NOT your addresses. Your own key material is neither read nor");
    println!("used here -- a build check cannot depend on a secret. To see the addresses");
    println!("your mnemonic derives, use `slh-address` or `addresses`.");
    println!();
    println!("rustc pinned        1.96.1   (rust-toolchain.toml)");
    println!("                    compare against `rustc --version`; a mismatch is not");
    println!("                    known to change the output, but is not assumed safe");
    println!();

    println!("-- derivation ------------------------------------------------");
    println!("  purpose           {PURPOSE}'");
    println!("  coin type         {COIN_TYPE}'");
    println!("  xi domain         {}", String::from_utf8_lossy(XI_DOMAIN));
    for scheme in Scheme::ALL {
        println!(
            "  scheme {}          {:<24} {}",
            scheme.index(),
            scheme.label(),
            Derivation { scheme: *scheme, ..Derivation::DEFAULT }.path(0, 0)
        );
    }
    println!();

    println!("-- binding digest (shared by every scheme) -------------------");
    let view = canonical_spend();
    println!("  canonical digest  {}", hex::encode(binding_digest(&view)?));
    println!();

    // Every SLH-DSA set, because each is a different address from the same
    // mnemonic and "the SLH-DSA address" is no longer a thing that exists.
    // `128-24` is skipped: reproducing it means 2^22 WOTS+ public keys, and a
    // verification aid nobody waits two minutes for is a verification aid
    // nobody runs. Its script is still covered — the emitted bytes do not
    // depend on the key, so `slh-address --set 128-24` reproduces it for
    // anyone who wants the address itself.
    for (scheme, set) in slh_wallet::SLH_SCHEMES {
        if set.hp >= 16 {
            // The key is skipped — 2^22 WOTS+ public keys is a hundred seconds,
            // and a verification aid nobody waits for is one nobody runs. The
            // *script* is not skipped: it is emitted from the public key this
            // derivation is frozen at, so the emitter is still checked here,
            // which is the half of the pipeline a build can actually change.
            let pk = slh_wallet::keygen::public_key_from_bytes(
                &hex::decode(FROZEN_128_24_PK).expect("frozen public key hex"),
            )?;
            let plan = slh_script::BlobPlan::for_params(set);
            let script =
                slh_script::build_vault_script(&pk, &plan, slh_wallet::CANONICAL_OUTPUT_COUNT)?
                    .script;
            println!("-- {} (scheme {}) --", set.name, scheme.index());
            println!("  key not derived   {} WOTS+ public keys, about 100 seconds;", set.leaves_per_tree());
            println!("                    run `kaspa-vault slh-address --set 128-24` for it");
            println!("  script from       the frozen public key below, not re-derived");
            println!("  PK.seed|PK.root   {FROZEN_128_24_PK}");
            println!("  witness blobs     {}", plan.blob_count());
            println!("  redeem script     {} bytes", script.len());
            println!("  script sha256     {}", sha256_hex(&script));
            println!();
            continue;
        }
        let slh_xi = Derivation { scheme: *scheme, ..Derivation::DEFAULT }.xi(&seed, 0, 0)?;
        let (slh_vault, _) = slh_wallet::SlhVault::from_xi(set, &slh_xi)?;
        let slh_script = slh_vault.redeem_script()?;
        println!("-- {} (scheme {}) --", set.name, scheme.index());
        println!("  xi                {}", hex::encode(slh_xi));
        println!("  PK.seed           {}", hex::encode(slh_vault.public_key.seed));
        println!("  PK.root           {}", hex::encode(slh_vault.public_key.root));
        println!("  witness blobs     {}", slh_vault.plan.blob_count());
        println!("  redeem script     {} bytes", slh_script.len());
        println!("  script sha256     {}", sha256_hex(&slh_script));
        println!("  address (tn10)    {}", slh_vault.address(Prefix::Testnet)?);
        println!("  address (mainnet) {}", slh_vault.address(Prefix::Mainnet)?);
        println!();
    }

    println!("-- LMS h=15 w=2 (scheme 1) --");
    eprintln!("(deriving the LMS vault: 32,768 one-time keys, a few seconds)");
    let lms_xi = Derivation { scheme: Scheme::LmsSha256, ..Derivation::DEFAULT }.xi(&seed, 0, 0)?;
    let (lms_vault, _) = lms_wallet::vault::Vault::from_xi(&lms_xi);
    let lms_script = lms_vault.redeem_script(0)?;
    println!("  xi                {}", hex::encode(lms_xi));
    println!("  I                 {}", hex::encode(lms_vault.public_key.id));
    println!("  T[1]              {}", hex::encode(lms_vault.public_key.root));
    println!("  redeem script     {} bytes (leaf 0)", lms_script.len());
    println!("  script sha256     {}", sha256_hex(&lms_script));
    println!("  leaf 0 (tn10)     {}", lms_vault.address(Prefix::Testnet, 0)?);
    println!("  leaf 0 (mainnet)  {}", lms_vault.address(Prefix::Mainnet, 0)?);
    println!();
    println!("Any difference above is a compatibility break: addresses funded under");
    println!("the other construction cannot be spent by this build.");
    Ok(())
}
