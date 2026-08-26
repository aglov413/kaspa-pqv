//! Wallet behaviour: leaf discovery, spend construction, and the sign-once
//! invariant.

use anyhow::Result;
use kaspa_addresses::{Address, Prefix};
use kaspa_bip32::{Language, Mnemonic};
use lms_script::binding::OutputView;
use kaspa_consensus_core::config::params::{Params, TESTNET_PARAMS};
use lms_wallet::derivation::{derive_xi, Scheme};
use lms_wallet::journal::{sign_once, FileJournal, LeafId, MemoryJournal, SpendJournal, SpendRecord};
use lms_wallet::scan::UtxoSource;
use lms_wallet::spend::{build_spend, VaultUtxo};
use lms_wallet::vault::Vault;
use std::collections::HashMap;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

static TN_PARAMS: Params = TESTNET_PARAMS;

fn seed() -> Vec<u8> {
    let m = Mnemonic::new(TEST_MNEMONIC, Language::English).unwrap();
    hex::decode(m.create_seed(None)).unwrap()
}

/// h=15 keygen builds 32,768 leaf keys, so it is done once per test binary and
/// the signing key is rebuilt from the cached seed material on demand.
fn xi() -> &'static [u8; 32] {
    static XI: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    XI.get_or_init(|| derive_xi(&seed(), Scheme::LmsSha256, 0, 0).unwrap())
}

fn vault() -> (Vault, oxicrypt_lms::lms_sha256_m32_h15_w2::LmsSigningKey) {
    Vault::from_xi(xi())
}

/// A standard pay-to-script-hash output. Preflight rejects non-standard script
/// types, as a mempool would, so test outputs must be real scripts.
fn p2sh_output(amount: u64, tag: u8) -> OutputView {
    let spk = kaspa_txscript::pay_to_script_hash_script(&[tag; 40]);
    OutputView { amount, spk_version: spk.version(), script: spk.script().to_vec() }
}

fn outputs() -> Vec<OutputView> {
    vec![
        p2sh_output(900_000_000, 0xaa),
        p2sh_output(90_000_000, 0xbb),
    ]
}

fn utxo(leaf: u32) -> VaultUtxo {
    VaultUtxo { txid: [0x77; 32], index: 0, amount: 1_000_000_000, leaf }
}

/// Fixture UTXO source.
struct Balances(HashMap<String, u64>);

impl UtxoSource for Balances {
    fn balance(&self, address: &Address) -> Result<u64> {
        Ok(self.0.get(&address.to_string()).copied().unwrap_or(0))
    }
}

// ---------------------------------------------------------------------------
// Sign-once invariant
// ---------------------------------------------------------------------------

/// Re-signing the same digest returns the stored signature, so retrying a
/// broadcast is safe and idempotent.
#[test]
fn same_digest_reuses_the_stored_signature() {
    let (vault, mut sk) = vault();
    let mut journal = MemoryJournal::default();

    let first = build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &outputs(), &TN_PARAMS, 60).unwrap();
    assert!(!first.reused_stored_signature);

    let second = build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &outputs(), &TN_PARAMS, 60).unwrap();
    assert!(second.reused_stored_signature, "expected the stored signature");
    assert_eq!(first.signature_script, second.signature_script, "bytes must be identical");
    assert_eq!(first.digest, second.digest);
}

/// A different digest under the same leaf is refused. This is the fee-bump
/// case, and the one that loses funds if it succeeds.
#[test]
fn a_different_digest_under_the_same_leaf_is_refused() {
    let (vault, mut sk) = vault();
    let mut journal = MemoryJournal::default();

    build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &outputs(), &TN_PARAMS, 60).unwrap();

    // A fee bump: same destination, less change.
    let mut bumped = outputs();
    bumped[1].amount -= 1_000_000;

    let err = build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &bumped, &TN_PARAMS, 60)
        .expect_err("re-signing a different digest must be refused");
    let msg = err.to_string();
    assert!(msg.contains("already signed"), "unhelpful error: {msg}");
    assert!(msg.contains("Rebroadcast"), "error should point at the safe action: {msg}");
}

/// The record is durable before the signature is returned, so a crash cannot
/// leave an issued signature untracked.
#[test]
fn the_record_is_persisted_before_the_signature_is_returned() {
    let mut journal = MemoryJournal::default();
    let leaf = LeafId::new([0xab; 16], 3);

    let outcome = sign_once(&mut journal, leaf, [0x11; 32], || {
        // At this point the journal must not yet contain the record...
        Ok(vec![0xcd; 8])
    })
    .unwrap();

    // ...and by the time we hold the signature, it must.
    assert_eq!(outcome.signature(), &[0xcd; 8]);
    assert_eq!(journal.get(&leaf).unwrap().digest, [0x11; 32]);
}

/// A failing signer must not leave a record behind — otherwise a transient
/// error would permanently burn a leaf.
#[test]
fn a_failed_signature_does_not_burn_the_leaf() {
    let mut journal = MemoryJournal::default();
    let leaf = LeafId::new([0xab; 16], 0);

    let err = sign_once(&mut journal, leaf, [0x22; 32], || anyhow::bail!("hsm unavailable"));
    assert!(err.is_err());
    assert!(journal.get(&leaf).is_none(), "a failed signature burned the leaf");

    // The leaf is still usable.
    sign_once(&mut journal, leaf, [0x22; 32], || Ok(vec![1, 2, 3])).unwrap();
}

/// Different leaves and different vaults are independent.
#[test]
fn leaves_and_vaults_are_independent() {
    let mut journal = MemoryJournal::default();
    let a = LeafId::new([0x01; 16], 0);
    let b = LeafId::new([0x01; 16], 1);
    let c = LeafId::new([0x02; 16], 0);

    sign_once(&mut journal, a, [0xaa; 32], || Ok(vec![1])).unwrap();
    sign_once(&mut journal, b, [0xbb; 32], || Ok(vec![2])).unwrap();
    sign_once(&mut journal, c, [0xcc; 32], || Ok(vec![3])).unwrap();

    assert_eq!(journal.get(&a).unwrap().signature, vec![1]);
    assert_eq!(journal.get(&b).unwrap().signature, vec![2]);
    assert_eq!(journal.get(&c).unwrap().signature, vec![3]);
}

/// The file journal survives a restart — the whole point of persisting.
#[test]
fn file_journal_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("lms-journal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("spends.journal");
    let _ = std::fs::remove_file(&path);

    let leaf = LeafId::new([0x5a; 16], 9);
    {
        let mut journal = FileJournal::open(&path).unwrap();
        assert!(journal.is_empty());
        sign_once(&mut journal, leaf, [0x33; 32], || Ok(vec![0xde, 0xad])).unwrap();
    }

    // A fresh process reopening the file must see the burned leaf.
    let mut reopened = FileJournal::open(&path).unwrap();
    assert_eq!(reopened.len(), 1);
    assert_eq!(reopened.get(&leaf).unwrap().signature, vec![0xde, 0xad]);

    assert!(
        sign_once(&mut reopened, leaf, [0x44; 32], || Ok(vec![0xbe, 0xef])).is_err(),
        "a restart must not forget that a leaf has signed"
    );

    std::fs::remove_file(&path).ok();
}

/// A corrupted journal must refuse to load rather than silently reading as
/// "this leaf never signed", which is the direction that loses funds.
#[test]
fn a_corrupted_journal_refuses_to_load() {
    let dir = std::env::temp_dir().join(format!("lms-journal-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("corrupt.journal");
    std::fs::write(&path, "not-a-valid-record\n").unwrap();

    let err = FileJournal::open(&path).expect_err("corrupt journal must not load");
    assert!(err.to_string().contains("unreadable"), "unhelpful error: {err}");

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// Spend construction and scanning
// ---------------------------------------------------------------------------

/// The redeem script is unrolled to a fixed output count, so a spend of the
/// wrong shape is refused before signing rather than producing an unspendable
/// transaction.
#[test]
fn a_wrong_output_count_is_refused_before_signing() {
    let (vault, mut sk) = vault();
    let mut journal = MemoryJournal::default();

    let mut one = outputs();
    one.truncate(1);
    assert!(build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &one, &TN_PARAMS, 60).is_err());

    // Crucially, the leaf was not burned by the rejected attempt.
    assert!(journal.get(&LeafId::new(vault.public_key.id, 0)).is_none());
    build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &outputs(), &TN_PARAMS, 60).unwrap();
}

/// Spending more than the UTXO holds is refused.
#[test]
fn overspending_is_refused() {
    let (vault, mut sk) = vault();
    let mut journal = MemoryJournal::default();

    let mut too_much = outputs();
    too_much[0].amount = 2_000_000_000;
    assert!(build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &too_much, &TN_PARAMS, 60).is_err());
}

/// Scanning finds the funded leaf, which is how a wallet learns where it is in
/// the tree.
#[test]
fn scanning_finds_the_live_leaf() {
    let (vault, _) = vault();
    let funded_leaf = 7u32;
    let address = vault.address(Prefix::Mainnet, funded_leaf).unwrap();

    let source = Balances(HashMap::from([(address.to_string(), 500_000_000)]));
    let result = lms_wallet::scan::scan_range(&source, &vault, Prefix::Mainnet, 0, 64).unwrap();

    assert_eq!(result.funded.len(), 1);
    assert_eq!(result.live_leaf().unwrap().leaf, funded_leaf);
    assert_eq!(result.total(), 500_000_000);
    assert!(!result.is_ambiguous());
}

/// An empty vault scans clean.
#[test]
fn an_unfunded_vault_has_no_live_leaf() {
    let (vault, _) = vault();
    let source = Balances(HashMap::new());
    let result = lms_wallet::scan::scan_range(&source, &vault, Prefix::Mainnet, 0, 64).unwrap();
    assert!(result.live_leaf().is_none());
    assert_eq!(result.total(), 0);
}

/// Two funded leaves are surfaced rather than silently resolved: it usually
/// means someone paid into an address the vault has already moved past, and
/// that leaf's one-time key may already have signed.
#[test]
fn multiple_funded_leaves_are_flagged() {
    let (vault, _) = vault();
    let source = Balances(HashMap::from([
        (vault.address(Prefix::Mainnet, 2).unwrap().to_string(), 100),
        (vault.address(Prefix::Mainnet, 5).unwrap().to_string(), 200),
    ]));

    let result = lms_wallet::scan::scan_range(&source, &vault, Prefix::Mainnet, 0, 64).unwrap();
    assert!(result.is_ambiguous());
    assert_eq!(result.live_leaf().unwrap().leaf, 2, "lowest funded leaf is the live one");
    assert_eq!(result.total(), 300);
}

/// A record round-trips through the journal unchanged.
#[test]
fn records_round_trip() {
    let mut journal = MemoryJournal::default();
    let record = SpendRecord {
        leaf: LeafId::new([0x11; 16], 4),
        digest: [0x22; 32],
        signature: vec![0x33; 64],
    };
    journal.put(record.clone()).unwrap();
    assert_eq!(journal.get(&record.leaf).unwrap(), record);
}

// ---------------------------------------------------------------------------
// Leaf budget and migration
// ---------------------------------------------------------------------------

use lms_wallet::spend::plan_migration;
use lms_wallet::vault::{
    change_target, BudgetStatus, ChangeTarget, LeafBudget, LEAF_CRITICAL_REMAINING,
    LEAF_WARNING_THRESHOLD, PARAMS,
};

fn budget(leaf: u32) -> LeafBudget {
    LeafBudget { leaf, total: PARAMS.leaf_count(), remaining: PARAMS.leaf_count() - leaf - 1 }
}

/// h=15 gives 32,768 one-time keys.
#[test]
fn vault_holds_the_expected_number_of_leaves() {
    assert_eq!(PARAMS.leaf_count(), 32_768);
    assert_eq!(PARAMS.h, 15);
}

/// The status ladder, at each boundary.
#[test]
fn budget_status_crosses_its_thresholds() {
    assert_eq!(budget(0).status(), BudgetStatus::Healthy);
    assert_eq!(budget(LEAF_WARNING_THRESHOLD - 1).status(), BudgetStatus::Healthy);
    assert_eq!(budget(LEAF_WARNING_THRESHOLD).status(), BudgetStatus::Approaching);

    let critical_leaf = PARAMS.leaf_count() - LEAF_CRITICAL_REMAINING - 1;
    assert_eq!(budget(critical_leaf).status(), BudgetStatus::Critical);
    assert_eq!(budget(PARAMS.leaf_count() - 1).status(), BudgetStatus::Exhausted);
}

/// Only a healthy vault stays quiet.
#[test]
fn migration_is_prompted_once_the_threshold_is_passed() {
    assert!(!budget(0).should_prompt_migration());
    assert!(budget(LEAF_WARNING_THRESHOLD).should_prompt_migration());
    assert!(budget(PARAMS.leaf_count() - 1).should_prompt_migration());
}

/// The summary a user sees after a spend says the number and, past the
/// threshold, what to do about it.
#[test]
fn budget_summary_names_the_action() {
    let healthy = budget(0).summary();
    assert!(healthy.contains("32767 of 32768"), "{healthy}");

    let approaching = budget(LEAF_WARNING_THRESHOLD).summary();
    assert!(approaching.contains("migrating"), "{approaching}");

    let exhausted = budget(PARAMS.leaf_count() - 1).summary();
    assert!(exhausted.contains("exhausted"), "{exhausted}");
}

/// Change advances the vault by one leaf, until there is no next leaf.
#[test]
fn change_advances_the_vault_then_rolls_over() {
    let n = PARAMS.leaf_count();

    assert_eq!(change_target(0, 0, n), ChangeTarget::NextLeaf { key_index: 0, leaf: 1 });
    assert_eq!(change_target(3, 500, n), ChangeTarget::NextLeaf { key_index: 3, leaf: 501 });
    assert!(!change_target(0, 0, n).is_migration());

    // The last leaf has no successor, so change starts the next vault.
    let rolled = change_target(7, n - 1, n);
    assert_eq!(rolled, ChangeTarget::NextVault { key_index: 8, leaf: 0 });
    assert!(rolled.is_migration());
}

/// A spend reports its budget and where change should go.
#[test]
fn a_spend_reports_the_budget_and_change_target() {
    let (vault, mut sk) = vault();
    let mut journal = MemoryJournal::default();

    let signed =
        build_spend(&mut journal, &vault, &mut sk, &utxo(0), 4, 1, &outputs(), &TN_PARAMS, 60).unwrap();

    assert_eq!(signed.budget.leaf, 0);
    assert_eq!(signed.budget.total, 32_768);
    assert_eq!(signed.budget.remaining, 32_767);
    assert_eq!(signed.budget.status(), BudgetStatus::Healthy);
    assert_eq!(signed.change_target, ChangeTarget::NextLeaf { key_index: 4, leaf: 1 });
}

/// A migration is available at any point, not only at exhaustion — a user who
/// wants a fresh vault early can take one.
#[test]
fn a_migration_can_be_planned_early() {
    let (vault, _) = vault();
    let plan = plan_migration(&vault, 2, &utxo(0), 5_000).unwrap();

    assert_eq!(plan.from_key_index, 2);
    assert_eq!(plan.leaf, 0);
    assert_eq!(plan.amount, 1_000_000_000 - 5_000);
    // Mid-vault, change still advances within the same vault.
    assert_eq!(plan.to_key_index, 2);
}

/// At the last leaf, the migration target is the next key index.
#[test]
fn migration_from_the_last_leaf_targets_the_next_vault() {
    let (vault, _) = vault();
    let last = PARAMS.leaf_count() - 1;
    let plan = plan_migration(&vault, 2, &utxo(last), 5_000).unwrap();

    assert_eq!(plan.from_key_index, 2);
    assert_eq!(plan.to_key_index, 3, "an exhausted vault must roll to the next key index");
}

/// A fee larger than the balance is refused rather than underflowing.
#[test]
fn a_migration_fee_cannot_exceed_the_balance() {
    let (vault, _) = vault();
    assert!(plan_migration(&vault, 0, &utxo(0), 2_000_000_000).is_err());
}

/// A bounded scan from a journal hint is what routine operation uses — the
/// full 32,768-leaf enumeration is reserved for recovery.
#[test]
fn scanning_from_a_hint_finds_the_next_live_leaf() {
    use lms_wallet::scan::{scan_from_hint, DEFAULT_SCAN_WINDOW};

    let (vault, _) = vault();
    let live = 41u32;
    let source = Balances(HashMap::from([(
        vault.address(Prefix::Mainnet, live).unwrap().to_string(),
        7_500,
    )]));

    // The journal says leaf 40 signed, so scanning starts there.
    let found = scan_from_hint(&source, &vault, Prefix::Mainnet, 40, DEFAULT_SCAN_WINDOW).unwrap();
    assert_eq!(found.live_leaf().unwrap().leaf, live);

    // A hint past the live leaf misses it, which is why the window exists and
    // why recovery falls back to a full scan.
    let missed = scan_from_hint(&source, &vault, Prefix::Mainnet, 100, DEFAULT_SCAN_WINDOW).unwrap();
    assert!(missed.live_leaf().is_none());
}

// ---------------------------------------------------------------------------
// Preflight: everything that could reject a transaction, checked before the
// one-time key signs.
// ---------------------------------------------------------------------------

use lms_wallet::preflight::preflight;

/// A canonical spend passes preflight and reports what it will cost.
#[test]
fn preflight_reports_the_real_masses() {
    let (vault, _) = vault();
    let report = preflight(&TN_PARAMS, &vault, &utxo(0), 1, &outputs(), 60).expect("preflight");

    println!("{}", report.summary());
    println!(
        "  ~{} spends per block",
        report.spends_per_block(TN_PARAMS.block_mass_limits.compute)
    );

    // Transient mass dominates for a vault spend: the script is large but
    // cheap to verify, so bytes cost more than computation.
    assert!(
        report.normalized_transient_mass > report.compute_mass,
        "expected transient mass to dominate (transient {}, compute {})",
        report.normalized_transient_mass,
        report.compute_mass
    );
    assert_eq!(report.normalized_max_mass, report.normalized_transient_mass);
    assert!(report.fee >= report.minimum_fee);
}

/// An underpaid spend is refused BEFORE signing — otherwise raising the fee
/// afterwards would need the one-time key to sign twice.
#[test]
fn an_underpaid_spend_is_refused_before_signing() {
    let (vault, mut sk) = vault();
    let mut journal = MemoryJournal::default();

    // Leave almost nothing as fee.
    let starved = vec![p2sh_output(999_999_000, 0xaa), p2sh_output(900, 0xbb)];

    let err = build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &starved, &TN_PARAMS, 60)
        .expect_err("an underpaid spend must be refused");
    let msg = err.to_string();
    assert!(msg.contains("below the"), "{msg}");
    assert!(msg.contains("cannot sign twice"), "the error should explain why: {msg}");

    // And crucially, the leaf was NOT burned by the rejected attempt.
    assert!(
        journal.get(&LeafId::new(vault.public_key.id, 0)).is_none(),
        "a rejected spend burned the one-time key"
    );
    build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &outputs(), &TN_PARAMS, 60).unwrap();
}

/// Non-standard output scripts are refused. A mempool would drop the
/// transaction, and by then the leaf would be spent.
#[test]
fn non_standard_outputs_are_refused_before_signing() {
    let (vault, mut sk) = vault();
    let mut journal = MemoryJournal::default();

    let junk = vec![
        OutputView { amount: 900_000_000, spk_version: 0, script: vec![0xaa; 34] },
        p2sh_output(90_000_000, 0xbb),
    ];

    let err = build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &junk, &TN_PARAMS, 60)
        .expect_err("a non-standard output must be refused");
    assert!(err.to_string().contains("standard script type"), "{err}");
    assert!(journal.get(&LeafId::new(vault.public_key.id, 0)).is_none());
}

/// A tiny change output inflates storage mass past what a block can hold.
/// KIP-9 charges C * (1/output), so dust is enormously expensive.
#[test]
fn a_dust_change_output_is_refused() {
    let (vault, _) = vault();
    let dusty = vec![p2sh_output(994_000_000, 0xaa), p2sh_output(1_000, 0xbb)];

    let err = preflight(&TN_PARAMS, &vault, &utxo(0), 1, &dusty, 60)
        .expect_err("a dust change output must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("storage mass") || msg.contains("never be included"),
        "expected a storage-mass rejection, got: {msg}"
    );
}

/// A spend that passes preflight carries the report through to the caller.
#[test]
fn a_signed_spend_carries_its_preflight_report() {
    let (vault, mut sk) = vault();
    let mut journal = MemoryJournal::default();

    let signed =
        build_spend(&mut journal, &vault, &mut sk, &utxo(0), 0, 1, &outputs(), &TN_PARAMS, 60)
            .unwrap();

    assert!(signed.preflight.fee >= signed.preflight.minimum_fee);
    assert!(signed.preflight.size > 20_000, "a vault spend is a large transaction");
}

// ---------------------------------------------------------------------------
// Positioning the signing key at an arbitrary leaf.
//
// This path had no coverage and shipped broken: it used oxicrypt's gated
// `from_private_key`, which fails until the module's power-up self-tests have
// run, while every other call site used an `_internal` variant. Every test
// above obtains its signing key from `Vault::from_xi` at leaf 0, so nothing
// exercised it.
// ---------------------------------------------------------------------------

use lms_wallet::vault::{run_self_tests, signing_key_at};

/// The self-tests run, and running them twice is fine.
#[test]
fn crypto_self_tests_pass_and_are_idempotent() {
    run_self_tests().expect("LMS known-answer tests must pass");
    run_self_tests().expect("a second call must be a no-op, not an error");
}

/// A positioned key lands on the requested leaf without burning the ones
/// before it.
#[test]
fn a_signing_key_can_be_positioned_at_a_leaf() {
    for leaf in [0u32, 1, 9, 1_000, PARAMS.leaf_count() - 1] {
        let key = signing_key_at(xi(), leaf)
            .unwrap_or_else(|e| panic!("positioning at leaf {leaf} failed: {e}"));
        assert_eq!(key.leaf_index(), leaf);
    }
}

/// Out-of-range leaves are refused rather than wrapping.
#[test]
fn positioning_past_the_last_leaf_is_refused() {
    assert!(signing_key_at(xi(), PARAMS.leaf_count()).is_err());
}

/// A positioned key signs the same bytes the sequentially-advanced key would.
///
/// This is the property that makes positioning safe: skipping ahead must not
/// change what a leaf produces, or a vault restored by positioning would sign
/// differently from one advanced step by step.
#[test]
fn a_positioned_key_signs_identically_to_an_advanced_one() {
    let digest = [0x5au8; 32];
    let target = 3u32;

    // Advance sequentially, burning the leaves before the target.
    let (_, mut advanced) = vault();
    for _ in 0..target {
        advanced.sign_internal(&[0u8; 32]).unwrap();
    }
    let from_advance = advanced.sign_internal(&digest).unwrap();

    // Jump straight there.
    let mut positioned = signing_key_at(xi(), target).unwrap();
    let from_position = positioned.sign_internal(&digest).unwrap();

    assert_eq!(
        from_advance.to_vec(),
        from_position.to_vec(),
        "a positioned key must produce the same signature as an advanced one"
    );
}

/// And the signature a positioned key produces actually verifies against the
/// vault's public key.
#[test]
fn a_positioned_key_produces_a_verifiable_signature() {
    use oxicrypt_lms::lms_sha256_m32_h15_w2 as lms;

    let (vault, _) = vault();
    let digest = [0xc3u8; 32];
    let leaf = 12u32;

    let mut key = signing_key_at(xi(), leaf).unwrap();
    let signature = key.sign_internal(&digest).unwrap();

    let public_key = key.public_key();
    assert!(
        lms::verify_internal(&public_key, &digest, &signature),
        "a positioned key produced a signature that does not verify"
    );

    // And it is the same vault the wallet derives.
    assert_eq!(&public_key[8..24], &vault.public_key.id[..]);
}
