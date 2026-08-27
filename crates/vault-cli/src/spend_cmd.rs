//! The `spend` command.
//!
//! Ordering is the whole design here. A one-time key signs once, so every
//! check that could reject the transaction runs *before* the signature exists,
//! and the journal record is durable before the signature reaches this code.
//! After signing there is no way to change the fee, the destination, or
//! anything else the binding digest covers.

use anyhow::{bail, ensure, Context, Result};
use kaspa_addresses::{Address, Prefix};
use kaspa_consensus_core::config::params::Params;
use kaspa_txscript::pay_to_address_script;
use vault_node::NodeClient;
use lms_script::binding::OutputView;
use lms_wallet::journal::{FileJournal, LeafId, SpendJournal};
use lms_wallet::preflight::estimate;
use lms_wallet::spend::{build_spend, VaultUtxo};
use lms_wallet::tx::assemble;
use lms_wallet::vault::{signing_key_at, Vault};

/// Compute budget declared while sizing. The real value is measured during
/// assembly; this only has to be in the right ballpark for the mass estimate.
const SIZING_BUDGET_UNITS: u16 = 60;

/// Fee margin over the relay minimum, in percent.
///
/// A vault spend cannot be fee-bumped — bumping changes the binding digest and
/// the one-time key cannot sign again — so the fee is set with headroom rather
/// than at the floor.
const FEE_MARGIN_PERCENT: u64 = 20;

pub struct SpendRequest<'a> {
    pub vault: &'a Vault,
    pub xi: &'a [u8; 32],
    pub key_index: u32,
    pub prefix: Prefix,
    pub params: &'a Params,
    pub destination: Address,
    pub amount: u64,
    pub fee: Option<u64>,
    pub journal_path: String,
    pub confirmed: bool,
    pub dry_run: bool,
}

fn to_output(address: &Address, amount: u64) -> OutputView {
    let spk = pay_to_address_script(address);
    OutputView { amount, spk_version: spk.version(), script: spk.script().to_vec() }
}

/// Find the funded leaf and the UTXO sitting on it.
async fn locate_funds(
    client: &NodeClient,
    vault: &Vault,
    prefix: Prefix,
    window: u32,
) -> Result<(u32, VaultUtxo)> {
    let addresses: Vec<Address> =
        (0..window.min(vault.leaf_count())).map(|l| vault.address(prefix, l)).collect::<Result<_>>()?;

    let utxos = client.utxos_for(&addresses).await?;

    let mut found = Vec::new();
    for (leaf, address) in addresses.iter().enumerate() {
        if let Some(entries) = utxos.get(&address.to_string()) {
            if !entries.is_empty() {
                found.push((leaf as u32, entries.clone()));
            }
        }
    }

    let (leaf, entries) = match found.len() {
        0 => bail!("no funded leaf found in the first {window} addresses"),
        1 => found.into_iter().next().expect("checked"),
        n => bail!(
            "{n} funded leaves ({:?}). A vault spends one leaf at a time; resolve this \
             before spending, because a payment that arrived at an already-advanced \
             address may sit on a one-time key that has already signed.",
            found.iter().map(|(l, _)| *l).collect::<Vec<_>>()
        ),
    };

    ensure!(
        entries.len() == 1,
        "leaf {leaf} holds {} UTXOs; a vault spend consumes exactly one input",
        entries.len()
    );
    let entry = &entries[0];

    Ok((
        leaf,
        VaultUtxo { txid: entry.txid, index: entry.index, amount: entry.amount, leaf },
    ))
}

pub async fn run(req: SpendRequest<'_>, client: &NodeClient) -> Result<()> {
    let (leaf, utxo) = locate_funds(client, req.vault, req.prefix, 64).await?;
    eprintln!("found {} sompi at leaf {leaf}", utxo.amount);

    let change_target = req.vault.change_target(req.key_index, leaf);
    ensure!(
        !change_target.is_migration(),
        "this vault's last leaf is funded; use the migration path so change starts \
         key index {}",
        change_target.key_index()
    );
    let change_address = req.vault.address(req.prefix, change_target.leaf())?;

    // Decide the fee before anything signs. `estimate` reports the relay floor
    // without rejecting an underpaid shape, which is what makes this possible.
    let provisional = vec![
        to_output(&req.destination, req.amount),
        to_output(&change_address, utxo.amount.saturating_sub(req.amount)),
    ];
    let probe = estimate(req.params, req.vault, &utxo, 1, &provisional, SIZING_BUDGET_UNITS)?;

    let fee = match req.fee {
        Some(f) => f,
        None => probe.minimum_fee * (100 + FEE_MARGIN_PERCENT) / 100,
    };

    ensure!(
        req.amount + fee <= utxo.amount,
        "amount {} plus fee {fee} exceeds the {} available",
        req.amount,
        utxo.amount
    );
    let change = utxo.amount - req.amount - fee;

    let outputs = vec![to_output(&req.destination, req.amount), to_output(&change_address, change)];
    let report = estimate(req.params, req.vault, &utxo, 1, &outputs, SIZING_BUDGET_UNITS)?;
    let budget = req.vault.budget_after(leaf);

    println!();
    println!("  spend from   leaf {leaf}  ({})", req.vault.address(req.prefix, leaf)?);
    println!("  to           {}", req.destination);
    println!("  amount       {} sompi", req.amount);
    println!("  change to    leaf {}  ({change_address})", change_target.leaf());
    println!("  change       {change} sompi");
    println!("  fee          {fee} sompi (relay minimum {})", report.minimum_fee);
    println!("  size         {} bytes, mass {}", report.size, report.normalized_max_mass);
    println!();
    println!("  This consumes one-time key {leaf}, permanently. {}", budget.summary());
    if budget.should_prompt_migration() {
        println!("  {:?}: plan a migration to key index {}.", budget.status(), req.key_index + 1);
    }
    println!();

    if !req.confirmed {
        bail!(
            "not confirmed. Re-run with --yes once the details above are correct. \
             Signing burns one-time key {leaf} whether or not the transaction confirms, \
             and the fee cannot be raised afterwards."
        );
    }

    // Everything below this line is irreversible.
    let mut journal =
        FileJournal::open(&req.journal_path).context("opening the spend journal")?;
    let already = journal.get(&LeafId::new(req.vault.public_key.id, leaf)).is_some();
    if already {
        eprintln!("leaf {leaf} has signed before; reusing the stored signature");
    }

    eprintln!("positioning signing key at leaf {leaf} (a few seconds)...");
    let mut signing_key = signing_key_at(req.xi, leaf)?;

    let signed = build_spend(
        &mut journal,
        req.vault,
        &mut signing_key,
        &utxo,
        req.key_index,
        1,
        &outputs,
        req.params,
        SIZING_BUDGET_UNITS,
    )?;

    let assembled = assemble(&signed, &utxo, 1, &outputs)?;
    println!(
        "signed. digest {}, {} script units, {} compute-budget units",
        hex::encode(signed.digest),
        assembled.measured_script_units,
        assembled.declared_budget_units
    );

    if req.dry_run {
        println!("dry run: not broadcasting. The signature is recorded in {}.", req.journal_path);
        println!("Re-running with the same amount will reuse it rather than sign again.");
        return Ok(());
    }

    let txid = client.broadcast(&assembled.tx).await?;
    println!("broadcast {txid}");
    println!();
    println!("{}", signed.budget.summary());
    Ok(())
}
