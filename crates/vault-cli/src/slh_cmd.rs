//! SLH-DSA vault commands.
//!
//! Separate from the LMS commands rather than folded into them, because almost
//! nothing is shared at the command level: there is one address instead of
//! 32,768, no leaf to select, no journal to consult, and no exhaustion budget
//! to report. Spending twice is ordinary rather than catastrophic.
//!
//! What *is* shared is the part that must not diverge — the binding digest, the
//! derivation table and the mass calculation — and that lives in `vault-core`.

use anyhow::{bail, ensure, Context, Result};
use kaspa_addresses::{Address, Prefix};
use kaspa_txscript::pay_to_script_hash_script;
use vault_node::NodeClient;
use slh_wallet::spend::{build_spend, preflight, VaultUtxo, PREFLIGHT_BUDGET_UNITS};
use slh_wallet::{params_for, vault_path, Scheme, SlhVault};
use vault_core::binding::OutputView;

use crate::{Args, Resolved};

/// Kaspa's smallest unit, per KAS.
const SOMPI: f64 = 100_000_000.0;

fn kas(sompi: u64) -> String {
    format!("{:.8}", sompi as f64 / SOMPI)
}

pub fn open_vault(resolved: &Resolved, scheme: Scheme) -> Result<SlhVault> {
    let (vault, _) = open_vault_with_key(resolved, scheme)?;
    Ok(vault)
}

fn open_vault_with_key(
    resolved: &Resolved,
    scheme: Scheme,
) -> Result<(SlhVault, slh_wallet::Keypair)> {
    let set = params_for(scheme)
        .ok_or_else(|| anyhow::anyhow!("{} is not an SLH-DSA scheme", scheme.label()))?;
    let derivation =
        vault_core::Derivation { scheme, ..vault_core::Derivation::DEFAULT };
    let xi = derivation
        .xi_from(&resolved.material, 0, resolved.key_index)
        .context("deriving the vault seed")?;

    // Key generation builds the whole top XMSS tree. Under `128-24` that is
    // 2^22 WOTS+ public keys and minutes of hashing, and silence there looks
    // like a hang rather than like work.
    if set.hp >= 16 {
        eprintln!(
            "generating a {} key: {} WOTS+ public keys for the top tree. This takes \
             minutes — it is the cost of d=1, not a fault.",
            set.name,
            set.leaves_per_tree()
        );
    }
    SlhVault::from_xi(set, &xi)
}

pub fn cmd_address(resolved: &Resolved, scheme: Scheme, prefix: Prefix) -> Result<()> {
    let vault = open_vault(resolved, scheme)?;
    let address = vault.address(prefix)?;
    let script = vault.redeem_script()?;
    let set = vault.p;

    println!("{} vault", set.name);
    println!("  derivation      {}", vault_path(scheme, 0, resolved.key_index));
    println!("  key from        {}", resolved.origin);
    println!("  network         {}", resolved.network);
    println!(
        "  parameters      n={} h={} d={} h'={} a={} k={} lg(w)={} m={}",
        set.n, set.h, set.d, set.hp, set.a, set.k, set.lgw, set.m
    );
    println!("  signature       {} bytes, {} elements", set.sig_len(), set.sig_elements());
    println!("  PK.seed         {}", hex::encode(vault.public_key.seed));
    println!("  PK.root         {}", hex::encode(vault.public_key.root));
    println!("  redeem script   {} bytes, {} witness blobs", script.len(), vault.plan.blob_count());
    println!();
    println!("  address         {address}");
    println!();
    println!("  One address, reusable. Change returns here, so the vault can be spent");
    println!("  again from the output of its own spend.");
    if set.sig_limit_log2 < 64 {
        // Converted to years rather than left as a power of two, because
        // "2^24" reads as a small number and the only question that matters is
        // whether a vault could plausibly reach it.
        let years = set.signature_limit() / 365;
        println!();
        println!(
            "  Limited to 2^{} signatures under one key, not 2^64 — counting every",
            set.sig_limit_log2
        );
        println!("  signature, including ones the chain never sees. At one spend a day");
        println!("  that is {years} years. Nothing here counts them or enforces the cap.");
    }
    Ok(())
}

async fn connect(network: &str) -> Result<NodeClient> {
    eprintln!("connecting to {network} via the public node network...");
    match network {
        "mainnet" => NodeClient::mainnet().await,
        _ => NodeClient::testnet10().await,
    }
}

/// Every UTXO at the vault address, largest first.
async fn vault_utxos(client: &NodeClient, address: &Address) -> Result<Vec<VaultUtxo>> {
    let found = client.utxos_for(std::slice::from_ref(address)).await?;
    let mut utxos: Vec<VaultUtxo> = found
        .get(&address.to_string())
        .map(|entries| {
            entries
                .iter()
                .map(|e| VaultUtxo { txid: e.txid, index: e.index, amount: e.amount })
                .collect()
        })
        .unwrap_or_default();
    utxos.sort_by_key(|u| std::cmp::Reverse(u.amount));
    Ok(utxos)
}

pub async fn cmd_balance(resolved: &Resolved, scheme: Scheme, prefix: Prefix) -> Result<()> {
    let vault = open_vault(resolved, scheme)?;
    let address = vault.address(prefix)?;

    let client = connect(&resolved.network).await?;
    let utxos = vault_utxos(&client, &address).await?;
    client.disconnect().await.ok();

    println!("vault {address}");
    if utxos.is_empty() {
        println!("  unfunded");
        return Ok(());
    }
    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    for u in &utxos {
        println!("  {} KAS  {}:{}", kas(u.amount), hex::encode(u.txid), u.index);
    }
    println!("  ---");
    println!("  {} KAS across {} UTXO(s)", kas(total), utxos.len());
    Ok(())
}

fn p2sh_or_pubkey_output(address: &Address, amount: u64) -> Result<OutputView> {
    let spk = kaspa_txscript::pay_to_address_script(address);
    Ok(OutputView { amount, spk_version: spk.version(), script: spk.script().to_vec() })
}

pub async fn cmd_spend(
    args: &Args,
    resolved: &Resolved,
    scheme: Scheme,
    prefix: Prefix,
) -> Result<()> {
    let destination = args
        .to
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--to is required: where should the coins go?"))?;
    let destination = Address::try_from(destination).context("--to is not a valid address")?;
    ensure!(
        destination.prefix == prefix,
        "--to is a {} address but the network is {}",
        destination.prefix,
        resolved.network
    );
    let amount = args
        .amount
        .ok_or_else(|| anyhow::anyhow!("--amount is required, in sompi"))?;

    let (vault, keypair) = open_vault_with_key(resolved, scheme)?;
    let address = vault.address(prefix)?;

    let client = connect(&resolved.network).await?;
    let utxos = vault_utxos(&client, &address).await?;
    ensure!(!utxos.is_empty(), "vault {address} holds no coins");

    // One input per spend: the redeem script is unrolled to a single input's
    // introspection, so consolidating several UTXOs would need a different
    // script.
    let utxo = utxos[0];
    if utxos.len() > 1 {
        eprintln!(
            "note: vault holds {} UTXOs; spending the largest ({} KAS). Each spend \
             consumes exactly one.",
            utxos.len(),
            kas(utxo.amount)
        );
    }

    let params = match resolved.network.as_str() {
        "mainnet" => kaspa_consensus_core::config::params::MAINNET_PARAMS,
        _ => kaspa_consensus_core::config::params::TESTNET_PARAMS,
    };

    // Discover the fee floor for this shape before choosing one.
    let change_spk = pay_to_script_hash_script(&vault.redeem_script()?);
    let provisional = vec![
        p2sh_or_pubkey_output(&destination, amount)?,
        OutputView {
            amount: utxo.amount.saturating_sub(amount) / 2,
            spk_version: change_spk.version(),
            script: change_spk.script().to_vec(),
        },
    ];
    let probe = preflight(&params, &vault, &utxo, 1, &provisional, PREFLIGHT_BUDGET_UNITS)?;

    let fee = match args.fee {
        Some(f) => f,
        None => probe.minimum_fee.saturating_mul(12) / 10, // 20% over the floor
    };
    ensure!(
        amount + fee < utxo.amount,
        "amount {} plus fee {} exceeds the {} KAS in the UTXO",
        kas(amount),
        kas(fee),
        kas(utxo.amount)
    );

    let change = utxo.amount - amount - fee;
    let outputs = vec![
        p2sh_or_pubkey_output(&destination, amount)?,
        OutputView {
            amount: change,
            spk_version: change_spk.version(),
            script: change_spk.script().to_vec(),
        },
    ];

    let spend = build_spend(&params, &vault, &keypair, &utxo, 1, &outputs)
        .context("building the spend")?;

    println!();
    println!("{} vault spend", vault.p.name);
    println!("  from            {address}");
    println!("  spending        {} KAS  ({}:{})", kas(utxo.amount), hex::encode(utxo.txid), utxo.index);
    println!("  to              {destination}");
    println!("  amount          {} KAS", kas(amount));
    println!("  change          {} KAS  (back to the vault)", kas(change));
    println!("  fee             {} KAS  (floor {} KAS)", kas(fee), kas(spend.report.minimum_fee));
    println!();
    println!("  size            {} bytes", spend.size());
    println!("  script units    {} (budget {} units)", spend.measured_script_units, spend.declared_budget_units);
    println!("  mass            {} normalized (block limit {})", spend.report.normalized_max_mass, params.block_mass_limits.compute);
    println!("                  compute {}, transient {} normalized, storage {}", spend.report.compute_mass, spend.report.normalized_transient_mass, spend.report.storage_mass);
    println!("  txid            {}", spend.txid());
    println!();
    println!("  Verified against the consensus script engine with the declared compute");
    println!("  budget enforced. Re-signing is safe if this is rejected.");

    if args.dry_run {
        println!();
        println!("dry run: not broadcast.");
        client.disconnect().await.ok();
        return Ok(());
    }

    if !args.yes {
        eprintln!();
        eprint!("broadcast? type yes to continue: ");
        use std::io::{BufRead, Write};
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if line.trim() != "yes" {
            client.disconnect().await.ok();
            bail!("aborted");
        }
    }

    let id = client.broadcast(&spend.tx).await;
    client.disconnect().await.ok();
    match id {
        Ok(id) => {
            println!();
            println!("broadcast: {id}");
            Ok(())
        }
        Err(e) => {
            bail!(
                "{e}\n\nNothing was consumed. The vault key is stateless, so the same spend \
                 can be rebuilt at a different fee and broadcast again."
            )
        }
    }
}
