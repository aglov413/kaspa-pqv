//! `kaspa-vault` — command-line wallet for post-quantum LMS vaults.
//!
//! ```text
//! kaspa-vault addresses  (--mnemonic <words> | --key <xprv|seed|privkey>) [options]
//! kaspa-vault balance    (--mnemonic <words> | --key <xprv|seed|privkey>) [options]
//! kaspa-vault spend       --to <address> --amount <sompi> [--fee N] [--yes] [--dry-run]
//! kaspa-vault init-env
//! kaspa-vault info
//!
//! Credentials can come from `.env` instead of the command line, which keeps
//! them out of shell history and out of `ps` output. See [`env`].
//! ```
//!
//! Spending is deliberately absent from this first cut. The signing path is
//! built and tested, but wiring it to a command means a mistyped argument can
//! burn a one-time key — so it lands together with the confirmation flow rather
//! than before it.

mod artifacts_cmd;
mod env;
mod slh_cmd;
mod spend_cmd;

use anyhow::{bail, ensure, Context, Result};
use env::{
    EnvFile, ENV_KEY, ENV_KEY_INDEX, ENV_KEY_SLH, ENV_MNEMONIC, ENV_MNEMONIC_SLH, ENV_NETWORK,
    ENV_TEMPLATE,
};
use kaspa_addresses::Prefix;
use vault_node::NodeClient;
use lms_wallet::derivation::{vault_path, Derivation, Scheme};
use lms_wallet::key_material::KeyMaterial;
use lms_wallet::vault::{Vault, LEAF_WARNING_THRESHOLD, PARAMS};

const DEFAULT_ADDRESS_COUNT: u32 = 8;

pub struct Args {
    pub command: String,
    pub mnemonic: Option<String>,
    pub key: Option<String>,
    pub key_index: Option<u32>,
    pub count: u32,
    pub network: Option<String>,
    pub env_file: Option<String>,
    pub to: Option<String>,
    pub amount: Option<u64>,
    pub fee: Option<u64>,
    pub journal: Option<String>,
    pub yes: bool,
    pub dry_run: bool,
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());

    let mut parsed = Args {
        command,
        mnemonic: None,
        key: None,
        key_index: None,
        count: DEFAULT_ADDRESS_COUNT,
        network: None,
        env_file: None,
        to: None,
        amount: None,
        fee: None,
        journal: None,
        yes: false,
        dry_run: false,
    };

    while let Some(flag) = args.next() {
        let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--mnemonic" => parsed.mnemonic = Some(value()?),
            "--key" => parsed.key = Some(value()?),
            "--key-index" => parsed.key_index = Some(value()?.parse().context("--key-index")?),
            "--count" => parsed.count = value()?.parse().context("--count")?,
            "--network" => parsed.network = Some(value()?),
            "--env-file" => parsed.env_file = Some(value()?),
            "--to" => parsed.to = Some(value()?),
            "--amount" => parsed.amount = Some(value()?.parse().context("--amount")?),
            "--fee" => parsed.fee = Some(value()?.parse().context("--fee")?),
            "--journal" => parsed.journal = Some(value()?),
            "--yes" => parsed.yes = true,
            "--dry-run" => parsed.dry_run = true,
            other => bail!("unrecognised flag: {other}"),
        }
    }
    Ok(parsed)
}

fn prefix_for(network: &str) -> Result<Prefix> {
    match network {
        "tn10" | "testnet" | "testnet-10" => Ok(Prefix::Testnet),
        "mainnet" => Ok(Prefix::Mainnet),
        other => bail!("unknown network {other:?}; use tn10 or mainnet"),
    }
}

/// Everything a command needs, after flags, environment and `.env` are merged.
pub struct Resolved {
    pub material: KeyMaterial,
    pub origin: String,
    pub key_index: u32,
    pub network: String,
}

/// Which environment variables hold key material for a scheme.
///
/// A scheme-specific variable wins if it is set; otherwise both schemes fall
/// back to the shared pair, which is the intended production shape — one
/// mnemonic, one backup, every scheme derived from it.
fn key_vars(scheme: Scheme, env: &EnvFile) -> (&'static str, &'static str) {
    match scheme {
        Scheme::SlhDsaSha2_128s
            if env.get(ENV_MNEMONIC_SLH).is_some() || env.get(ENV_KEY_SLH).is_some() =>
        {
            (ENV_MNEMONIC_SLH, ENV_KEY_SLH)
        }
        _ => (ENV_MNEMONIC, ENV_KEY),
    }
}

/// Merge the three sources. A flag always wins; the file never overrides
/// something set deliberately in the environment.
fn resolve(args: &Args, env: &EnvFile, scheme: Scheme) -> Result<Resolved> {
    let (env_mnemonic, env_key) = key_vars(scheme, env);
    let mnemonic = args.mnemonic.clone().or_else(|| env.get(env_mnemonic));
    let key = args.key.clone().or_else(|| env.get(env_key));

    let (material, origin) = match (mnemonic, key) {
        (Some(_), Some(_)) => bail!(
            "both a mnemonic and a key were supplied. Give exactly one, and check \
             {env_mnemonic} / {env_key} if you did not pass both on the command line."
        ),
        (Some(words), None) => {
            let origin = if args.mnemonic.is_some() {
                "--mnemonic".to_string()
            } else {
                format!("{env_mnemonic} ({})", env.source_of(env_mnemonic).unwrap_or("environment"))
            };
            (KeyMaterial::from_mnemonic(&words)?, origin)
        }
        (None, Some(k)) => {
            let origin = if args.key.is_some() {
                "--key".to_string()
            } else {
                format!("{env_key} ({})", env.source_of(env_key).unwrap_or("environment"))
            };
            (KeyMaterial::parse(&k)?, origin)
        }
        (None, None) => bail!(
            "no key supplied. Pass --mnemonic or --key, or set {env_mnemonic} / \
             {env_key} in a .env file (run `kaspa-vault init-env` to create one)."
        ),
    };

    let key_index = match args.key_index {
        Some(i) => i,
        None => match env.get(ENV_KEY_INDEX) {
            Some(v) => v.parse().with_context(|| format!("{ENV_KEY_INDEX}={v:?}"))?,
            None => 0,
        },
    };

    let network = args
        .network
        .clone()
        .or_else(|| env.get(ENV_NETWORK))
        .unwrap_or_else(|| "tn10".to_string());

    Ok(Resolved { material, origin, key_index, network })
}

/// Derive a vault, reporting progress — h=15 key generation takes seconds and
/// silence looks like a hang.
fn open_vault(resolved: &Resolved) -> Result<Vault> {
    let material = &resolved.material;

    eprintln!("key source: {} from {}", material.describe(), resolved.origin);
    if let Some(warning) = material.warning() {
        eprintln!();
        eprintln!("  WARNING: {warning}");
        eprintln!();
    }
    if !material.is_quantum_isolated() {
        eprintln!(
            "  This vault is NOT isolated from classical keys. Do not use it for \
             post-quantum storage unless the key was generated solely for this purpose."
        );
        eprintln!();
    }

    let xi = Derivation::DEFAULT.xi_from(material, 0, resolved.key_index)?;

    eprintln!(
        "deriving vault at {} ({} one-time keys, this takes a few seconds)...",
        vault_path(Scheme::LmsSha256, 0, resolved.key_index),
        PARAMS.leaf_count()
    );
    let (vault, _signing_key) = Vault::from_xi(&xi);
    Ok(vault)
}

fn cmd_info() {
    println!("Kaspa post-quantum vault");
    println!();
    println!("  signature scheme   LMS_SHA256_M32_H15 / LMOTS_SHA256_N32_W2");
    println!("                     RFC 8554, NIST SP 800-208");
    println!("  one-time keys      {} per vault", PARAMS.leaf_count());
    println!("  warning threshold  {LEAF_WARNING_THRESHOLD} leaves used");
    println!("  derivation         {}", vault_path(Scheme::LmsSha256, 0, 0));
    println!("  address type       P2SH (indistinguishable on-chain from any other P2SH)");
    println!();
    println!("  Each leaf signs exactly once. Spending advances the vault to the next");
    println!("  leaf, so the live leaf is whichever address holds coins.");
}

fn cmd_addresses(args: &Args, env: &EnvFile) -> Result<()> {
    let resolved = resolve(args, env, Scheme::LmsSha256)?;
    let vault = open_vault(&resolved)?;
    let prefix = prefix_for(&resolved.network)?;

    println!("vault {} (key index {})", hex::encode(vault.public_key.id), resolved.key_index);
    for leaf in 0..args.count.min(vault.leaf_count()) {
        println!("  leaf {leaf:>5}  {}", vault.address(prefix, leaf)?);
    }
    Ok(())
}

async fn cmd_balance(args: &Args, env: &EnvFile) -> Result<()> {
    let resolved = resolve(args, env, Scheme::LmsSha256)?;
    let vault = open_vault(&resolved)?;
    let prefix = prefix_for(&resolved.network)?;

    let addresses: Vec<_> = (0..args.count.min(vault.leaf_count()))
        .map(|leaf| vault.address(prefix, leaf))
        .collect::<Result<_>>()?;

    eprintln!("connecting to {} via the public node network...", resolved.network);
    let client = match resolved.network.as_str() {
        "mainnet" => NodeClient::mainnet().await?,
        _ => NodeClient::testnet10().await?,
    };

    let utxos = client.utxos_for(&addresses).await?;
    client.disconnect().await?;

    let mut total = 0u64;
    let mut funded = Vec::new();
    for (leaf, address) in addresses.iter().enumerate() {
        let held: u64 =
            utxos.get(&address.to_string()).map(|v| v.iter().map(|u| u.amount).sum()).unwrap_or(0);
        total += held;
        if held > 0 {
            funded.push(leaf as u32);
        }
        println!("  leaf {leaf:>5}  {address}  {held} sompi");
    }

    println!();
    println!("total {total} sompi across {} scanned leaves", addresses.len());
    match funded.len() {
        0 => println!("no funded leaf in this range"),
        1 => println!("live leaf: {}", funded[0]),
        _ => println!(
            "WARNING: {} funded leaves ({funded:?}). This usually means a payment \
             arrived at an address the vault has already moved past; that leaf's \
             one-time key may already have signed.",
            funded.len()
        ),
    }
    Ok(())
}

/// Write a `.env` template with restrictive permissions.
fn cmd_init_env(path: &str) -> Result<()> {
    if std::path::Path::new(path).exists() {
        bail!("{path} already exists; refusing to overwrite a file that may hold a key");
    }

    std::fs::write(path, ENV_TEMPLATE).with_context(|| format!("writing {path}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {path}"))?;
    }

    println!("wrote {path} (mode 600)");
    println!();
    println!("Edit it to add your mnemonic or key. It stores key material in plaintext,");
    println!("so keep it out of version control — add `.env` to your .gitignore.");
    Ok(())
}

async fn cmd_spend(args: &Args, env: &EnvFile) -> Result<()> {
    use kaspa_consensus_core::config::params::{MAINNET_PARAMS, TESTNET_PARAMS};

    let resolved = resolve(args, env, Scheme::LmsSha256)?;
    let prefix = prefix_for(&resolved.network)?;

    let destination: kaspa_addresses::Address =
        args.to.as_deref().context("--to <address> is required")?.try_into().map_err(|e| {
            anyhow::anyhow!("--to is not a valid Kaspa address: {e:?}")
        })?;
    ensure!(
        destination.prefix == prefix,
        "destination is a {} address but the wallet is on {}",
        destination.prefix,
        prefix
    );
    let amount = args.amount.context("--amount <sompi> is required")?;

    let material = &resolved.material;
    eprintln!("key source: {} from {}", material.describe(), resolved.origin);
    if let Some(warning) = material.warning() {
        eprintln!();
        eprintln!("  WARNING: {warning}");
        eprintln!();
    }

    let xi = Derivation::DEFAULT.xi_from(material, 0, resolved.key_index)?;
    eprintln!("deriving vault (this takes a few seconds)...");
    let (vault, _) = Vault::from_xi(&xi);

    let params = if resolved.network == "mainnet" { MAINNET_PARAMS } else { TESTNET_PARAMS };

    eprintln!("connecting to {} via the public node network...", resolved.network);
    let client = match resolved.network.as_str() {
        "mainnet" => vault_node::NodeClient::mainnet().await?,
        _ => vault_node::NodeClient::testnet10().await?,
    };

    let request = spend_cmd::SpendRequest {
        vault: &vault,
        xi: &xi,
        key_index: resolved.key_index,
        prefix,
        params: &params,
        destination,
        amount,
        fee: args.fee,
        journal_path: args.journal.clone().unwrap_or_else(|| "vault.journal".into()),
        confirmed: args.yes,
        dry_run: args.dry_run,
    };

    let result = spend_cmd::run(request, &client).await;
    client.disconnect().await.ok();
    result
}

fn usage() {
    eprintln!("kaspa-vault <command> [options]");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  info                    scheme and parameter summary
  artifacts               every value an address depends on, for build verification
  slh-address             SLH-DSA vault address (stateless scheme)
  slh-balance             what the SLH-DSA vault holds
  slh-spend               spend from the SLH-DSA vault");
    eprintln!("  init-env                write a .env template (mode 600)");
    eprintln!("  addresses               derive vault addresses");
    eprintln!("  balance                 query balances via the public node network");
    eprintln!("  spend                   spend from the funded leaf");
    eprintln!();
    eprintln!("key (one required):");
    eprintln!("  --mnemonic WORDS  BIP39 mnemonic phrase");
    eprintln!("  --key KEY         extended private key (xprv…/kprv…),");
    eprintln!("                    128-char BIP39 seed, or 64-char private key");
    eprintln!();
    eprintln!("  Credentials may instead come from the environment or a .env file:");
    eprintln!("    {ENV_MNEMONIC}, {ENV_KEY},");
    eprintln!("    {ENV_NETWORK}, {ENV_KEY_INDEX}");
    eprintln!();
    eprintln!("options:");
    eprintln!("  --env-file PATH which .env to read (default ./.env)");
    eprintln!("  --key-index N   which vault under the seed (default 0)");
    eprintln!();
    eprintln!("spend options:");
    eprintln!("  --to ADDRESS    destination (required)");
    eprintln!("  --amount N      sompi to send (required)");
    eprintln!("  --fee N         fee in sompi (default: relay minimum + 20%)");
    eprintln!("  --journal PATH  spend journal (default ./vault.journal)");
    eprintln!("  --dry-run       sign but do not broadcast");
    eprintln!("  --yes           confirm; without it the spend is only previewed");
    eprintln!("  --count N       leaves to show (default {DEFAULT_ADDRESS_COUNT})");
    eprintln!("  --network NET   tn10 (default) or mainnet");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let env = EnvFile::load(args.env_file.as_deref().map(std::path::Path::new))?;
    if let Some(path) = env.path() {
        eprintln!("loaded {}", path.display());
    }

    match args.command.as_str() {
        "info" => cmd_info(),
        "artifacts" => artifacts_cmd::cmd_artifacts()?,
        "init-env" => cmd_init_env(args.env_file.as_deref().unwrap_or(".env"))?,
        "addresses" => cmd_addresses(&args, &env)?,
        "balance" => cmd_balance(&args, &env).await?,
        "spend" => cmd_spend(&args, &env).await?,
        "slh-address" => {
            let resolved = resolve(&args, &env, Scheme::SlhDsaSha2_128s)?;
            let prefix = prefix_for(&resolved.network)?;
            slh_cmd::cmd_address(&resolved, prefix)?
        }
        "slh-balance" => {
            let resolved = resolve(&args, &env, Scheme::SlhDsaSha2_128s)?;
            let prefix = prefix_for(&resolved.network)?;
            slh_cmd::cmd_balance(&resolved, prefix).await?
        }
        "slh-spend" => {
            let resolved = resolve(&args, &env, Scheme::SlhDsaSha2_128s)?;
            let prefix = prefix_for(&resolved.network)?;
            slh_cmd::cmd_spend(&args, &resolved, prefix).await?
        }
        "help" | "--help" | "-h" => usage(),
        other => {
            eprintln!("unknown command: {other}");
            usage();
            std::process::exit(2);
        }
    }
    Ok(())
}
