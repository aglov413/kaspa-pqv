//! Live check: reach a testnet-10 node through the Public Node Network and
//! confirm it can serve vault queries.
//!
//! Run with `cargo run -p lms-node --example tn10_probe`.

use kaspa_addresses::Prefix;
use lms_node::NodeClient;
use lms_wallet::derivation::{derive_xi, Scheme};
use lms_wallet::vault::Vault;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("connecting to testnet-10 via PNN...");
    let client = NodeClient::testnet10().await?;
    println!("connected: network {}", client.network());

    let m = kaspa_bip32::Mnemonic::new(TEST_MNEMONIC, kaspa_bip32::Language::English)?;
    let seed = hex::decode(m.create_seed(None))?;
    let xi = derive_xi(&seed, Scheme::LmsSha256, 0, 0)?;

    println!("deriving vault (h=15 keygen, a few seconds)...");
    let (vault, _sk) = Vault::from_xi(&xi);

    // Only the first few leaves — enumerating all 32,768 is a recovery-path
    // operation, not something to do against a public node.
    let addresses: Vec<_> =
        (0..4).map(|leaf| vault.address(Prefix::Testnet, leaf)).collect::<Result<_, _>>()?;

    println!("querying {} vault addresses...", addresses.len());
    let utxos = client.utxos_for(&addresses).await?;

    for (leaf, address) in addresses.iter().enumerate() {
        let held: u64 = utxos.get(&address.to_string()).map(|v| v.iter().map(|u| u.amount).sum()).unwrap_or(0);
        println!("  leaf {leaf}: {address}  ({held} sompi)");
    }

    client.disconnect().await?;
    println!("ok");
    Ok(())
}
