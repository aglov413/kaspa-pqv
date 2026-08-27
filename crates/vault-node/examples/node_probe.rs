//! Ask a node what it is running, and whether the features this design needs
//! are live on the network it serves.
//!
//! The vault verifier depends on KIP-10 / KIP-17 introspection opcodes and on
//! v1 transactions carrying a `compute_budget` field. Whether those are active
//! is a property of the deployed network, not of this source checkout, so it
//! has to be asked rather than inferred.
//!
//! ```text
//! cargo run -p vault-node --release --example node_probe -- ws://127.0.0.1:17110 mainnet
//! ```

use kaspa_consensus_core::network::{NetworkId, NetworkType};
use vault_node::NodeClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let url = args.next().unwrap_or_else(|| "ws://127.0.0.1:17110".to_string());
    let network = match args.next().as_deref() {
        Some("mainnet") | None => NetworkId::new(NetworkType::Mainnet),
        Some("tn10") => NetworkId::with_suffix(NetworkType::Testnet, 10),
        Some(other) => anyhow::bail!("unknown network {other}"),
    };

    println!("connecting to {url} ({network})...");
    let client = NodeClient::connect_to_url(&url, network).await?;
    client.report_server_info().await?;
    client.disconnect().await?;
    Ok(())
}
