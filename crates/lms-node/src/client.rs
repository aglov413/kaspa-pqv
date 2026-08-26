//! wRPC client wrapper.

use anyhow::{anyhow, Context, Result};
use kaspa_addresses::Address;
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_consensus_core::tx::Transaction;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_wrpc_client::client::{ConnectOptions, ConnectStrategy};
use kaspa_wrpc_client::{KaspaRpcClient, Resolver, WrpcEncoding};
use lms_wallet::scan::UtxoSource;
use std::sync::Mutex;
use std::time::Duration;

/// A UTXO held by a vault address.
#[derive(Clone, Debug)]
pub struct VaultUtxoEntry {
    pub txid: [u8; 32],
    pub index: u32,
    pub amount: u64,
    pub block_daa_score: u64,
}

/// A connection to a Kaspa node.
pub struct NodeClient {
    rpc: KaspaRpcClient,
    network: NetworkId,
    /// Balances are fetched asynchronously but [`UtxoSource`] is synchronous,
    /// because the wallet's scanning logic is deliberately I/O-free. Callers
    /// pre-load balances with [`NodeClient::load_balances`] and the trait then
    /// reads from this cache.
    cache: Mutex<std::collections::HashMap<String, u64>>,
}

impl NodeClient {
    /// Testnet-10, via the Public Node Network. Toccata is active there.
    pub async fn testnet10() -> Result<Self> {
        Self::connect_pnn(NetworkId::with_suffix(NetworkType::Testnet, 10)).await
    }

    /// Mainnet, via the Public Node Network.
    ///
    /// Reachable, but the PNN is documented as being for development and
    /// testing. A vault holding real value should use
    /// [`NodeClient::connect_to_url`] against a node you control.
    pub async fn mainnet() -> Result<Self> {
        Self::connect_pnn(NetworkId::new(NetworkType::Mainnet)).await
    }

    /// Connect through the Public Node Network.
    ///
    /// The Kaspa Resolver picks a public node for `network` with the fewest
    /// active client connections.
    pub async fn connect_pnn(network: NetworkId) -> Result<Self> {
        let rpc = KaspaRpcClient::new(
            WrpcEncoding::Borsh,
            None,
            Some(Resolver::default()),
            Some(network),
            None,
        )
        .context("building wRPC client")?;

        Self::finish_connect(rpc, network).await
    }

    /// Connect to a specific node, e.g. `ws://127.0.0.1:17210`.
    pub async fn connect_to_url(url: &str, network: NetworkId) -> Result<Self> {
        let rpc = KaspaRpcClient::new(WrpcEncoding::Borsh, Some(url), None, Some(network), None)
            .context("building wRPC client")?;
        Self::finish_connect(rpc, network).await
    }

    async fn finish_connect(rpc: KaspaRpcClient, network: NetworkId) -> Result<Self> {
        rpc.connect(Some(ConnectOptions {
            block_async_connect: true,
            strategy: ConnectStrategy::Fallback,
            connect_timeout: Some(Duration::from_secs(20)),
            ..Default::default()
        }))
        .await
        .map_err(|e| anyhow!("connect failed: {e}"))?;

        let client = Self { rpc, network, cache: Mutex::new(Default::default()) };
        client.assert_node_is_usable().await?;
        Ok(client)
    }

    /// Refuse to operate against a node that cannot serve this vault.
    ///
    /// A synced node on the wrong network, or one still syncing, would report
    /// empty balances — which a vault wallet must not read as "no funds here".
    async fn assert_node_is_usable(&self) -> Result<()> {
        let info = self
            .rpc
            .get_server_info()
            .await
            .map_err(|e| anyhow!("get_server_info failed: {e}"))?;

        if !info.is_synced {
            return Err(anyhow!(
                "node is not synced; a vault scan against an unsynced node would report \
                 empty addresses and could be mistaken for a spent vault"
            ));
        }
        if !info.has_utxo_index {
            return Err(anyhow!(
                "node has no UTXO index (start it with --utxoindex); address balance \
                 lookups are unavailable without it"
            ));
        }
        if info.network_id != self.network {
            return Err(anyhow!(
                "node is on {} but this vault is for {}",
                info.network_id,
                self.network
            ));
        }
        Ok(())
    }

    pub fn network(&self) -> NetworkId {
        self.network
    }

    /// Fetch every UTXO held by `addresses`, keyed by address string.
    pub async fn utxos_for(
        &self,
        addresses: &[Address],
    ) -> Result<std::collections::HashMap<String, Vec<VaultUtxoEntry>>> {
        let mut out: std::collections::HashMap<String, Vec<VaultUtxoEntry>> = Default::default();
        if addresses.is_empty() {
            return Ok(out);
        }

        let entries = self
            .rpc
            .get_utxos_by_addresses(addresses.to_vec())
            .await
            .map_err(|e| anyhow!("get_utxos_by_addresses failed: {e}"))?;

        for entry in entries {
            let Some(address) = entry.address else { continue };
            out.entry(address.to_string()).or_default().push(VaultUtxoEntry {
                txid: entry.outpoint.transaction_id.as_bytes(),
                index: entry.outpoint.index,
                amount: entry.utxo_entry.amount,
                block_daa_score: entry.utxo_entry.block_daa_score,
            });
        }
        Ok(out)
    }

    /// Pre-load balances so the synchronous [`UtxoSource`] can serve a scan.
    pub async fn load_balances(&self, addresses: &[Address]) -> Result<()> {
        let utxos = self.utxos_for(addresses).await?;
        let mut cache = self.cache.lock().expect("balance cache poisoned");
        for address in addresses {
            let key = address.to_string();
            let total = utxos.get(&key).map(|v| v.iter().map(|u| u.amount).sum()).unwrap_or(0);
            cache.insert(key, total);
        }
        Ok(())
    }

    /// Broadcast a signed transaction.
    ///
    /// A vault spend is single-use: the one-time key that signed it cannot sign
    /// anything else, so a rejection here is not something to retry with a
    /// different transaction. Rebroadcast the same bytes.
    pub async fn broadcast(&self, tx: &Transaction) -> Result<String> {
        let rpc_tx: kaspa_rpc_core::RpcTransaction = tx.into();
        let id = self
            .rpc
            .submit_transaction(rpc_tx, false)
            .await
            .map_err(|e| anyhow!("submit_transaction rejected the spend: {e}"))?;
        Ok(id.to_string())
    }

    /// Report what the node is running and how far along the chain it is.
    ///
    /// Which script features are live is a property of the deployed network,
    /// not of this source checkout, so it is asked rather than assumed.
    pub async fn report_server_info(&self) -> Result<()> {
        let info = self
            .rpc
            .get_server_info()
            .await
            .map_err(|e| anyhow!("get_server_info failed: {e}"))?;
        println!("  server version    {}", info.server_version);
        println!("  network           {}", info.network_id);
        println!("  synced            {}", info.is_synced);
        println!("  utxo-indexed      {}", info.has_utxo_index);
        println!("  virtual DAA score {}", info.virtual_daa_score);

        let dag = self
            .rpc
            .get_block_dag_info()
            .await
            .map_err(|e| anyhow!("get_block_dag_info failed: {e}"))?;
        println!("  pruning point     {}", dag.pruning_point_hash);
        println!("  tips              {}", dag.tip_hashes.len());

        // Whether the Toccata script features are live is decided by what the
        // network actually carries, not by what this checkout compiles. v1
        // transactions are the ones with a `compute_budget` field, which the
        // vault verifier needs.
        let Some(tip) = dag.tip_hashes.first().copied() else { return Ok(()) };
        let block = self
            .rpc
            .get_block(tip, true)
            .await
            .map_err(|e| anyhow!("get_block failed: {e}"))?;
        let mut versions: std::collections::BTreeMap<u16, usize> = Default::default();
        for tx in &block.transactions {
            *versions.entry(tx.version).or_default() += 1;
        }
        println!("  tip block tx versions {versions:?}");
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.rpc.disconnect().await.map_err(|e| anyhow!("disconnect failed: {e}"))
    }
}

impl UtxoSource for NodeClient {
    fn balance(&self, address: &Address) -> anyhow::Result<u64> {
        let cache = self.cache.lock().expect("balance cache poisoned");
        cache.get(&address.to_string()).copied().ok_or_else(|| {
            anyhow!(
                "balance for {address} was not pre-loaded; call load_balances() for the \
                 address range before scanning"
            )
        })
    }
}
