//! Executes generated scripts with Kaspa's real consensus engine and reports
//! what they cost.
//!
//! Nothing here reimplements script semantics. `TxScriptEngine` is the same
//! type a Toccata node runs, so a script that passes here passes for the same
//! reasons it would on-chain — and `used_script_units()` is the node's own
//! accounting, not an estimate.

use anyhow::{anyhow, Result};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::{SigCacheKey, TxScriptEngine};

/// What a script cost when executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    /// Script bytes. Lands in the transaction, so it is charged as mass at
    /// `mass_per_tx_byte`.
    pub script_bytes: usize,
    /// Script units consumed at runtime, as the engine counts them.
    /// `SCRIPT_UNITS_PER_GRAM` is 100.
    pub script_units: u64,
}

impl Cost {
    /// Runtime cost in grams.
    pub fn grams(&self) -> u64 {
        self.script_units / 100
    }

    /// Compute-budget units an input must declare to afford this,
    /// `GRAMS_PER_COMPUTE_BUDGET_UNIT` being 100. Rounded up.
    pub fn compute_budget_units(&self) -> u64 {
        self.grams().div_ceil(100)
    }
}

/// Run a standalone script to completion.
///
/// Returns the cost on success, or the engine's own error on failure — an
/// important distinction for negative tests, where the *reason* a bad
/// signature is rejected matters as much as the rejection.
pub fn execute(script: &[u8]) -> Result<Cost> {
    let reused = SigHashReusedValuesUnsync::new();
    let sig_cache: Cache<SigCacheKey, bool> = Cache::new(0);
    let mut vm = TxScriptEngine::<PopulatedTransaction, SigHashReusedValuesUnsync>::from_script(
        script,
        &reused,
        &sig_cache,
        Default::default(),
    );

    vm.execute().map_err(|e| anyhow!("script failed: {e}"))?;

    Ok(Cost { script_bytes: script.len(), script_units: vm.used_script_units().0 })
}

/// Execute a script in transaction context, so introspection opcodes work.
///
/// `from_script` has no transaction attached, which is fine for pure
/// computation but not for `OpTxOutputAmount` and friends. The binding digest
/// is built entirely from introspection, so it can only be tested here.
pub fn execute_with_tx(
    script: &[u8],
    tx: &kaspa_consensus_core::tx::Transaction,
    utxos: Vec<kaspa_consensus_core::tx::UtxoEntry>,
    input_index: usize,
) -> Result<Cost> {
    use kaspa_txscript::EngineCtx;

    let reused = SigHashReusedValuesUnsync::new();
    let sig_cache: Cache<SigCacheKey, bool> = Cache::new(0);

    let populated = PopulatedTransaction::new(tx, utxos.clone());
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &populated.tx.inputs[input_index],
        input_index,
        &utxos[input_index],
        EngineCtx::new(&sig_cache).with_reused(&reused),
        Default::default(),
    );

    vm.execute().map_err(|e| anyhow!("script failed: {e}"))?;
    Ok(Cost { script_bytes: script.len(), script_units: vm.used_script_units().0 })
}
