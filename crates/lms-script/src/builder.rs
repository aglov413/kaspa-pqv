//! Thin wrapper over Kaspa's `ScriptBuilder`.
//!
//! Exists so the generator can talk in terms of LMS operations while every
//! emitted byte still goes through the consensus builder — no hand-assembled
//! opcodes, and push encoding is whatever the engine itself considers minimal.

use anyhow::Result;
use kaspa_txscript::script_builder::ScriptBuilder;

/// Accumulates a script.
pub struct ScriptWriter {
    inner: ScriptBuilder,
}

impl Default for ScriptWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptWriter {
    pub fn new() -> Self {
        Self { inner: ScriptBuilder::new() }
    }

    /// Append a single opcode.
    pub fn op(&mut self, opcode: u8) -> Result<&mut Self> {
        self.inner.add_op(opcode).map_err(anyhow::Error::from)?;
        Ok(self)
    }

    /// Append several opcodes in order.
    pub fn ops(&mut self, opcodes: &[u8]) -> Result<&mut Self> {
        self.inner.add_ops(opcodes).map_err(anyhow::Error::from)?;
        Ok(self)
    }

    /// Append a data push.
    pub fn data(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.inner.add_data(data).map_err(anyhow::Error::from)?;
        Ok(self)
    }

    /// Append a minimally-encoded numeric push.
    pub fn num(&mut self, value: i64) -> Result<&mut Self> {
        self.inner.add_i64(value).map_err(anyhow::Error::from)?;
        Ok(self)
    }

    /// Bytes emitted so far.
    pub fn len(&self) -> usize {
        self.inner.script().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Finish and return the script.
    pub fn build(mut self) -> Vec<u8> {
        self.inner.drain()
    }
}
