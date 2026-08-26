//! Vault primitives that are independent of the signature scheme.
//!
//! Two things live here, and they are here for opposite reasons.
//!
//! [`binding`] is here because **divergence is silent and irreversible**. The
//! binding digest is reconstructed inside the redeem script from introspection
//! and independently off-chain when the transaction is built; if the two ever
//! disagree the signature verifies against a message nobody reconstructs and
//! the UTXO is bricked with no error anywhere. Once a second scheme exists,
//! two copies of that file is two chances to drift apart on a component that
//! is already verified on-chain. There is one copy.
//!
//! [`builder`] is here because it is trivial and shared — every emitter wants
//! the same thin wrapper over Kaspa's own `ScriptBuilder`.
//!
//! Nothing scheme-specific belongs in this crate. LMS parameters live in
//! `lms-script`, SLH-DSA parameters in `slh-script`.

pub mod binding;
pub mod builder;

pub use binding::{
    binding_digest, binding_preimage, emit_binding_digest, spk_wire_bytes, OutputView, SpendView,
    MAX_AMOUNT, MAX_OUTPOINT_INDEX, MAX_OUTPUT_COUNT, MAX_SPK_LEN, MAX_TX_VERSION,
};
pub use builder::ScriptWriter;
