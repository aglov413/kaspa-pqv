//! Generates a fully unrolled Kaspa txscript verifier for LMS / LM-OTS
//! signatures (RFC 8554, NIST SP 800-208).
//!
//! Kaspa script has no loops, so every hash-chain iteration and every Merkle
//! path step is emitted explicitly. Three facts about the engine make this
//! affordable, all verified against `crypto/txscript` in rusty-kaspa:
//!
//! - `OpSHA256` costs 1 script unit per byte hashed (`HashOpcodePricing`).
//! - `MAX_OPS_PER_SCRIPT` is 1_000_000, not Bitcoin's 201.
//! - Opcodes inside an untaken `OpIf` branch are never executed, so they cost
//!   script *bytes* but zero script *units*. Winternitz chains have
//!   data-dependent length, and this is what makes unrolling them to the worst
//!   case cheap in the average case.
//!
//! It also relies on `OpSubstr`, `OpDiv`, `OpMod` and `OpBin2Num`, which Kaspa
//! enables and Bitcoin disables.

pub mod binding;
pub mod builder;
pub mod ots;
pub mod params;
pub mod verify;

pub use builder::ScriptWriter;
pub use ots::{coef, cksm, coefficient_source};
pub use binding::{binding_digest, binding_preimage, emit_binding_digest, OutputView, SpendView};
pub use params::LmsParams;
pub use verify::{emit_vault_script, emit_verify, LmsPublicKey};
