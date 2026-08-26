//! Generates a fully unrolled Kaspa txscript verifier for SLH-DSA-SHA2-128s
//! signatures (FIPS 205), so a Kaspa vault can be spent by a **stateless**
//! post-quantum signature.
//!
//! # Why this scheme, and only this scheme
//!
//! Kaspa script has `OpSHA256`, `OpBlake2b` and `OpBlake3`, and no Keccak or
//! SHAKE. FIPS 204 (ML-DSA) opens verification by rejection-sampling a
//! polynomial matrix from ~13 KB of SHAKE128 output, and Falcon needs the same
//! primitive for hash-to-point; implementing Keccak-f[1600] in script, with
//! `OpLShift`/`OpRShift` disabled, is not a real option. SLH-DSA with the SHA2
//! parameter sets is therefore the only stateless post-quantum signature that
//! can be verified directly by Kaspa's own opcodes.
//!
//! # What it costs, structurally
//!
//! LMS verification is one WOTS+ verification plus a Merkle path. SLH-DSA is
//! FORS plus **seven** WOTS+ verifications, one per hypertree layer, and every
//! hash carries a 64-byte constant block and a 22-byte address rather than
//! LMS's 22-byte prefix. That is where the order of magnitude goes, and it is
//! the price of not having to remember which one-time key was used.
//!
//! # The two hazards this crate is organised around
//!
//! [`adrs`] is the compressed hash address. Wrong bytes there produce a
//! verifier that is self-consistent and rejects every real signature.
//!
//! [`witness`] exists because a signature has 491 `n`-byte elements and
//! `MAX_STACK_SIZE` is 244, counting both stacks. The signature is pushed as
//! blobs and sliced, which is not free and is accounted for explicitly.
//!
//! [`reference`] is a host-side verifier that exposes every intermediate, so
//! the emitted script is checked against known values rather than against a
//! single pass/fail bit.

pub mod adrs;
pub mod emit;
pub mod frame;
pub mod params;
pub mod reference;
pub mod witness;

pub use adrs::Adrs;
pub use emit::{build_vault_script, build_verify_script, emit_vault_script, emit_verify, VaultScript};
pub use reference::{PublicKey, Signature};
pub use witness::BlobPlan;

// The binding digest is shared with the LMS scheme rather than reimplemented:
// two copies of it is two chances for the in-script and off-chain
// constructions to drift apart, and a drift bricks UTXOs silently.
pub use vault_core::{binding, ScriptWriter};
