//! Generates a fully unrolled Kaspa txscript verifier for SLH-DSA signatures,
//! so a Kaspa vault can be spent by a **stateless** post-quantum signature —
//! and signs for them, since two of the three supported parameter sets have no
//! implementation anywhere else.
//!
//! # Three parameter sets
//!
//! [`params`] carries `SLH-DSA-SHA2-128s` (FIPS 205), `SLH-DSA-SHA2-128-24`
//! (NIST SP 800-230 ipd) and `SLH-DSA-SHA2-128-24d2` (**not a standard**). One
//! emitter, one reference verifier and one signer serve all three; they differ
//! only in the constants. That is what makes the two unstandardised sets
//! testable at all — the `128s` instantiation is held against `fips205`
//! key-for-key and signature-for-signature, and it is the same code.
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
//! FORS plus `d` WOTS+ verifications, one per hypertree layer, and every hash
//! carries a 64-byte constant block and a 22-byte address rather than LMS's
//! 22-byte prefix. That is where the cost goes, and it is the price of not
//! having to remember which one-time key was used.
//!
//! `d` and `w` are what the parameter set moves, in opposite directions:
//! `128s` pays 7 layers of 35 chains of up to 15 hashes, the 2^24 sets pay one
//! or two layers of 68 chains of up to 3. The second shape is a quarter of the
//! on-chain cost, which is the whole reason for carrying more than one set.
//!
//! # The two hazards this crate is organised around
//!
//! [`adrs`] is the compressed hash address. Wrong bytes there produce a
//! verifier that is self-consistent and rejects every real signature.
//!
//! [`witness`] exists because a signature has 241 to 491 `n`-byte elements and
//! `MAX_STACK_SIZE` is 244, counting both stacks — so not even the smallest
//! fits, once the verifier's working frame is on the stack with it. The
//! signature is pushed as blobs and sliced, which is not free and is accounted
//! for explicitly.
//!
//! [`reference`] is a host-side verifier that exposes every intermediate, so
//! the emitted script is checked against known values rather than against a
//! single pass/fail bit.
//!
//! [`signer`] is key generation and signing. It is here because a parameter set
//! that cannot sign cannot be measured end to end, and a measurement that stops
//! short of a real signature is a model.

pub mod adrs;
pub mod emit;
pub mod frame;
pub mod params;
pub mod reference;
pub mod signer;
pub mod witness;

pub use adrs::Adrs;
pub use emit::{build_vault_script, build_verify_script, emit_vault_script, emit_verify, VaultScript};
pub use reference::{PublicKey, Signature};
pub use signer::{SecretSeeds, SigningKey};
pub use witness::BlobPlan;

// The binding digest is shared with the LMS scheme rather than reimplemented:
// two copies of it is two chances for the in-script and off-chain
// constructions to drift apart, and a drift bricks UTXOs silently.
pub use vault_core::{binding, ScriptWriter};
