//! Full LMS signature verification, emitted as unrolled Kaspa txscript.
//!
//! Implements RFC 8554 §5.4.2 (Algorithm 6a) with §4.5 (Algorithm 4b) inlined.
//!
//! # Pinned leaf index
//!
//! `q`, the one-time-key index, is a *script constant*, not a witness value.
//! Each leaf therefore has its own P2SH address, which buys three things:
//!
//! - The hash prefixes `I || u32str(q) || …` stay literal pushes, which cost
//!   zero script units at runtime.
//! - One-time-key state lives in the UTXO set. Leaf `q` can only ever spend the
//!   UTXO at address `q`, so "which index have I burned" is answered by
//!   scanning addresses rather than by a counter file that must survive a
//!   decade and a mnemonic restore.
//! - `node_num = 2^h + q` becomes a compile-time constant, so the Merkle path's
//!   odd/even branching is resolved at generation time and emits no
//!   conditionals at all.
//!
//! It does not remove the reuse hazard: signing two *different* transactions
//! from the same address still exposes the one-time key. That is a wallet
//! constraint — sign once, persist the signed transaction, rebroadcast rather
//! than re-sign.
//!
//! # Witness layout
//!
//! Pushed by the signature script, bottom first:
//!
//! ```text
//! path[h-1] … path[0], y[p-1] … y[0], C, message
//! ```

use anyhow::{ensure, Result};
use kaspa_txscript::opcodes::codes::*;

use crate::builder::ScriptWriter;
use crate::ots::emit_coefficient;
use crate::params::{LmsParams, D_INTR, D_LEAF, D_MESG, D_PBLC, I_LEN, N};

/// An LMS public key, as pinned into a redeem script.
#[derive(Clone, Debug)]
pub struct LmsPublicKey {
    /// RFC 8554 `I`, the key identifier.
    pub id: [u8; I_LEN],
    /// RFC 8554 `T[1]`, the Merkle root.
    pub root: [u8; N],
}

/// Hash prefix `I || u32str(idx) || u16str(domain)`.
fn prefix(id: &[u8; I_LEN], idx: u32, domain: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(I_LEN + 6);
    out.extend_from_slice(id);
    out.extend_from_slice(&idx.to_be_bytes());
    out.extend_from_slice(&domain.to_be_bytes());
    out
}

/// Emit the complete verifier for one leaf index.
///
/// Consumes the witness and leaves a single boolean: true iff the signature
/// verifies under `key` for leaf `q`.
pub fn emit_verify(
    w: &mut ScriptWriter,
    params: &LmsParams,
    key: &LmsPublicKey,
    q: u32,
) -> Result<()> {
    ensure!(q < params.leaf_count(), "leaf {q} out of range for h = {}", params.h);

    emit_message_digest(w, params, key, q)?;
    emit_checksum_and_v(w, params)?;
    emit_chains(w, params, key, q)?;
    emit_candidate_key(w, params, key, q)?;
    emit_merkle_path(w, params, key, q)?;

    // Compare against the pinned root.
    w.data(&key.root)?;
    w.op(OpEqual)?;
    Ok(())
}

/// `Q = H(I || u32str(q) || u16str(D_MESG) || C || message)`.
///
/// Stack: `[…, y[0], C, message]` → `[…, y[0], Q]`
fn emit_message_digest(
    w: &mut ScriptWriter,
    _params: &LmsParams,
    key: &LmsPublicKey,
    q: u32,
) -> Result<()> {
    w.op(OpSwap)?; // [.., message, C]
    w.data(&prefix(&key.id, q, D_MESG))?; // [.., message, C, pfx]
    w.op(OpSwap)?; // [.., message, pfx, C]
    w.op(OpCat)?; // [.., message, pfx||C]
    w.op(OpSwap)?; // [.., pfx||C, message]
    w.op(OpCat)?; // [.., pfx||C||message]
    w.op(OpSHA256)?; // [.., Q]
    Ok(())
}

/// `V = Q || u16str(cksm(Q))`, per RFC 8554 §4.4.
///
/// The checksum is what prevents an attacker advancing a message coefficient:
/// raising any `coef(Q,i,w)` lowers the sum, which would require walking a
/// checksum chain backwards.
///
/// Stack: `[…, Q]` → `[…, V]`
fn emit_checksum_and_v(w: &mut ScriptWriter, params: &LmsParams) -> Result<()> {
    // Accumulate sum(max_coef - coef(Q, i, w)) over the u message chains.
    w.num(0)?;
    w.op(OpToAltStack)?;

    for i in 0..params.u {
        emit_coefficient(w, params, i)?; // [.., Q, a_i]
        w.num(i64::from(params.max_coef()))?; // [.., Q, a_i, max]
        w.op(OpSwap)?; // [.., Q, max, a_i]
        w.op(OpSub)?; // [.., Q, max - a_i]
        w.op(OpFromAltStack)?;
        w.op(OpAdd)?;
        w.op(OpToAltStack)?;
    }

    w.op(OpFromAltStack)?; // [.., Q, sum]
    w.num(1i64 << params.ls)?;
    w.op(OpMul)?; // [.., Q, cksm]

    // u16str(cksm): RFC 8554 is big-endian, OpNum2Bin is little-endian
    // sign-magnitude, so the two bytes are produced then swapped. The value is
    // bounded by u * max_coef << ls, which the parameter sets keep under
    // 2^15, so the sign bit is always clear.
    w.num(2)?;
    w.op(OpNum2Bin)?; // [.., Q, [lo, hi]]
    w.op(OpDup)?;
    w.num(1)?;
    w.num(2)?;
    w.op(OpSubstr)?; // [.., Q, n2b, hi]
    w.op(OpSwap)?; // [.., Q, hi, n2b]
    w.num(0)?;
    w.num(1)?;
    w.op(OpSubstr)?; // [.., Q, hi, lo]
    w.op(OpCat)?; // [.., Q, hi||lo]
    w.op(OpCat)?; // [.., Q||cksm] = V
    Ok(())
}

/// The `p` Winternitz chains.
///
/// Each chain walks `y[i]` forward from its coefficient to `2^w - 2`. The step
/// count is data-dependent and script has no loops, so all `2^w - 1` steps are
/// emitted and each is gated on `j >= a_i`. Untaken branches cost script bytes
/// but zero script units, which is what makes this affordable.
///
/// Stack: `[…, y[p-1] … y[0], V]` → `[…, V]` with `z[0..p-1]` on the alt stack
fn emit_chains(
    w: &mut ScriptWriter,
    params: &LmsParams,
    key: &LmsPublicKey,
    q: u32,
) -> Result<()> {
    for i in 0..params.p {
        emit_coefficient(w, params, i)?; // [.., y[i], V, a_i]
        w.op(OpToAltStack)?; // [.., y[i], V]
        w.op(OpSwap)?; // [.., V, y[i]]

        for j in 0..params.max_coef() {
            // Recover a_i without consuming it.
            w.op(OpFromAltStack)?;
            w.op(OpDup)?;
            w.op(OpToAltStack)?; // [.., V, tmp, a_i]
            w.num(i64::from(j))?; // [.., V, tmp, a_i, j]
            w.op(OpSwap)?; // [.., V, tmp, j, a_i]
            w.op(OpGreaterThanOrEqual)?; // [.., V, tmp, j >= a_i]

            w.op(OpIf)?;
            {
                // tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)
                let mut pfx = prefix(&key.id, q, u16::try_from(i).expect("p fits in u16"));
                pfx.push(u8::try_from(j).expect("max_coef fits in u8"));
                w.data(&pfx)?; // [.., V, tmp, pfx]
                w.op(OpSwap)?; // [.., V, pfx, tmp]
                w.op(OpCat)?; // [.., V, pfx||tmp]
                w.op(OpSHA256)?; // [.., V, tmp']
            }
            w.op(OpEndIf)?;
        }

        w.op(OpFromAltStack)?;
        w.op(OpDrop)?; // discard a_i
        w.op(OpToAltStack)?; // stash z[i]
    }
    Ok(())
}

/// `Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || … || z[p-1])`.
///
/// Stack: `[…, V]` + alt `[z[0] … z[p-1]]` → `[…, Kc]`
fn emit_candidate_key(
    w: &mut ScriptWriter,
    params: &LmsParams,
    key: &LmsPublicKey,
    q: u32,
) -> Result<()> {
    w.op(OpDrop)?; // V is no longer needed

    // Pop every z back. The alt stack yields z[p-1] first, so after this the
    // main stack has z[0] on top.
    for _ in 0..params.p {
        w.op(OpFromAltStack)?;
    }

    // Fold left: prefix, then z[0], z[1], … in order.
    //
    // This is linear accumulation, which costs O(p^2) because OpCat is charged
    // the length of its result. A balanced concatenation tree would cut it to
    // O(p log p); see NOTES.md. Correctness first.
    w.data(&prefix(&key.id, q, D_PBLC))?; // [.., z[0], pfx]
    w.op(OpSwap)?; // [.., pfx, z[0]]
    w.op(OpCat)?;
    for _ in 1..params.p {
        w.op(OpSwap)?; // [.., acc, z[i]] -> deeper acc
        w.op(OpCat)?;
    }
    w.op(OpSHA256)?; // [.., Kc]
    Ok(())
}

/// Walk the Merkle path from the leaf to the root.
///
/// Because `q` is pinned, `node_num = 2^h + q` is a constant and the odd/even
/// choice at each level is resolved here rather than in script — the emitted
/// path contains no conditionals.
///
/// Stack: `[path[h-1] … path[0], Kc]` → `[…, root_candidate]`
fn emit_merkle_path(
    w: &mut ScriptWriter,
    params: &LmsParams,
    key: &LmsPublicKey,
    q: u32,
) -> Result<()> {
    let mut node = params.leaf_count() + q;

    // tmp = H(I || u32str(node) || u16str(D_LEAF) || Kc)
    w.data(&prefix(&key.id, node, D_LEAF))?; // [.., Kc, pfx]
    w.op(OpSwap)?; // [.., pfx, Kc]
    w.op(OpCat)?;
    w.op(OpSHA256)?; // [.., tmp]

    while node > 1 {
        let pfx = prefix(&key.id, node / 2, D_INTR);
        let sibling_is_left = node % 2 == 1;

        // Stack here: [.., path[i], tmp]
        if sibling_is_left {
            // tmp = H(pfx || path[i] || tmp)
            w.op(OpSwap)?; // [.., tmp, path]
            w.data(&pfx)?; // [.., tmp, path, pfx]
            w.op(OpSwap)?; // [.., tmp, pfx, path]
            w.op(OpCat)?; // [.., tmp, pfx||path]
            w.op(OpSwap)?; // [.., pfx||path, tmp]
            w.op(OpCat)?; // [.., pfx||path||tmp]
        } else {
            // tmp = H(pfx || tmp || path[i])
            w.data(&pfx)?; // [.., path, tmp, pfx]
            w.op(OpSwap)?; // [.., path, pfx, tmp]
            w.op(OpCat)?; // [.., path, pfx||tmp]
            w.op(OpSwap)?; // [.., pfx||tmp, path]
            w.op(OpCat)?; // [.., pfx||tmp||path]
        }
        w.op(OpSHA256)?;
        node /= 2;
    }
    Ok(())
}

/// The complete vault redeem script: reconstruct `D`, then verify an LMS
/// signature over it.
///
/// This is what a funded address actually commits to. The two halves compose
/// without glue because [`emit_binding_digest`](crate::binding::emit_binding_digest)
/// leaves `D` on top of the stack, which is precisely where [`emit_verify`]
/// expects the signed message.
///
/// The witness supplies everything else, pushed bottom first:
///
/// ```text
/// path[h-1] … path[0], y[p-1] … y[0], C
/// ```
///
/// Note the message is *absent* from the witness. That is the whole point: the
/// signature commits to this transaction's outpoint and outputs, reconstructed
/// from introspection, rather than to a value the spender chooses. A verifier
/// that takes the message from the witness lets anyone holding a valid
/// signature redirect the spend.
///
/// `output_count` is fixed because Kaspa script has no loops, so a vault
/// defines one canonical spend shape — destination plus change. A different
/// shape needs its own branch.
pub fn emit_vault_script(
    w: &mut ScriptWriter,
    params: &LmsParams,
    key: &LmsPublicKey,
    q: u32,
    output_count: usize,
) -> Result<()> {
    crate::binding::emit_binding_digest(w, output_count)?;
    emit_verify(w, params, key, q)
}
