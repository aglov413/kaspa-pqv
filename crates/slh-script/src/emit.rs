//! The SLH-DSA-SHA2-128s verifier, emitted as unrolled Kaspa txscript.
//!
//! Implements FIPS 205 Algorithm 20 (`slh_verify_internal`) with Algorithms 8,
//! 11, 17 and 21 inlined, for the SHA2 category-1 parameter set only.
//!
//! # Shape of the emitted script
//!
//! ```text
//! prologue      move the witness blobs to the alt stack, which becomes a queue
//! binding       reconstruct D from introspection            (vault_core::binding)
//! H_msg         two SHA-256 calls -> a 30-byte digest
//! indices       md, idx_tree, idx_leaf carved out of the digest
//! FORS          14 groups: one leaf hash and a 12-node path, then T_k
//! hypertree     7 layers: 35 Winternitz chains, T_len, then a 9-node path
//! epilogue      compare against the pinned PK.root
//! ```
//!
//! # Why every hash is expensive here
//!
//! Each hash is `SHA-256(PK.seed || toByte(0,48) || ADRS^c || M)`. The first 64
//! bytes are constant and free to *push*, but not free to *hash* — the engine
//! charges one script unit per byte hashed, so a 16-byte message costs 102
//! units to hash rather than 16. LMS pays 54 for the same shape. That factor,
//! multiplied by roughly ten times as many hashes, is the cost of statelessness.
//!
//! # The two data-dependent branches
//!
//! Winternitz chain length depends on the message digit, so all 15 steps are
//! emitted and gated on `digit <= step`. Untaken branches cost script bytes and
//! zero script units, which is what makes the worst case affordable.
//!
//! Merkle sibling order depends on an index bit. Unlike LMS — where the leaf is
//! pinned in the script and the whole path is resolved at generation time —
//! SLH-DSA derives its position from the message, so both orders are emitted.
//! The branch is a single `OpSwap`: `H(pfx || a || b)` and `H(pfx || b || a)`
//! differ only in the order of two stack items.

use anyhow::{ensure, Result};
use kaspa_txscript::opcodes::codes::*;
use vault_core::ScriptWriter;

use crate::adrs::hash_pad;
use crate::frame::Frame;
use crate::params::*;
use crate::reference::PublicKey;
use crate::witness::BlobPlan;

/// Emits a verifier and tracks the stack it is building.
pub struct Emitter<'a> {
    w: &'a mut ScriptWriter,
    f: Frame,
    plan: BlobPlan,
    pk: PublicKey,
    /// Next signature element to consume, in signature order.
    next_element: usize,
    /// Elements already sliced onto the alt stack and not yet consumed.
    pending: usize,
    /// Largest frame the emitter has held, for the stack-limit accounting.
    peak_frame: usize,
}

impl<'a> Emitter<'a> {
    pub fn new(w: &'a mut ScriptWriter, pk: PublicKey, plan: BlobPlan) -> Self {
        Self { w, f: Frame::new(), plan, pk, next_element: 0, pending: 0, peak_frame: 0 }
    }

    // ---- primitive wrappers, each keeping the frame in step ----------------

    fn op(&mut self, code: u8) -> Result<()> {
        self.w.op(code)?;
        Ok(())
    }

    fn data(&mut self, bytes: &[u8]) -> Result<()> {
        self.w.data(bytes)?;
        self.f.push_transient();
        self.note_peak();
        Ok(())
    }

    fn num(&mut self, value: i64) -> Result<()> {
        self.w.num(value)?;
        self.f.push_transient();
        self.note_peak();
        Ok(())
    }

    fn note_peak(&mut self) {
        self.peak_frame = self.peak_frame.max(self.f.len());
    }

    fn cat(&mut self) -> Result<()> {
        self.op(OpCat)?;
        self.f.replace(2, "_")
    }

    fn sha256(&mut self) -> Result<()> {
        self.op(OpSHA256)?;
        self.f.replace(1, "_")
    }

    fn swap(&mut self) -> Result<()> {
        self.op(OpSwap)?;
        self.f.swap()
    }

    fn dup(&mut self) -> Result<()> {
        self.op(OpDup)?;
        self.f.push_transient();
        self.note_peak();
        Ok(())
    }

    fn over(&mut self) -> Result<()> {
        self.op(OpOver)?;
        self.f.push_transient();
        self.note_peak();
        Ok(())
    }

    fn drop_top(&mut self) -> Result<()> {
        self.op(OpDrop)?;
        self.f.pop()?;
        Ok(())
    }

    fn binary_num_op(&mut self, code: u8) -> Result<()> {
        self.op(code)?;
        self.f.replace(2, "_")
    }

    /// Copy a named slot to the top of the stack. Charged its length.
    fn pick(&mut self, name: &str) -> Result<()> {
        let depth = self.f.depth(name)?;
        self.num(depth as i64)?;
        self.op(OpPick)?;
        self.f.pop()?; // the depth argument
        self.f.push_transient();
        self.note_peak();
        Ok(())
    }

    /// Move a named slot to the top of the stack. Free — a permutation.
    fn roll(&mut self, name: &str) -> Result<()> {
        let depth = self.f.depth(name)?;
        self.num(depth as i64)?;
        self.op(OpRoll)?;
        self.f.pop()?;
        self.f.roll(depth)
    }

    /// `OpRoll` by literal depth, for the local rearrangements inside an
    /// expression where the operands have no names.
    fn roll_depth(&mut self, depth: usize) -> Result<()> {
        self.num(depth as i64)?;
        self.op(OpRoll)?;
        self.f.pop()?;
        self.f.roll(depth)
    }

    fn name_top(&mut self, name: &str) -> Result<()> {
        self.f.rename_top(name)
    }

    fn discard(&mut self, name: &str) -> Result<()> {
        self.roll(name)?;
        self.drop_top()
    }

    fn substr(&mut self, start: usize, end: usize) -> Result<()> {
        self.num(start as i64)?;
        self.num(end as i64)?;
        self.op(OpSubstr)?;
        self.f.replace(3, "_")
    }

    // ---- composite helpers -------------------------------------------------

    /// Rewrite the number on top of the stack as `width` big-endian bytes.
    ///
    /// `OpNum2Bin` produces little-endian sign-magnitude; every integer inside
    /// an ADRS is big-endian. The reversal is explicit because there is no
    /// opcode for it, and because getting it backwards produces a verifier that
    /// is perfectly self-consistent and agrees with nothing else in the world.
    ///
    /// The caller is responsible for the value fitting: `OpNum2Bin` rejects a
    /// magnitude needing the sign bit, so `width` bytes hold values below
    /// `2^(8*width - 1)`.
    fn emit_be_bytes(&mut self, width: usize) -> Result<()> {
        ensure!((1..=8).contains(&width), "OpNum2Bin handles 1..=8 bytes, not {width}");
        self.num(width as i64)?;
        self.op(OpNum2Bin)?;
        self.f.replace(2, "_")?;

        if width == 1 {
            return Ok(());
        }

        // [le]
        self.dup()?;
        self.substr(width - 1, width)?; // [le, acc]
        for k in (0..width - 1).rev() {
            self.swap()?; // [acc, le]
            self.dup()?; // [acc, le, le]
            self.substr(k, k + 1)?; // [acc, le, b]
            self.roll_depth(2)?; // [le, b, acc]
            self.swap()?; // [le, acc, b]
            self.cat()?; // [le, acc]
        }
        self.op(OpNip)?; // drop the little-endian original
        self.f.nip()
    }

    /// Read bytes `[start, start+len)` of a named slot as a big-endian integer.
    fn emit_be_int_from(&mut self, name: &str, start: usize, len: usize) -> Result<()> {
        ensure!(len > 0 && len <= 7, "big-endian field of {len} bytes will not fit an i64");
        self.num(0)?;
        for i in start..start + len {
            self.num(256)?;
            self.binary_num_op(OpMul)?;
            self.pick(name)?;
            self.substr(i, i + 1)?;
            // A lone byte >= 0x80 decodes as negative zero under Kaspa's
            // sign-magnitude numbers; the pad clears the sign bit. Same trap
            // as `lms_script::ots::emit_coefficient`.
            self.data(&[0x00])?;
            self.cat()?;
            self.op(OpBin2Num)?;
            self.f.replace(1, "_")?;
            self.binary_num_op(OpAdd)?;
        }
        Ok(())
    }

    /// The `i`-th `lgw`-bit digit of a named 16-byte slot, most significant
    /// nibble of each byte first — `base_2b(x, 4, ..)`.
    fn emit_nibble_of(&mut self, name: &str, i: usize) -> Result<()> {
        let byte = i / 2;
        self.pick(name)?;
        self.substr(byte, byte + 1)?;
        self.data(&[0x00])?;
        self.cat()?;
        self.op(OpBin2Num)?;
        self.f.replace(1, "_")?;
        self.num(16)?;
        self.binary_num_op(if i.is_multiple_of(2) { OpDiv } else { OpMod })
    }

    // ---- the witness queue -------------------------------------------------

    /// Fetch the next signature element onto the top of the stack.
    ///
    /// Slices a fresh blob first when the queue has run dry. Elements are
    /// stashed back on the alt stack in reverse so they pop in signature order,
    /// above whatever blobs remain.
    fn fetch(&mut self, name: &str) -> Result<()> {
        if self.pending == 0 {
            let (blob, pos) = self.plan.locate(self.next_element);
            ensure!(pos == 0, "blob {blob} was entered at element {pos}, not its start");
            self.slice_blob(self.plan.blobs[blob])?;
        }
        self.op(OpFromAltStack)?;
        self.f.push(name);
        self.note_peak();
        self.pending -= 1;
        self.next_element += 1;
        Ok(())
    }

    /// Cut one blob into `count` elements, pushed back to the alt stack in
    /// reverse order.
    fn slice_blob(&mut self, count: usize) -> Result<()> {
        self.op(OpFromAltStack)?;
        self.f.push_transient();
        self.note_peak();

        // Peel elements off the back, so the first element is stashed last and
        // ends up on top of the alt stack.
        for k in (1..count).rev() {
            let len = (k + 1) * N;
            self.dup()?;
            self.substr(len - N, len)?;
            self.op(OpToAltStack)?;
            self.f.pop()?;
            self.substr(0, len - N)?;
        }
        self.op(OpToAltStack)?;
        self.f.pop()?;
        self.pending = count;
        Ok(())
    }

    // ---- hashing -----------------------------------------------------------

    /// Emit `Trunc_n(SHA-256(prefix || message))` where the prefix is already
    /// on top of the stack and the message is the item beneath it.
    fn finish_hash(&mut self) -> Result<()> {
        self.swap()?;
        self.cat()?;
        self.sha256()?;
        self.substr(0, N)
    }
}


// =========================================================================
// Phases
// =========================================================================

impl Emitter<'_> {
    /// `H_msg(R, PK.seed, PK.root, M')` — FIPS 205 §11.2.1 for SHA2.
    ///
    /// Two SHA-256 calls: an inner digest over the whole message, then one
    /// MGF1 block. `M` is 30 bytes and MGF1 emits 32 per block, so the counter
    /// is always zero and the loop unrolls to nothing.
    ///
    /// Stack: `[.., D]` -> `[.., digest]`
    fn emit_h_msg(&mut self) -> Result<()> {
        self.fetch("r")?; // [D, R]
        self.dup()?; // R is needed again by the outer hash

        // PK.root and the empty-context prefix are constants, so they ride
        // along in the same free literal push.
        let mut tail = Vec::with_capacity(2 * N + 2);
        tail.extend_from_slice(&self.pk.seed);
        tail.extend_from_slice(&self.pk.root);
        tail.extend_from_slice(&[0u8, 0u8]); // toByte(0,1) || toByte(|ctx|,1)
        self.data(&tail)?;
        self.cat()?; // R || PK.seed || PK.root || 00 00
        self.roll("d")?;
        self.cat()?; // .. || M
        self.sha256()?; // digest1

        self.swap()?; // [digest1, R]
        let seed = self.pk.seed;
        self.data(&seed)?;
        self.cat()?; // R || PK.seed
        self.swap()?;
        self.cat()?; // R || PK.seed || digest1
        self.data(&0u32.to_be_bytes())?; // MGF1 counter
        self.cat()?;
        self.sha256()?;
        self.substr(0, M)?;
        self.name_top("digest")
    }

    /// Carve `idx_tree` and `idx_leaf` out of the digest.
    ///
    /// This is what replaces LMS's counter: the position in the hypertree is a
    /// function of the message, so nothing has to be remembered between
    /// signatures.
    fn emit_indices(&mut self) -> Result<()> {
        self.emit_be_int_from("digest", MD_LEN, IDX_TREE_LEN)?;
        self.num(1i64 << IDX_TREE_BITS)?;
        self.binary_num_op(OpMod)?;
        self.name_top("tree")?;

        self.emit_be_int_from("digest", MD_LEN + IDX_TREE_LEN, IDX_LEAF_LEN)?;
        self.num(1i64 << HP)?;
        self.binary_num_op(OpMod)?;
        self.name_top("leaf")
    }

    /// `pad || layer || treeAddress || type || keyPairAddress`, the 78-byte
    /// head shared by every hash in one context.
    fn emit_hash_context(
        &mut self,
        layer: usize,
        ty: u8,
        kp: Option<&str>,
        trailing_zero_words: usize,
    ) -> Result<()> {
        let mut base = hash_pad(&self.pk.seed);
        base.push(u8::try_from(layer).expect("layer < d"));
        self.data(&base)?;
        self.pick("tree")?;
        self.emit_be_bytes(8)?;
        self.cat()?;
        self.data(&[ty])?;
        self.cat()?;
        match kp {
            Some(slot) => {
                self.pick(slot)?;
                self.emit_be_bytes(4)?;
            }
            None => self.data(&[0u8; 4])?,
        }
        self.cat()?;
        for _ in 0..trailing_zero_words {
            self.data(&[0u8; 4])?;
            self.cat()?;
        }
        Ok(())
    }

    /// Emit one Merkle step: `H(prefix || a || b)` where the sibling order is
    /// chosen by a bit of a runtime index.
    ///
    /// Expects `[.., node, sibling, prefix]` and the bit source named by
    /// `bit_slot`. Leaves the new node.
    fn emit_merkle_step(&mut self, bit_slot: &str, bit: usize) -> Result<()> {
        self.name_top("pfx")?;
        self.roll("node")?;
        self.roll("auth")?; // [.., pfx, node, auth]

        self.pick(bit_slot)?;
        if bit > 0 {
            self.num(1i64 << bit)?;
            self.binary_num_op(OpDiv)?;
        }
        self.num(2)?;
        self.binary_num_op(OpMod)?;

        // The whole odd/even case split is one swap: the operands are the same
        // two 16-byte values, only their order differs.
        self.op(OpIf)?;
        self.f.pop()?;
        self.swap()?;
        self.op(OpEndIf)?;

        self.cat()?; // node || auth, or auth || node
        self.cat()?; // prefix || ..
        self.sha256()?;
        self.substr(0, N)?;
        self.name_top("node")
    }

    /// FORS: `k` few-time trees, each opened at one leaf, hashed into `PK_FORS`.
    ///
    /// FORS is what absorbs the residual risk of a stateless scheme. The leaf
    /// indices come from the message, so two messages can collide on a tree;
    /// `k = 14` independent trees mean a collision degrades security rather
    /// than destroying it, which is exactly the property LMS lacks.
    fn emit_fors(&mut self) -> Result<()> {
        self.emit_hash_context(0, FORS_TREE, Some("leaf"), 0)?;
        self.name_top("hcf")?;

        self.emit_hash_context(0, FORS_ROOTS, Some("leaf"), 2)?;
        self.name_top("racc")?;

        for i in 0..K {
            // indices[i] = the i-th 12-bit field of md
            let bit = i * A;
            let byte0 = bit / 8;
            let shift = 24 - A - (bit % 8);
            self.emit_be_int_from("digest", byte0, 3)?;
            if shift > 0 {
                self.num(1i64 << shift)?;
                self.binary_num_op(OpDiv)?;
            }
            self.num(1i64 << A)?;
            self.binary_num_op(OpMod)?;
            self.name_top("idx")?;

            // The tree index of the opened leaf, i * 2^a + indices[i]. Halving
            // it j+1 times gives the index at height j+1, which is why no
            // running value has to be maintained.
            self.pick("idx")?;
            self.num((i as i64) << A)?;
            self.binary_num_op(OpAdd)?;
            self.name_top("lx")?;

            self.fetch("sk")?;
            self.pick("hcf")?;
            self.data(&[0u8; 5])?; // treeHeight = 0, plus the high byte of treeIndex
            self.cat()?;
            self.pick("lx")?;
            self.emit_be_bytes(3)?;
            self.cat()?;
            self.finish_hash()?;
            self.name_top("node")?;

            for j in 0..A {
                self.fetch("auth")?;
                self.pick("lx")?;
                self.num(1i64 << (j + 1))?;
                self.binary_num_op(OpDiv)?;
                self.emit_be_bytes(3)?;
                self.pick("hcf")?;
                let mut tail = (j as u32 + 1).to_be_bytes().to_vec();
                tail.push(0x00); // high byte of the 4-byte tree index
                self.data(&tail)?;
                self.cat()?;
                self.swap()?;
                self.cat()?;
                self.emit_merkle_step("idx", j)?;
            }

            self.roll("racc")?;
            self.swap()?;
            self.cat()?;
            self.name_top("racc")?;
            self.discard("lx")?;
            self.discard("idx")?;
        }

        self.roll("racc")?;
        self.sha256()?;
        self.substr(0, N)?;
        self.name_top("node")?;
        self.discard("hcf")?;
        self.discard("digest")
    }

    /// One hypertree layer: a WOTS+ verification, then a `h'`-node auth path.
    ///
    /// Seven of these is where the on-chain cost lives. Each WOTS+ chain is
    /// unrolled to its worst case of 15 steps and gated, so an average spend
    /// executes about half of what it pays for in script bytes.
    fn emit_layer(&mut self, layer: usize) -> Result<()> {
        // The address of this layer's tree and leaf, both shifts of idx_tree.
        if layer == 0 {
            self.pick("tree")?;
            self.name_top("ltree")?;
            self.pick("leaf")?;
            self.name_top("lleaf")?;
        } else {
            self.pick("tree")?;
            self.num(1i64 << (HP * layer))?;
            self.binary_num_op(OpDiv)?;
            self.name_top("ltree")?;

            self.pick("tree")?;
            self.num(1i64 << (HP * (layer - 1)))?;
            self.binary_num_op(OpDiv)?;
            self.num(1i64 << HP)?;
            self.binary_num_op(OpMod)?;
            self.name_top("lleaf")?;
        }

        // Three hash contexts share a 73-byte base; building it once and
        // deriving keeps the per-layer setup off the hot path.
        let mut base = hash_pad(&self.pk.seed);
        base.push(u8::try_from(layer).expect("layer < d"));
        self.data(&base)?;
        self.pick("ltree")?;
        self.emit_be_bytes(8)?;
        self.cat()?;
        self.name_top("hcb")?;

        self.pick("lleaf")?;
        self.emit_be_bytes(4)?;
        self.name_top("kp4")?;

        self.pick("hcb")?;
        self.data(&[WOTS_HASH])?;
        self.cat()?;
        self.pick("kp4")?;
        self.cat()?;
        self.name_top("hcw")?;

        self.pick("hcb")?;
        self.data(&[WOTS_PK])?;
        self.cat()?;
        self.pick("kp4")?;
        self.cat()?;
        self.data(&[0u8; 8])?;
        self.cat()?;
        self.name_top("hcp")?;

        self.pick("hcb")?;
        self.data(&[TREE])?;
        self.cat()?;
        self.data(&[0u8; 4])?; // setTypeAndClear zeroes the key pair word
        self.cat()?;
        self.name_top("hct")?;

        self.discard("hcb")?;
        self.discard("kp4")?;

        self.emit_wots(layer)?;

        for k in 0..HP {
            self.fetch("auth")?;
            self.pick("lleaf")?;
            self.num(1i64 << (k + 1))?;
            self.binary_num_op(OpDiv)?;
            self.emit_be_bytes(2)?;
            self.pick("hct")?;
            let mut tail = (k as u32 + 1).to_be_bytes().to_vec();
            tail.extend_from_slice(&[0u8, 0u8]); // high half of the tree index
            self.data(&tail)?;
            self.cat()?;
            self.swap()?;
            self.cat()?;
            self.emit_merkle_step("lleaf", k)?;
        }

        self.discard("hct")?;
        self.discard("ltree")?;
        self.discard("lleaf")
    }

    /// `wots_pkFromSig`: recover a WOTS+ public key from the signature and the
    /// node being signed.
    fn emit_wots(&mut self, _layer: usize) -> Result<()> {
        // The checksum needs every message digit, so it is accumulated in its
        // own pass; the digits are then re-read per chain rather than stored,
        // which keeps 35 values off a stack that is already the binding limit.
        self.num(0)?;
        self.name_top("csum")?;
        for i in 0..LEN1 {
            self.emit_nibble_of("node", i)?;
            self.num(i64::from(W) - 1)?;
            self.swap()?;
            self.binary_num_op(OpSub)?;
            self.binary_num_op(OpAdd)?;
            self.name_top("csum")?;
        }

        self.pick("hcp")?;
        self.name_top("acc")?;

        for i in 0..LEN {
            if i < LEN1 {
                self.emit_nibble_of("node", i)?;
            } else {
                // csum is shifted left by 4 and split into three digits, which
                // for a 12-bit checksum is just its nibbles, most significant
                // first.
                self.pick("csum")?;
                match i - LEN1 {
                    0 => {
                        self.num(256)?;
                        self.binary_num_op(OpDiv)?;
                    }
                    1 => {
                        self.num(16)?;
                        self.binary_num_op(OpDiv)?;
                        self.num(16)?;
                        self.binary_num_op(OpMod)?;
                    }
                    _ => {
                        self.num(16)?;
                        self.binary_num_op(OpMod)?;
                    }
                }
            }
            self.name_top("d")?;

            // Folding the chain address into the context leaves only the hash
            // address to push per step — one byte instead of eight, over 3,675
            // emitted steps.
            self.pick("hcw")?;
            let mut chain_tail = (i as u32).to_be_bytes().to_vec();
            chain_tail.extend_from_slice(&[0u8; 3]); // high 3 bytes of hashAddress
            self.data(&chain_tail)?;
            self.cat()?;
            self.name_top("hcwi")?;
            self.roll("d")?;

            self.fetch("x")?;
            for step in 0..(W - 1) {
                self.over()?; // the digit
                self.num(i64::from(step))?;
                self.binary_num_op(OpLessThanOrEqual)?;
                self.op(OpIf)?;
                self.f.pop()?;
                self.pick("hcwi")?;
                self.data(&[u8::try_from(step).expect("step < 16")])?;
                self.cat()?;
                self.finish_hash()?;
                self.name_top("x")?;
                self.op(OpEndIf)?;
            }

            self.discard("d")?;
            self.discard("hcwi")?;
            self.roll("acc")?;
            self.swap()?;
            self.cat()?;
            self.name_top("acc")?;
        }

        self.roll("acc")?;
        self.sha256()?;
        self.substr(0, N)?;
        self.name_top("wpk")?;

        self.discard("node")?;
        self.discard("csum")?;
        self.discard("hcw")?;
        self.discard("hcp")?;
        self.name_top("node")
    }
}

/// Emit the complete vault redeem script.
///
/// The witness supplies only the signature, as blobs. The message is *not* in
/// the witness: it is reconstructed from transaction introspection, so the
/// signature commits to this spend rather than to whatever the spender cares to
/// present.
fn emit_prologue(e: &mut Emitter, blob_count: usize) -> Result<()> {
    // The witness pushed the blobs in consumption order, so moving them all to
    // the alt stack reverses them into a queue with the first-needed on top.
    // Moves between stacks are free (`push_unmetered`), which is what makes
    // the queue affordable at all.
    for _ in 0..blob_count {
        e.op(OpToAltStack)?;
    }
    Ok(())
}

/// The verifier proper, assuming the signed message is already on top of the
/// stack.
///
/// Split out from [`emit_vault_script`] so the signature machinery can be
/// executed against a *known* message and compared with the reference
/// implementation, independently of transaction introspection. The vault
/// script is this function with the message replaced by a digest the script
/// reconstructs rather than one the spender supplies.
fn emit_body(e: &mut Emitter) -> Result<()> {
    e.emit_h_msg()?;
    e.emit_indices()?;
    e.emit_fors()?;

    for layer in 0..D {
        e.emit_layer(layer)?;
    }

    e.discard("tree")?;
    e.discard("leaf")?;

    ensure!(
        e.next_element == SIG_ELEMENTS,
        "verifier consumed {} of {SIG_ELEMENTS} signature elements",
        e.next_element
    );
    ensure!(e.pending == 0, "{} sliced elements were never consumed", e.pending);
    e.f.expect_top(&["node"])?;
    ensure!(e.f.len() == 1, "verifier left {} stray stack items", e.f.len() - 1);

    let root = e.pk.root;
    e.data(&root)?;
    e.op(OpEqual)?;
    e.f.replace(2, "_")
}

/// Emit the complete vault redeem script.
pub fn emit_vault_script(
    w: &mut ScriptWriter,
    pk: &PublicKey,
    plan: &BlobPlan,
    output_count: usize,
) -> Result<usize> {
    let mut e = Emitter::new(w, *pk, plan.clone());
    emit_prologue(&mut e, plan.blob_count())?;
    vault_core::binding::emit_binding_digest(e.w, output_count)?;
    e.f.push("d");
    emit_body(&mut e)?;
    Ok(e.peak_frame)
}

/// Emit a bare signature verifier that takes its message from the witness.
///
/// **Not for a vault.** A verifier whose message comes from the witness lets
/// anyone holding a valid signature present it against any spend; it exists so
/// the FIPS 205 machinery can be differentially tested against the reference
/// on known messages, without transaction context.
pub fn emit_verify(w: &mut ScriptWriter, pk: &PublicKey, plan: &BlobPlan) -> Result<usize> {
    let mut e = Emitter::new(w, *pk, plan.clone());
    emit_prologue(&mut e, plan.blob_count())?;
    e.f.push("d");
    emit_body(&mut e)?;
    Ok(e.peak_frame)
}

/// Build a bare verifier. See [`emit_verify`] for why this is not a vault.
pub fn build_verify_script(pk: &PublicKey, plan: &BlobPlan) -> Result<VaultScript> {
    let mut w = ScriptWriter::new();
    let peak_frame = emit_verify(&mut w, pk, plan)?;
    Ok(VaultScript { script: w.build(), plan: plan.clone(), peak_frame })
}

/// Build the redeem script for a vault.
pub fn build_vault_script(
    pk: &PublicKey,
    plan: &BlobPlan,
    output_count: usize,
) -> Result<VaultScript> {
    let mut w = ScriptWriter::new();
    let peak_frame = emit_vault_script(&mut w, pk, plan, output_count)?;
    Ok(VaultScript { script: w.build(), plan: plan.clone(), peak_frame })
}

/// Where the verifier's inputs come from, so a caller cannot mix them up.
#[derive(Clone, Debug)]
pub struct VaultScript {
    pub script: Vec<u8>,
    pub plan: BlobPlan,
    /// Peak main-stack depth the emitter believed it was holding.
    pub peak_frame: usize,
}

impl VaultScript {
    /// Combined worst-case stack occupancy, which consensus caps at
    /// `MAX_STACK_SIZE` across *both* stacks.
    pub fn peak_stack(&self) -> usize {
        self.plan.peak_stack_estimate(self.peak_frame)
    }
}
