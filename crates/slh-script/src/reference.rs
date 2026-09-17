//! A host-side SLH-DSA verifier, written to mirror the emitted script step for
//! step, for any supported parameter set.
//!
//! This is not a second implementation for its own sake — it is the oracle.
//! `fips205` verifies a signature and returns one boolean, which tells you
//! nothing about *where* an emitter diverges. This one exposes every
//! intermediate the script also computes (the digest, the indices, each FORS
//! root, each WOTS+ chain value, each layer's node), so a differential test can
//! point at the first opcode that is wrong rather than at "the script failed".
//!
//! For `128s` it is itself checked against `fips205::slh_dsa_sha2_128s::verify`
//! on real keys and signatures, so the oracle is not trusted on its own
//! authority. The other two sets have no third-party implementation to check
//! against — nobody ships SP 800-230 yet — so what stands behind them instead
//! is that this code is *the same code*: one implementation, parameterised,
//! whose `128s` instantiation is pinned to an independent one.

use crate::adrs::{hash, Adrs};
use crate::params::*;
use anyhow::{ensure, Result};

/// A parsed SLH-DSA public key.
///
/// The parameter set is not stored: a public key is 32 bytes under every set
/// supported here, so the bytes alone cannot say which one they belong to.
/// That is a property of SLH-DSA, not an omission — the set is carried by the
/// vault, the derivation path and the script, all of which name it explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub seed: [u8; N],
    pub root: [u8; N],
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == 2 * N, "public key must be {} bytes, got {}", 2 * N, bytes.len());
        let mut seed = [0u8; N];
        let mut root = [0u8; N];
        seed.copy_from_slice(&bytes[..N]);
        root.copy_from_slice(&bytes[N..]);
        Ok(Self { seed, root })
    }

    pub fn to_bytes(self) -> [u8; 2 * N] {
        let mut out = [0u8; 2 * N];
        out[..N].copy_from_slice(&self.seed);
        out[N..].copy_from_slice(&self.root);
        out
    }
}

/// A signature, split into the `n`-byte elements the script consumes.
#[derive(Clone, Debug)]
pub struct Signature {
    /// Which set this signature was parsed under. Two sets can produce
    /// signatures of the same length in principle, so the layout is never
    /// inferred from the byte count alone.
    pub p: &'static Params,
    pub randomness: [u8; N],
    /// `k` groups of `1 + a` elements: the FORS secret value then its auth path.
    pub fors: Vec<[u8; N]>,
    /// `d` groups of `len + h'` elements: a WOTS+ signature then an auth path.
    pub ht: Vec<[u8; N]>,
}

impl Signature {
    pub fn from_bytes(p: &'static Params, bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == p.sig_len(),
            "{} signature must be {} bytes, got {}",
            p.name,
            p.sig_len(),
            bytes.len()
        );
        let elems: Vec<[u8; N]> = bytes
            .chunks_exact(N)
            .map(|c| <[u8; N]>::try_from(c).expect("chunk is n bytes"))
            .collect();
        let fors_count = p.k * (1 + p.a);
        Ok(Self {
            p,
            randomness: elems[0],
            fors: elems[1..1 + fors_count].to_vec(),
            ht: elems[1 + fors_count..].to_vec(),
        })
    }

    /// Serialise back to the wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.p.sig_len());
        out.extend_from_slice(&self.randomness);
        for e in self.fors.iter().chain(self.ht.iter()) {
            out.extend_from_slice(e);
        }
        out
    }

    /// The `i`-th FORS group: `(sk, auth[0..a])`.
    pub fn fors_group(&self, i: usize) -> (&[u8; N], &[[u8; N]]) {
        let base = i * (1 + self.p.a);
        (&self.fors[base], &self.fors[base + 1..base + 1 + self.p.a])
    }

    /// The `j`-th hypertree layer: `(wots[0..len], auth[0..h'])`.
    pub fn ht_layer(&self, j: usize) -> (&[[u8; N]], &[[u8; N]]) {
        let (len, hp) = (self.p.len(), self.p.hp);
        let base = j * (len + hp);
        (&self.ht[base..base + len], &self.ht[base + len..base + len + hp])
    }
}

/// Every intermediate the script recomputes, kept so a differential test can
/// localise a divergence instead of merely observing one.
#[derive(Clone, Debug)]
pub struct Trace {
    pub p: &'static Params,
    /// `H_msg` output, `m` bytes.
    pub digest: Vec<u8>,
    pub idx_tree: u64,
    pub idx_leaf: u32,
    /// `base_2b(md, a, k)` — which FORS leaf each tree opens.
    pub fors_indices: Vec<u32>,
    pub fors_roots: Vec<[u8; N]>,
    pub pk_fors: [u8; N],
    /// The `(tree address, key pair address)` in force at each hypertree layer.
    pub layer_addresses: Vec<(u64, u32)>,
    /// `base_2b(node, lgw, len)` including the checksum digits, per layer.
    pub wots_messages: Vec<Vec<u32>>,
    /// The node entering each layer; `nodes[0]` is `PK_FORS`.
    pub nodes: Vec<[u8; N]>,
    /// The recomputed hypertree root, compared against `PK.root`.
    pub root: [u8; N],
}

impl Trace {
    pub fn md(&self) -> &[u8] {
        &self.digest[..self.p.md_len()]
    }
}

/// `H_msg(R, PK.seed, PK.root, M')` for the SHA2 parameter sets: an inner
/// SHA-256 followed by one MGF1-SHA-256 block.
///
/// `m` is at most 30 bytes for every supported set and MGF1 emits 32 per
/// block, so the counter only ever takes the value zero — the script emits a
/// single truncated block, not a loop.
pub fn h_msg(p: &Params, r: &[u8; N], pk: &PublicKey, message: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut inner = Sha256::new();
    inner.update(r);
    inner.update(pk.seed);
    inner.update(pk.root);
    inner.update(message);
    let digest1 = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(r);
    outer.update(pk.seed);
    outer.update(digest1);
    outer.update(0u32.to_be_bytes());
    let block = outer.finalize();

    block[..p.m].to_vec()
}

/// `M' = toByte(0,1) || toByte(|ctx|,1) || ctx || M`, FIPS 205 Algorithm 19.
///
/// The vault always signs with an empty context, so the prefix is two zero
/// bytes. They are not decorative: omitting them makes every signature this
/// verifier accepts un-verifiable by any standards-conforming implementation,
/// which would quietly turn the vault into a private scheme.
pub fn context_prefixed(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + message.len());
    out.extend_from_slice(&[0u8, 0u8]);
    out.extend_from_slice(message);
    out
}

/// `base_2b(x, b, out_len)`: big-endian `b`-bit fields, MSB first.
pub fn base_2b(x: &[u8], b: u32, out_len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_len);
    let (mut inn, mut bits, mut total) = (0usize, 0u32, 0u64);
    for _ in 0..out_len {
        while bits < b {
            total = (total << 8) + u64::from(x[inn]);
            inn += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((total >> bits) & ((1u64 << b) - 1)) as u32);
    }
    out
}

/// `toInt(x, n)`: a big-endian byte string as an integer.
pub fn to_int(x: &[u8]) -> u64 {
    x.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

/// The WOTS+ message digits: `len1` digits of `m`, then `len2` checksum digits.
pub fn wots_message(p: &Params, m: &[u8; N]) -> Vec<u32> {
    let mut msg = base_2b(m, p.lgw, p.len1());

    let csum: u32 = msg.iter().map(|d| p.w() - 1 - d).sum();
    // The checksum spans `len2 * lgw` bits, left-shifted so the field ends on a
    // byte boundary; `base_2b` then reads it back as `len2` digits. For every
    // set here that is the same as taking the digits of `csum` directly, but
    // the shift is what the standard says and what a set with an odd `len2`
    // would need.
    let shift = (8 - (p.csum_bits() & 7)) & 7;
    let width = ((p.csum_bits() + shift) / 8) as usize;
    let bytes = ((csum as u64) << shift).to_be_bytes();
    msg.extend(base_2b(&bytes[8 - width..], p.lgw, p.len2()));
    msg
}

/// `chain(X, i, s, PK.seed, ADRS)`: `s` iterations of `F` from hash address `i`.
pub fn chain(pk_seed: &[u8; N], adrs: &Adrs, x: [u8; N], i: u32, s: u32) -> [u8; N] {
    let mut adrs = *adrs;
    let mut tmp = x;
    for j in i..i + s {
        adrs.set_hash_address(j);
        tmp = hash(pk_seed, &adrs, &[&tmp]);
    }
    tmp
}

/// `wots_pkFromSig`: recover the WOTS+ public key a signature implies.
pub fn wots_pk_from_sig(
    p: &Params,
    pk_seed: &[u8; N],
    adrs: &Adrs,
    sig: &[[u8; N]],
    m: &[u8; N],
) -> ([u8; N], Vec<u32>) {
    let msg = wots_message(p, m);
    let mut adrs = *adrs;
    let mut tmp = Vec::with_capacity(p.len());
    for (i, digit) in msg.iter().enumerate() {
        adrs.set_chain_address(i as u32);
        tmp.push(chain(pk_seed, &adrs, sig[i], *digit, p.w() - 1 - digit));
    }

    let mut pk_adrs = adrs;
    pk_adrs.set_type_and_clear(WOTS_PK);
    pk_adrs.set_key_pair_address(adrs.key_pair_address());
    let parts: Vec<&[u8]> = tmp.iter().map(|t| t.as_slice()).collect();
    (hash(pk_seed, &pk_adrs, &parts), msg)
}

/// `xmss_pkFromSig`: a WOTS+ public key plus an auth path gives a subtree root.
pub fn xmss_pk_from_sig(
    p: &Params,
    pk_seed: &[u8; N],
    adrs: &Adrs,
    idx: u32,
    wots_sig: &[[u8; N]],
    auth: &[[u8; N]],
    m: &[u8; N],
) -> ([u8; N], Vec<u32>) {
    let mut adrs = *adrs;
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair_address(idx);
    let (mut node, msg) = wots_pk_from_sig(p, pk_seed, &adrs, wots_sig, m);

    adrs.set_type_and_clear(TREE);
    adrs.set_tree_index(idx);
    for (k, sibling) in auth.iter().enumerate() {
        adrs.set_tree_height(k as u32 + 1);
        // Both branches divide the running index by two; only the operand
        // order differs. Writing it as a shift makes that explicit — the
        // emitted script computes `idx >> (k+1)` directly rather than
        // maintaining a running halved value.
        adrs.set_tree_index(idx >> (k + 1));
        node = if (idx >> k) & 1 == 0 {
            hash(pk_seed, &adrs, &[&node, sibling])
        } else {
            hash(pk_seed, &adrs, &[sibling, &node])
        };
    }
    (node, msg)
}

/// Split `H_msg` output into `(md, idx_tree, idx_leaf)`.
///
/// Shared with the signer, which has to land on the same hypertree position
/// the verifier will recompute. `idx_tree` is the constant zero when `d == 1`,
/// where the digest carries no tree index at all.
pub fn split_digest(p: &Params, digest: &[u8]) -> (Vec<u8>, u64, u32) {
    let md = digest[..p.md_len()].to_vec();
    let idx_tree = if p.idx_tree_bits() == 0 {
        0
    } else {
        to_int(&digest[p.md_len()..p.md_len() + p.idx_tree_len()])
            & (u64::MAX >> (64 - p.idx_tree_bits()))
    };
    let idx_leaf = (to_int(&digest[p.md_len() + p.idx_tree_len()..]) & ((1 << p.hp) - 1)) as u32;
    (md, idx_tree, idx_leaf)
}

/// `fors_pkFromSig`, returning each tree's root as well as `PK_FORS`.
///
/// Takes the FORS elements rather than a whole [`Signature`], because the
/// signer needs `PK_FORS` at a point where the rest of the signature does not
/// exist yet — and both sides deriving it from the same function is what keeps
/// signer and verifier from disagreeing about what FORS produced.
pub fn fors_pk_from_sig(
    p: &Params,
    pk_seed: &[u8; N],
    adrs: &Adrs,
    fors: &[[u8; N]],
    md: &[u8],
) -> (Vec<u32>, Vec<[u8; N]>, [u8; N]) {
    let mut adrs = *adrs;
    let indices = base_2b(md, p.a as u32, p.k);

    let mut fors_roots = Vec::with_capacity(p.k);
    for (i, &idx) in indices.iter().enumerate() {
        let group = i * (1 + p.a);
        let (sk, auth) = (&fors[group], &fors[group + 1..group + 1 + p.a]);
        let leaf_index = ((i as u32) << p.a) + idx;

        adrs.set_tree_height(0);
        adrs.set_tree_index(leaf_index);
        let mut node = hash(pk_seed, &adrs, &[sk]);

        for (j, sibling) in auth.iter().enumerate() {
            adrs.set_tree_height(j as u32 + 1);
            adrs.set_tree_index(leaf_index >> (j + 1));
            node = if (idx >> j) & 1 == 0 {
                hash(pk_seed, &adrs, &[&node, sibling])
            } else {
                hash(pk_seed, &adrs, &[sibling, &node])
            };
        }
        fors_roots.push(node);
    }

    let mut roots_adrs = adrs;
    roots_adrs.set_type_and_clear(FORS_ROOTS);
    roots_adrs.set_key_pair_address(adrs.key_pair_address());
    let root_parts: Vec<&[u8]> = fors_roots.iter().map(|r| r.as_slice()).collect();
    let pk_fors = hash(pk_seed, &roots_adrs, &root_parts);
    (indices, fors_roots, pk_fors)
}

/// Verify, returning the full trace whether or not it succeeds.
///
/// Failure is reported by `trace.root != pk.root`, not by an early return, so
/// a negative test can still see how far the computation agreed.
pub fn verify_traced(pk: &PublicKey, sig: &Signature, message: &[u8]) -> Trace {
    let p = sig.p;
    let digest = h_msg(p, &sig.randomness, pk, &context_prefixed(message));
    let (md, idx_tree, idx_leaf) = split_digest(p, &digest);

    // --- FORS ---------------------------------------------------------------
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair_address(idx_leaf);

    let (fors_indices, fors_roots, pk_fors) =
        fors_pk_from_sig(p, &pk.seed, &adrs, &sig.fors, &md);

    // --- Hypertree ----------------------------------------------------------
    let mut node = pk_fors;
    let mut nodes = vec![pk_fors];
    let mut layer_addresses = Vec::with_capacity(p.d);
    let mut wots_messages = Vec::with_capacity(p.d);

    let mut tree = idx_tree;
    let mut leaf = idx_leaf;
    for layer in 0..p.d {
        if layer > 0 {
            leaf = (tree & ((1 << p.hp) - 1)) as u32;
            tree >>= p.hp;
        }
        layer_addresses.push((tree, leaf));

        let mut layer_adrs = Adrs::new();
        layer_adrs.set_layer(layer as u32);
        layer_adrs.set_tree_address(tree);

        let (wots_sig, auth) = sig.ht_layer(layer);
        let (next, msg) =
            xmss_pk_from_sig(p, &pk.seed, &layer_adrs, leaf, wots_sig, auth, &node);
        wots_messages.push(msg);
        node = next;
        nodes.push(node);
    }

    Trace {
        p,
        digest,
        idx_tree,
        idx_leaf,
        fors_indices,
        fors_roots,
        pk_fors,
        layer_addresses,
        wots_messages,
        nodes,
        root: node,
    }
}

/// Verify, as a boolean.
pub fn verify(pk: &PublicKey, sig: &Signature, message: &[u8]) -> bool {
    verify_traced(pk, sig, message).root == pk.root
}
