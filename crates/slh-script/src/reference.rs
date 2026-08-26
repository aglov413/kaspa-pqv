//! A host-side SLH-DSA-SHA2-128s verifier, written to mirror the emitted
//! script step for step.
//!
//! This is not a second implementation for its own sake — it is the oracle.
//! `fips205` verifies a signature and returns one boolean, which tells you
//! nothing about *where* an emitter diverges. This one exposes every
//! intermediate the script also computes (the digest, the indices, each FORS
//! root, each WOTS+ chain value, each layer's node), so a differential test can
//! point at the first opcode that is wrong rather than at "the script failed".
//!
//! It is itself checked against `fips205::slh_dsa_sha2_128s::verify` on real
//! keys and signatures, so the oracle is not trusted on its own authority.

use crate::adrs::{hash, Adrs};
use crate::params::*;
use anyhow::{ensure, Result};

/// A parsed SLH-DSA public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub seed: [u8; N],
    pub root: [u8; N],
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == PK_LEN, "public key must be {PK_LEN} bytes, got {}", bytes.len());
        let mut seed = [0u8; N];
        let mut root = [0u8; N];
        seed.copy_from_slice(&bytes[..N]);
        root.copy_from_slice(&bytes[N..]);
        Ok(Self { seed, root })
    }
}

/// A signature, split into the `n`-byte elements the script consumes.
#[derive(Clone, Debug)]
pub struct Signature {
    pub randomness: [u8; N],
    /// `k` groups of `1 + a` elements: the FORS secret value then its auth path.
    pub fors: Vec<[u8; N]>,
    /// `d` groups of `len + h'` elements: a WOTS+ signature then an auth path.
    pub ht: Vec<[u8; N]>,
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == SIG_LEN, "signature must be {SIG_LEN} bytes, got {}", bytes.len());
        let elems: Vec<[u8; N]> = bytes
            .chunks_exact(N)
            .map(|c| <[u8; N]>::try_from(c).expect("chunk is n bytes"))
            .collect();
        let fors_count = K * (1 + A);
        Ok(Self {
            randomness: elems[0],
            fors: elems[1..1 + fors_count].to_vec(),
            ht: elems[1 + fors_count..].to_vec(),
        })
    }

    /// The `i`-th FORS group: `(sk, auth[0..a])`.
    pub fn fors_group(&self, i: usize) -> (&[u8; N], &[[u8; N]]) {
        let base = i * (1 + A);
        (&self.fors[base], &self.fors[base + 1..base + 1 + A])
    }

    /// The `j`-th hypertree layer: `(wots[0..len], auth[0..h'])`.
    pub fn ht_layer(&self, j: usize) -> (&[[u8; N]], &[[u8; N]]) {
        let base = j * (LEN + HP);
        (&self.ht[base..base + LEN], &self.ht[base + LEN..base + LEN + HP])
    }
}

/// Every intermediate the script recomputes, kept so a differential test can
/// localise a divergence instead of merely observing one.
#[derive(Clone, Debug)]
pub struct Trace {
    pub digest: [u8; M],
    pub idx_tree: u64,
    pub idx_leaf: u32,
    /// `base_2b(md, a, k)` — which FORS leaf each tree opens.
    pub fors_indices: [u32; K],
    pub fors_roots: Vec<[u8; N]>,
    pub pk_fors: [u8; N],
    /// The `(tree address, key pair address)` in force at each hypertree layer.
    pub layer_addresses: Vec<(u64, u32)>,
    /// `base_2b(node, lgw, len)` including the checksum digits, per layer.
    pub wots_messages: Vec<[u32; LEN]>,
    /// The node entering each layer; `nodes[0]` is `PK_FORS`.
    pub nodes: Vec<[u8; N]>,
    /// The recomputed hypertree root, compared against `PK.root`.
    pub root: [u8; N],
}

impl Trace {
    pub fn md(&self) -> &[u8] {
        &self.digest[..MD_LEN]
    }
}

/// `H_msg(R, PK.seed, PK.root, M')` for the SHA2 parameter sets: an inner
/// SHA-256 followed by one MGF1-SHA-256 block.
///
/// `M` is 30 bytes and MGF1 emits 32 per block, so the counter only ever takes
/// the value zero — the script emits a single truncated block, not a loop.
pub fn h_msg(r: &[u8; N], pk: &PublicKey, message: &[u8]) -> [u8; M] {
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

    let mut out = [0u8; M];
    out.copy_from_slice(&block[..M]);
    out
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

/// The WOTS+ message digits: `len1` nibbles of `m`, then `len2` checksum
/// nibbles.
pub fn wots_message(m: &[u8; N]) -> [u32; LEN] {
    let mut msg = [0u32; LEN];
    let base = base_2b(m, LGW, LEN1);
    msg[..LEN1].copy_from_slice(&base);

    let csum: u32 = base.iter().map(|d| W - 1 - d).sum();
    // len2 * lgw = 12 bits, so the shift is 4 and the three digits are simply
    // the nibbles of the 12-bit checksum, most significant first.
    let shifted = csum << ((8 - ((LEN2 as u32 * LGW) & 7)) & 7);
    let bytes = (shifted as u16).to_be_bytes();
    msg[LEN1..].copy_from_slice(&base_2b(&bytes, LGW, LEN2));
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
    pk_seed: &[u8; N],
    adrs: &Adrs,
    sig: &[[u8; N]],
    m: &[u8; N],
) -> ([u8; N], [u32; LEN]) {
    let msg = wots_message(m);
    let mut adrs = *adrs;
    let mut tmp = Vec::with_capacity(LEN);
    for (i, digit) in msg.iter().enumerate() {
        adrs.set_chain_address(i as u32);
        tmp.push(chain(pk_seed, &adrs, sig[i], *digit, W - 1 - digit));
    }

    let mut pk_adrs = adrs;
    pk_adrs.set_type_and_clear(WOTS_PK);
    pk_adrs.set_key_pair_address(adrs.key_pair_address());
    let parts: Vec<&[u8]> = tmp.iter().map(|t| t.as_slice()).collect();
    (hash(pk_seed, &pk_adrs, &parts), msg)
}

/// `xmss_pkFromSig`: a WOTS+ public key plus an auth path gives a subtree root.
pub fn xmss_pk_from_sig(
    pk_seed: &[u8; N],
    adrs: &Adrs,
    idx: u32,
    wots_sig: &[[u8; N]],
    auth: &[[u8; N]],
    m: &[u8; N],
) -> ([u8; N], [u32; LEN]) {
    let mut adrs = *adrs;
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair_address(idx);
    let (mut node, msg) = wots_pk_from_sig(pk_seed, &adrs, wots_sig, m);

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

/// Verify, returning the full trace whether or not it succeeds.
///
/// Failure is reported by `trace.root != pk.root`, not by an early return, so
/// a negative test can still see how far the computation agreed.
pub fn verify_traced(pk: &PublicKey, sig: &Signature, message: &[u8]) -> Trace {
    let digest = h_msg(&sig.randomness, pk, &context_prefixed(message));

    let md = &digest[..MD_LEN];
    let idx_tree = to_int(&digest[MD_LEN..MD_LEN + IDX_TREE_LEN])
        & (u64::MAX >> (64 - IDX_TREE_BITS));
    let idx_leaf = (to_int(&digest[MD_LEN + IDX_TREE_LEN..]) & ((1 << HP) - 1)) as u32;

    // --- FORS ---------------------------------------------------------------
    let mut adrs = Adrs::new();
    adrs.set_tree_address(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair_address(idx_leaf);

    let indices_vec = base_2b(md, A as u32, K);
    let mut fors_indices = [0u32; K];
    fors_indices.copy_from_slice(&indices_vec);

    let mut fors_roots = Vec::with_capacity(K);
    for (i, &idx) in fors_indices.iter().enumerate() {
        let (sk, auth) = sig.fors_group(i);
        let leaf_index = ((i as u32) << A) + idx;

        adrs.set_tree_height(0);
        adrs.set_tree_index(leaf_index);
        let mut node = hash(&pk.seed, &adrs, &[sk]);

        for (j, sibling) in auth.iter().enumerate() {
            adrs.set_tree_height(j as u32 + 1);
            adrs.set_tree_index(leaf_index >> (j + 1));
            node = if (idx >> j) & 1 == 0 {
                hash(&pk.seed, &adrs, &[&node, sibling])
            } else {
                hash(&pk.seed, &adrs, &[sibling, &node])
            };
        }
        fors_roots.push(node);
    }

    let mut roots_adrs = adrs;
    roots_adrs.set_type_and_clear(FORS_ROOTS);
    roots_adrs.set_key_pair_address(idx_leaf);
    let root_parts: Vec<&[u8]> = fors_roots.iter().map(|r| r.as_slice()).collect();
    let pk_fors = hash(&pk.seed, &roots_adrs, &root_parts);

    // --- Hypertree ----------------------------------------------------------
    let mut node = pk_fors;
    let mut nodes = vec![pk_fors];
    let mut layer_addresses = Vec::with_capacity(D);
    let mut wots_messages = Vec::with_capacity(D);

    let mut tree = idx_tree;
    let mut leaf = idx_leaf;
    for layer in 0..D {
        if layer > 0 {
            leaf = (tree & ((1 << HP) - 1)) as u32;
            tree >>= HP;
        }
        layer_addresses.push((tree, leaf));

        let mut layer_adrs = Adrs::new();
        layer_adrs.set_layer(layer as u32);
        layer_adrs.set_tree_address(tree);

        let (wots_sig, auth) = sig.ht_layer(layer);
        let (next, msg) =
            xmss_pk_from_sig(&pk.seed, &layer_adrs, leaf, wots_sig, auth, &node);
        wots_messages.push(msg);
        node = next;
        nodes.push(node);
    }

    Trace {
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
