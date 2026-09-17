//! Key generation and signing, for every parameter set this crate emits a
//! verifier for.
//!
//! # Why this exists at all
//!
//! `fips205` implements the twelve sets FIPS 205 standardises, and nothing
//! implements the ones SP 800-230 proposes — the draft is months old and has no
//! reference code. A parameter set that cannot sign cannot be measured
//! end-to-end, and a measurement that stops short of a real signature is a
//! model, which is the thing this workspace exists not to produce.
//!
//! So this is a full FIPS 205 signer, parameterised. It is **not** a
//! replacement for `fips205` in any security sense: it exists to make the two
//! unstandardised sets measurable, and its `128s` instantiation is held against
//! `fips205` key-for-key and signature-for-signature by
//! `reference_oracle::the_signer_reproduces_fips205`. That test is what makes
//! the other two sets believable, since the code under them is identical and
//! only the constants differ.
//!
//! # Where the time goes
//!
//! Signing an XMSS tree of height `h'` costs `2^h'` WOTS+ public keys, and each
//! of those is `len` chains of `w - 1` hashes. That product is the entire story
//! of why the three sets sign so differently:
//!
//! | | leaves per tree | hashes per leaf | per signature |
//! |---|---|---|---|
//! | `128s` | 512 | ~175 | ~4 million |
//! | `128-24` | 4,194,304 | ~290 | ~1.5 billion |
//! | `128-24d2` | 4,096 | ~290 | ~2 million |
//!
//! `128-24`'s column is not a defect — SP 800-230 is explicit that it targets
//! "sign-once, verify-many", where the signer is a build server and the
//! verifiers are everyone. It is simply the number a vault owner would be
//! paying, on whatever machine holds the key, and it deserves to be measured
//! rather than asserted.
//!
//! Two things keep that number from being worse than it has to be. The first
//! 64 bytes of every SLH-DSA hash are `PK.seed || toByte(0, 48)`, constant for
//! the life of a key, so [`Midstate`] compresses that block once and every hash
//! starts from the result — close to half the compression function calls for
//! the short messages that dominate. The second is that leaves are computed on
//! all cores.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::adrs::{Adrs, ADRS_LEN};
use crate::params::*;
use crate::reference::{base_2b, fors_pk_from_sig, h_msg, split_digest, wots_message, PublicKey};

/// The SHA-256 initial hash value, FIPS 180-4 §5.3.3.
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// `SHA-256` resumed after the constant first block.
///
/// Every hash in the SHA2 parameter sets is
/// `SHA-256(PK.seed || toByte(0, 64-n) || ADRS^c || M)`, whose first 64 bytes
/// are exactly one compression block and are the same for every hash under one
/// key. Compressing it once per key rather than once per hash removes a block
/// from a 2-block hash, and the signer does over a billion of them.
///
/// This is an optimisation of [`crate::adrs::hash`], not a variant of it:
/// `matches_the_plain_hasher` holds the two against each other on random
/// inputs, because a midstate that drifted would produce a key nothing else in
/// the world agrees with.
#[derive(Clone, Copy)]
pub struct Midstate {
    state: [u32; 8],
}

impl Midstate {
    pub fn new(pk_seed: &[u8; N]) -> Self {
        let mut block = [0u8; 64];
        block[..N].copy_from_slice(pk_seed);
        let mut state = SHA256_IV;
        sha2::compress256(&mut state, &[block.into()]);
        Self { state }
    }

    /// `Trunc_n(SHA-256(PK.seed || pad || ADRS^c || M))`, resumed from the
    /// midstate.
    ///
    /// Assembles into a stack buffer rather than a `Vec`. Signing a `128-24`
    /// key calls this over a billion times, and a heap allocation per call is
    /// the difference between minutes and tens of minutes.
    pub fn hash(&self, adrs: &Adrs, parts: &[&[u8]]) -> [u8; N] {
        use sha2::digest::generic_array::GenericArray;

        let tail: usize = parts.iter().map(|p| p.len()).sum();
        let total = 64 + ADRS_LEN + tail;

        // The longest message any SLH-DSA hash takes is `T_len`'s `len` chain
        // values; `len` is 68 at its largest here, so 1088 bytes plus the
        // address and SHA-256's own padding.
        let mut buf = [0u8; BUF_LEN];
        assert!(
            ADRS_LEN + tail + 72 <= BUF_LEN,
            "a {tail}-byte hash message does not fit the midstate buffer"
        );

        buf[..ADRS_LEN].copy_from_slice(adrs.as_bytes());
        let mut at = ADRS_LEN;
        for part in parts {
            buf[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        buf[at] = 0x80;
        at += 1;
        let padded = (at + 8).div_ceil(64) * 64;
        buf[padded - 8..padded].copy_from_slice(&((total as u64) * 8).to_be_bytes());

        let mut state = self.state;
        for block in buf[..padded].chunks_exact(64) {
            // `from_slice` is a reference cast, so the block is compressed
            // where it already sits rather than copied into a GenericArray.
            sha2::compress256(&mut state, core::slice::from_ref(GenericArray::from_slice(block)));
        }

        let mut out = [0u8; N];
        for (i, word) in state.iter().take(N / 4).enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Stack buffer for one hash preimage: the address, the longest message any
/// parameter set produces (`len * n`, 1088 bytes), and SHA-256's padding.
const BUF_LEN: usize = 1280;

/// The three secrets FIPS 205 Algorithm 21 draws.
///
/// `SK.seed` generates every secret value in the key; `SK.prf` derandomises
/// signing; `PK.seed` is public and is the key's domain separator. All three
/// are `n` bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretSeeds {
    pub sk_seed: [u8; N],
    pub sk_prf: [u8; N],
    pub pk_seed: [u8; N],
}

impl core::fmt::Debug for SecretSeeds {
    /// Redacted deliberately: these are the whole key, and a `{:?}` in a log
    /// line is a plausible way to lose a vault.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretSeeds(<redacted>, pk_seed={})", hex::encode(self.pk_seed))
    }
}

/// How large a leaf layer may be kept between signatures, in bytes.
///
/// `128-24` is one tree of 4,194,304 leaves — 67 MB at `n = 16` — and it is
/// the same tree for every signature that key will ever make. Holding it turns
/// the second signature from a minute into a second. The other two sets have
/// trees of a few thousand leaves, where the cache is irrelevant either way.
const LEAF_CACHE_BYTES: usize = 128 << 20;

/// One cached leaf layer: which `(layer, tree address)` it belongs to, and the
/// `2^h'` WOTS+ public keys themselves.
type LeafCache = Mutex<Option<(usize, u64, Arc<Vec<[u8; N]>>)>>;

/// A key pair, and enough cached work to sign more than once without paying
/// for the hypertree twice.
pub struct SigningKey {
    pub p: &'static Params,
    seeds: SecretSeeds,
    public: PublicKey,
    mid: Midstate,
    /// The most recently built leaf layer.
    leaves: LeafCache,
}

impl SigningKey {
    /// `slh_keygen_internal(SK.seed, SK.prf, PK.seed)`, FIPS 205 Algorithm 18.
    ///
    /// Takes its secrets as arguments rather than drawing them, which is what
    /// makes a vault reproducible from a mnemonic. For `128-24` this builds a
    /// tree of four million leaves and takes about a hundred seconds.
    pub fn generate(p: &'static Params, seeds: SecretSeeds) -> Self {
        let mid = Midstate::new(&seeds.pk_seed);
        let key = Self {
            p,
            seeds,
            public: PublicKey { seed: seeds.pk_seed, root: [0u8; N] },
            mid,
            leaves: Mutex::new(None),
        };
        // The top layer's single tree; its root is the public key.
        let (root, _) = key.xmss_tree(p.d - 1, 0, 0);
        Self { public: PublicKey { seed: seeds.pk_seed, root }, ..key }
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// `slh_sign_internal` with `opt_rand = PK.seed`, FIPS 205 Algorithm 19.
    ///
    /// Deterministic, which is what a vault wants: a cold signer may have no
    /// entropy worth trusting, and a rebuilt spend has to reproduce byte for
    /// byte so its compute budget stays the one that was measured.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let p = self.p;
        let m_prime = crate::reference::context_prefixed(message);

        // PRF_msg(SK.prf, opt_rand, M') = Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M')).
        let mut prf_input = Vec::with_capacity(N + m_prime.len());
        prf_input.extend_from_slice(&self.seeds.pk_seed); // opt_rand, deterministic variant
        prf_input.extend_from_slice(&m_prime);
        let mut randomness = [0u8; N];
        randomness.copy_from_slice(&hmac_sha256(&self.seeds.sk_prf, &prf_input)[..N]);

        let digest = h_msg(p, &randomness, &self.public, &m_prime);
        let (md, idx_tree, idx_leaf) = split_digest(p, &digest);

        let mut out = Vec::with_capacity(p.sig_len());
        out.extend_from_slice(&randomness);

        // --- FORS -----------------------------------------------------------
        let mut fors_adrs = Adrs::new();
        fors_adrs.set_tree_address(idx_tree);
        fors_adrs.set_type_and_clear(FORS_TREE);
        fors_adrs.set_key_pair_address(idx_leaf);
        let fors_sig = self.fors_sign(&fors_adrs, &md);
        for e in &fors_sig {
            out.extend_from_slice(e);
        }

        // The message the hypertree signs is PK_FORS, recovered through the
        // verifier's own path rather than recomputed here — one definition of
        // what FORS produced, shared by both sides.
        let (_, _, pk_fors) = fors_pk_from_sig(p, &self.seeds.pk_seed, &fors_adrs, &fors_sig, &md);

        // --- Hypertree ------------------------------------------------------
        let mut node = pk_fors;
        let mut tree = idx_tree;
        let mut leaf = idx_leaf;
        for layer in 0..p.d {
            if layer > 0 {
                leaf = (tree & ((1 << p.hp) - 1)) as u32;
                tree >>= p.hp;
            }
            let mut adrs = Adrs::new();
            adrs.set_layer(layer as u32);
            adrs.set_tree_address(tree);

            let wots = self.wots_sign(&node, layer, tree, leaf);
            for e in &wots {
                out.extend_from_slice(e);
            }
            let (root, auth) = self.xmss_tree(layer, tree, leaf);
            for e in &auth {
                out.extend_from_slice(e);
            }
            node = root;
        }

        debug_assert_eq!(out.len(), p.sig_len());
        out
    }

    // ---- WOTS+ ------------------------------------------------------------

    /// The secret value of chain `i`, `PRF(PK.seed, SK.seed, skADRS)`.
    fn wots_sk(&self, layer: usize, tree: u64, kp: u32, i: usize) -> [u8; N] {
        let mut adrs = Adrs::new();
        adrs.set_layer(layer as u32);
        adrs.set_tree_address(tree);
        adrs.set_type_and_clear(WOTS_PRF);
        adrs.set_key_pair_address(kp);
        adrs.set_chain_address(i as u32);
        self.mid.hash(&adrs, &[&self.seeds.sk_seed])
    }

    /// `chain(X, i, s, PK.seed, ADRS)`.
    fn chain(&self, adrs: &Adrs, x: [u8; N], start: u32, steps: u32) -> [u8; N] {
        let mut adrs = *adrs;
        let mut tmp = x;
        for j in start..start + steps {
            adrs.set_hash_address(j);
            tmp = self.mid.hash(&adrs, &[&tmp]);
        }
        tmp
    }

    /// `wots_pkGen`, FIPS 205 Algorithm 6 — one XMSS leaf.
    fn wots_pk_gen(&self, layer: usize, tree: u64, kp: u32) -> [u8; N] {
        let p = self.p;
        let mut adrs = Adrs::new();
        adrs.set_layer(layer as u32);
        adrs.set_tree_address(tree);
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair_address(kp);

        let mut tmp = Vec::with_capacity(p.len());
        for i in 0..p.len() {
            let sk = self.wots_sk(layer, tree, kp, i);
            adrs.set_chain_address(i as u32);
            tmp.push(self.chain(&adrs, sk, 0, p.w() - 1));
        }

        let mut pk_adrs = adrs;
        pk_adrs.set_type_and_clear(WOTS_PK);
        pk_adrs.set_key_pair_address(kp);
        let parts: Vec<&[u8]> = tmp.iter().map(|t| t.as_slice()).collect();
        self.mid.hash(&pk_adrs, &parts)
    }

    /// `wots_sign`, FIPS 205 Algorithm 7.
    fn wots_sign(&self, m: &[u8; N], layer: usize, tree: u64, kp: u32) -> Vec<[u8; N]> {
        let p = self.p;
        let msg = wots_message(p, m);
        let mut adrs = Adrs::new();
        adrs.set_layer(layer as u32);
        adrs.set_tree_address(tree);
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair_address(kp);

        msg.iter()
            .enumerate()
            .map(|(i, &digit)| {
                let sk = self.wots_sk(layer, tree, kp, i);
                adrs.set_chain_address(i as u32);
                self.chain(&adrs, sk, 0, digit)
            })
            .collect()
    }

    // ---- FORS -------------------------------------------------------------

    /// `fors_sign`, FIPS 205 Algorithm 16: `k` groups of a secret value and an
    /// auth path.
    /// The `k` trees are independent, so they are built on `k` threads. Under
    /// `128-24` each is 16.7 million leaves and this is most of what signing
    /// costs; under the other two sets the threads are noise either way.
    fn fors_sign(&self, adrs: &Adrs, md: &[u8]) -> Vec<[u8; N]> {
        let p = self.p;
        let indices = base_2b(md, p.a as u32, p.k);

        let groups: Vec<Vec<[u8; N]>> = std::thread::scope(|scope| {
            let handles: Vec<_> = indices
                .iter()
                .enumerate()
                .map(|(i, &idx)| scope.spawn(move || self.fors_tree(adrs, i, idx)))
                .collect();
            handles.into_iter().map(|h| h.join().expect("FORS worker panicked")).collect()
        });

        groups.concat()
    }

    /// One FORS tree's group: its opened secret value, then its auth path.
    fn fors_tree(&self, adrs: &Adrs, i: usize, idx: u32) -> Vec<[u8; N]> {
        let p = self.p;
        let base = i as u64;

        // The tree index is global across all k trees: tree `i`'s leaf `j` is
        // index `i * 2^a + j`, and a node at height `z` is at
        // `i * 2^(a-z) + (j >> z)`. Getting this wrong gives a signer that is
        // self-consistent and produces signatures nothing verifies.
        let (_, auth) = treehash_auth(
            p.a,
            idx,
            |local| {
                let global = (base << p.a) + local;
                let sk = self.fors_sk(adrs, global);
                let mut leaf_adrs = *adrs;
                leaf_adrs.set_tree_height(0);
                leaf_adrs.set_tree_index(global as u32);
                self.mid.hash(&leaf_adrs, &[&sk])
            },
            |height, index, left, right| {
                let global = (base << (p.a - height)) + index;
                let mut node_adrs = *adrs;
                node_adrs.set_tree_height(height as u32);
                node_adrs.set_tree_index(global as u32);
                self.mid.hash(&node_adrs, &[left, right])
            },
        );

        let mut group = Vec::with_capacity(1 + p.a);
        group.push(self.fors_sk(adrs, (base << p.a) + u64::from(idx)));
        group.extend(auth);
        group
    }

    /// `fors_skGen`, FIPS 205 Algorithm 14.
    fn fors_sk(&self, adrs: &Adrs, index: u64) -> [u8; N] {
        let mut sk_adrs = *adrs;
        sk_adrs.set_type_and_clear(FORS_PRF);
        sk_adrs.set_key_pair_address(adrs.key_pair_address());
        sk_adrs.set_tree_index(index as u32);
        self.mid.hash(&sk_adrs, &[&self.seeds.sk_seed])
    }

    // ---- XMSS -------------------------------------------------------------

    /// The root of one XMSS tree and the auth path opening `target`.
    ///
    /// The leaf layer is cached, because a `d = 1` set signs from the same
    /// four-million-leaf tree every time and rebuilding it per signature would
    /// double an already large number for nothing.
    fn xmss_tree(&self, layer: usize, tree: u64, target: u32) -> ([u8; N], Vec<[u8; N]>) {
        let p = self.p;
        let leaves = self.leaf_layer(layer, tree);

        treehash_auth(
            p.hp,
            target,
            |i| leaves[i as usize],
            |height, index, left, right| {
                let mut adrs = Adrs::new();
                adrs.set_layer(layer as u32);
                adrs.set_tree_address(tree);
                adrs.set_type_and_clear(TREE);
                adrs.set_tree_height(height as u32);
                adrs.set_tree_index(index as u32);
                self.mid.hash(&adrs, &[left, right])
            },
        )
    }

    /// Every WOTS+ public key in one XMSS tree, computed on all cores.
    fn leaf_layer(&self, layer: usize, tree: u64) -> Arc<Vec<[u8; N]>> {
        {
            let held = self.leaves.lock().expect("leaf cache");
            if let Some((l, t, cached)) = held.as_ref() {
                if *l == layer && *t == tree {
                    return Arc::clone(cached);
                }
            }
        }

        let count = self.p.leaves_per_tree() as usize;
        let leaves =
            Arc::new(parallel_map(count, |i| self.wots_pk_gen(layer, tree, i as u32)));

        if count * N <= LEAF_CACHE_BYTES {
            *self.leaves.lock().expect("leaf cache") = Some((layer, tree, Arc::clone(&leaves)));
        }
        leaves
    }
}

/// `HMAC-SHA-256(key, message)`, RFC 2104.
///
/// Written out rather than pulled in: it is nine lines, it is used once per
/// signature, and `hmac` would be a dependency whose version has to be pinned
/// for a vault address to stay reproducible.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut padded = [0u8; 64];
    if key.len() > 64 {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner = Sha256::new();
    inner.update(padded.map(|b| b ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(padded.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// Build a binary hash tree of height `z`, returning its root and the auth
/// path opening leaf `target`.
///
/// Streaming: leaves are consumed left to right against a stack of pending
/// nodes, so the memory is `O(z)` rather than `O(2^z)`. That matters for FORS
/// under `128-24`, whose trees have 16.7 million leaves — materialising one
/// would cost 268 MB to then read `a` nodes out of it.
///
/// `node` receives `(height, index, left, right)` with the index local to this
/// tree; callers that address nodes globally offset it themselves.
fn treehash_auth<L, H>(z: usize, target: u32, leaf: L, node: H) -> ([u8; N], Vec<[u8; N]>)
where
    L: Fn(u64) -> [u8; N],
    H: Fn(usize, u64, &[u8; N], &[u8; N]) -> [u8; N],
{
    let mut auth = vec![[0u8; N]; z];
    let mut stack: Vec<(usize, u64, [u8; N])> = Vec::with_capacity(z + 1);

    for i in 0..1u64 << z {
        let mut height = 0usize;
        let mut index = i;
        let mut value = leaf(i);

        loop {
            // The auth path at height `height` is the sibling of the target's
            // ancestor there, which is the node whose index differs in its
            // lowest bit.
            if height < z && index == (u64::from(target) >> height) ^ 1 {
                auth[height] = value;
            }
            match stack.last() {
                Some(&(h, left_index, left)) if h == height => {
                    stack.pop();
                    value = node(height + 1, index >> 1, &left, &value);
                    debug_assert_eq!(left_index, index ^ 1);
                    height += 1;
                    index >>= 1;
                }
                _ => break,
            }
        }
        stack.push((height, index, value));
    }

    let (height, _, root) = stack.pop().expect("a tree of height z has a root");
    debug_assert!(stack.is_empty() && height == z);
    (root, auth)
}

/// `map` over `0..count` on every available core.
///
/// `std::thread::scope` rather than a work-stealing pool: the work items here
/// are uniform to within a few percent — every leaf is the same `len` chains —
/// so a static split is within noise of anything cleverer, and it keeps the
/// dependency count where it is.
fn parallel_map<F>(count: usize, f: F) -> Vec<[u8; N]>
where
    F: Fn(usize) -> [u8; N] + Sync,
{
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(count.max(1));
    if threads <= 1 || count < 1024 {
        return (0..count).map(f).collect();
    }

    // Chunks are handed out dynamically so that a busy core does not strand a
    // block of leaves behind it.
    let chunk = 64usize;
    let next = AtomicUsize::new(0);
    let f = &f;
    let next = &next;

    let mut parts: Vec<Vec<(usize, Vec<[u8; N]>)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(move || {
                    let mut mine = Vec::new();
                    loop {
                        let start = next.fetch_add(chunk, Ordering::Relaxed);
                        if start >= count {
                            break;
                        }
                        let end = (start + chunk).min(count);
                        mine.push((start, (start..end).map(f).collect::<Vec<_>>()));
                    }
                    mine
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("leaf worker panicked")).collect()
    });

    let mut out = vec![[0u8; N]; count];
    for part in parts.drain(..) {
        for (start, values) in part {
            out[start..start + values.len()].copy_from_slice(&values);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::{verify, Signature};

    fn seeds(tag: u8) -> SecretSeeds {
        SecretSeeds { sk_seed: [tag; N], sk_prf: [tag ^ 0x5a; N], pk_seed: [tag ^ 0xa5; N] }
    }

    /// The midstate is an optimisation of the plain hasher, so it must agree
    /// with it on every shape of input the signer uses — one-block messages,
    /// two-part Merkle inputs, and the `len`-part WOTS+ compression.
    #[test]
    fn matches_the_plain_hasher() {
        let pk_seed = [0x3c; N];
        let mid = Midstate::new(&pk_seed);
        let mut adrs = Adrs::new();
        adrs.set_tree_address(0x0102_0304_0506_0708);
        adrs.set_type_and_clear(TREE);
        adrs.set_tree_index(12345);

        let one = [0x11; N];
        let two = [0x22; N];
        let many: Vec<[u8; N]> = (0..68).map(|i| [i as u8; N]).collect();
        let many_parts: Vec<&[u8]> = many.iter().map(|m| m.as_slice()).collect();

        for parts in [vec![&one[..]], vec![&one[..], &two[..]], many_parts] {
            assert_eq!(
                mid.hash(&adrs, &parts),
                crate::adrs::hash(&pk_seed, &adrs, &parts),
                "midstate diverged from the plain hasher"
            );
        }
    }

    /// A tree's auth path must open the leaf it claims to. Checked by walking
    /// the path back up to the root, which is what a verifier does.
    #[test]
    fn auth_paths_reconstruct_the_root() {
        let hash = |h: usize, i: u64, l: &[u8; N], r: &[u8; N]| {
            use sha2::{Digest, Sha256};
            let mut d = Sha256::new();
            d.update((h as u64).to_be_bytes());
            d.update(i.to_be_bytes());
            d.update(l);
            d.update(r);
            let full = d.finalize();
            let mut out = [0u8; N];
            out.copy_from_slice(&full[..N]);
            out
        };
        let leaf = |i: u64| {
            let mut out = [0u8; N];
            out[..8].copy_from_slice(&i.to_be_bytes());
            out
        };

        for z in [1usize, 3, 9] {
            for target in [0u32, 1, (1 << z) - 1] {
                let (root, auth) = treehash_auth(z, target, leaf, hash);
                let mut node = leaf(u64::from(target));
                for (j, sibling) in auth.iter().enumerate() {
                    let index = u64::from(target) >> (j + 1);
                    node = if (target >> j) & 1 == 0 {
                        hash(j + 1, index, &node, sibling)
                    } else {
                        hash(j + 1, index, sibling, &node)
                    };
                }
                assert_eq!(node, root, "z={z} target={target}");
            }
        }
    }

    /// The point of the whole module: a signature this signer produces must
    /// verify under the reference verifier the script mirrors.
    ///
    /// `128-24` is excluded here and covered by an `#[ignore]`d test, because
    /// its key generation is a minute of hashing — see `end_to_end.rs`.
    #[test]
    fn signatures_verify_under_the_reference() {
        for set in [&SHA2_128S, &SHA2_128_24_D2] {
            let key = SigningKey::generate(set, seeds(0x42));
            let sig_bytes = key.sign(b"a message");
            assert_eq!(sig_bytes.len(), set.sig_len(), "{}", set.name);

            let sig = Signature::from_bytes(set, &sig_bytes).expect("parse");
            assert!(verify(&key.public_key(), &sig, b"a message"), "{}", set.name);

            // A different message must not verify, or the signature is not
            // binding anything.
            assert!(!verify(&key.public_key(), &sig, b"another message"), "{}", set.name);
        }
    }

    /// Signing is deterministic, so a rebuilt spend reproduces byte for byte
    /// and the compute budget measured for it stays correct.
    #[test]
    fn signing_is_deterministic() {
        let key = SigningKey::generate(&SHA2_128_24_D2, seeds(0x17));
        assert_eq!(key.sign(b"once"), key.sign(b"once"));
        assert_ne!(key.sign(b"once"), key.sign(b"twice"));
    }

    /// Two keys from different seeds must differ, and the same seeds must give
    /// the same key — the property a mnemonic-derived vault depends on.
    #[test]
    fn keygen_is_deterministic_in_its_seeds() {
        let a = SigningKey::generate(&SHA2_128_24_D2, seeds(1));
        let b = SigningKey::generate(&SHA2_128_24_D2, seeds(1));
        let c = SigningKey::generate(&SHA2_128_24_D2, seeds(2));
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a.public_key(), c.public_key());
        assert_eq!(a.public_key().seed, seeds(1).pk_seed, "PK.seed is public and carried through");
    }

    /// The parallel map must produce exactly what a serial one would, at both
    /// sides of the threshold where it starts using threads.
    #[test]
    fn parallel_map_matches_a_serial_one() {
        for count in [0usize, 1, 1023, 1024, 5000] {
            let f = |i: usize| {
                let mut out = [0u8; N];
                out[..8].copy_from_slice(&(i as u64).to_be_bytes());
                out
            };
            let parallel = parallel_map(count, f);
            let serial: Vec<[u8; N]> = (0..count).map(f).collect();
            assert_eq!(parallel, serial, "count={count}");
        }
    }
}
