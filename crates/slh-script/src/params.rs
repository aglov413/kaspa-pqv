//! SLH-DSA parameter sets, all at security category 1 with SHA-2.
//!
//! Three sets are supported, and the differences between them are the whole
//! point of this crate now rather than an afterthought:
//!
//! | | `128s` | `128-24` | `128-24d2` |
//! |---|---|---|---|
//! | source | FIPS 205 Table 2 | SP 800-230 ipd Table 1 | proposed here |
//! | signatures per key | 2^64 | 2^24 | 2^24 |
//! | `h` / `d` / `h'` | 63 / 7 / 9 | 22 / 1 / 22 | 24 / 2 / 12 |
//! | `a` / `k` | 12 / 14 | 24 / 6 | 14 / 11 |
//! | `lg(w)` | 4 | 2 | 2 |
//! | signature | 7856 B | **3856 B** | 5216 B |
//!
//! # Why a 2^24 signature limit is free for a vault
//!
//! FIPS 205 sizes every standard set for 2^64 signatures under one key, which
//! is the right target for a general-purpose signature and absurd for a vault:
//! a vault that spends once a day exhausts 2^24 in forty-five thousand years.
//! SP 800-230 (initial public draft, April 2026) proposes parameter sets that
//! buy the difference back as signature size, and a vault is exactly the use
//! case it names — "sign-once, verify-many", where verification is what is
//! paid for.
//!
//! # Why `128-24` is not simply the best of the three
//!
//! `d = 1` means the hypertree is a single XMSS tree of `2^22` leaves, and
//! every signature has to build all of it: roughly 1.1 billion hashes per
//! signature, against 4 million for `128s`. That is a deliberate trade in the
//! draft — signing happens once on a machine with time, verification happens
//! everywhere — but it is a trade, and for a vault whose signer may be an
//! air-gapped laptop it is the expensive half.
//!
//! `128-24d2` is the same signature limit with the signing cost handed back:
//! `d = 2` and `h' = 12` mean two trees of 4096 leaves, ~2 million hashes, at
//! the cost of 1360 more signature bytes. It is **not** a NIST proposal — it is
//! stated here as a parameter set to measure, and [`SHA2_128_24_D2`] says so.
//! Nothing in this workspace should present it as standardised.
//!
//! Security levels are not reasoned about here. The sets that came from a
//! standards document carry that document's analysis; the one that did not
//! carries none, which is the first thing to say about it.

/// Security parameter / hash output length, in bytes.
///
/// A constant rather than a field of [`Params`] because every supported set is
/// category 1, and because it is the length of most of the byte arrays in this
/// crate. [`Params::n`] restates it so the check that they agree is possible.
pub const N: usize = 16;

/// The `toByte(0, 64 - n)` padding that follows `PK.seed` in every SHA2
/// category-1 hash, so the compression function's first block is consumed by
/// constant data.
pub const PAD_LEN: usize = 64 - N;

/// ADRS type constants, FIPS 205 §4.2.
///
/// `WOTS_PRF` and `FORS_PRF` are never seen by a verifier — they address the
/// pseudorandom generation of secret values, which only a signer does. They are
/// here rather than in the signer because they share the type field's namespace
/// with the five a verifier does use, and a collision between the two halves
/// would be a domain separation failure.
pub const WOTS_HASH: u8 = 0;
pub const WOTS_PK: u8 = 1;
pub const TREE: u8 = 2;
pub const FORS_TREE: u8 = 3;
pub const FORS_ROOTS: u8 = 4;
pub const WOTS_PRF: u8 = 5;
pub const FORS_PRF: u8 = 6;

/// One SLH-DSA parameter set.
///
/// Only the eight independent parameters are stored; everything else is
/// derived by the `const fn` accessors below, from the formulas in FIPS 205
/// §11 rather than from a table. That is deliberate — a table of derived
/// lengths is a table that can disagree with itself, and `derived_lengths_*`
/// checks the derivations against the two published tables instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// The name this set is known by, used in reports and error messages.
    pub name: &'static str,
    /// Security parameter, in bytes. Always [`N`] here.
    pub n: usize,
    /// Total hypertree height.
    pub h: usize,
    /// Hypertree layers.
    pub d: usize,
    /// Height of each XMSS tree, `h / d`.
    pub hp: usize,
    /// FORS tree height.
    pub a: usize,
    /// Number of FORS trees.
    pub k: usize,
    /// Winternitz `lg(w)`.
    pub lgw: u32,
    /// `H_msg` output length, in bytes.
    pub m: usize,
    /// `lg` of the signatures one key may make, as the set's source states it.
    ///
    /// **Not derivable from `h`.** A hypertree has `2^h` leaf positions, but
    /// signing is randomised and the security bound accounts for positions
    /// being reused, so the two differ by a factor the analysis chooses:
    /// `128s` is `h = 63` with a 2^64 limit, `128-24` is `h = 22` with a 2^24
    /// limit. Computing one from the other gives a number that is wrong in
    /// both directions depending on the set, which is why it is stated.
    pub sig_limit_log2: u32,
    /// Where this set comes from, for anything that reports it to a human.
    pub source: &'static str,
}

/// **SLH-DSA-SHA2-128s**, FIPS 205 Table 2. The standardised set, good for
/// 2^64 signatures.
///
/// `128f` is not offered and would not be worth offering: it trades 7
/// hypertree layers for 22, and every extra layer is a full WOTS+
/// verification. Fast signing and slow verification is the wrong side of the
/// trade when verification is the thing being paid for on-chain.
pub static SHA2_128S: Params = Params {
    name: "SLH-DSA-SHA2-128s",
    n: N,
    h: 63,
    d: 7,
    hp: 9,
    a: 12,
    k: 14,
    lgw: 4,
    m: 30,
    sig_limit_log2: 64,
    source: "FIPS 205",
};

/// **SLH-DSA-SHA2-128-24**, NIST SP 800-230 ipd (April 2026) Table 1.
///
/// Category 1 at a hard limit of 2^24 signatures per key, which halves the
/// signature against `128s`. Signing is the price: `d = 1` over `h' = 22`
/// means one XMSS tree of 4,194,304 leaves, rebuilt for every signature.
pub static SHA2_128_24: Params = Params {
    name: "SLH-DSA-SHA2-128-24",
    n: N,
    h: 22,
    d: 1,
    hp: 22,
    a: 24,
    k: 6,
    lgw: 2,
    m: 21,
    // The "-24" in the name. `h` is 22: the draft allows each of the 2^22
    // hypertree positions to be signed at more than once, and sizes FORS for
    // it. Reading the limit off `h` would understate it fourfold.
    sig_limit_log2: 24,
    source: "NIST SP 800-230 ipd (draft)",
};

/// **Not a standard.** The same 2^24 limit as [`SHA2_128_24`] with the signing
/// cost brought back to something a cold signer can pay.
///
/// `d = 2` over `h' = 12` is two trees of 4096 leaves instead of one of four
/// million, which is three orders of magnitude off the signing cost, for 1360
/// bytes of signature. Whether that is a good trade is what measuring it is
/// for.
///
/// This set appears in no standards document. It is implemented, tested and
/// measured on exactly the same footing as the other two so the comparison is
/// real, and it should never be described as anything but a proposal.
pub static SHA2_128_24_D2: Params = Params {
    name: "SLH-DSA-SHA2-128-24d2",
    n: N,
    h: 24,
    d: 2,
    hp: 12,
    a: 14,
    k: 11,
    lgw: 2,
    m: 24,
    // Targets the same limit as the draft set. With `h = 24` that is one
    // signature per hypertree position, where `128s` allows two and the draft
    // set four — more conservative on reuse than either, which is an
    // observation and not an analysis. Nobody has analysed this set.
    sig_limit_log2: 24,
    source: "none — proposed here, unanalysed",
};

/// Every supported set, in the order reports should list them.
pub static ALL: &[&Params] = &[&SHA2_128S, &SHA2_128_24, &SHA2_128_24_D2];

impl Params {
    /// Winternitz parameter, `2^lgw`.
    pub const fn w(&self) -> u32 {
        1 << self.lgw
    }

    /// WOTS+ chains covering the message, `ceil(8n / lgw)`.
    pub const fn len1(&self) -> usize {
        (8 * self.n).div_ceil(self.lgw as usize)
    }

    /// WOTS+ chains covering the checksum,
    /// `floor(lg(len1 * (w - 1)) / lgw) + 1`.
    pub const fn len2(&self) -> usize {
        let max = self.len1() * (self.w() as usize - 1);
        (max.ilog2() as usize) / (self.lgw as usize) + 1
    }

    /// Total WOTS+ chains.
    ///
    /// `len` is FIPS 205's name for this count, not a collection length, so
    /// there is nothing for `is_empty` to mean.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.len1() + self.len2()
    }

    /// Bits the WOTS+ checksum digits span, `len2 * lgw`.
    pub const fn csum_bits(&self) -> u32 {
        self.len2() as u32 * self.lgw
    }

    /// Bytes of `digest` consumed by the FORS indices, `ceil(k*a/8)`.
    pub const fn md_len(&self) -> usize {
        (self.k * self.a).div_ceil(8)
    }

    /// Bytes of `digest` consumed by the tree index, `ceil((h - h/d)/8)`.
    ///
    /// Zero when `d == 1`: a one-layer hypertree has exactly one tree, so
    /// there is no tree index to carve out and `idx_tree` is the constant 0.
    pub const fn idx_tree_len(&self) -> usize {
        (self.h - self.h / self.d).div_ceil(8)
    }

    /// Bytes of `digest` consumed by the leaf index, `ceil(h/(8d))`.
    pub const fn idx_leaf_len(&self) -> usize {
        self.h.div_ceil(8 * self.d)
    }

    /// Bits retained from `tmp_idx_tree`, `h - h/d`.
    pub const fn idx_tree_bits(&self) -> u32 {
        (self.h - self.h / self.d) as u32
    }

    /// Public key length: `PK.seed || PK.root`.
    pub const fn pk_len(&self) -> usize {
        2 * self.n
    }

    /// Signature length: `(1 + k(1 + a) + h + d*len) * n`.
    pub const fn sig_len(&self) -> usize {
        self.sig_elements() * self.n
    }

    /// Number of `n`-byte elements in a signature.
    pub const fn sig_elements(&self) -> usize {
        1 + self.k * (1 + self.a) + self.h + self.d * self.len()
    }

    /// Leaves in one XMSS tree, `2^h'` — the work one signature costs on top
    /// of the FORS and WOTS+ chains it publishes.
    pub const fn leaves_per_tree(&self) -> u64 {
        1u64 << self.hp
    }

    /// Signatures one key may make, saturating at `u64::MAX` for `128s`'s
    /// 2^64 — a number that does not fit the type it would be counted in,
    /// which is itself the reason nothing here counts them.
    pub const fn signature_limit(&self) -> u64 {
        if self.sig_limit_log2 >= 64 {
            u64::MAX
        } else {
            1u64 << self.sig_limit_log2
        }
    }

    /// Byte width an ADRS word needs to carry values up to `max`, inclusive.
    ///
    /// `OpNum2Bin` produces sign-magnitude and refuses a magnitude that would
    /// need the sign bit, so a value of 57,343 needs three bytes and not two.
    /// Getting this one byte too narrow is a script that fails only for the
    /// indices that happen to be large.
    pub const fn word_width_for(max: u64) -> usize {
        let mut width = 1;
        while width < 8 && max >= 1u64 << (8 * width - 1) {
            width += 1;
        }
        width
    }

    /// Width of the FORS tree index, which addresses all `k` trees at once as
    /// `i * 2^a + index`.
    pub const fn fors_index_width(&self) -> usize {
        Self::word_width_for((self.k as u64) << self.a)
    }

    /// Width of an XMSS tree index, which addresses one tree's `2^h'` leaves.
    pub const fn xmss_index_width(&self) -> usize {
        Self::word_width_for(self.leaves_per_tree() - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derived lengths must agree with FIPS 205 Table 2 and SP 800-230
    /// Table 1, which state them directly rather than deriving them.
    #[test]
    fn derived_lengths_match_the_published_tables() {
        // FIPS 205 Table 2.
        let p = &SHA2_128S;
        assert_eq!((p.len1(), p.len2(), p.len()), (32, 3, 35));
        assert_eq!(p.sig_len(), 7856, "FIPS 205 Table 2 signature size");
        assert_eq!(p.pk_len(), 32, "FIPS 205 Table 2 public key size");
        assert_eq!(p.sig_elements(), 491);

        // SP 800-230 ipd Table 1: 32-byte public key, 3856-byte signature.
        let p = &SHA2_128_24;
        assert_eq!((p.len1(), p.len2(), p.len()), (64, 4, 68));
        assert_eq!(p.sig_len(), 3856, "SP 800-230 Table 1 signature size");
        assert_eq!(p.pk_len(), 32, "SP 800-230 Table 1 public key size");

        // Derived, since no table states it.
        let p = &SHA2_128_24_D2;
        assert_eq!(p.sig_len(), 5216);
    }

    /// `m` is stated by both documents *and* derivable from the index widths.
    /// They have to agree, or the digest is being split at the wrong offsets.
    #[test]
    fn the_digest_is_exactly_consumed() {
        for p in ALL {
            assert_eq!(
                p.md_len() + p.idx_tree_len() + p.idx_leaf_len(),
                p.m,
                "{}: digest is not fully consumed",
                p.name
            );
            assert!(p.m <= 32, "{}: H_msg needs more than one MGF1 block", p.name);
        }
    }

    /// A one-layer hypertree has no tree index at all, which is a shape the
    /// emitter has to handle rather than a degenerate case to guard against.
    #[test]
    fn one_layer_sets_carve_no_tree_index() {
        assert_eq!(SHA2_128_24.idx_tree_len(), 0);
        assert_eq!(SHA2_128_24.idx_tree_bits(), 0);
        assert_eq!(SHA2_128_24.hp, SHA2_128_24.h, "d = 1 means one tree of full height");
    }

    /// `len2` follows FIPS 205's formula, restated the long way.
    #[test]
    fn len2_matches_the_standards_formula() {
        for p in ALL {
            let max = p.len1() * (p.w() as usize - 1);
            let lg = (usize::BITS - max.leading_zeros()) as usize - 1;
            assert_eq!(p.len2(), lg / p.lgw as usize + 1, "{}", p.name);
        }
    }

    /// The element count is what forces blob-and-slice witness encoding:
    /// `MAX_STACK_SIZE` is 244 and counts **both** stacks, so a signature has
    /// to leave room for the verifier's working frame as well as itself.
    ///
    /// `128-24` is the interesting one: 241 elements is *under* the limit, so
    /// a naive encoding looks like it fits — and then does not, because the
    /// frame needs a dozen slots and the message digest needs one more. Three
    /// elements of headroom is not a margin to build an address on.
    #[test]
    fn no_signature_fits_the_stack_whole() {
        const FRAME_ALLOWANCE: usize = 12;
        for p in ALL {
            assert!(
                p.sig_elements() + FRAME_ALLOWANCE > kaspa_txscript::MAX_STACK_SIZE,
                "{} would fit on the stack with room to work; the blob plan could be simpler",
                p.name
            );
        }
        assert!(
            SHA2_128_24.sig_elements() < kaspa_txscript::MAX_STACK_SIZE,
            "128-24 is expected to be under the limit on element count alone"
        );
    }

    /// Index widths must hold the largest index each addresses, and `OpNum2Bin`
    /// will not spend the sign bit on magnitude.
    #[test]
    fn index_widths_hold_their_largest_value() {
        for p in ALL {
            let fors_max = ((p.k as u64) << p.a) - 1;
            assert!(fors_max < 1u64 << (8 * p.fors_index_width() - 1), "{}", p.name);
            assert!(p.fors_index_width() <= 4, "{}: FORS index exceeds its ADRS word", p.name);

            let xmss_max = p.leaves_per_tree() - 1;
            assert!(xmss_max < 1u64 << (8 * p.xmss_index_width() - 1), "{}", p.name);
            assert!(p.xmss_index_width() <= 4, "{}: XMSS index exceeds its ADRS word", p.name);
        }
        // The widths the pre-parameterised emitter hard-coded, pinned so the
        // generalisation is checked against what was known to work.
        assert_eq!((SHA2_128S.fors_index_width(), SHA2_128S.xmss_index_width()), (3, 2));
    }

    /// The signature limit is stated by each set's source, **not** computed
    /// from `h`. This test exists because computing it from `h` is the obvious
    /// wrong thing to do, and it was done once: it reported `SLH-DSA-SHA2-128-24`
    /// — a set named for its 2^24 limit — as allowing 2^22.
    #[test]
    fn the_signature_limit_is_not_the_hypertree_height() {
        assert_eq!(SHA2_128S.sig_limit_log2, 64, "FIPS 205 states 2^64");
        assert_eq!(SHA2_128S.h, 63, "...at h = 63, so the two are not equal");

        assert_eq!(SHA2_128_24.sig_limit_log2, 24, "SP 800-230 states 2^24");
        assert_eq!(SHA2_128_24.h, 22, "...at h = 22, so the two are not equal");

        // Every set signs more times than it has hypertree positions, or the
        // name would be describing a different quantity than the analysis does.
        for p in ALL {
            assert!(
                p.sig_limit_log2 >= p.h as u32,
                "{}: a limit below the hypertree height would be strange",
                p.name
            );
        }
        assert_eq!(SHA2_128S.signature_limit(), u64::MAX, "2^64 saturates a u64");
        assert_eq!(SHA2_128_24.signature_limit(), 16_777_216);
    }

    /// Every set must be distinguishable by name, since the name is what ends
    /// up in reports and in the derivation path's documentation.
    #[test]
    fn names_are_unique() {
        for (i, a) in ALL.iter().enumerate() {
            for b in &ALL[i + 1..] {
                assert_ne!(a.name, b.name);
                assert_ne!(a, b);
            }
        }
    }
}
