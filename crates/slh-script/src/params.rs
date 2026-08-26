//! SLH-DSA-SHA2-128s parameters, FIPS 205 Table 2 (security category 1).
//!
//! Only the `s` ("small signature") variant is implemented, and deliberately.
//! `128f` trades 22 hypertree layers for 7, and every extra layer is a full
//! WOTS+ verification — roughly 11,600 hashes instead of 3,900. Fast signing
//! and slow verification is exactly the wrong side of the tradeoff when
//! verification is the thing being paid for on-chain.

/// Security parameter / hash output length, in bytes.
pub const N: usize = 16;
/// Total hypertree height.
pub const H: usize = 63;
/// Hypertree layers.
pub const D: usize = 7;
/// Height of each XMSS tree, `h / d`.
pub const HP: usize = 9;
/// FORS tree height.
pub const A: usize = 12;
/// Number of FORS trees.
pub const K: usize = 14;
/// Winternitz `lg(w)`.
pub const LGW: u32 = 4;
/// Winternitz parameter, `2^lgw`.
pub const W: u32 = 16;
/// WOTS+ chains covering the message.
pub const LEN1: usize = 32;
/// WOTS+ chains covering the checksum.
pub const LEN2: usize = 3;
/// Total WOTS+ chains.
pub const LEN: usize = LEN1 + LEN2;
/// `H_msg` output length, in bytes.
pub const M: usize = 30;

/// Bytes of `digest` consumed by the FORS indices, `ceil(k*a/8)`.
pub const MD_LEN: usize = (K * A).div_ceil(8);
/// Bytes of `digest` consumed by the tree index, `ceil((h - h/d)/8)`.
pub const IDX_TREE_LEN: usize = (H - H / D).div_ceil(8);
/// Bytes of `digest` consumed by the leaf index, `ceil(h/(8d))`.
pub const IDX_LEAF_LEN: usize = H.div_ceil(8 * D);
/// Bits retained from `tmp_idx_tree`, `h - h/d`.
pub const IDX_TREE_BITS: u32 = (H - H / D) as u32;

/// Public key length: `PK.seed || PK.root`.
pub const PK_LEN: usize = 2 * N;
/// Signature length: `(1 + k(1 + a) + h + d*len) * n`.
pub const SIG_LEN: usize = (1 + K * (1 + A) + H + D * LEN) * N;

/// Number of `n`-byte elements in a signature.
pub const SIG_ELEMENTS: usize = SIG_LEN / N;

/// ADRS type constants, FIPS 205 §4.2.
pub const WOTS_HASH: u8 = 0;
pub const WOTS_PK: u8 = 1;
pub const TREE: u8 = 2;
pub const FORS_TREE: u8 = 3;
pub const FORS_ROOTS: u8 = 4;

/// The `toByte(0, 64 - n)` padding that follows `PK.seed` in every SHA2
/// category-1 hash, so the compression function's first block is consumed by
/// constant data.
pub const PAD_LEN: usize = 64 - N;

#[cfg(test)]
mod tests {
    use super::*;

    /// The derived lengths must agree with FIPS 205 Table 2, which states them
    /// directly rather than deriving them.
    #[test]
    fn derived_lengths_match_the_standard() {
        assert_eq!(LEN1, (8 * N).div_ceil(LGW as usize));
        // len2 = floor(lg(len1 * (w - 1)) / lgw) + 1
        let len2 = (usize::BITS - (LEN1 * (W as usize - 1)).leading_zeros()) as usize;
        assert_eq!(LEN2, (len2 - 1) / LGW as usize + 1);
        assert_eq!(SIG_LEN, 7856, "FIPS 205 Table 2 signature size");
        assert_eq!(PK_LEN, 32, "FIPS 205 Table 2 public key size");
        assert_eq!(SIG_ELEMENTS, 491);
        assert_eq!(MD_LEN + IDX_TREE_LEN + IDX_LEAF_LEN, M, "digest is fully consumed");
        assert_eq!((MD_LEN, IDX_TREE_LEN, IDX_LEAF_LEN), (21, 7, 2));
    }

    /// The element count is what forces blob-and-slice witness encoding:
    /// `MAX_STACK_SIZE` is 244 and counts both stacks.
    #[test]
    #[allow(clippy::assertions_on_constants)] // pinning a relationship between two consts is the point
    fn signature_element_count_exceeds_the_stack_limit() {
        assert!(SIG_ELEMENTS > kaspa_txscript::MAX_STACK_SIZE);
    }
}
