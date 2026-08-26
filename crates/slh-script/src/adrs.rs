//! The compressed hash address, FIPS 205 §11.2.
//!
//! Every hash in SLH-DSA is `H(PK.seed || toByte(0, 64-n) || ADRS^c || M)`,
//! where `ADRS^c` is a structured address identifying *where in the hypertree*
//! the hash sits. Domain separation is the entire security argument for reusing
//! one hash function across FORS leaves, WOTS+ chains and Merkle nodes, so a
//! wrong byte here does not fail loudly — it produces a consistent-but-wrong
//! verifier that rejects every real signature, or worse, one that accepts
//! across domains.
//!
//! LMS had no analogue: its prefixes are `I || u32str(idx) || u16str(D)`, flat
//! and 22 bytes by luck rather than by compression. Here the 32-byte address is
//! squeezed to 22 by dropping the high bytes of the layer, tree and type words,
//! which are provably zero for these parameters.
//!
//! ```text
//! offset  len  field
//!      0    1  layer address      (low byte of a 4-byte word)
//!      1    8  tree address       (low 8 bytes of a 12-byte word)
//!      9    1  type               (low byte of a 4-byte word)
//!     10    4  word 1  key pair address    | key pair | tree height (=0)
//!     14    4  word 2  chain address       | 0        | tree height
//!     18    4  word 3  hash address        | 0        | tree index
//! ```
//!
//! All three words are big-endian, which is the opposite of every integer in
//! the binding digest. That asymmetry is the trap.

use crate::params::*;

/// Length of a compressed address.
pub const ADRS_LEN: usize = 22;

/// A compressed ADRS, held as the bytes that actually get hashed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Adrs(pub [u8; ADRS_LEN]);

impl core::fmt::Debug for Adrs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Adrs(layer={} tree={} type={} w1={} w2={} w3={})",
            self.0[0], self.tree_address(), self.0[9],
            self.word(1), self.word(2), self.word(3))
    }
}

impl Adrs {
    pub fn new() -> Self {
        Self([0u8; ADRS_LEN])
    }

    pub fn as_bytes(&self) -> &[u8; ADRS_LEN] {
        &self.0
    }

    pub fn set_layer(&mut self, layer: u32) -> &mut Self {
        self.0[0] = layer as u8;
        self
    }

    /// The tree address occupies the low 8 bytes of a 12-byte field; the high
    /// 4 bytes are dropped by compression and are zero for every parameter set
    /// (`h - h/d` never exceeds 64).
    pub fn set_tree_address(&mut self, tree: u64) -> &mut Self {
        self.0[1..9].copy_from_slice(&tree.to_be_bytes());
        self
    }

    pub fn tree_address(&self) -> u64 {
        u64::from_be_bytes(self.0[1..9].try_into().expect("8 bytes"))
    }

    /// `setTypeAndClear`: sets the type *and zeroes all three words*. Forgetting
    /// the clear is the classic ADRS bug, so the two are not separable here.
    pub fn set_type_and_clear(&mut self, ty: u8) -> &mut Self {
        self.0[9] = ty;
        self.0[10..22].fill(0);
        self
    }

    fn set_word(&mut self, index: usize, value: u32) -> &mut Self {
        let off = 10 + 4 * (index - 1);
        self.0[off..off + 4].copy_from_slice(&value.to_be_bytes());
        self
    }

    pub fn word(&self, index: usize) -> u32 {
        let off = 10 + 4 * (index - 1);
        u32::from_be_bytes(self.0[off..off + 4].try_into().expect("4 bytes"))
    }

    pub fn set_key_pair_address(&mut self, kp: u32) -> &mut Self {
        self.set_word(1, kp)
    }
    pub fn key_pair_address(&self) -> u32 {
        self.word(1)
    }
    pub fn set_chain_address(&mut self, i: u32) -> &mut Self {
        self.set_word(2, i)
    }
    pub fn set_hash_address(&mut self, j: u32) -> &mut Self {
        self.set_word(3, j)
    }
    pub fn set_tree_height(&mut self, z: u32) -> &mut Self {
        self.set_word(2, z)
    }
    pub fn set_tree_index(&mut self, i: u32) -> &mut Self {
        self.set_word(3, i)
    }
}

impl Default for Adrs {
    fn default() -> Self {
        Self::new()
    }
}

/// The constant head of every hash preimage: `PK.seed || toByte(0, 64-n)`.
///
/// Exactly one SHA-256 block, and entirely known at script-generation time, so
/// it is emitted as a literal push and costs zero script units.
pub fn hash_pad(pk_seed: &[u8; N]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(pk_seed);
    out.extend_from_slice(&[0u8; PAD_LEN]);
    out
}

/// `Trunc_n(SHA-256(PK.seed || pad || ADRS^c || M))`.
///
/// `F`, `H` and `T_l` are the same function for the SHA2 category-1 parameter
/// sets; they differ only in how much message they are given. Keeping one
/// implementation means the script emitter has one shape to match.
pub fn hash(pk_seed: &[u8; N], adrs: &Adrs, message: &[&[u8]]) -> [u8; N] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(hash_pad(pk_seed));
    h.update(adrs.as_bytes());
    for part in message {
        h.update(part);
    }
    let full = h.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Field offsets, asserted against the layout table in the module docs
    /// rather than against the setters that produced them.
    #[test]
    fn field_offsets_are_where_the_layout_says() {
        let mut a = Adrs::new();
        a.set_layer(0x11);
        a.set_tree_address(0x2233_4455_6677_8899);
        a.set_type_and_clear(0xaa);
        a.set_key_pair_address(0xbbcc_ddee);
        a.set_chain_address(0x0102_0304);
        a.set_hash_address(0x0506_0708);
        assert_eq!(
            a.as_bytes()[..],
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
            ]
        );
    }

    /// `setTypeAndClear` must wipe the words. A verifier that sets the type
    /// while leaving a stale chain address still verifies self-consistently and
    /// rejects every genuine signature.
    #[test]
    fn set_type_and_clear_wipes_all_three_words() {
        let mut a = Adrs::new();
        a.set_key_pair_address(1).set_chain_address(2).set_hash_address(3);
        a.set_type_and_clear(TREE);
        assert_eq!(&a.as_bytes()[10..22], &[0u8; 12]);
        assert_eq!(a.as_bytes()[9], TREE);
    }

    /// Tree height and key pair address alias different words. Confusing them
    /// is silent, because both are small integers.
    #[test]
    fn tree_height_aliases_word_two_not_word_one() {
        let mut a = Adrs::new();
        a.set_tree_height(7);
        assert_eq!(a.word(1), 0, "tree height must not land in the key pair word");
        assert_eq!(a.word(2), 7);
    }

    /// The padded head is exactly one SHA-256 block.
    #[test]
    fn hash_pad_is_one_compression_block() {
        assert_eq!(hash_pad(&[0xa5; N]).len(), 64);
    }
}
