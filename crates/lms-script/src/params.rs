//! LMS / LM-OTS parameter sets, per RFC 8554 §4.1 and §5.1.

/// A concrete LMS + LM-OTS parameter pair.
///
/// Only SHA-256 with n = 32 is supported: it is what Kaspa's `OpSHA256`
/// computes, which is the entire reason this design is cheap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LmsParams {
    /// Winternitz depth. Chains run to `2^w - 1`, so `w` trades script size
    /// against signature size: larger `w` means fewer, longer chains (small
    /// signature, big script), smaller `w` means more, shorter chains.
    pub w: u32,
    /// Merkle tree height. `2^h` one-time keys, i.e. `2^h` lifetime signatures.
    pub h: u32,
    /// Number of hash chains, `u + v`.
    pub p: usize,
    /// Chains covering the message digest, `ceil(8n/w)`.
    pub u: usize,
    /// Chains covering the checksum.
    pub v: usize,
    /// Checksum left-shift, `16 - v*w`.
    pub ls: u32,
    /// RFC 8554 `lms_algorithm_type`.
    pub lms_type: u32,
    /// RFC 8554 `lmots_algorithm_type`.
    pub lmots_type: u32,
}

/// Hash output length. Fixed at SHA-256.
pub const N: usize = 32;
/// Length of the `I` key identifier.
pub const I_LEN: usize = 16;

/// Domain separation constants, RFC 8554 §3.1.3.
pub const D_PBLC: u16 = 0x8080;
pub const D_MESG: u16 = 0x8181;
pub const D_LEAF: u16 = 0x8282;
pub const D_INTR: u16 = 0x8383;

impl LmsParams {
    /// `LMS_SHA256_M32_H5` / `LMOTS_SHA256_N32_W2`.
    ///
    /// Chains are at most 3 steps, so the unrolled verifier is small. The
    /// starting point for the proof of concept.
    pub const SHA256_H5_W2: Self = Self {
        w: 2,
        h: 5,
        p: 133,
        u: 128,
        v: 5,
        ls: 6,
        lms_type: 0x0000_0005,
        lmots_type: 0x0000_0002,
    };

    /// `LMS_SHA256_M32_H10` / `LMOTS_SHA256_N32_W2`.
    pub const SHA256_H10_W2: Self = Self { h: 10, lms_type: 0x0000_0006, ..Self::SHA256_H5_W2 };

    /// `LMS_SHA256_M32_H15` / `LMOTS_SHA256_N32_W2`. 32,768 leaves.
    pub const SHA256_H15_W2: Self = Self { h: 15, lms_type: 0x0000_0007, ..Self::SHA256_H5_W2 };

    /// `LMS_SHA256_M32_H20` / `LMOTS_SHA256_N32_W2`. 1,048,576 leaves.
    pub const SHA256_H20_W2: Self = Self { h: 20, lms_type: 0x0000_0008, ..Self::SHA256_H5_W2 };

    /// `LMS_SHA256_M32_H25` / `LMOTS_SHA256_N32_W2`. 33,554,432 leaves.
    pub const SHA256_H25_W2: Self = Self { h: 25, lms_type: 0x0000_0009, ..Self::SHA256_H5_W2 };

    /// `LMS_SHA256_M32_H5` / `LMOTS_SHA256_N32_W1`.
    ///
    /// Chains are a single step, so the unrolled script is at its smallest and
    /// the signature at its largest. The opposite end of the tradeoff from w=4.
    pub const SHA256_H5_W1: Self = Self {
        w: 1,
        h: 5,
        p: 265,
        u: 256,
        v: 9,
        ls: 7,
        lms_type: 0x0000_0005,
        lmots_type: 0x0000_0001,
    };

    /// `LMS_SHA256_M32_H5` / `LMOTS_SHA256_N32_W4`.
    ///
    /// Half the signature of `w = 2`, chains up to 15 steps, so a larger
    /// script. The size tradeoff is measured, not assumed — see the harness.
    pub const SHA256_H5_W4: Self = Self {
        w: 4,
        h: 5,
        p: 67,
        u: 64,
        v: 3,
        ls: 4,
        lms_type: 0x0000_0005,
        lmots_type: 0x0000_0003,
    };

    /// Maximum chain index, `2^w - 1`.
    pub const fn max_coef(&self) -> u32 {
        (1u32 << self.w) - 1
    }

    /// Number of one-time keys, `2^h`.
    pub const fn leaf_count(&self) -> u32 {
        1u32 << self.h
    }

    /// LM-OTS signature length: `u32str(type) || C || y[0..p-1]`.
    pub const fn ots_sig_len(&self) -> usize {
        4 + N + self.p * N
    }

    /// Full LMS signature length, RFC 8554 §5.4.
    pub const fn signature_len(&self) -> usize {
        4 + self.ots_sig_len() + 4 + (self.h as usize) * N
    }

    /// Public key length: `u32str(lms_type) || u32str(lmots_type) || I || T[1]`.
    pub const fn public_key_len(&self) -> usize {
        4 + 4 + I_LEN + N
    }

    /// Worst-case number of executed chain hashes across all `p` chains.
    ///
    /// Each chain runs from its coefficient to `2^w - 2`, so a coefficient of
    /// zero costs the full `2^w - 1` iterations.
    pub const fn worst_case_chain_hashes(&self) -> usize {
        self.p * (self.max_coef() as usize)
    }

    /// Expected number of executed chain hashes, averaging coefficients
    /// uniformly. Roughly half the worst case, and what a typical spend pays,
    /// since untaken branches cost no script units.
    pub fn expected_chain_hashes(&self) -> f64 {
        self.p as f64 * (self.max_coef() as f64) / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Derived parameters must satisfy RFC 8554 §4.1.
    #[test]
    fn derived_parameters_are_self_consistent() {
        for p in [
            LmsParams::SHA256_H5_W1,
            LmsParams::SHA256_H5_W2,
            LmsParams::SHA256_H10_W2,
            LmsParams::SHA256_H5_W4,
        ] {
            assert_eq!(p.u, (8 * N).div_ceil(p.w as usize), "u = ceil(8n/w)");
            assert_eq!(p.p, p.u + p.v, "p = u + v");
            assert_eq!(p.ls, 16 - (p.v as u32) * p.w, "ls = 16 - v*w");
        }
    }

    /// Cross-check against the lengths oxicrypt-lms derives independently.
    #[test]
    fn lengths_match_the_reference_parameter_set() {
        let p = LmsParams::SHA256_H5_W2;
        assert_eq!(p.ots_sig_len(), 4 + 32 + 133 * 32);
        assert_eq!(p.signature_len(), 4 + p.ots_sig_len() + 4 + 5 * 32);
        assert_eq!(p.public_key_len(), 56);
        assert_eq!(p.leaf_count(), 32);
    }

    /// The w tradeoff, stated as an assertion so it cannot drift.
    #[test]
    fn w2_has_a_larger_signature_but_a_shorter_worst_case_chain() {
        let w2 = LmsParams::SHA256_H5_W2;
        let w4 = LmsParams::SHA256_H5_W4;
        assert!(w2.signature_len() > w4.signature_len());
        assert!(w2.worst_case_chain_hashes() < w4.worst_case_chain_hashes());
        assert_eq!(w2.worst_case_chain_hashes(), 133 * 3);
        assert_eq!(w4.worst_case_chain_hashes(), 67 * 15);
    }
}
