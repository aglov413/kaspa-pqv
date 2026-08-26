//! LM-OTS verification, emitted as unrolled Kaspa txscript (RFC 8554 §4.5).

use anyhow::{ensure, Result};
use kaspa_txscript::opcodes::codes::*;

use crate::builder::ScriptWriter;
use crate::params::LmsParams;

/// RFC 8554 §3.1.3 `coef(S, i, w)`: the `i`-th `w`-bit field of `S`,
/// most-significant-first within each byte.
///
/// The reference the emitted script is checked against.
pub fn coef(s: &[u8], i: usize, w: u32) -> u32 {
    let bit = i * w as usize;
    let byte = s[bit / 8];
    let shift = 8 - w - (bit % 8) as u32;
    (u32::from(byte) >> shift) & ((1u32 << w) - 1)
}

/// Emit script that reads `coef(V, i, w)` from the value on top of the stack.
///
/// Precondition:  `[..., V]`
/// Postcondition: `[..., V, a_i]`
///
/// `V` is left in place because every chain needs it in turn.
///
/// The `0x00` append before `OpBin2Num` is load-bearing: Kaspa's numeric
/// encoding is little-endian sign-magnitude, so a lone byte with the high bit
/// set decodes as *negative zero* rather than its value. Without the pad,
/// every coefficient drawn from a byte ≥ 0x80 would silently read as 0. See
/// `tests/opcode_semantics.rs`.
pub fn emit_coefficient(w: &mut ScriptWriter, params: &LmsParams, i: usize) -> Result<()> {
    ensure!(i < params.p, "chain index {i} out of range for p = {}", params.p);

    let bit = i * params.w as usize;
    let byte_idx = bit / 8;
    let shift = 8 - params.w - (bit % 8) as u32;

    w.op(OpDup)?;
    w.num(byte_idx as i64)?;
    w.num(byte_idx as i64 + 1)?;
    w.op(OpSubstr)?;

    // Clear the sign bit before numeric interpretation.
    w.data(&[0x00])?;
    w.op(OpCat)?;
    w.op(OpBin2Num)?;

    if shift > 0 {
        w.num(1i64 << shift)?;
        w.op(OpDiv)?;
    }
    w.num(1i64 << params.w)?;
    w.op(OpMod)?;

    Ok(())
}

/// RFC 8554 §4.4 `cksm(S)`, for the message digest `Q`.
///
/// The checksum is what stops an attacker walking any chain further forward:
/// increasing one message coefficient necessarily decreases the checksum,
/// which would require walking a checksum chain *backwards*.
pub fn cksm(q: &[u8], params: &LmsParams) -> u16 {
    let mut sum: u32 = 0;
    for i in 0..params.u {
        sum += params.max_coef() - coef(q, i, params.w);
    }
    #[allow(clippy::cast_possible_truncation)]
    ((sum << params.ls) as u16)
}

/// `V = Q || cksm(Q)`, the string the `p` coefficients are read from.
pub fn coefficient_source(q_digest: &[u8; 32], params: &LmsParams) -> Vec<u8> {
    let mut v = q_digest.to_vec();
    v.extend_from_slice(&cksm(q_digest, params).to_be_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8554 §3.1.3 worked example: coefficients of a known byte string.
    #[test]
    fn coef_matches_the_rfc_example() {
        // RFC 8554: for S = 0x1234, coef(S, 0, 4) = 1 and coef(S, 1, 4) = 2.
        let s = [0x12u8, 0x34];
        assert_eq!(coef(&s, 0, 4), 1);
        assert_eq!(coef(&s, 1, 4), 2);
        assert_eq!(coef(&s, 2, 4), 3);
        assert_eq!(coef(&s, 3, 4), 4);

        // And for w = 2, the same bytes split into 2-bit fields.
        assert_eq!(coef(&s, 0, 2), 0b00);
        assert_eq!(coef(&s, 1, 2), 0b01);
        assert_eq!(coef(&s, 2, 2), 0b00);
        assert_eq!(coef(&s, 3, 2), 0b10);
    }

    /// The checksum fits the field the parameters reserve for it.
    #[test]
    fn cksm_fits_the_reserved_coefficients() {
        let params = LmsParams::SHA256_H5_W2;
        // All-zero digest maximises the checksum: u * (2^w - 1).
        let max_sum = (params.u as u32) * params.max_coef();
        assert!(
            max_sum << params.ls <= u32::from(u16::MAX),
            "checksum overflows 16 bits"
        );

        let zero = [0u8; 32];
        assert_eq!(cksm(&zero, &params), (max_sum << params.ls) as u16);
    }

    /// `V` is exactly the length the coefficient indices assume.
    #[test]
    fn coefficient_source_covers_every_chain() {
        for params in [LmsParams::SHA256_H5_W2, LmsParams::SHA256_H5_W4] {
            let v = coefficient_source(&[0xa5u8; 32], &params);
            let last_bit = (params.p - 1) * params.w as usize;
            assert!(
                last_bit / 8 < v.len(),
                "p = {} chains read past the end of V ({} bytes)",
                params.p,
                v.len()
            );
        }
    }
}
