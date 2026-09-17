//! Blob-and-slice witness encoding.
//!
//! An SLH-DSA signature is 241 to 491 `n`-byte elements, depending on the
//! parameter set. `MAX_STACK_SIZE` is **244, counting both stacks**, so the LMS
//! approach — push every element and address it directly — is not available for
//! any of them. The signature is pushed as a smaller number of concatenated
//! blobs and sliced back apart in script.
//!
//! # What slicing actually costs
//!
//! `OpSubstr` is charged only for the substring it produces, and moves between
//! the two stacks are free (`push_unmetered`). The expensive part is that
//! `OpSubstr` *consumes* the blob, so extracting one element requires an
//! `OpDup` of everything still in the blob. Extracting `e` elements from a blob
//! therefore costs
//!
//! ```text
//! sum over k of 2 * 16k  =  16 * e * (e + 1)   script units
//! ```
//!
//! Summed over a whole signature of `E` elements in blobs of `e`, that is
//! `16 * E * (e + 1)` — linear in the blob size. Big blobs are quadratic;
//! small blobs need more stack slots. [`BlobPlan`] makes the tradeoff explicit
//! and [`BlobPlan::peak_stack_estimate`] is what keeps it legal.
//!
//! # Consumption order
//!
//! The verifier consumes elements in exactly the order the signature stores
//! them — `R`, then each FORS group, then each hypertree layer's WOTS+
//! signature followed by its auth path. That is not a coincidence to rely on
//! silently, so it is asserted in the tests rather than assumed.
//!
//! Blobs are pushed by the witness in consumption order, so the *last* one
//! pushed is the last one needed. The verifier's prologue moves all of them to
//! the alt stack, which reverses them, and from then on the alt stack is a
//! queue: the next blob is always one free `OpFromAltStack` away. Sliced
//! elements are pushed back onto the alt stack above the remaining blobs, so
//! they are consumed before the queue advances.

use anyhow::{ensure, Result};
use vault_core::ScriptWriter;

use crate::params::{Params, N};

/// Elements per blob.
///
/// Chosen by measurement, not by argument: see the `blob_size_sweep` test,
/// which reports script units and peak stack for a range of values. Four keeps
/// slicing near its practical floor while leaving roughly a hundred stack slots
/// of headroom under the 244 limit.
pub const BLOB_ELEMS: usize = 4;

/// How a signature is cut into blobs.
///
/// Carries its parameter set, because the plan is part of the redeem script
/// and therefore part of the address: a plan built for one set and used to
/// slice another's signature would produce a script that is internally
/// consistent and unspendable.
#[derive(Clone, Debug)]
pub struct BlobPlan {
    pub p: &'static Params,
    /// Elements in each blob, in consumption order.
    pub blobs: Vec<usize>,
}

impl BlobPlan {
    pub fn new(p: &'static Params, elems_per_blob: usize) -> Result<Self> {
        ensure!(elems_per_blob > 0, "a blob must hold at least one element");
        let mut blobs = Vec::new();
        let mut left = p.sig_elements();
        while left > 0 {
            let take = left.min(elems_per_blob);
            blobs.push(take);
            left -= take;
        }
        Ok(Self { p, blobs })
    }

    /// The default plan for a set: [`BLOB_ELEMS`] elements per blob.
    pub fn for_params(p: &'static Params) -> Self {
        Self::new(p, BLOB_ELEMS).expect("BLOB_ELEMS is non-zero")
    }

    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }

    /// Which blob holds element `index`, and its position within that blob.
    pub fn locate(&self, index: usize) -> (usize, usize) {
        let mut seen = 0;
        for (b, &count) in self.blobs.iter().enumerate() {
            if index < seen + count {
                return (b, index - seen);
            }
            seen += count;
        }
        panic!("element {index} is past the end of the signature");
    }

    /// Script units the slicing costs, by the model in the module docs.
    ///
    /// An estimate, and labelled as one — the measured number comes from the
    /// engine. It exists so the blob size can be chosen before the whole
    /// verifier is built.
    pub fn estimated_slice_units(&self) -> u64 {
        self.blobs
            .iter()
            .map(|&e| {
                // Extracting the first e-1 elements costs 2 * (bytes remaining);
                // the final element is already alone and costs nothing.
                (1..e).map(|k| 2 * (N * (e - k + 1)) as u64).sum::<u64>()
            })
            .sum()
    }

    /// Worst-case combined stack occupancy, which must stay under
    /// `MAX_STACK_SIZE`.
    ///
    /// The peak is at the first slice: every blob but one is still queued, the
    /// blob being cut is expanded into its elements, and the verifier's own
    /// working frame sits on the data stack.
    pub fn peak_stack_estimate(&self, working_frame: usize) -> usize {
        let largest = self.blobs.iter().copied().max().unwrap_or(0);
        self.blob_count() - 1 + largest + working_frame
    }

    /// The witness: every blob pushed in consumption order.
    ///
    /// This is the whole signature script apart from the redeem script itself,
    /// so its length is the witness half of the on-chain cost.
    pub fn witness_pushes(&self, signature: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            signature.len() == self.p.sig_len(),
            "{} signature must be {} bytes, got {}",
            self.p.name,
            self.p.sig_len(),
            signature.len()
        );
        let mut w = ScriptWriter::new();
        let mut offset = 0;
        for &count in &self.blobs {
            let bytes = count * N;
            w.data(&signature[offset..offset + bytes])?;
            offset += bytes;
        }
        Ok(w.build())
    }

    /// A witness of the right *length* filled with zeros, for sizing an
    /// unsigned transaction before a one-time cost is paid to sign it.
    pub fn placeholder_witness(&self) -> Result<Vec<u8>> {
        self.witness_pushes(&vec![0u8; self.p.sig_len()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ALL;

    #[test]
    fn every_element_lands_in_exactly_one_blob() {
        for set in ALL {
            let plan = BlobPlan::for_params(set);
            assert_eq!(plan.blobs.iter().sum::<usize>(), set.sig_elements(), "{}", set.name);
            for i in 0..set.sig_elements() {
                let (b, pos) = plan.locate(i);
                assert!(pos < plan.blobs[b]);
            }
            // Locations are strictly increasing, so nothing is aliased.
            let mut prev = (0usize, 0usize);
            for i in 1..set.sig_elements() {
                let here = plan.locate(i);
                assert!(here > prev, "{}: element {i} does not follow its predecessor", set.name);
                prev = here;
            }
        }
    }

    #[test]
    fn the_witness_reassembles_the_signature() {
        for set in ALL {
            let plan = BlobPlan::for_params(set);
            let sig: Vec<u8> = (0..set.sig_len()).map(|i| (i % 251) as u8).collect();
            let witness = plan.witness_pushes(&sig).unwrap();

            // Every signature byte must appear, in order, inside the pushes.
            let mut recovered = Vec::new();
            let mut i = 0;
            while i < witness.len() {
                let op = witness[i];
                let (len, header) = match op {
                    0x4c => (witness[i + 1] as usize, 2),
                    0x4d => (u16::from_le_bytes([witness[i + 1], witness[i + 2]]) as usize, 3),
                    n if n <= 0x4b => (n as usize, 1),
                    other => panic!("unexpected opcode {other:#x} in a push-only witness"),
                };
                recovered.extend_from_slice(&witness[i + header..i + header + len]);
                i += header + len;
            }
            assert_eq!(recovered, sig, "{}", set.name);
        }
    }

    /// A plan must refuse a signature from a different set. The sets have
    /// different signature lengths, so this is a length check — but it is the
    /// check standing between "wrong parameter set" and an unspendable vault.
    #[test]
    fn a_plan_refuses_another_sets_signature() {
        let plan = BlobPlan::for_params(&crate::params::SHA2_128S);
        let wrong = vec![0u8; crate::params::SHA2_128_24.sig_len()];
        let err = plan.witness_pushes(&wrong).unwrap_err().to_string();
        assert!(err.contains("SLH-DSA-SHA2-128s"), "error should name the expected set: {err}");
    }

    #[test]
    fn the_placeholder_is_the_size_of_a_real_witness() {
        for set in ALL {
            let plan = BlobPlan::for_params(set);
            let sig: Vec<u8> = (0..set.sig_len()).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                plan.placeholder_witness().unwrap().len(),
                plan.witness_pushes(&sig).unwrap().len(),
                "{}",
                set.name
            );
        }
    }

    #[test]
    fn the_default_plan_fits_the_stack_limit() {
        for set in ALL {
            let plan = BlobPlan::for_params(set);
            // 32 slots is a generous allowance for the verifier's working
            // frame, which never exceeds a dozen.
            let peak = plan.peak_stack_estimate(32);
            assert!(
                peak < kaspa_txscript::MAX_STACK_SIZE,
                "{}: peak stack {peak} exceeds MAX_STACK_SIZE",
                set.name
            );
        }
    }

    /// A single blob holding the whole signature is what the naive encoding
    /// would do, and it is quadratic. Pinned so the tradeoff cannot be
    /// forgotten.
    #[test]
    fn one_big_blob_is_quadratically_worse() {
        for set in ALL {
            let small = BlobPlan::for_params(set);
            let huge = BlobPlan::new(set, set.sig_elements()).unwrap();
            assert_eq!(huge.blob_count(), 1);
            assert!(
                huge.estimated_slice_units() > 20 * small.estimated_slice_units(),
                "{}: small {} vs huge {}",
                set.name,
                small.estimated_slice_units(),
                huge.estimated_slice_units()
            );
        }
    }
}
