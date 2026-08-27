//! Differential test: the off-chain binding-digest serializer against the
//! in-script reconstruction, executed by the consensus engine.
//!
//! Divergence here does not fail loudly. The signature verifies against a
//! message the script will never rebuild, and the UTXO is unspendable with no
//! error anywhere. So the two constructions are compared over randomised
//! transactions rather than a single happy-path vector.

use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    ScriptPublicKey, ScriptVec, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
    TransactionId, UtxoEntry,
};
use kaspa_txscript::opcodes::codes::*;
use vault_harness::execute_with_tx;
use lms_script::binding::{binding_digest, binding_preimage, emit_binding_digest, OutputView, SpendView};
use lms_script::ScriptWriter;

/// Deterministic pseudo-random bytes, so failures reproduce.
fn prng(seed: u64) -> impl FnMut() -> u64 {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}

/// Build a transaction matching a `SpendView`, and the script that rebuilds
/// its digest, then assert the engine agrees with the off-chain serializer.
fn assert_agrees(view: &SpendView) {
    let expected = binding_digest(view).expect("off-chain digest");

    let outputs: Vec<TransactionOutput> = view
        .outputs
        .iter()
        .map(|o| {
            TransactionOutput::new(
                o.amount,
                ScriptPublicKey::new(o.spk_version, ScriptVec::from_slice(&o.script)),
            )
        })
        .collect();

    // The script reconstructs D and compares it against the expected value.
    // If they differ the engine rejects, which is the whole assertion.
    let mut w = ScriptWriter::new();
    emit_binding_digest(&mut w, view.outputs.len()).expect("emit");
    w.data(&expected).unwrap();
    w.op(OpEqual).unwrap();
    let script = w.build();

    // The verifier lives in the UTXO's script_public_key: Kaspa requires the
    // signature script to be push-only, so it cannot hold the reconstruction.
    let outpoint = TransactionOutpoint::new(
        TransactionId::from_slice(&view.outpoint_txid),
        view.outpoint_index,
    );
    let input = TransactionInput::new_with_compute_budget(outpoint, vec![], 0, 1000);
    let tx = Transaction::new(
        view.tx_version,
        vec![input],
        outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let utxo = UtxoEntry::new(
        1_000_000_000,
        ScriptPublicKey::new(0, ScriptVec::from_slice(&script)),
        0,
        false,
        None,
    );

    execute_with_tx(&script, &tx, vec![utxo], 0).unwrap_or_else(|e| {
        panic!(
            "in-script digest disagrees with the off-chain serializer\n  \
             preimage: {}\n  expected D: {}\n  {e}",
            hex::encode(binding_preimage(view).unwrap()),
            hex::encode(expected),
        )
    });
}

fn canonical_view() -> SpendView {
    SpendView {
        tx_version: 1,
        outpoint_txid: core::array::from_fn(|i| i as u8),
        outpoint_index: 0,
        outputs: vec![
            OutputView { amount: 100_000_000, spk_version: 0, script: vec![0xaa; 35] },
            OutputView { amount: 899_000_000, spk_version: 0, script: vec![0xbb; 35] },
        ],
    }
}

/// The canonical two-output vault spend.
#[test]
fn canonical_spend_agrees() {
    assert_agrees(&canonical_view());
}

/// The engine settles the spk_len question the PQV draft is self-contradictory
/// about: does `spk` include the 2-byte version prefix?
///
/// If `OpTxOutputSpkLen` returns `len(script) + 2` and `OpTxOutputSpk` pushes
/// the version-prefixed encoding, the 133-byte preimage is right and the
/// draft's 129-byte worked vector is wrong.
#[test]
fn spk_is_version_prefixed_on_the_wire() {
    let view = canonical_view();
    let preimage = binding_preimage(&view).unwrap();
    assert_eq!(preimage.len(), 133);
    // Length prefix for a 35-byte script is 37, little-endian.
    assert_eq!(&preimage[39 + 8..39 + 10], &37u16.to_le_bytes());
    assert_agrees(&view);
}

/// Output counts other than two, since the script unrolls to a fixed count.
#[test]
fn varying_output_counts_agree() {
    for count in 1..=6usize {
        let mut view = canonical_view();
        view.outputs = (0..count)
            .map(|i| OutputView {
                amount: 1_000_000 * (i as u64 + 1),
                spk_version: 0,
                script: vec![0x10 + i as u8; 20 + i],
            })
            .collect();
        assert_agrees(&view);
    }
}

/// Non-zero SPK versions, which is where the big-endian trap hides. Standard
/// relay rejects these today, so nothing else in the test suite would catch a
/// byte-order mistake.
#[test]
fn non_zero_spk_versions_agree() {
    for version in [1u16, 2, 0x00ff, 0x0100, 0x1234, 0x7fff] {
        let mut view = canonical_view();
        view.outputs[0].spk_version = version;
        view.outputs[1].spk_version = version.rotate_left(8);
        assert_agrees(&view);
    }
}

/// Field boundaries: amounts and script lengths near what the fixed-width
/// encoding can express.
#[test]
fn boundary_values_agree() {
    let cases: Vec<SpendView> = vec![
        SpendView { outpoint_index: i32::MAX as u32, ..canonical_view() },
        SpendView { tx_version: 0x7FFF, ..canonical_view() },
        SpendView {
            outputs: vec![OutputView { amount: 1, spk_version: 0, script: vec![] }],
            ..canonical_view()
        },
        SpendView {
            // Just under 2^63-1, the largest the 8-byte sign-magnitude field holds.
            outputs: vec![OutputView {
                amount: i64::MAX as u64,
                spk_version: 0,
                script: vec![0xcc; 35],
            }],
            ..canonical_view()
        },
        SpendView {
            outputs: vec![OutputView { amount: 0, spk_version: 0, script: vec![0xdd; 200] }],
            ..canonical_view()
        },
    ];
    for view in &cases {
        assert_agrees(view);
    }
}

/// Randomised transactions, which is what actually shakes out indexing bugs.
#[test]
fn randomised_spends_agree() {
    let mut rng = prng(0xC0FFEE);
    for _ in 0..40 {
        let count = (rng() % 4 + 1) as usize;
        let outputs = (0..count)
            .map(|_| {
                let script_len = (rng() % 60) as usize;
                OutputView {
                    amount: rng() % (i64::MAX as u64),
                    spk_version: (rng() % 0x8000) as u16,
                    script: (0..script_len).map(|_| (rng() & 0xff) as u8).collect(),
                }
            })
            .collect();

        assert_agrees(&SpendView {
            tx_version: (rng() % 0x8000) as u16,
            outpoint_txid: core::array::from_fn(|_| (rng() & 0xff) as u8),
            outpoint_index: (rng() % 0x8000_0000) as u32,
            outputs,
        });
    }
}

/// The negative control: a digest that should NOT match must be rejected, or
/// every assertion above is vacuous.
#[test]
fn a_wrong_digest_is_rejected() {
    let view = canonical_view();
    let mut wrong = binding_digest(&view).unwrap();
    wrong[0] ^= 0x01;

    let outputs: Vec<TransactionOutput> = view
        .outputs
        .iter()
        .map(|o| {
            TransactionOutput::new(
                o.amount,
                ScriptPublicKey::new(o.spk_version, ScriptVec::from_slice(&o.script)),
            )
        })
        .collect();

    let mut w = ScriptWriter::new();
    emit_binding_digest(&mut w, view.outputs.len()).unwrap();
    w.data(&wrong).unwrap();
    w.op(OpEqual).unwrap();
    let script = w.build();

    let outpoint =
        TransactionOutpoint::new(TransactionId::from_slice(&view.outpoint_txid), view.outpoint_index);
    let input = TransactionInput::new_with_compute_budget(outpoint, vec![], 0, 1000);
    let tx =
        Transaction::new(view.tx_version, vec![input], outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let utxo = UtxoEntry::new(
        1_000_000_000,
        ScriptPublicKey::new(0, ScriptVec::from_slice(&script)),
        0,
        false,
        None,
    );

    assert!(execute_with_tx(&script, &tx, vec![utxo], 0).is_err(), "a wrong digest was accepted");
}
