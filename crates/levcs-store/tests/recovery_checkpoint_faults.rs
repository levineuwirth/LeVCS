//! Scope 4-A2 acceptance: the physical-fault seam reaches checkpoint
//! installation.
//!
//! Its own test binary, for the reason `recovery_eio.rs` states: the armed
//! fault in `sys.rs` is a one-shot global, so a test that arms one must not
//! share a process with tests that also go through the funnel. Within this
//! binary the arming is serialized by a mutex, because `cargo test` runs a
//! binary's tests in parallel threads and two concurrently armed faults would
//! be a race by construction.
//!
//! These tests exist because of a review finding, and the finding is worth
//! recording: `install` wrote the checkpoint body with `File::write_all`
//! instead of `sys::write_vectored_all`. The bytes were therefore invisible to
//! `DurabilityCounters`, and — the part that mattered — the `ENOSPC` /
//! short-write / cursor-skew seam could not reach checkpoint installation *at
//! all*. No fault campaign could have exercised this path, and none of the
//! existing checkpoint tests could have noticed, because they all simulate
//! damage by rewriting files after the fact rather than by making the write
//! itself fail. A fault that cannot be delivered is not a covered case.

#[cfg(all(feature = "failpoints", feature = "store-internals"))]
mod faults {
    use levcs_store::checkpoint::{
        install, list_generations, Checkpoint, CheckpointError, CheckpointLoad, ReceiptRecord,
    };
    use levcs_store::drive::faults::{arm, disarm, Fault};
    use levcs_store::index::{
        NamespaceCatalog, NamespaceLifecycle, NamespaceRecord, NamespaceStorageMode,
    };
    use levcs_store::recovery::{checkpoint_for_recovery, load_checkpoint, ShardRecoveryReport};
    use levcs_store::types::{DurabilityCounters, NamespaceId, OperationId};

    use levcs_core::ObjectId;

    const ROOT: [u8; 16] = [0x11; 16];
    const SHARD: u16 = 1;

    fn ns(b: u8) -> NamespaceId {
        NamespaceId([b; 32])
    }

    fn oid(b: u8) -> ObjectId {
        ObjectId([b; 32])
    }

    /// Deliberately several hundred bytes of body, so a short write can land in
    /// the middle of it rather than at a structural boundary.
    fn checkpoint(sequence: u64) -> Checkpoint {
        let mut catalog = NamespaceCatalog::new();
        for i in 1..=3u8 {
            catalog
                .bind(NamespaceRecord {
                    namespace: ns(i),
                    genesis_authority: oid(0xA0 + i),
                    current_authority: oid(0xB0 + i),
                    lifecycle: NamespaceLifecycle::Active,
                    storage_mode: NamespaceStorageMode::Full,
                    repo_sequence: sequence,
                    previous_event_digest: oid(0xC0 + i),
                })
                .expect("bind");
        }
        Checkpoint {
            root_uuid: ROOT,
            shard_index: SHARD,
            shard_committed_sequence: sequence,
            active_journal_id: [0x22; 16],
            active_journal_offset: 512,
            created_at_micros: 1_700_000_000_000_000,
            catalog,
            refs: Vec::new(),
            receipts: vec![ReceiptRecord {
                namespace: ns(1),
                operation_id: OperationId([sequence as u8; 16]),
                operation_digest: oid(0xC0),
                repo_sequence: sequence,
                shard_sequence: sequence,
                current_authority: oid(0xB1),
                refs: Vec::new(),
                objects_new: 1,
                retry_until_micros: 1_700_000_900_000_000,
                first_receipt_visibility_micros: Some(1_700_000_000_100_000),
                receipt_visible_until_micros: 1_700_000_900_000_000,
            }],
        }
    }

    fn generations(dir: &std::path::Path) -> Vec<u64> {
        list_generations(dir)
            .expect("list")
            .iter()
            .map(|(g, _)| *g)
            .collect()
    }

    // =======================================================================
    // ENOSPC
    // =======================================================================

    /// Plan §10's `ENOSPC` row, applied to a checkpoint rather than a journal
    /// append. The checkpoint is derived state, so the correct behavior is not
    /// poisoning: the install fails, nothing is renamed, and the store keeps
    /// running from the previous generation.
    #[test]
    fn enospc_during_a_checkpoint_write_leaves_the_previous_generation_intact() {
        let serial = levcs_store::drive::faults::serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let counters = DurabilityCounters::default();
        install(dir.path(), &checkpoint(10), &counters).expect("install the predecessor");

        disarm(&serial);
        arm(&serial, Fault::NoSpace);
        let outcome = install(dir.path(), &checkpoint(20), &counters);
        disarm(&serial);

        let err = outcome.expect_err(
            "ENOSPC must reach checkpoint installation; if this passes, the write \
             is bypassing the sys funnel again",
        );
        let message = err.to_string();
        assert!(
            message.contains("ENOSPC") || message.contains("space"),
            "the failure must name the physical cause, got: {message}"
        );

        assert_eq!(
            generations(dir.path()),
            vec![10],
            "the failed generation must never appear under its final name"
        );

        // And the store still opens from the surviving generation.
        let mut report = ShardRecoveryReport::new(SHARD);
        let load = load_checkpoint(dir.path(), &ROOT, SHARD, 2).expect("load");
        let restored = checkpoint_for_recovery(load, &ROOT, SHARD, &mut report)
            .expect("a full disk must not cost the shard its checkpoint");
        assert_eq!(restored.shard_committed_sequence, 10);
        assert!(!report.offline_rebuild_required);
    }

    // =======================================================================
    // Short write
    // =======================================================================

    /// A short write is not an error at the syscall layer — it leaves a durable
    /// prefix — so the only thing that can catch it is completeness. Two claims
    /// here, and they are separate: the install refuses, *and* the prefix that
    /// survives on disk would not validate even if something renamed it into
    /// place. The second is what makes the first a safety net rather than the
    /// only line of defense.
    #[test]
    fn a_short_write_never_yields_a_checkpoint_that_validates() {
        let serial = levcs_store::drive::faults::serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let counters = DurabilityCounters::default();
        install(dir.path(), &checkpoint(10), &counters).expect("install the predecessor");

        let full_len = checkpoint(20).encode().expect("encode").len();
        let prefix = 200usize;
        assert!(
            prefix < full_len,
            "the injected prefix must actually be short of the body"
        );

        disarm(&serial);
        arm(
            &serial,
            Fault::ShortWrite {
                prefix_bytes: prefix,
            },
        );
        let outcome = install(dir.path(), &checkpoint(20), &counters);
        disarm(&serial);

        let err = outcome.expect_err("an incomplete body must fail the install");
        assert!(
            err.to_string().contains("short write"),
            "the failure must say what happened, got: {err}"
        );
        assert_eq!(counters.snapshot().short_writes, 1, "counted, not silent");
        assert_eq!(
            generations(dir.path()),
            vec![10],
            "a partial body must not be renamed into a generation name"
        );

        // The prefix survives as a temporary. Rename it into the final name by
        // hand — which is exactly what a buggy install, or a future one that
        // renames before checking, would do — and confirm the codec refuses it.
        // A truncated checkpoint must fail validation, not load.
        let tmp = dir.path().join("20.checkpoint.tmp");
        assert_eq!(
            std::fs::metadata(&tmp)
                .expect("the prefix is left for forensics")
                .len(),
            prefix as u64
        );
        std::fs::rename(&tmp, dir.path().join("20.checkpoint")).expect("rename by hand");

        match load_checkpoint(dir.path(), &ROOT, SHARD, 2).expect("load") {
            CheckpointLoad::Loaded {
                checkpoint,
                rejected,
                ..
            } => {
                assert_eq!(
                    checkpoint.shard_committed_sequence, 10,
                    "the torn generation must be rejected and the predecessor used"
                );
                assert_eq!(rejected.len(), 1);
                assert!(
                    matches!(
                        rejected[0].1,
                        CheckpointError::Trailer
                            | CheckpointError::BodyDigest
                            | CheckpointError::Truncated
                            | CheckpointError::Body(_)
                    ),
                    "a torn checkpoint must be refused by its own structure, got {:?}",
                    rejected[0].1
                );
            }
            CheckpointLoad::Empty => panic!("two files are present"),
            CheckpointLoad::OfflineRebuildRequired { .. } => {
                panic!("the intact predecessor must still load")
            }
        }

        // The length check is the first defense and it fired, which leaves the
        // digest untested. So pad the torn prefix back out to its declared
        // length with zeros: the file is now structurally well-formed and only
        // the content is wrong, so nothing but the body digest can catch it.
        // Without this, "a torn checkpoint does not load" would rest entirely
        // on a length field the tearing happened to have preserved.
        let padded = dir.path().join("20.checkpoint");
        let mut bytes = std::fs::read(&padded).expect("read the torn prefix");
        bytes.resize(full_len, 0);
        let intact = install_bytes_for_inspection(&checkpoint(20));
        bytes[full_len - intact.trailer_len..].copy_from_slice(&intact.trailer);
        std::fs::write(&padded, &bytes).expect("write the padded torn body");

        match load_checkpoint(dir.path(), &ROOT, SHARD, 2).expect("load") {
            CheckpointLoad::Loaded { rejected, .. } => {
                assert_eq!(
                    rejected[0].1,
                    CheckpointError::BodyDigest,
                    "a zero-filled tail is exactly what the body digest exists to catch"
                );
            }
            CheckpointLoad::Empty | CheckpointLoad::OfflineRebuildRequired { .. } => {
                panic!("the intact predecessor must still load")
            }
        }
    }

    /// The trailer of a well-formed encoding of the same checkpoint, so a
    /// truncated body can be padded back to a structurally valid file whose
    /// only remaining defect is its content.
    struct Trailer {
        trailer: Vec<u8>,
        trailer_len: usize,
    }

    fn install_bytes_for_inspection(checkpoint: &Checkpoint) -> Trailer {
        let bytes = checkpoint.encode().expect("encode");
        let trailer_len = levcs_store::checkpoint::CHECKPOINT_TRAILER_LEN;
        Trailer {
            trailer: bytes[bytes.len() - trailer_len..].to_vec(),
            trailer_len,
        }
    }

    // =======================================================================
    // Cursor skew
    // =======================================================================

    /// Plan §5.2's "unexpected file position". The body is written in full, so
    /// nothing about the bytes is wrong — only the cursor is. That the install
    /// still fails is the proof the position check is on this path too, and not
    /// only on the journal's.
    #[test]
    fn a_skewed_cursor_during_a_checkpoint_write_fails_the_install() {
        let serial = levcs_store::drive::faults::serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let counters = DurabilityCounters::default();
        install(dir.path(), &checkpoint(10), &counters).expect("install the predecessor");

        disarm(&serial);
        arm(&serial, Fault::CursorSkew { delta: -8 });
        let outcome = install(dir.path(), &checkpoint(20), &counters);
        disarm(&serial);

        let err = outcome.expect_err("an unexpected file position must fail the install");
        assert!(
            err.to_string().contains("unexpected file position"),
            "got: {err}"
        );
        assert_eq!(generations(dir.path()), vec![10]);
    }

    // =======================================================================
    // The fence
    // =======================================================================

    /// `EIO` on the fence. Armed *after* the write, which only works because
    /// fault selection is positional: the write no longer eats a fault meant
    /// for the fence.
    #[test]
    fn an_eio_on_the_checkpoint_fence_leaves_no_generation_behind() {
        let serial = levcs_store::drive::faults::serial();
        let dir = tempfile::tempdir().expect("tempdir");
        let counters = DurabilityCounters::default();
        install(dir.path(), &checkpoint(10), &counters).expect("install the predecessor");

        disarm(&serial);
        arm(&serial, Fault::FenceEio);
        let outcome = install(dir.path(), &checkpoint(20), &counters);
        disarm(&serial);

        outcome.expect_err("an unfenced checkpoint must not be installed");
        assert_eq!(
            generations(dir.path()),
            vec![10],
            "the rename happens only after the fence"
        );
        assert!(
            counters.snapshot().bytes_written > 0,
            "the body was written before the fence failed, and must be counted"
        );
    }
}
