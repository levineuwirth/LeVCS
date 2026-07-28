#![cfg(all(feature = "store-internals", feature = "failpoints"))]

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use levcs_store::drive::{faults, ShardDrive};
use levcs_store::format::{Manifest, TailRange, JOURNAL_HEADER_LEN};
use levcs_store::journal::Journal;
use levcs_store::segment::{self, RootLayout};
use levcs_store::{DurabilityCounters, NamespaceId};

fn append(drive: &mut ShardDrive, repo_sequence: u64) {
    let frame = drive
        .build_frame(
            NamespaceId([0xA5; 32]),
            repo_sequence,
            vec![repo_sequence as u8; 64],
        )
        .expect("build frame");
    drive
        .append_group_and_fence(&[frame])
        .expect("append and fence");
}

fn only_active_journal(active: &Path) -> PathBuf {
    let mut journals: Vec<PathBuf> = std::fs::read_dir(active)
        .expect("list active")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "journal")
        })
        .collect();
    assert_eq!(
        journals.len(),
        1,
        "write readiness requires one active journal"
    );
    journals.pop().expect("one journal")
}

#[test]
fn nonempty_recovery_preserves_evidence_seals_the_exact_prefix_and_opens_fresh() {
    let _serial = faults::serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let (root_uuid, original_path, original_bytes) = {
        let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
        append(&mut drive, 0);
        append(&mut drive, 1);
        let path = drive.journal_path().to_path_buf();
        (
            drive.root_uuid(),
            path.clone(),
            std::fs::read(path).expect("read crash image"),
        )
    };

    let recovered =
        ShardDrive::reopen_through_recovery(dir.path(), 0).expect("recover nonempty journal");
    assert!(recovered.report.ready);
    assert_eq!(recovered.adopted_shard_sequences, vec![0, 1]);
    let evidence = recovered
        .report
        .preserved_journal
        .as_ref()
        .expect("recovery must retain the original inode");
    assert_eq!(
        std::fs::read(evidence).expect("read evidence"),
        original_bytes,
        "recovery may not truncate or rewrite the crash image"
    );
    assert!(
        !original_path.exists(),
        "the old active name must be retired"
    );

    let paths = RootLayout::new(dir.path()).shard(0);
    let fresh = only_active_journal(&paths.active());
    assert_ne!(fresh, original_path);
    let counters = Arc::new(DurabilityCounters::default());
    let (journal, scan) = Journal::open(&fresh, &root_uuid, counters).expect("open fresh");
    assert!(scan.frames.is_empty());
    assert_eq!(scan.stop_offset, JOURNAL_HEADER_LEN as u64);
    assert_eq!(journal.next_shard_sequence(), 2);
    assert!(
        std::fs::read_dir(paths.segments())
            .expect("segments")
            .all(|entry| !entry
                .expect("entry")
                .path()
                .extension()
                .is_some_and(|extension| extension == "prefix")),
        "a successful recovery may not leak a construction prefix"
    );

    let manifest_generation = recovered.recovered.manifest_generation;
    drop(recovered);
    let second =
        ShardDrive::reopen_through_recovery(dir.path(), 0).expect("idempotent re-recovery");
    assert_eq!(second.recovered.manifest_generation, manifest_generation);
    assert!(second.report.preserved_journal.is_none());
    assert_eq!(only_active_journal(&paths.active()), fresh);
}

#[test]
fn torn_first_frame_is_quarantined_and_replaced_without_an_empty_segment() {
    let _serial = faults::serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let (root_uuid, original_path, original_bytes) = {
        let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
        let frame = drive
            .build_frame(NamespaceId([0xB6; 32]), 0, vec![0x7E; 256])
            .expect("build");
        let encoded = frame.encode().expect("encode");
        let path = drive.journal_path().to_path_buf();
        let file = OpenOptions::new().write(true).open(&path).expect("open");
        file.write_at(&encoded[..encoded.len() / 2], JOURNAL_HEADER_LEN as u64)
            .expect("write torn first frame");
        file.sync_data().expect("fence torn bytes");
        (
            drive.root_uuid(),
            path.clone(),
            std::fs::read(path).expect("read crash image"),
        )
    };

    let recovered =
        ShardDrive::reopen_through_recovery(dir.path(), 0).expect("recover torn first frame");
    assert!(recovered.report.ready);
    assert!(recovered.adopted_shard_sequences.is_empty());
    assert!(recovered.report.quarantined_bytes > 0);
    let evidence = recovered
        .report
        .preserved_journal
        .as_ref()
        .expect("damaged zero-frame journal must be retained");
    assert_eq!(std::fs::read(evidence).expect("evidence"), original_bytes);
    assert_ne!(
        std::fs::read(&original_path).expect("fresh journal at reused sequence name"),
        original_bytes,
        "the sequence-zero pathname may be reused, but it must name a fresh inode"
    );

    let paths = RootLayout::new(dir.path()).shard(0);
    assert!(
        std::fs::read_dir(paths.segments())
            .expect("segments")
            .all(|entry| entry
                .expect("entry")
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("seg")),
        "an empty validated prefix is not a segment"
    );
    let fresh = only_active_journal(&paths.active());
    let counters = Arc::new(DurabilityCounters::default());
    let (journal, scan) = Journal::open(&fresh, &root_uuid, counters).expect("open fresh");
    assert!(scan.frames.is_empty());
    assert_eq!(journal.next_shard_sequence(), 0);
}

#[test]
fn healthy_empty_active_journal_is_already_write_ready_and_is_not_replaced() {
    let _serial = faults::serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let (root_uuid, original) = {
        let drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
        (drive.root_uuid(), drive.journal_path().to_path_buf())
    };

    let recovered =
        ShardDrive::reopen_through_recovery(dir.path(), 0).expect("recover healthy empty");
    assert!(recovered.report.ready);
    assert!(recovered.report.preserved_journal.is_none());
    assert_eq!(recovered.recovered.manifest_generation, None);
    let paths = RootLayout::new(dir.path()).shard(0);
    assert_eq!(only_active_journal(&paths.active()), original);
    let (journal, scan) = Journal::open(
        &original,
        &root_uuid,
        Arc::new(DurabilityCounters::default()),
    )
    .expect("open");
    assert!(scan.frames.is_empty());
    assert_eq!(journal.next_shard_sequence(), 0);
}

#[test]
fn rejected_newer_generation_forces_recovery_artifacts_above_every_immutable_name() {
    let _serial = faults::serial();
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
        append(&mut drive, 0);
        drive.seal_and_install().expect("generation one");
        append(&mut drive, 1);

        let paths = drive.shard_paths();
        let selected = segment::read_manifest(paths, 1, &drive.root_uuid()).expect("manifest one");
        let rejected = Manifest {
            root_uuid: drive.root_uuid(),
            generation: 100,
            base_generation: 0,
            retained_tail_ranges: selected.retained_tail_ranges.clone(),
            index_runs: vec![(99, "missing.idx".into())],
            checkpoints: Vec::new(),
            committed_shard_sequence: selected.committed_shard_sequence,
        };
        segment::install_manifest(paths, &rejected, 2, &DurabilityCounters::default())
            .expect("publish rejected newer manifest");
    }

    let recovered =
        ShardDrive::reopen_through_recovery(dir.path(), 0).expect("fallback and repair");
    assert_eq!(recovered.recovered.manifest_generation, Some(101));
    assert_eq!(recovered.adopted_shard_sequences, vec![0, 1]);
}

#[test]
fn journal_creation_reuses_one_target_scoped_temp_after_an_interrupted_attempt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let active = dir.path().join("active");
    std::fs::create_dir(&active).expect("active");
    std::fs::write(active.join(".0.journal.tmp"), [0xA5; 31]).expect("partial temp");
    let counters = Arc::new(DurabilityCounters::default());
    let journal = Journal::create(
        &active,
        [7; 16],
        0,
        0,
        [9; 16],
        1 << 20,
        1,
        Arc::clone(&counters),
    )
    .expect("resume partial creation");
    assert_eq!(journal.next_shard_sequence(), 0);
    assert!(!active.join(".0.journal.tmp").exists());
    assert_eq!(only_active_journal(&active), active.join("0.journal"));

    let reopened = Journal::create(&active, [8; 16], 0, 0, [9; 16], 1 << 20, 2, counters)
        .expect("resume after final rename");
    assert_eq!(reopened.journal_id(), [7; 16]);
    assert_eq!(
        std::fs::read_dir(active).expect("active entries").count(),
        1
    );
}

#[test]
fn recovered_prefix_resumes_one_deterministic_partial_copy() {
    let _serial = faults::serial();
    let dir = tempfile::tempdir().expect("tempdir");
    let (root_uuid, journal_path, paths) = {
        let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
        append(&mut drive, 0);
        (
            drive.root_uuid(),
            drive.journal_path().to_path_buf(),
            drive.shard_paths().clone(),
        )
    };
    let original = std::fs::read(&journal_path).expect("original");
    let counters = Arc::new(DurabilityCounters::default());
    let (journal, scan) =
        Journal::open(&journal_path, &root_uuid, Arc::clone(&counters)).expect("open journal");
    let artifact = paths.segments().join(format!(
        ".recovery-{}-1.prefix",
        hex::encode(journal.journal_id())
    ));
    std::fs::write(&artifact, &original[..137]).expect("partial prefix");

    let installed = segment::seal_recovered_prefix(
        journal.file(),
        journal.header(),
        &scan,
        &paths,
        1,
        &counters,
    )
    .expect("resume and seal");
    assert!(installed.exists());
    assert!(!artifact.exists());
    assert_eq!(
        std::fs::read(journal_path).expect("source after seal"),
        original,
        "the source journal must remain byte-for-byte unchanged"
    );
}

#[test]
fn manifest_install_resumes_exact_temp_and_exact_final_but_rejects_difference() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layout = RootLayout::new(dir.path());
    let counters = DurabilityCounters::default();
    segment::initialize_root(&layout, 1, [0xC7; 16], 1, &counters).expect("initialize");
    let paths = layout.shard(0);
    let manifest = Manifest {
        root_uuid: [0xC7; 16],
        generation: 1,
        base_generation: 0,
        retained_tail_ranges: vec![TailRange {
            generation: 1,
            first_shard_sequence: 0,
            last_shard_sequence: 0,
            filename: "1-0-0.seg".into(),
        }],
        index_runs: Vec::new(),
        checkpoints: Vec::new(),
        committed_shard_sequence: 0,
    };
    let encoded = manifest.encode().expect("encode");
    let temp = paths.manifests().join("1.manifest.tmp");
    std::fs::write(&temp, &encoded).expect("exact temp");
    File::open(&temp)
        .expect("open temp")
        .sync_data()
        .expect("fence");
    segment::install_manifest(&paths, &manifest, 2, &counters).expect("resume exact temp");

    std::fs::write(&temp, &encoded).expect("temp after final");
    segment::install_manifest(&paths, &manifest, 2, &counters)
        .expect("resume after final publication");
    assert!(!temp.exists());

    std::fs::write(&temp, [0xDD; 64]).expect("different temp");
    let error = segment::install_manifest(&paths, &manifest, 2, &counters)
        .expect_err("different temp must not be overwritten");
    assert!(error.to_string().contains("different bytes"));
}
