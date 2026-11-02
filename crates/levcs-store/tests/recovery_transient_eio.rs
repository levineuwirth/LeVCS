//! Audit finding S1, and scope 3.8 step 5 as amended by contract review
//! 2026-11-02-B: a read error in a shard's active journal refuses the open
//! before that shard's recovery changes anything, so it can cost no
//! acknowledged commit.
//!
//! Its own test binary, like `recovery_eio.rs`: the armed fault in `sys.rs` is
//! a one-shot global, and every test here holds `drive::faults::serial()` for
//! its whole body so no other read in the process can consume it.

#![cfg(all(
    feature = "store-privileged",
    feature = "store-internals",
    feature = "failpoints"
))]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use levcs_store::drive::faults::{arm, disarm, serial, Fault};
use levcs_store::format::{JournalHeader, JOURNAL_HEADER_LEN};
use levcs_store::journal::scan_journal;
use levcs_store::segment::RootLayout;
use levcs_store::types::{NamespaceId, OperationId, StoreError};
use levcs_store::{StoreEngine, StoreOptions, TransactionStatus};

#[path = "support/engine_matrix.rs"]
mod engine_matrix;

use engine_matrix::{create_transaction, namespace_on_shard, options, push_transaction, submit};

/// The one active journal of shard 0.
fn active_journal(root: &Path) -> PathBuf {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(RootLayout::new(root).shard(0).active())
        .expect("the active directory")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    assert_eq!(entries.len(), 1, "one active journal: {entries:?}");
    entries.pop().unwrap()
}

/// Where each frame of the active journal begins.
fn frame_offsets(root: &Path) -> Vec<u64> {
    let mut file = File::open(active_journal(root)).expect("open the journal");
    let mut head = [0u8; JOURNAL_HEADER_LEN];
    file.read_exact(&mut head).expect("read the header");
    let header = JournalHeader::decode(&head).expect("a valid header");
    scan_journal(&file, &header, JOURNAL_HEADER_LEN as u64)
        .frames
        .iter()
        .map(|frame| frame.offset)
        .collect()
}

/// Every file under `root` but `LOCK`, by path, with its length and digest:
/// what a refused open must leave exactly as it found.
fn tree(root: &Path) -> BTreeMap<PathBuf, (u64, [u8; 32])> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, (u64, [u8; 32])>) {
        for entry in std::fs::read_dir(dir).expect("read a directory") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                walk(root, &path, out);
            } else if path.file_name().is_some_and(|name| name != "LOCK") {
                let bytes = std::fs::read(&path).expect("read a file");
                out.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    (bytes.len() as u64, *blake3::hash(&bytes).as_bytes()),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// A create and eight pushes, operations 1 to 9, then a clean shutdown.
fn nine_commits(root: &Path) -> NamespaceId {
    let namespace = namespace_on_shard(0, 1, 0);
    let engine = StoreEngine::open(options(root, 1)).expect("open");
    for operation in 1..=9u8 {
        let transaction = if operation == 1 {
            create_transaction(namespace, operation)
        } else {
            push_transaction(namespace, operation, 0x40 + operation)
        };
        let outcome = submit(&engine, transaction);
        assert!(outcome.receipt().is_some(), "{:?}", outcome.error());
    }
    namespace
}

fn committed(engine: &StoreEngine, namespace: NamespaceId, operation: u8) -> bool {
    matches!(
        engine.transaction_status(namespace, OperationId([operation; 16])),
        Ok(TransactionStatus::Committed(_))
    )
}

/// Opens `root` with one read error armed at `offset`, and returns the result.
fn open_with_read_error_at(
    serial: &levcs_store::drive::faults::FaultSerial,
    offset: u64,
    options: StoreOptions,
) -> Result<StoreEngine, StoreError> {
    arm(serial, Fault::ReadEioAtOrAfter { offset });
    let opened = StoreEngine::open(options);
    disarm(serial);
    opened
}

/// Nine commits, a clean shutdown, and one read error during the next open,
/// on the second frame of the active journal. The open is refused, naming the
/// read, and nothing under the root changes; the open after it, on a healthy
/// device, finds all nine.
///
/// Before the fix, recovery sealed the frame below the error, retired the
/// journal, and started a fresh one at the second sequence, and only then
/// refused the open. The healthy open after it found operations 2 to 9
/// `Unknown`; they survived only as quarantined evidence.
#[test]
fn a_read_error_in_the_active_journal_refuses_the_open_and_changes_nothing() {
    let serial = serial();
    disarm(&serial);
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    let namespace = nine_commits(&root);
    let offsets = frame_offsets(&root);
    assert_eq!(offsets.len(), 9, "nine frames in the active journal");
    let before = tree(&root);

    let error = open_with_read_error_at(&serial, offsets[1], options(&root, 1))
        .err()
        .expect("a read error in the active journal refuses the open");
    let message = error.to_string();
    assert!(
        message.contains(&format!("failed at offset {}", offsets[1]))
            && message.contains("changed nothing in this shard"),
        "the refusal must say where the read failed and that nothing changed: {message}"
    );
    assert_eq!(tree(&root), before, "a refused open changed the root");

    let engine = StoreEngine::open(options(&root, 1)).expect("a healthy reopen");
    for operation in 1..=9u8 {
        assert!(
            committed(&engine, namespace, operation),
            "operation {operation} was lost to a read error"
        );
    }
}

/// The guarantee is per shard. With two shards, a read error in the second
/// one's journal refuses the open after the first has completed its ordinary
/// recovery, which the open may keep. The second shard's files are left exactly
/// as they were, nothing of its journal reaches the quarantine, and a healthy
/// retry recovers every commit on both.
#[test]
fn a_read_error_in_a_later_shard_leaves_that_shard_untouched() {
    let serial = serial();
    disarm(&serial);
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    let first = namespace_on_shard(0, 2, 0);
    let second = namespace_on_shard(1, 2, 0);
    {
        let engine = StoreEngine::open(options(&root, 2)).expect("open");
        let created = submit(&engine, create_transaction(first, 1));
        assert!(created.receipt().is_some(), "{:?}", created.error());
        for operation in 1..=9u8 {
            let transaction = if operation == 1 {
                create_transaction(second, operation)
            } else {
                push_transaction(second, operation, 0x40 + operation)
            };
            let outcome = submit(&engine, transaction);
            assert!(outcome.receipt().is_some(), "{:?}", outcome.error());
        }
    }

    // The fault fires at the first read at or past this offset. The first
    // shard's journal holds one frame, so its reads all fall below the second
    // shard's ninth frame, and the error lands in the second shard's scan.
    let layout = RootLayout::new(&root);
    let second_dir = layout.shard(1).dir;
    let mut file = File::open(
        std::fs::read_dir(layout.shard(1).active())
            .expect("the second shard's active directory")
            .next()
            .expect("an active journal")
            .expect("an entry")
            .path(),
    )
    .expect("open the second shard's journal");
    let mut head = [0u8; JOURNAL_HEADER_LEN];
    file.read_exact(&mut head).expect("read the header");
    let header = JournalHeader::decode(&head).expect("a valid header");
    let frames = scan_journal(&file, &header, JOURNAL_HEADER_LEN as u64).frames;
    assert_eq!(frames.len(), 9, "nine frames in the second shard's journal");
    let journal_id: String = header
        .journal_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    drop(file);
    let before = tree(&second_dir);

    let error = open_with_read_error_at(&serial, frames[8].offset, options(&root, 2))
        .err()
        .expect("a read error in the second shard refuses the open");
    let message = error.to_string();
    assert!(
        message.contains("shard 1:") && message.contains("changed nothing in this shard"),
        "{message}"
    );
    assert_eq!(
        tree(&second_dir),
        before,
        "the refused shard's files changed"
    );
    let quarantined: Vec<String> = std::fs::read_dir(layout.quarantine_dir())
        .map(|entries| {
            entries
                .map(|entry| {
                    entry
                        .expect("an entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .filter(|name| name.contains(&journal_id))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        quarantined.is_empty(),
        "nothing of the refused shard's journal may reach the quarantine: {quarantined:?}"
    );

    let engine = StoreEngine::open(options(&root, 2)).expect("a healthy retry");
    assert!(committed(&engine, first, 1), "the first shard's commit");
    for operation in 1..=9u8 {
        assert!(
            committed(&engine, second, operation),
            "operation {operation} on the second shard"
        );
    }
}

/// For a device that cannot be repaired, the operator may accept losing what
/// lies past the read error. The open then adopts the frames before it, the
/// whole journal is preserved in quarantine, and the store goes on: the next
/// commit lands after the adopted prefix, and later opens need no option.
#[test]
fn accepting_an_unreadable_tail_adopts_the_prefix_and_preserves_the_journal() {
    let serial = serial();
    disarm(&serial);
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    let namespace = nine_commits(&root);
    let offsets = frame_offsets(&root);
    let journal = std::fs::read(active_journal(&root)).expect("the journal's bytes");

    let mut accepting = options(&root, 1);
    accepting.accept_unreadable_journal_tail = true;
    let engine = open_with_read_error_at(&serial, offsets[1], accepting)
        .expect("accepting the unreadable tail opens the store");
    assert!(
        committed(&engine, namespace, 1),
        "the readable prefix is adopted"
    );
    for operation in 2..=9u8 {
        assert!(
            !committed(&engine, namespace, operation),
            "operation {operation} lay past the read error and was accepted as lost"
        );
    }
    let quarantine = RootLayout::new(&root).quarantine_dir();
    let preserved = std::fs::read_dir(&quarantine)
        .expect("the quarantine directory")
        .map(|entry| std::fs::read(entry.expect("an entry").path()).expect("read"))
        .any(|bytes| bytes == journal);
    assert!(preserved, "the whole journal is preserved in quarantine");

    let next = submit(&engine, push_transaction(namespace, 10, 0x60));
    assert!(next.receipt().is_some(), "{:?}", next.error());
    drop(engine);

    let engine = StoreEngine::open(options(&root, 1)).expect("a later open needs no option");
    assert!(committed(&engine, namespace, 1));
    assert!(committed(&engine, namespace, 10));
}
