//! Scope 3.4 link-then-unlink: recovery's disposition of an `active/` journal
//! when a seal was interrupted.
//!
//! Sealing links the journal into `segments/` (step 4), installs the manifest
//! generation and swaps `CURRENT` (step 5), and only then unlinks the `active/`
//! name (step 6). Both names exist across the whole install, so no crash point
//! leaves the frames unreachable — the hole a *rename* here would open.
//!
//! The cost is a state recovery must expect, and the two crash points are
//! **opposite errors**, which is why they are two dedicated tests rather than
//! one parameterized one:
//!
//! - crash between 4 and 5 — an orphan segment no manifest references. The
//!   journal is still the authority; ignoring it would drop every frame the
//!   manifest does not yet name.
//! - crash between 5 and 6 — a manifest that *does* reference a segment whose
//!   `journal_id` is the active journal's. The seal completed; replaying the
//!   journal as well would adopt every frame twice.
//!
//! Nothing here builds a fake image: every fixture runs the real
//! `Journal::create` / `append_group_and_fence` / `segment::seal_journal` /
//! `segment::install_manifest` and then stops at the crash point under test.

#[path = "recovery_reference_frame.rs"]
mod reference;

use std::sync::Arc;

use levcs_store::format::{Manifest, TailRange};
use levcs_store::journal::Journal;
use levcs_store::recovery::{
    classify_active_journal, complete_interrupted_seal, verify_shard_sequence,
    ActiveJournalDisposition, FrameFacts, ShardSequenceFault,
};
use levcs_store::segment::{self, RootLayout, ShardPaths};
use levcs_store::types::DurabilityCounters;

use reference::{FrameSpec, ROOT_UUID};

const SHARD: u16 = 0;
const PREALLOCATED: u64 = 256 * 1024;
const GENERATION: u64 = 1;

struct Fixture {
    _dir: tempfile::TempDir,
    layout: RootLayout,
    paths: ShardPaths,
    counters: Arc<DurabilityCounters>,
    journal_id: [u8; 16],
    active_path: std::path::PathBuf,
    segment_path: std::path::PathBuf,
    sealed: Vec<u64>,
}

impl Fixture {
    /// Build a root, append three frames, fence them, and run scope 3.4 step 4
    /// (the `link`). Stops there — the caller decides how far the seal got.
    fn sealed_through_link() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = RootLayout::new(dir.path().join("root"));
        let counters = Arc::new(DurabilityCounters::default());
        segment::initialize_root(&layout, 1, ROOT_UUID, 1, &counters).expect("initialize");
        let paths = layout.shard(SHARD);

        let journal_id = [0x7Au8; 16];
        let mut journal = Journal::create(
            &paths.active(),
            journal_id,
            0,
            SHARD,
            ROOT_UUID,
            PREALLOCATED,
            1,
            counters.clone(),
        )
        .expect("create journal");
        let active_path = journal.path().to_path_buf();

        let frames: Vec<_> = (0..3)
            .map(|sequence| {
                FrameSpec::new(sequence)
                    .with_journal_id(journal_id)
                    .to_frame()
            })
            .collect();
        let sealed = journal
            .append_group_and_fence(&frames)
            .expect("append and fence");

        let segment_path =
            segment::seal_journal(&mut journal, &paths, GENERATION, &counters).expect("seal");

        Self {
            _dir: dir,
            layout,
            paths,
            counters,
            journal_id,
            active_path,
            segment_path,
            sealed,
        }
    }

    fn manifest(&self) -> Manifest {
        let filename = self
            .segment_path
            .file_name()
            .expect("name")
            .to_string_lossy()
            .to_string();
        Manifest {
            root_uuid: ROOT_UUID,
            generation: GENERATION,
            base_generation: 0,
            retained_tail_ranges: vec![TailRange {
                generation: GENERATION,
                first_shard_sequence: *self.sealed.first().expect("sealed"),
                last_shard_sequence: *self.sealed.last().expect("sealed"),
                filename,
            }],
            index_runs: Vec::new(),
            checkpoints: Vec::new(),
            committed_shard_sequence: *self.sealed.last().expect("sealed"),
        }
    }

    fn install_manifest(&self) {
        segment::install_manifest(&self.paths, &self.manifest(), 2, &self.counters)
            .expect("install manifest");
    }

    fn selected_manifest(&self) -> Manifest {
        segment::load_manifest_with_fallback(&self.paths, &ROOT_UUID)
            .expect("resolve")
            .expect("a manifest must be selected")
            .0
    }
}

// ===========================================================================
// Both names exist across the install — the property the amendment buys
// ===========================================================================

#[test]
fn the_frames_are_reachable_under_both_names_between_link_and_unlink() {
    let f = Fixture::sealed_through_link();
    assert!(
        f.active_path.exists(),
        "step 4 links rather than renames, so the active name must survive it"
    );
    assert!(f.segment_path.exists());

    let reader = segment::SegmentReader::open(&f.segment_path, &ROOT_UUID).expect("segment opens");
    assert_eq!(reader.footer().journal_id, f.journal_id);
    assert_eq!(reader.footer().first_shard_sequence, f.sealed[0]);
    assert_eq!(
        reader.footer().last_shard_sequence,
        *f.sealed.last().expect("sealed")
    );
}

// ===========================================================================
// Crash between step 4 and step 5 — the orphan segment
// ===========================================================================

#[test]
fn a_crash_between_the_link_and_the_manifest_leaves_the_journal_authoritative() {
    // The seal linked the segment but never installed a manifest naming it.
    // Nothing references the segment, so it must be ignored and the still
    // present journal scanned.
    let f = Fixture::sealed_through_link();
    assert!(
        segment::load_manifest_with_fallback(&f.paths, &ROOT_UUID)
            .expect("resolve")
            .is_none(),
        "no manifest generation exists yet, which is the whole point of this case"
    );

    // An empty manifest stands in for "whatever step 2 selected", which here
    // references nothing.
    let empty = Manifest {
        root_uuid: ROOT_UUID,
        generation: 0,
        base_generation: 0,
        retained_tail_ranges: Vec::new(),
        index_runs: Vec::new(),
        checkpoints: Vec::new(),
        committed_shard_sequence: 0,
    };
    let disposition = classify_active_journal(&f.paths, &empty, &f.journal_id, &ROOT_UUID)
        .expect("classification");

    match disposition {
        ActiveJournalDisposition::Replay => {}
        ActiveJournalDisposition::AlreadySealed { .. } => panic!(
            "an orphan segment that no manifest references must NOT be taken as a \
             completed seal; treating it as one drops every frame the manifest \
             does not yet name"
        ),
    }

    // And the journal really does still hold the frames.
    let (_, scan) = Journal::open(&f.active_path, &ROOT_UUID, f.counters.clone()).expect("reopen");
    assert_eq!(
        scan.frames
            .iter()
            .map(|frame| frame.shard_sequence)
            .collect::<Vec<_>>(),
        f.sealed,
        "the acknowledged prefix must be recoverable from the journal"
    );
}

#[test]
fn an_orphan_segment_from_a_different_journal_is_also_ignored() {
    // Same crash point, but the manifest that step 2 selected references some
    // *other* segment. The `journal_id` comparison, not the presence of any
    // segment, is what decides.
    let f = Fixture::sealed_through_link();
    let mut other = f.manifest();
    other.retained_tail_ranges[0].filename = "9-0-0.seg".into();

    let disposition =
        classify_active_journal(&f.paths, &other, &f.journal_id, &ROOT_UUID).expect("classify");
    match disposition {
        ActiveJournalDisposition::Replay => {}
        ActiveJournalDisposition::AlreadySealed { .. } => {
            panic!("a manifest naming a segment that does not exist cannot prove a seal")
        }
    }
}

// ===========================================================================
// Crash between step 5 and step 6 — the completed seal
// ===========================================================================

#[test]
fn a_crash_between_the_manifest_and_the_unlink_completes_the_seal() {
    let f = Fixture::sealed_through_link();
    f.install_manifest();
    // Step 6 never ran: the active name is still there.
    assert!(f.active_path.exists());

    let manifest = f.selected_manifest();
    let disposition = classify_active_journal(&f.paths, &manifest, &f.journal_id, &ROOT_UUID)
        .expect("classification");

    match disposition {
        ActiveJournalDisposition::AlreadySealed {
            ref segment,
            first_shard_sequence,
            last_shard_sequence,
        } => {
            assert_eq!(segment, &f.segment_path);
            assert_eq!(first_shard_sequence, f.sealed[0]);
            assert_eq!(last_shard_sequence, *f.sealed.last().expect("sealed"));
        }
        ActiveJournalDisposition::Replay => panic!(
            "a manifest-referenced segment carrying this journal's journal_id \
             proves the seal completed; replaying the journal as well would adopt \
             every frame twice"
        ),
    }

    let before = f.counters.snapshot().fsync_dir;
    complete_interrupted_seal(&f.active_path, &f.paths, &f.counters).expect("finish the unlink");

    assert!(
        !f.active_path.exists(),
        "the stale active name must be gone once the manifest is durable"
    );
    assert!(
        f.segment_path.exists(),
        "the frames stay reachable through the segment"
    );
    assert!(
        f.counters.snapshot().fsync_dir > before,
        "the unlink must be made durable, not merely issued"
    );
}

#[test]
fn completing_an_already_completed_seal_is_idempotent() {
    // A crash *after* the unlink but before its directory fsync leaves nothing
    // to unlink. Finishing the fsync is still correct and must not error.
    let f = Fixture::sealed_through_link();
    f.install_manifest();
    complete_interrupted_seal(&f.active_path, &f.paths, &f.counters).expect("first");
    complete_interrupted_seal(&f.active_path, &f.paths, &f.counters)
        .expect("a second completion must be a no-op, not a failure");
    assert!(!f.active_path.exists());
}

// ===========================================================================
// Double adoption is what the disposition prevents — proved, not assumed
// ===========================================================================

#[test]
fn adopting_a_completed_seal_twice_would_duplicate_shard_sequences() {
    // The lead asked for this to be asserted rather than relied on: if a future
    // change ever let recovery replay the journal *and* take the segment's
    // frames from the manifest, the duplicate detector must catch it.
    let f = Fixture::sealed_through_link();
    f.install_manifest();

    let reader = segment::SegmentReader::open(&f.segment_path, &ROOT_UUID).expect("open segment");
    let from_segment: Vec<FrameFacts> = f
        .sealed
        .iter()
        .map(|sequence| {
            let frame = reader.read_frame(*sequence).expect("read frame");
            FrameFacts::from_header(&frame.header)
        })
        .collect();

    // The correct behaviour: exactly one adoption, contiguous.
    verify_shard_sequence(&from_segment, f.sealed[0])
        .expect("adopting the sealed frames once is contiguous");

    // The incorrect behaviour this disposition exists to prevent.
    let (_, scan) = Journal::open(&f.active_path, &ROOT_UUID, f.counters.clone()).expect("reopen");
    let from_journal: Vec<FrameFacts> = scan
        .frames
        .iter()
        .map(|frame| FrameFacts::from_header(&frame.header))
        .collect();
    assert_eq!(from_journal.len(), from_segment.len());

    // Two realistic shapes of double adoption, both of which must be refused.
    //
    // Concatenated — the segment's frames followed by the journal's, which is
    // what "replay the journal after loading the manifest" produces.
    let mut concatenated = from_segment.clone();
    concatenated.extend(from_journal.clone());
    match verify_shard_sequence(&concatenated, f.sealed[0]) {
        Err(ShardSequenceFault::Regression { previous, observed }) => {
            assert_eq!(previous, *f.sealed.last().expect("sealed"));
            assert_eq!(observed, f.sealed[0]);
        }
        Err(other) => panic!("expected a regression at the seam, got {other:?}"),
        Ok(()) => panic!(
            "double adoption must be detectable; a verifier that accepts it would \
             let an interrupted seal publish every frame twice"
        ),
    }

    // Sorted — what a set union of the two sources would produce, where the
    // repetition is adjacent rather than at a seam.
    let mut sorted: Vec<FrameFacts> = from_segment.clone();
    sorted.extend(from_journal);
    sorted.sort_by_key(|facts| facts.shard_sequence);
    match verify_shard_sequence(&sorted, f.sealed[0]) {
        Err(ShardSequenceFault::Duplicate { shard_sequence }) => {
            assert_eq!(
                shard_sequence, f.sealed[0],
                "the first repeated sequence is the one reported"
            );
        }
        Err(other) => panic!("expected a duplicate, got {other:?}"),
        Ok(()) => panic!("an adjacent repetition must be refused as a duplicate"),
    }
}

#[test]
fn taking_the_frames_from_the_manifest_alone_recovers_the_whole_acknowledged_prefix() {
    // The other half of the claim: not replaying the journal loses nothing,
    // because the segment carries every frame the journal held.
    let f = Fixture::sealed_through_link();
    f.install_manifest();
    complete_interrupted_seal(&f.active_path, &f.paths, &f.counters).expect("finish");

    let manifest = f.selected_manifest();
    let range = &manifest.retained_tail_ranges[0];
    let reader =
        segment::SegmentReader::open(&f.paths.segments().join(&range.filename), &ROOT_UUID)
            .expect("segment opens");

    assert_eq!(reader.footer().frame_count, f.sealed.len() as u64);
    for sequence in &f.sealed {
        let frame = reader
            .read_frame(*sequence)
            .expect("every sealed frame is readable");
        assert_eq!(frame.header.shard_sequence, *sequence);
    }
}

// ===========================================================================
// The healthy case
// ===========================================================================

#[test]
fn a_live_journal_with_no_matching_segment_is_replayed() {
    let f = Fixture::sealed_through_link();
    f.install_manifest();
    complete_interrupted_seal(&f.active_path, &f.paths, &f.counters).expect("finish");

    // A brand new journal opened after the seal. Its journal_id matches no
    // segment, so it is live.
    let fresh_id = [0x5Cu8; 16];
    let journal = Journal::create(
        &f.paths.active(),
        fresh_id,
        *f.sealed.last().expect("sealed") + 1,
        SHARD,
        ROOT_UUID,
        PREALLOCATED,
        2,
        f.counters.clone(),
    )
    .expect("create the next journal");
    drop(journal);

    let manifest = f.selected_manifest();
    match classify_active_journal(&f.paths, &manifest, &fresh_id, &ROOT_UUID).expect("classify") {
        ActiveJournalDisposition::Replay => {}
        ActiveJournalDisposition::AlreadySealed { .. } => panic!(
            "a fresh journal shares no journal_id with any sealed segment and must \
             be replayed"
        ),
    }
    let _ = &f.layout;
}
