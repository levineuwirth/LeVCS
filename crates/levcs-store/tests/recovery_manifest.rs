//! Scope 4-A2 acceptance: recovery step 2, the `CURRENT` -> manifest pointer
//! and its fallback.
//!
//! Manifests and `CURRENT` are written with A1's frozen codec
//! (`format::Manifest::encode`, `format::CurrentPointer::encode`) and read back
//! through `segment::read_current` and `segment::read_manifest`. There is no
//! reference codec for these bytes: an earlier draft had one, and it was a
//! second implementation of bytes A1 owns.
//!
//! The three manifest cases are distinct branches and are not collapsed here:
//!
//! - corrupt `CURRENT` with a valid predecessor — *the pointer does not
//!   validate*;
//! - valid `CURRENT` naming a missing manifest generation — *the pointer
//!   validates, its referent is absent*;
//! - valid `CURRENT` naming a manifest that fails its own checksum — *the
//!   pointer validates, its referent is corrupt*.
//!
//! Each asserts its own `ManifestFallbackReason`, so an implementation that
//! reached the right generation by the wrong route fails.

#[path = "recovery_reference_frame.rs"]
mod reference;

use levcs_store::recovery::{
    resolve_manifest, ManifestFallbackReason, ManifestSelection, ManifestSource,
    PresenceAndLengthValidator, ReferencedFileFault, ReferencedFileValidator,
};
use levcs_store::segment;

use reference::{manifest, ShardDir, ROOT_UUID};

const SEGMENT_LEN: usize = 4096;
const MAX_CANDIDATES: usize = 8;

fn resolve(shard: &ShardDir) -> Option<ManifestSelection> {
    resolve_manifest(
        &shard.paths,
        &ROOT_UUID,
        &PresenceAndLengthValidator::default(),
        MAX_CANDIDATES,
    )
    .expect("resolution must not fail; a bad pointer is a fallback, not an error")
}

/// A2's reason-carrying resolver and A1's boolean one must select the same
/// generation.
///
/// Called from each case below, so "A2 refines A1's answer rather than offering
/// a second opinion" is checked once per physical image rather than asserted
/// once in prose. A2 may legitimately refuse a generation A1 accepts, because
/// its referent validation is stronger than existence; it may never accept one
/// A1 refuses.
fn assert_agrees_with_a1(shard: &ShardDir) {
    let a2 = resolve(shard);
    let a1 = segment::load_manifest_with_fallback(&shard.paths, &ROOT_UUID)
        .expect("A1's resolver must not fail either");

    match (&a2, &a1) {
        (Some(selection), Some((manifest, used_fallback))) => {
            assert_eq!(
                selection.generation, manifest.generation,
                "A2 and A1 must select the same manifest generation"
            );
            assert_eq!(
                matches!(selection.source, ManifestSource::Fallback { .. }),
                *used_fallback,
                "A2's source and A1's fallback flag must agree"
            );
        }
        (None, None) => {}
        (Some(selection), None) => panic!(
            "A2 selected generation {} that A1 refused entirely",
            selection.generation
        ),
        (None, Some((manifest, _))) => panic!(
            "A2 refused everything while A1 accepted generation {}; the only \
             licensed difference is stricter referent validation, and this \
             fixture has no invalid referent",
            manifest.generation
        ),
    }
}

/// Two valid generations, 3 and 4, with `CURRENT` naming 4.
fn two_generations() -> ShardDir {
    let shard = ShardDir::new();
    for generation in [3u64, 4] {
        let segment = format!("{generation}-0-9.seg");
        shard.write_placeholder_segment(&segment, SEGMENT_LEN);
        shard.write_manifest(&manifest(generation, &segment));
    }
    shard.write_current(4, ROOT_UUID);
    shard
}

// ===========================================================================
// The healthy path
// ===========================================================================

#[test]
fn a_valid_current_naming_a_valid_manifest_is_used_directly() {
    let shard = two_generations();
    let selection = resolve(&shard).expect("a generation must be selected");
    assert_eq!(selection.generation, 4);
    assert_eq!(selection.source, ManifestSource::Current);
    assert!(selection.rejected.is_empty());
    assert_agrees_with_a1(&shard);
}

// ===========================================================================
// Branch 1 — the pointer does not validate
// ===========================================================================

#[test]
fn a_corrupt_current_falls_back_to_the_newest_valid_predecessor_manifest() {
    let shard = two_generations();
    shard.corrupt("CURRENT", 12);

    let selection = resolve(&shard).expect("the predecessor must be reachable");
    assert_eq!(
        selection.generation, 4,
        "the newest valid manifest generation wins, whatever the broken pointer said"
    );
    match selection.source {
        ManifestSource::Fallback {
            reason: ManifestFallbackReason::CurrentCorrupt(_),
        } => {}
        ref other => panic!(
            "a corrupt pointer must be reported as a pointer failure, never as a \
             referent failure; got {other:?}"
        ),
    }
    assert_agrees_with_a1(&shard);
}

#[test]
fn a_corrupt_current_whose_newest_manifest_is_also_corrupt_falls_further_back() {
    let shard = two_generations();
    shard.corrupt("CURRENT", 12);
    shard.corrupt("manifests/4.manifest", 30);

    let selection = resolve(&shard).expect("generation 3 must be reachable");
    assert_eq!(selection.generation, 3);
    match selection.source {
        ManifestSource::Fallback {
            reason: ManifestFallbackReason::CurrentCorrupt(_),
        } => {}
        ref other => panic!(
            "the reported reason is why CURRENT was abandoned, not why an \
             intermediate generation was skipped; got {other:?}"
        ),
    }
    assert_eq!(
        selection.rejected.len(),
        1,
        "the skipped generation must be reported, not silently passed over"
    );
    assert_eq!(selection.rejected[0].0, 4);
    match selection.rejected[0].1 {
        ManifestFallbackReason::ReferentCorrupt { generation, .. } => assert_eq!(generation, 4),
        ref other => panic!("expected a corrupt referent, got {other:?}"),
    }
    assert_agrees_with_a1(&shard);
}

#[test]
fn a_missing_current_falls_back_to_the_newest_valid_manifest() {
    let shard = two_generations();
    std::fs::remove_file(shard.paths.current()).expect("remove");

    let selection = resolve(&shard).expect("a generation must be selected");
    assert_eq!(selection.generation, 4);
    assert_eq!(
        selection.source,
        ManifestSource::Fallback {
            reason: ManifestFallbackReason::CurrentMissing
        }
    );
    assert_agrees_with_a1(&shard);
}

#[test]
fn a_current_naming_another_store_root_is_refused_as_a_pointer_failure() {
    let shard = two_generations();
    shard.write_current(4, [0xEE; 16]);

    let selection = resolve(&shard).expect("a generation must be selected");
    assert_eq!(
        selection.source,
        ManifestSource::Fallback {
            reason: ManifestFallbackReason::CurrentRootUuidMismatch
        },
        "root_uuid binding is what catches a CURRENT copied in from another instance"
    );
    assert_eq!(selection.generation, 4);
    assert_agrees_with_a1(&shard);
}

// ===========================================================================
// Branch 2 — the pointer validates, its referent is absent
// ===========================================================================

#[test]
fn a_valid_current_naming_a_missing_manifest_generation_falls_back() {
    let shard = two_generations();
    // The pointer stays intact and keeps naming generation 9, which was never
    // written. This is a failure the single-`CURRENT` layout could not express.
    shard.write_current(9, ROOT_UUID);

    let selection = resolve(&shard).expect("the newest present generation must be reachable");
    assert_eq!(selection.generation, 4);
    assert_eq!(
        selection.source,
        ManifestSource::Fallback {
            reason: ManifestFallbackReason::ReferentMissing { generation: 9 }
        },
        "an absent referent is not the same fault as a pointer that does not validate"
    );
    assert_eq!(
        selection.rejected,
        vec![(9, ManifestFallbackReason::ReferentMissing { generation: 9 })]
    );
    assert_agrees_with_a1(&shard);
}

// ===========================================================================
// Branch 3 — the pointer validates, its referent fails its own checksum
// ===========================================================================

#[test]
fn a_valid_current_naming_a_manifest_that_fails_its_own_checksum_falls_back() {
    let shard = two_generations();
    // CURRENT still names 4 and still validates. Generation 4's own bytes are
    // damaged.
    shard.corrupt("manifests/4.manifest", 40);

    let selection = resolve(&shard).expect("generation 3 must be reachable");
    assert_eq!(selection.generation, 3);
    match selection.source {
        ManifestSource::Fallback {
            reason: ManifestFallbackReason::ReferentCorrupt { generation, .. },
        } => assert_eq!(generation, 4),
        ref other => panic!(
            "a corrupt referent is a third distinct branch, not the corrupt-pointer \
             one; got {other:?}"
        ),
    }
    assert_agrees_with_a1(&shard);
}

#[test]
fn the_three_branches_report_three_different_reasons() {
    // The point of scope 4-A2's "may not be collapsed" is only checkable by
    // comparing the three outcomes against each other.
    let corrupt_pointer = {
        let shard = two_generations();
        shard.corrupt("CURRENT", 12);
        resolve(&shard).expect("selected").source
    };
    let missing_referent = {
        let shard = two_generations();
        shard.write_current(9, ROOT_UUID);
        resolve(&shard).expect("selected").source
    };
    let corrupt_referent = {
        let shard = two_generations();
        shard.corrupt("manifests/4.manifest", 40);
        resolve(&shard).expect("selected").source
    };

    assert_ne!(corrupt_pointer, missing_referent);
    assert_ne!(corrupt_pointer, corrupt_referent);
    assert_ne!(missing_referent, corrupt_referent);
}

// ===========================================================================
// A manifest whose referenced files do not validate
// ===========================================================================

#[test]
fn a_corrupt_segment_referenced_by_the_active_manifest_forces_a_fallback() {
    let shard = two_generations();
    // Generation 4's manifest is intact; the segment it names is truncated to
    // nothing, which is what a failed link or a partially copied restore leaves
    // behind. `segment::manifest_referents_present` answers existence, so this
    // is exactly the case A2's referent validator exists for — and the one
    // place A2 and A1 legitimately disagree.
    std::fs::write(shard.paths.segments().join("4-0-9.seg"), b"").expect("truncate segment");

    let selection = resolve(&shard).expect("generation 3 must be reachable");
    assert_eq!(selection.generation, 3);
    assert_eq!(
        selection.source,
        ManifestSource::Fallback {
            reason: ManifestFallbackReason::ReferentFileInvalid {
                generation: 4,
                filename: "4-0-9.seg".into(),
                cause: ReferencedFileFault::TooShort,
            }
        },
        "scope 3.8 step 2 falls back when ANY referenced file fails validation, \
         not only when the manifest itself is corrupt"
    );

    let (a1, _) = segment::load_manifest_with_fallback(&shard.paths, &ROOT_UUID)
        .expect("A1 resolves")
        .expect("A1 accepts generation 4 on existence alone");
    assert_eq!(
        a1.generation, 4,
        "this is the documented difference: existence accepts a zero-length \
         segment, A2's validator does not"
    );
}

#[test]
fn a_missing_segment_referenced_by_the_active_manifest_forces_a_fallback() {
    let shard = two_generations();
    std::fs::remove_file(shard.paths.segments().join("4-0-9.seg")).expect("remove");

    let selection = resolve(&shard).expect("generation 3 must be reachable");
    assert_eq!(selection.generation, 3);
    assert_eq!(
        selection.source,
        ManifestSource::Fallback {
            reason: ManifestFallbackReason::ReferentFileInvalid {
                generation: 4,
                filename: "4-0-9.seg".into(),
                cause: ReferencedFileFault::Missing,
            }
        }
    );
    assert_agrees_with_a1(&shard);
}

#[test]
fn a_manifest_belonging_to_another_store_root_is_refused() {
    let shard = ShardDir::new();
    shard.write_placeholder_segment("4-0-9.seg", SEGMENT_LEN);
    let mut foreign = manifest(4, "4-0-9.seg");
    foreign.root_uuid = [0xEE; 16];
    shard.write_manifest(&foreign);
    shard.write_current(4, ROOT_UUID);

    assert_eq!(
        resolve(&shard),
        None,
        "no generation validates, so recovery must refuse rather than open an \
         empty shard"
    );
    assert_agrees_with_a1(&shard);
}

#[test]
fn a_manifest_whose_generation_disagrees_with_its_file_name_is_refused() {
    let shard = ShardDir::new();
    shard.write_placeholder_segment("4-0-9.seg", SEGMENT_LEN);
    let mislabelled = manifest(4, "4-0-9.seg");
    // Filed under the wrong name: the manifest says 4, the name says 5.
    std::fs::write(
        shard.paths.manifest(5),
        mislabelled.encode().expect("encode"),
    )
    .expect("write");
    shard.write_current(5, ROOT_UUID);

    assert_eq!(
        resolve(&shard),
        None,
        "a manifest misfiled under another generation's name must not be adopted"
    );
    assert_agrees_with_a1(&shard);
}

// ===========================================================================
// Bounds and hostile names
// ===========================================================================

#[test]
fn the_fallback_scan_is_bounded() {
    let shard = ShardDir::new();
    shard.write_placeholder_segment("1-0-9.seg", SEGMENT_LEN);
    shard.write_manifest(&manifest(1, "1-0-9.seg"));
    for generation in 2..=20u64 {
        let segment = format!("{generation}-0-9.seg");
        shard.write_placeholder_segment(&segment, SEGMENT_LEN);
        shard.write_manifest(&manifest(generation, &segment));
        shard.corrupt(&format!("manifests/{generation}.manifest"), 30);
    }
    let _ = std::fs::remove_file(shard.paths.current());

    assert_eq!(
        resolve_manifest(
            &shard.paths,
            &ROOT_UUID,
            &PresenceAndLengthValidator::default(),
            4,
        )
        .expect("resolution"),
        None,
        "with a candidate cap of four the good generation at the bottom is out \
         of reach; startup must refuse rather than hunt linearly"
    );

    let selection = resolve_manifest(
        &shard.paths,
        &ROOT_UUID,
        &PresenceAndLengthValidator::default(),
        64,
    )
    .expect("resolution")
    .expect("with a larger cap the good generation is found");
    assert_eq!(selection.generation, 1);
}

#[test]
fn an_empty_shard_directory_selects_nothing() {
    let shard = ShardDir::new();
    assert_eq!(resolve(&shard), None);
    assert_agrees_with_a1(&shard);
}

#[test]
fn a_manifest_naming_a_file_outside_the_shard_directory_is_refused_at_both_layers() {
    // A manifest filename is untrusted input at read time. Two independent
    // layers refuse a path component, and both are asserted: a single layer is
    // one edit away from being the only one.
    //
    // Layer 1, A1's codec: `format::Manifest` validates names on encode *and*
    // decode, so such a manifest cannot be produced or read back at all.
    let escaping = manifest(4, "../../etc/passwd");
    let encode_error = escaping
        .encode()
        .expect_err("A1's codec must refuse the name");
    assert!(
        format!("{encode_error}").contains("store name"),
        "expected a store-name rejection, got {encode_error}"
    );

    // Layer 2, A2's referent validator, which is what runs if a manifest ever
    // reaches it carrying such a name.
    let shard = ShardDir::new();
    let validator = PresenceAndLengthValidator::default();
    for name in ["../escape.seg", "a/b.seg", "", ".", ".."] {
        match validator.validate(&shard.paths.segments(), name) {
            Err(ReferencedFileFault::Invalid(_)) => {}
            Err(other) => panic!("{name} must be refused as a bad name, got {other:?}"),
            Ok(()) => panic!("{name} must be refused rather than followed"),
        }
    }
}
