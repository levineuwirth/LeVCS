//! Bounded invisible projection-staging sessions.
//!
//! B3 owns the storage mechanism. D0-B owns and freezes the adoption seam in
//! this file so B1 never has to read B3's on-disk representation directly.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use levcs_core::ObjectId;
use levcs_protocol::v2::{
    ProjectionStageManifestV1, ProjectionStageSessionV1, StagedProjectionInstallV1,
};

use crate::index::{IndexDelta, IndexRun};
use crate::roots::{CommittedRoot, RetainedIndexRun, RetainedProjectionArtifact};
use crate::types::{NamespaceId, StoreError};

/// One immutable artifact offered for adoption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionArtifact {
    pub path: PathBuf,
    pub digest: ObjectId,
    pub bytes: u64,
}

/// Everything B1 may inspect while revalidating a sealed staged projection.
///
/// This is deliberately read-only. Adoption may reject this state but may
/// never repair or mutate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionAdoptionResolution {
    pub session: ProjectionStageSessionV1,
    pub manifest: ProjectionStageManifestV1,
    pub artifacts: Arc<[ProjectionArtifact]>,
}

/// The only three ways ownership of an admitted adoption pin may end.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProjectionAdoptionOutcome {
    Adopted,
    DefinitivePreAppendFailure,
    TransferredToRecovery,
}

/// Resolution delivered to staging after production recovery has made the
/// final frame authoritative or proved that no complete frame exists.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecoveredProjectionOutcome {
    Committed,
    ProvedAbsent,
}

/// Recovery's resolution of a staging pin transferred across a poisoned
/// process boundary.
///
/// B3 consumes these notifications before expiry or cleanup may inspect the
/// recovered shard.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RecoveredProjectionResolution {
    pub session_id: [u8; 16],
    pub outcome: RecoveredProjectionOutcome,
}

/// Read-only recovery result for one authoritative staged-install frame.
///
/// A final frame carries only a canonical descriptor, not the installed
/// object's locations. Recovery obtains those locations and live file
/// ownership from B3 through this value. The vectors are newest-first where
/// order is observable by index lookup.
///
/// The fields remain private so recovery can compose the result into its
/// recovered root but cannot mutate staging state or reinterpret B3's on-disk
/// representation.
#[derive(Clone, Debug)]
pub(crate) struct RecoveredProjectionArtifacts {
    descriptor: StagedProjectionInstallV1,
    index_delta: Arc<IndexDelta>,
    /// Newest-first; each retained entry is also the lookup run, so lookup
    /// membership cannot accidentally diverge from physical ownership.
    retained_index_runs: Arc<[RetainedIndexRun]>,
    retained_artifacts: Arc<[RetainedProjectionArtifact]>,
}

impl RecoveredProjectionArtifacts {
    /// Construct the complete physical result of resolving one descriptor.
    ///
    /// B3 calls this only after mechanically verifying the descriptor against
    /// the sealed session, manifest, artifact hashes, and index. Identity,
    /// graph, policy, authority, and federation decisions are deliberately
    /// absent from this interface.
    pub(crate) fn new(
        descriptor: StagedProjectionInstallV1,
        index_delta: Arc<IndexDelta>,
        retained_index_runs: Arc<[RetainedIndexRun]>,
        retained_artifacts: Arc<[RetainedProjectionArtifact]>,
    ) -> Result<Self, StoreError> {
        let run_entries = retained_index_runs
            .iter()
            .try_fold(0u64, |count, retained| {
                count.checked_add(retained.run().entry_count())
            })
            .ok_or_else(|| {
                StoreError::Corruption(
                    "recovered staged-projection index entry count overflowed".into(),
                )
            })?;
        let delta_entries = u64::try_from(index_delta.len()).map_err(|_| {
            StoreError::Corruption(
                "recovered staged-projection delta count does not fit u64".into(),
            )
        })?;
        let total_entries = run_entries.checked_add(delta_entries).ok_or_else(|| {
            StoreError::Corruption(
                "recovered staged-projection total index count overflowed".into(),
            )
        })?;
        if total_entries == 0 {
            return Err(StoreError::Corruption(
                "committed staged projection resolved without object membership".into(),
            ));
        }
        if total_entries != descriptor.object_count {
            return Err(StoreError::Corruption(format!(
                "committed staged projection declares {} objects but its recovered \
                 index contains {total_entries}",
                descriptor.object_count
            )));
        }
        if retained_artifacts.is_empty() {
            return Err(StoreError::Corruption(
                "committed staged projection resolved without live artifact ownership".into(),
            ));
        }

        Ok(Self {
            descriptor,
            index_delta,
            retained_index_runs,
            retained_artifacts,
        })
    }

    pub(crate) fn descriptor(&self) -> &StagedProjectionInstallV1 {
        &self.descriptor
    }

    pub(crate) fn index_delta(&self) -> &Arc<IndexDelta> {
        &self.index_delta
    }

    pub(crate) fn index_runs_newest_first(&self) -> impl ExactSizeIterator<Item = &Arc<IndexRun>> {
        self.retained_index_runs.iter().map(RetainedIndexRun::run)
    }

    pub(crate) fn retained_index_runs(&self) -> &[RetainedIndexRun] {
        &self.retained_index_runs
    }

    pub(crate) fn retained_artifacts(&self) -> &[RetainedProjectionArtifact] {
        &self.retained_artifacts
    }
}

/// The complete staging-owned seam used by production recovery.
///
/// `resolve_committed` is read-only: the complete frame is already the
/// durable authority and resolution may inspect, open, hash, and pin its
/// immutable artifacts but may not repair them. `notify_recovered` is the
/// separate lifecycle transition performed only after recovery has either
/// incorporated a committed result into the recovered root or proved absence
/// by scanning the complete authoritative journal history.
pub(crate) trait ProjectionRecoveryResolver: Send + Sync {
    /// Sessions whose in-process adoption handle transferred responsibility
    /// to recovery before the previous engine stopped.
    fn transferred_sessions(&self, shard_index: u16) -> Result<Arc<[[u8; 16]]>, StoreError>;

    /// Resolve a canonical committed descriptor into exact namespace-scoped
    /// membership and live physical ownership.
    fn resolve_committed(
        &self,
        namespace: NamespaceId,
        descriptor: &StagedProjectionInstallV1,
    ) -> Result<RecoveredProjectionArtifacts, StoreError>;

    /// Finish one transferred session after the physical-state proof is
    /// complete. This transition must be idempotent: recovery remains unready
    /// if a later notification fails and repeats every notification on the
    /// next attempt.
    fn notify_recovered(&self, resolution: RecoveredProjectionResolution)
        -> Result<(), StoreError>;
}

/// B3's implementation behind the opaque handle.
///
/// The trait and constructor are crate-private: external callers may carry a
/// handle issued by staging but cannot forge one.
pub(crate) trait ProjectionAdoptionLifecycle: Send + Sync {
    fn resolution(&self) -> Result<Arc<ProjectionAdoptionResolution>, StoreError>;

    fn finish(&self, outcome: ProjectionAdoptionOutcome) -> Result<(), StoreError>;

    fn dropped_without_outcome(&self);
}

/// An unforgeable staging capability consumed alongside the wire descriptor.
///
/// Holding this value pins the sealed artifacts. Exactly one terminal outcome
/// must be recorded before it is dropped.
pub struct ProjectionAdoption {
    lifecycle: Arc<dyn ProjectionAdoptionLifecycle>,
    finished: bool,
}

impl ProjectionAdoption {
    pub(crate) fn new(lifecycle: Arc<dyn ProjectionAdoptionLifecycle>) -> Self {
        Self {
            lifecycle,
            finished: false,
        }
    }

    pub(crate) fn resolution(&self) -> Result<Arc<ProjectionAdoptionResolution>, StoreError> {
        self.lifecycle.resolution()
    }

    /// Prove artifact retention against the state readers actually capture.
    pub(crate) fn artifact_is_referenced(&self, root: &CommittedRoot, path: &Path) -> bool {
        root.references_path(path)
    }

    pub(crate) fn finish(mut self, outcome: ProjectionAdoptionOutcome) -> Result<(), StoreError> {
        self.lifecycle.finish(outcome)?;
        self.finished = true;
        Ok(())
    }
}

impl fmt::Debug for ProjectionAdoption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectionAdoption")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Drop for ProjectionAdoption {
    fn drop(&mut self) {
        if !self.finished {
            self.lifecycle.dropped_without_outcome();
        }
    }
}

/// D0-B's exact B1/B3 handoff payload.
pub(crate) struct StagedProjectionAdoption {
    pub(crate) descriptor: StagedProjectionInstallV1,
    pub(crate) handle: ProjectionAdoption,
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::sync::Mutex;

    use levcs_protocol::v2::{ProjectionMode, StageSourceKindV1};
    use tempfile::TempDir;

    use super::*;
    use crate::index::{IndexKey, IndexLocation};
    use crate::roots::{PinnedFile, ProjectionArtifactFormat};

    struct RecordingLifecycle {
        resolution: Arc<ProjectionAdoptionResolution>,
        outcomes: Mutex<Vec<ProjectionAdoptionOutcome>>,
        dropped: Mutex<u64>,
    }

    impl ProjectionAdoptionLifecycle for RecordingLifecycle {
        fn resolution(&self) -> Result<Arc<ProjectionAdoptionResolution>, StoreError> {
            Ok(Arc::clone(&self.resolution))
        }

        fn finish(&self, outcome: ProjectionAdoptionOutcome) -> Result<(), StoreError> {
            self.outcomes.lock().unwrap().push(outcome);
            Ok(())
        }

        fn dropped_without_outcome(&self) {
            *self.dropped.lock().unwrap() += 1;
        }
    }

    fn resolution() -> Arc<ProjectionAdoptionResolution> {
        Arc::new(ProjectionAdoptionResolution {
            session: ProjectionStageSessionV1 {
                session_id: [1; 16],
                destination_repo: ObjectId([2; 32]),
                destination_genesis: ObjectId([3; 32]),
                expected_authority: ObjectId([4; 32]),
                projection: ProjectionMode::Full,
                source_kind: StageSourceKindV1::Mirror,
                actor: [5; 32],
                actor_key_epoch: 7,
                source_generation_digest: ObjectId([6; 32]),
                fork_proof: None,
                final_operation_id: [8; 16],
                final_operation_digest: ObjectId([9; 32]),
                final_evidence_digest: ObjectId([10; 32]),
                total_object_count: 1,
                total_object_bytes: 1,
                chunk_count: 1,
                manifest_digest: ObjectId([11; 32]),
                expires_at_micros: 12,
            },
            manifest: ProjectionStageManifestV1 {
                session_id: [1; 16],
                chunk_digests: Vec::new(),
                objects: Vec::new(),
                membership_root: ObjectId([13; 32]),
            },
            artifacts: Arc::from([]),
        })
    }

    fn lifecycle() -> Arc<RecordingLifecycle> {
        Arc::new(RecordingLifecycle {
            resolution: resolution(),
            outcomes: Mutex::new(Vec::new()),
            dropped: Mutex::new(0),
        })
    }

    fn install() -> StagedProjectionInstallV1 {
        StagedProjectionInstallV1 {
            session_id: [20; 16],
            manifest_digest: ObjectId([21; 32]),
            projection: ProjectionMode::Full,
            object_count: 1,
            object_bytes: 32,
            membership_root: ObjectId([22; 32]),
            artifact_set_digest: ObjectId([23; 32]),
        }
    }

    fn recovered_artifacts(
        directory: &TempDir,
    ) -> Result<RecoveredProjectionArtifacts, StoreError> {
        let path = directory.path().join("projection-objects");
        File::create(&path)?;
        let mut delta = IndexDelta::new(8, 4096);
        delta.insert(
            IndexKey::new(NamespaceId([24; 32]), ObjectId([25; 32])),
            IndexLocation {
                segment_generation: 7,
                frame_offset: 128,
                frame_len: 256,
                object_type: 1,
                shard_sequence: 9,
            },
        )?;
        RecoveredProjectionArtifacts::new(
            install(),
            Arc::new(delta),
            Arc::from([]),
            Arc::from([RetainedProjectionArtifact::new(
                7,
                ProjectionArtifactFormat::CanonicalStageChunkV1,
                PinnedFile::open(path)?,
            )]),
        )
    }

    struct RecordingRecoveryResolver {
        artifacts: RecoveredProjectionArtifacts,
        transferred: Arc<[[u8; 16]]>,
        notifications: Mutex<Vec<RecoveredProjectionResolution>>,
    }

    impl ProjectionRecoveryResolver for RecordingRecoveryResolver {
        fn transferred_sessions(&self, _shard_index: u16) -> Result<Arc<[[u8; 16]]>, StoreError> {
            Ok(Arc::clone(&self.transferred))
        }

        fn resolve_committed(
            &self,
            _namespace: NamespaceId,
            descriptor: &StagedProjectionInstallV1,
        ) -> Result<RecoveredProjectionArtifacts, StoreError> {
            if self.artifacts.descriptor() != descriptor {
                return Err(StoreError::Corruption(
                    "descriptor did not name the sealed staging session".into(),
                ));
            }
            Ok(self.artifacts.clone())
        }

        fn notify_recovered(
            &self,
            resolution: RecoveredProjectionResolution,
        ) -> Result<(), StoreError> {
            self.notifications.lock().unwrap().push(resolution);
            Ok(())
        }
    }

    #[test]
    fn handle_drop_without_outcome_is_observable() {
        let lifecycle = lifecycle();
        let handle = ProjectionAdoption::new(lifecycle.clone());
        drop(handle);
        assert_eq!(*lifecycle.dropped.lock().unwrap(), 1);
        assert!(lifecycle.outcomes.lock().unwrap().is_empty());
    }

    #[test]
    fn each_terminal_outcome_suppresses_the_drop_bug() {
        for outcome in [
            ProjectionAdoptionOutcome::Adopted,
            ProjectionAdoptionOutcome::DefinitivePreAppendFailure,
            ProjectionAdoptionOutcome::TransferredToRecovery,
        ] {
            let lifecycle = lifecycle();
            ProjectionAdoption::new(lifecycle.clone())
                .finish(outcome)
                .unwrap();
            assert_eq!(&*lifecycle.outcomes.lock().unwrap(), &[outcome]);
            assert_eq!(*lifecycle.dropped.lock().unwrap(), 0);
        }
    }

    #[test]
    fn recovery_resolution_is_read_only_and_carries_live_ownership() {
        let directory = TempDir::new().unwrap();
        let artifacts = recovered_artifacts(&directory).unwrap();
        let retained_path = artifacts.retained_artifacts()[0].path().to_owned();
        let resolver = RecordingRecoveryResolver {
            artifacts,
            transferred: Arc::from([[20; 16], [26; 16]]),
            notifications: Mutex::new(Vec::new()),
        };

        let transferred = resolver.transferred_sessions(3).unwrap();
        assert_eq!(&*transferred, &[[20; 16], [26; 16]]);
        let recovered = resolver
            .resolve_committed(NamespaceId([24; 32]), &install())
            .unwrap();
        assert_eq!(recovered.descriptor(), &install());
        assert_eq!(recovered.index_delta().len(), 1);
        assert_eq!(recovered.index_runs_newest_first().len(), 0);
        assert!(recovered.retained_index_runs().is_empty());
        assert_eq!(recovered.retained_artifacts()[0].path(), retained_path);
    }

    #[test]
    fn recovery_notifies_both_terminal_physical_outcomes() {
        let directory = TempDir::new().unwrap();
        let resolver = RecordingRecoveryResolver {
            artifacts: recovered_artifacts(&directory).unwrap(),
            transferred: Arc::from([]),
            notifications: Mutex::new(Vec::new()),
        };
        for outcome in [
            RecoveredProjectionOutcome::Committed,
            RecoveredProjectionOutcome::ProvedAbsent,
        ] {
            resolver
                .notify_recovered(RecoveredProjectionResolution {
                    session_id: [20; 16],
                    outcome,
                })
                .unwrap();
        }
        assert_eq!(
            &*resolver.notifications.lock().unwrap(),
            &[
                RecoveredProjectionResolution {
                    session_id: [20; 16],
                    outcome: RecoveredProjectionOutcome::Committed,
                },
                RecoveredProjectionResolution {
                    session_id: [20; 16],
                    outcome: RecoveredProjectionOutcome::ProvedAbsent,
                },
            ]
        );
    }

    #[test]
    fn recovery_rejects_membership_without_live_artifact_ownership() {
        let mut delta = IndexDelta::new(8, 4096);
        delta
            .insert(
                IndexKey::new(NamespaceId([24; 32]), ObjectId([25; 32])),
                IndexLocation {
                    segment_generation: 7,
                    frame_offset: 128,
                    frame_len: 256,
                    object_type: 1,
                    shard_sequence: 9,
                },
            )
            .unwrap();
        let error = RecoveredProjectionArtifacts::new(
            install(),
            Arc::new(delta),
            Arc::from([]),
            Arc::from([]),
        )
        .unwrap_err();
        assert!(matches!(error, StoreError::Corruption(message) if message.contains("ownership")));
    }
}
