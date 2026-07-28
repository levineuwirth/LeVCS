//! Store configuration and its startup validation.
//!
//! Lead-owned (scope 2.1). Plan §9 requires strict configuration: unknown
//! modes and invalid limits fail startup, and tuning parameters may not be
//! raised to hide overload. Every check here is a refusal, never a clamp.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::types::{CommitEvidenceSigner, StoreError};

/// Expected on-disk attributes for the directories carrying journal and
/// segment writes.
///
/// Contract review 2026-07-24-B adds the matching
/// `[profile.filesystem].store_directory_attributes` to
/// `bench/reference-hardware.toml`. A benchmark run must verify the effective
/// attributes at startup and refuse on mismatch — recording alone would let a
/// silently copy-on-write-mounted run emit a bundle claiming `nodatacow`
/// (scope 9.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum StoreDirectoryAttributes {
    /// No expectation; do not check. Correct for ordinary deployments on
    /// filesystems where the attribute does not exist.
    #[default]
    Unchecked,
    /// Require `chattr +C` (nodatacow) on the journal and segment
    /// directories. Required for benchmark gates on the frozen btrfs profile.
    RequireNoDataCow,
    /// Require the absence of nodatacow.
    RequireDataCow,
}

#[derive(Clone)]
pub struct StoreOptions {
    pub root: PathBuf,

    // --- topology -------------------------------------------------------
    /// Frozen into `FORMAT` at initialization and immutable for the life of
    /// the root. Opening with a different value is a hard `FormatMismatch`,
    /// never a silent reroute: per-repository sequence ownership is only
    /// sound while a repository's shard assignment never moves (scope 2.5).
    pub shard_count: u16,

    // --- group commit ---------------------------------------------------
    pub max_group_transactions: u32,
    pub max_group_bytes: u64,
    pub max_group_idle: Duration,

    // --- journal and segments -------------------------------------------
    pub journal_preallocate_bytes: u64,
    pub segment_max_bytes: u64,
    pub manifest_retain: u32,
    pub open_segment_fd_cache: u32,
    pub store_directory_attributes: StoreDirectoryAttributes,

    // --- index and checkpoints ------------------------------------------
    pub max_active_index_entries: u64,
    pub max_active_index_bytes: u64,
    pub max_index_runs: u32,
    pub max_open_index_runs: u32,
    pub checkpoint_interval_transactions: u64,
    pub checkpoint_interval_bytes: u64,
    /// Plan §5.3: retain at least two independently validated checkpoint
    /// generations; if both are corrupt, enter explicit offline rebuild mode
    /// rather than an unbounded normal-readiness scan.
    pub checkpoint_retain: u32,
    pub max_replay_frames: u64,
    pub max_replay_bytes: u64,

    // --- transaction bounds ---------------------------------------------
    pub max_objects_per_transaction: u32,
    pub max_refs_per_transaction: u32,
    pub max_projection_objects: u64,
    pub max_projection_bytes: u64,
    pub max_projection_chunks: u32,
    /// Maximum number of transient entries in `OperationStatusRoot`.
    pub max_status_entries: u64,

    // --- projection staging ---------------------------------------------
    pub staging_max_sessions_per_principal: u32,
    pub staging_max_sessions_global: u32,
    pub staging_max_objects_per_principal: u64,
    pub staging_max_objects_global: u64,
    pub staging_max_bytes_per_principal: u64,
    pub staging_max_bytes_global: u64,
    pub staging_max_files_per_session: u64,
    pub staging_max_files_per_principal: u64,
    pub staging_max_files_global: u64,
    pub staging_session_max_age_micros: i64,
    pub staging_finalize_margin_micros: i64,
    pub minimum_projection_transfer_bytes_per_second: u64,
    pub staging_max_compaction_debt_bytes: u64,

    // --- retention and time ---------------------------------------------
    pub max_retry_window_micros: i64,
    pub terminal_status_grace_micros: i64,
    pub status_tombstone_grace_micros: i64,
    pub clock_skew_micros: i64,
    pub timer_resolution_micros: i64,
    pub replay_retention_micros: i64,

    // --- composition ----------------------------------------------------
    pub signer: Option<Arc<dyn CommitEvidenceSigner>>,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::new(),
            // Plan §5.2 default initial tuning: four storage shards, 512
            // transactions or 8 MiB maximum per group, 1 ms idle batching
            // delay. All measured internals until P2.
            shard_count: 4,
            max_group_transactions: 512,
            max_group_bytes: 8 * 1024 * 1024,
            max_group_idle: Duration::from_millis(1),
            journal_preallocate_bytes: 256 * 1024 * 1024,
            segment_max_bytes: 256 * 1024 * 1024,
            manifest_retain: 4,
            open_segment_fd_cache: 256,
            store_directory_attributes: StoreDirectoryAttributes::Unchecked,
            max_active_index_entries: 4_000_000,
            max_active_index_bytes: 512 * 1024 * 1024,
            max_index_runs: 64,
            max_open_index_runs: 32,
            checkpoint_interval_transactions: 1_000_000,
            checkpoint_interval_bytes: 4 * 1024 * 1024 * 1024,
            checkpoint_retain: 2,
            max_replay_frames: 4_000_000,
            max_replay_bytes: 8 * 1024 * 1024 * 1024,
            max_objects_per_transaction: 65_536,
            max_refs_per_transaction: 4_096,
            // The manifest is a flat canonical vector, so this is the codec's
            // item ceiling and not a tuning choice. See `validate`.
            max_projection_objects: 1_000_000,
            max_projection_bytes: 1024 * 1024 * 1024 * 1024,
            max_projection_chunks: 1_000_000,
            max_status_entries: 1_000_000,
            staging_max_sessions_per_principal: 2,
            staging_max_sessions_global: 16,
            staging_max_objects_per_principal: 200_000_000,
            staging_max_objects_global: 800_000_000,
            staging_max_bytes_per_principal: 2 * 1024 * 1024 * 1024 * 1024,
            staging_max_bytes_global: 8 * 1024 * 1024 * 1024 * 1024,
            staging_max_files_per_session: 1_000_002,
            staging_max_files_per_principal: 2_000_000,
            staging_max_files_global: 8_000_000,
            // A maximal 1 TiB projection at the supported 16 MiB/s floor
            // takes a little over 18 hours. The 24-hour session horizon
            // leaves room for the five-minute finalize margin.
            staging_session_max_age_micros: 24 * 60 * 60 * 1_000_000,
            staging_finalize_margin_micros: 5 * 60 * 1_000_000,
            minimum_projection_transfer_bytes_per_second: 16 * 1024 * 1024,
            staging_max_compaction_debt_bytes: 8 * 1024 * 1024 * 1024 * 1024,
            // Plan §7 stage 3 initial hosted defaults: +/-60 s skew, 1 s timer
            // resolution, at least 121 s replay retention.
            max_retry_window_micros: 900_000_000,
            terminal_status_grace_micros: 900_000_000,
            status_tombstone_grace_micros: 900_000_000,
            clock_skew_micros: 60_000_000,
            timer_resolution_micros: 1_000_000,
            replay_retention_micros: 121_000_000,
            signer: None,
        }
    }
}

macro_rules! require {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            return Err(StoreError::InvalidConfiguration(format!($($arg)*)));
        }
    };
}

impl StoreOptions {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            ..Default::default()
        }
    }

    /// Refuse every invalid configuration at startup. Plan §9: "Unknown modes
    /// and invalid limits fail startup" and every arithmetic relation is
    /// checked, not assumed to fit.
    pub fn validate(&self) -> Result<(), StoreError> {
        require!(
            !self.root.as_os_str().is_empty(),
            "storage root is required"
        );

        require!(
            self.shard_count >= 1 && self.shard_count <= 1024,
            "shard_count must be in 1..=1024, got {}",
            self.shard_count
        );

        require!(
            self.max_group_transactions >= 1,
            "max_group_transactions must be nonzero"
        );
        require!(self.max_group_bytes >= 1, "max_group_bytes must be nonzero");
        require!(
            self.manifest_retain >= 2,
            "manifest_retain must be at least 2 so recovery has a predecessor \
             manifest to fall back to, got {}",
            self.manifest_retain
        );
        require!(
            self.checkpoint_retain >= 2,
            "checkpoint_retain must be at least 2 per plan section 5.3, got {}",
            self.checkpoint_retain
        );
        require!(
            self.journal_preallocate_bytes >= self.max_group_bytes,
            "journal_preallocate_bytes ({}) must be at least max_group_bytes ({}) \
             or a maximal group cannot be appended to a fresh journal",
            self.journal_preallocate_bytes,
            self.max_group_bytes
        );
        require!(
            self.max_open_index_runs >= 1 && self.max_open_index_runs <= self.max_index_runs,
            "max_open_index_runs must be in 1..=max_index_runs"
        );
        require!(
            self.max_objects_per_transaction >= 1,
            "max_objects_per_transaction must be nonzero"
        );
        // The projection ceilings are bounded by what a manifest can actually
        // represent, not only by what an operator would like to allow.
        //
        // `ProjectionStageManifestV1` carries `objects` and `chunk_digests` as
        // flat canonical vectors, each capped at `MAX_CANONICAL_ITEMS`, and the
        // whole encoding is capped at `MAX_CANONICAL_BYTES`. A configuration
        // above those caps does not fail at seal after a long transfer — it
        // *cannot* succeed, and every session admitted under it burns a
        // principal's whole staging budget on a transfer guaranteed to be
        // refused when its manifest is encoded. Refusing at startup is the only
        // point where the operator learns this from the configuration rather
        // than from a stuck mirror.
        //
        // The old 100,000,000 default asserted a capability the format does not
        // have. Restoring it is not a matter of raising a decode ceiling:
        // supporting a hundred million objects requires a versioned
        // chunked/indexed manifest, so that a reader can bound its work without
        // materializing the whole membership set. A larger hostile-decode
        // ceiling would buy the object count by giving up the property that
        // makes the ceiling worth having.
        let canonical_items = levcs_protocol::codec::MAX_CANONICAL_ITEMS as u64;
        let canonical_bytes = levcs_protocol::codec::MAX_CANONICAL_BYTES as u64;
        require!(
            self.max_projection_objects >= 1 && self.max_projection_objects <= canonical_items,
            "max_projection_objects must be in 1..={canonical_items} while the staging \
             manifest is one flat canonical vector, got {}",
            self.max_projection_objects
        );
        require!(
            self.max_projection_chunks >= 1
                && u64::from(self.max_projection_chunks) <= canonical_items,
            "max_projection_chunks must be in 1..={canonical_items}: the manifest's \
             chunk_digests vector is bounded by the same item ceiling, got {}",
            self.max_projection_chunks
        );
        // Bytes are bounded transitively rather than directly: object bytes
        // travel in `ProjectionStageChunkV1`s, one canonical encoding each, so
        // no projection can carry more than its chunk allowance times the
        // canonical byte ceiling. This is a necessary condition and not a
        // sufficient one — a chunk also pays framing and descriptor overhead,
        // so a configuration passing here can still refuse an individual chunk.
        // A configuration failing here is unsatisfiable for every projection at
        // the declared maximum, which is the case worth refusing at startup.
        let representable_projection_bytes = u64::from(self.max_projection_chunks)
            .checked_mul(canonical_bytes)
            .ok_or_else(|| {
                StoreError::InvalidConfiguration(
                    "max_projection_chunks times the canonical byte ceiling overflows u64".into(),
                )
            })?;
        require!(
            self.max_projection_bytes >= 1
                && self.max_projection_bytes <= representable_projection_bytes,
            "max_projection_bytes must be in 1..={representable_projection_bytes} \
             (max_projection_chunks * {canonical_bytes}), got {}",
            self.max_projection_bytes
        );
        require!(
            self.max_status_entries >= 1,
            "max_status_entries must be nonzero"
        );
        require!(
            self.max_refs_per_transaction >= 1
                && (self.max_refs_per_transaction as usize) <= levcs_protocol::v2::MAX_REF_UPDATES,
            "max_refs_per_transaction must be in 1..={}",
            levcs_protocol::v2::MAX_REF_UPDATES
        );
        require!(
            self.staging_max_sessions_per_principal >= 1
                && self.staging_max_sessions_per_principal <= self.staging_max_sessions_global,
            "staging session limits must be nonzero and per-principal <= global"
        );
        require!(
            self.staging_max_objects_per_principal >= self.max_projection_objects
                && self.staging_max_objects_per_principal <= self.staging_max_objects_global,
            "staging object limits must admit one maximal projection and \
             per-principal must be <= global"
        );
        require!(
            self.staging_max_bytes_per_principal >= self.max_projection_bytes
                && self.staging_max_bytes_per_principal <= self.staging_max_bytes_global,
            "staging byte limits must admit one maximal projection and \
             per-principal must be <= global"
        );
        require!(
            self.staging_max_files_per_session >= u64::from(self.max_projection_chunks) + 2
                && self.staging_max_files_per_session <= self.staging_max_files_per_principal
                && self.staging_max_files_per_principal <= self.staging_max_files_global,
            "staging file limits must admit one maximal projection's chunks, \
             session record, and manifest, and \
             per-session <= per-principal <= global"
        );
        require!(
            self.staging_session_max_age_micros > 0,
            "staging_session_max_age_micros must be positive"
        );
        require!(
            self.staging_finalize_margin_micros >= 0,
            "staging_finalize_margin_micros must not be negative"
        );
        require!(
            self.minimum_projection_transfer_bytes_per_second >= 1,
            "minimum_projection_transfer_bytes_per_second must be nonzero"
        );
        require!(
            self.staging_max_compaction_debt_bytes >= self.max_projection_bytes,
            "staging_max_compaction_debt_bytes must admit one maximal projection"
        );

        let transfer_seconds = self
            .max_projection_bytes
            .checked_add(self.minimum_projection_transfer_bytes_per_second - 1)
            .ok_or_else(|| {
                StoreError::InvalidConfiguration(
                    "projection transfer ceiling division overflows u64".into(),
                )
            })?
            / self.minimum_projection_transfer_bytes_per_second;
        let transfer_micros = transfer_seconds.checked_mul(1_000_000).ok_or_else(|| {
            StoreError::InvalidConfiguration("projection transfer duration overflows u64".into())
        })?;
        let transfer_micros = i64::try_from(transfer_micros).map_err(|_| {
            StoreError::InvalidConfiguration(
                "projection transfer duration does not fit signed microseconds".into(),
            )
        })?;
        let required_session_age = transfer_micros
            .checked_add(self.staging_finalize_margin_micros)
            .ok_or_else(|| {
                StoreError::InvalidConfiguration(
                    "projection transfer duration plus finalize margin overflows i64".into(),
                )
            })?;
        require!(
            required_session_age <= self.staging_session_max_age_micros,
            "max projection requires {required_session_age}us at the supported transfer floor, \
             exceeding staging_session_max_age_micros ({})",
            self.staging_session_max_age_micros
        );

        require!(
            self.clock_skew_micros > 0,
            "clock_skew_micros must be positive"
        );
        require!(
            self.timer_resolution_micros > 0,
            "timer_resolution_micros must be positive"
        );
        require!(
            self.max_retry_window_micros > 0,
            "max_retry_window_micros must be positive"
        );
        require!(
            self.terminal_status_grace_micros >= 0,
            "terminal_status_grace_micros must not be negative"
        );
        require!(
            self.status_tombstone_grace_micros >= 0,
            "status_tombstone_grace_micros must not be negative"
        );

        // Plan §7 stage 3: an insertion-relative replay implementation
        // requires retention >= 2 * clock_skew + timer_resolution, and
        // startup rejects overflow, negative values, or a shorter horizon.
        // Delegated to the frozen protocol function so the store cannot
        // disagree with the contract Phase 0 pinned.
        levcs_protocol::v2::validate_replay_retention(
            self.replay_retention_micros,
            self.clock_skew_micros,
            self.timer_resolution_micros,
        )
        .map_err(|e| StoreError::InvalidConfiguration(format!("replay retention: {e}")))?;

        // Checked arithmetic on every retention sum that later code performs.
        self.max_retry_window_micros
            .checked_add(self.terminal_status_grace_micros)
            .and_then(|v| v.checked_add(self.status_tombstone_grace_micros))
            .ok_or_else(|| {
                StoreError::InvalidConfiguration(
                    "retry window plus terminal and tombstone grace overflows i64".into(),
                )
            })?;

        Ok(())
    }

    /// Physical shard owning a namespace.
    ///
    /// Frozen in D0 (scope 2.5). `repo_id` is a BLAKE3 digest, so any two
    /// bytes are uniform. This function is stable for the life of a root:
    /// changing it, or changing `shard_count`, moves repositories between
    /// shards and breaks the single-owner property that per-repository
    /// sequence assignment depends on.
    pub fn shard_of(namespace: &crate::types::NamespaceId, shard_count: u16) -> u16 {
        debug_assert!(shard_count >= 1);
        let bucket = u16::from_le_bytes([namespace.0[0], namespace.0[1]]);
        bucket % shard_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NamespaceId;

    fn valid() -> StoreOptions {
        StoreOptions::new("/tmp/levcs-store-test")
    }

    #[test]
    fn default_options_validate() {
        valid().validate().expect("defaults must be valid");
    }

    #[test]
    fn empty_root_is_refused() {
        let mut o = valid();
        o.root = PathBuf::new();
        assert!(o.validate().is_err());
    }

    #[test]
    fn replay_retention_shorter_than_the_checked_horizon_is_refused() {
        let mut o = valid();
        // Exactly one microsecond below 2 * skew + timer_resolution.
        o.replay_retention_micros = 2 * o.clock_skew_micros + o.timer_resolution_micros - 1;
        assert!(
            o.validate().is_err(),
            "retention below 2*skew+resolution must be refused, not clamped"
        );
    }

    #[test]
    fn replay_retention_exactly_at_the_horizon_is_accepted() {
        let mut o = valid();
        o.replay_retention_micros = 2 * o.clock_skew_micros + o.timer_resolution_micros;
        o.validate().expect("the boundary value is legal");
    }

    #[test]
    fn manifest_and_checkpoint_retention_below_two_is_refused() {
        let mut o = valid();
        o.manifest_retain = 1;
        assert!(o.validate().is_err());

        let mut o = valid();
        o.checkpoint_retain = 1;
        assert!(o.validate().is_err());
    }

    #[test]
    fn journal_smaller_than_a_maximal_group_is_refused() {
        let mut o = valid();
        o.journal_preallocate_bytes = o.max_group_bytes - 1;
        assert!(o.validate().is_err());
    }

    #[test]
    fn retention_sum_overflow_is_refused() {
        let mut o = valid();
        o.max_retry_window_micros = i64::MAX;
        o.terminal_status_grace_micros = 1;
        assert!(o.validate().is_err());
    }

    #[test]
    fn zero_status_or_staging_bounds_are_refused() {
        let mut o = valid();
        o.max_status_entries = 0;
        assert!(o.validate().is_err());

        let mut o = valid();
        o.staging_max_sessions_global = 0;
        assert!(o.validate().is_err());

        let mut o = valid();
        o.minimum_projection_transfer_bytes_per_second = 0;
        assert!(o.validate().is_err());
    }

    #[test]
    fn staging_feasibility_is_checked_before_startup() {
        let mut o = valid();
        o.staging_session_max_age_micros = o.staging_finalize_margin_micros;
        assert!(
            o.validate().is_err(),
            "a session too short for one maximal transfer must be refused"
        );
    }

    #[test]
    fn projection_ceilings_above_what_a_manifest_can_encode_are_refused() {
        let items = levcs_protocol::codec::MAX_CANONICAL_ITEMS as u64;

        let mut o = valid();
        o.max_projection_objects = items;
        o.validate()
            .expect("exactly the canonical item ceiling is representable");
        o.max_projection_objects = items + 1;
        assert!(
            o.validate().is_err(),
            "a projection larger than one canonical vector can never seal a manifest"
        );

        let mut o = valid();
        o.max_projection_chunks = u32::try_from(items + 1).expect("ceiling fits u32");
        o.staging_max_files_per_session = u64::from(o.max_projection_chunks) + 2;
        o.staging_max_files_per_principal = o.staging_max_files_per_session * 2;
        o.staging_max_files_global = o.staging_max_files_per_session * 8;
        assert!(
            o.validate().is_err(),
            "chunk_digests is bounded by the same item ceiling as the object vector"
        );

        // Bytes are refused only where the chunk allowance cannot carry them,
        // so this asserts the transitive bound rather than a fixed number.
        let mut o = valid();
        o.max_projection_chunks = 1;
        o.max_projection_bytes = levcs_protocol::codec::MAX_CANONICAL_BYTES as u64 + 1;
        assert!(
            o.validate().is_err(),
            "one chunk cannot carry more than one canonical encoding's worth of bytes"
        );
    }

    #[test]
    fn the_default_projection_ceilings_are_the_ones_the_format_can_represent() {
        let o = valid();
        assert_eq!(
            o.max_projection_objects,
            levcs_protocol::codec::MAX_CANONICAL_ITEMS as u64,
            "the default is the manifest ceiling; raising it needs a versioned \
             chunked manifest, not a larger decode ceiling"
        );
    }

    #[test]
    fn staging_nested_bounds_must_be_monotonic() {
        let mut o = valid();
        o.staging_max_bytes_per_principal = o.max_projection_bytes - 1;
        assert!(o.validate().is_err());

        let mut o = valid();
        o.staging_max_files_per_principal = o.staging_max_files_per_session - 1;
        assert!(o.validate().is_err());

        let mut o = valid();
        o.staging_max_files_per_session = u64::from(o.max_projection_chunks) + 1;
        assert!(o.validate().is_err());
    }

    #[test]
    fn shard_routing_is_stable_and_in_range() {
        for count in [1u16, 2, 4, 7, 256, 1024] {
            for seed in 0u8..64 {
                let ns = NamespaceId([seed; 32]);
                let a = StoreOptions::shard_of(&ns, count);
                let b = StoreOptions::shard_of(&ns, count);
                assert_eq!(a, b, "routing must be deterministic");
                assert!(a < count, "shard {a} out of range for count {count}");
            }
        }
    }
}
