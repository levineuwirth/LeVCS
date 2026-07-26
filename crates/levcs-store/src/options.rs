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
            max_projection_objects: 100_000_000,
            max_projection_bytes: 1024 * 1024 * 1024 * 1024,
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
        require!(
            self.max_refs_per_transaction >= 1
                && (self.max_refs_per_transaction as usize) <= levcs_protocol::v2::MAX_REF_UPDATES,
            "max_refs_per_transaction must be in 1..={}",
            levcs_protocol::v2::MAX_REF_UPDATES
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
