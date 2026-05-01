//! Handler trait per §6.2.

use std::fmt;
use std::ops::Range;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictRegion {
    pub description: String,
    pub base: Range<usize>,
    pub ours: Range<usize>,
    pub theirs: Range<usize>,
}

#[derive(Clone, Debug)]
pub enum MergeStatus {
    Merged {
        content: Vec<u8>,
        notes: Vec<MergeNote>,
    },
    Conflict {
        regions: Vec<ConflictRegion>,
        partial: Vec<u8>,
    },
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeNote {
    pub message: String,
}

pub struct MergeResult {
    pub handler: String,
    pub status: MergeStatus,
}

impl fmt::Debug for MergeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MergeResult")
            .field("handler", &self.handler)
            .field("status", &short_status(&self.status))
            .finish()
    }
}

fn short_status(s: &MergeStatus) -> &'static str {
    match s {
        MergeStatus::Merged { .. } => "Merged",
        MergeStatus::Conflict { .. } => "Conflict",
        MergeStatus::NotApplicable => "NotApplicable",
    }
}

/// Trait implemented by every handler in the cascade.
pub trait MergeHandler: Send + Sync {
    fn name(&self) -> &str;
    fn applicable(&self, path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> bool;
    fn merge(&self, path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult;
}
