//! levcs-merge: cascading merge engine with built-in handlers.
//!
//! Per spec §6 the engine is a cascade of handlers. Each handler can return
//! `Merged`, `Conflict`, or `NotApplicable`. The engine selects handlers by
//! file path / extension, applies the highest-priority applicable handler,
//! and falls through on `NotApplicable`.

pub mod handler;
pub mod engine;
pub mod textual;
pub mod format;
pub mod format_extra;
pub mod plugin;
pub mod record;
pub mod tree_sitter_handler;

pub use handler::{ConflictRegion, MergeHandler, MergeResult, MergeNote, MergeStatus};
pub use engine::{CascadeEngine, MergeConfig, MergeRule};
pub use record::{MergeRecord, FileRecord, FileStatus};
pub use tree_sitter_handler::{Lang, TreeSitterHandler};
