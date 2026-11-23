// SPDX-FileCopyrightText: 2026 Levi Neuwirth
// SPDX-License-Identifier: Apache-2.0

//! File merge handlers selected by path rule.
//!
//! The first matching path rule selects a handler. Textual merge is the
//! default and the fallback when the selected handler is inapplicable.
//! A handler's `Merged` or `Conflict` result ends dispatch.

pub mod engine;
pub mod format;
pub mod format_extra;
pub mod handler;
pub mod plugin;
pub mod record;
pub mod textual;
pub mod tree_sitter_handler;

pub use engine::{CascadeEngine, MergeConfig, MergeRule};
pub use handler::{ConflictRegion, MergeHandler, MergeNote, MergeResult, MergeStatus};
pub use record::{FileRecord, FileStatus, MergeRecord};
pub use tree_sitter_handler::{Lang, TreeSitterHandler};
