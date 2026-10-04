//! Pure state machine for the merge-review TUI.
//!
//! Lives separately from the terminal driver so it can be unit-tested
//! without touching crossterm or ratatui. The driver is a thin shim
//! that translates `KeyEvent → ReviewState method` and renders the
//! current state on every tick.
//!
//! The shape of the data:
//!   * One `FileEntry` per file in the merge record. Each entry carries
//!     all four byte arrays — `current` (engine output, possibly with
//!     conflict markers), `ours`, `base`, `theirs` — and the structured
//!     conflict regions the engine reported.
//!   * One `Resolution` per file, recording what the user picked. The
//!     default is `KeepCurrent`, which means "leave the working-tree
//!     bytes alone" — useful for files the user already edited by hand
//!     before launching review.
//!
//! `ReviewState::apply` walks the resolutions, writes the chosen bytes
//! to disk under `workdir`, and returns the count of files that changed.
//! The terminal driver calls it after the user quits.

use std::path::Path;

use levcs_merge::{ConflictRegion, MergeStatus};

/// What the user picked for a given file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Leave the working-tree bytes as-is. The default — preserves any
    /// hand-edits the user made before launching review.
    KeepCurrent,
    /// Replace the working-tree bytes with `ours`.
    AcceptOurs,
    /// Replace the working-tree bytes with `theirs`.
    AcceptTheirs,
    /// Replace the working-tree bytes with the user's own edited buffer
    /// (typically captured by spawning `$EDITOR` on the conflicted file).
    Edit { bytes: Vec<u8> },
    /// Mark this file as "do not write" — the working tree is left
    /// alone (same effect as `KeepCurrent` for `apply`, but distinct
    /// in the report so the caller can tell skipped from intentional).
    Skip,
}

#[derive(Clone, Debug)]
pub struct FileEntry {
    pub path: String,
    pub status: MergeStatus,
    pub current: Vec<u8>,
    pub ours: Vec<u8>,
    pub theirs: Vec<u8>,
    pub base: Vec<u8>,
    /// Handler that produced this file's outcome (e.g. "textual",
    /// "tree-sitter:rust"). Populated by the caller — the TUI uses it
    /// for display only.
    pub handler: String,
    /// Engine notes from the merge record (e.g. "recursive descent",
    /// "modify-vs-delete"). Free-form, multi-line.
    pub notes: String,
}

impl FileEntry {
    pub fn conflict_regions(&self) -> &[ConflictRegion] {
        match &self.status {
            MergeStatus::Conflict { regions, .. } => regions,
            _ => &[],
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReviewState {
    pub files: Vec<FileEntry>,
    pub resolutions: Vec<Resolution>,
    pub selected_file: usize,
    pub selected_region: usize,
    /// Set true when the user presses `q` or `Esc`. The driver loop
    /// reads this to know when to exit.
    pub quitting: bool,
    /// When true, the TUI runs in inspect-only mode (`merge --explain`):
    /// resolution-changing keys (`o`/`t`/`c`/`s`/`e`) are ignored and
    /// `apply` writes nothing. Navigation still works.
    pub read_only: bool,
}

impl ReviewState {
    pub fn new(files: Vec<FileEntry>) -> Self {
        let resolutions = vec![Resolution::KeepCurrent; files.len()];
        Self {
            files,
            resolutions,
            selected_file: 0,
            selected_region: 0,
            quitting: false,
            read_only: false,
        }
    }

    /// Read-only constructor used by `merge --explain`. Same as `new`
    /// but flips the read_only flag so resolution mutations are no-ops.
    pub fn new_read_only(files: Vec<FileEntry>) -> Self {
        let mut s = Self::new(files);
        s.read_only = true;
        s
    }

    /// Move file selection up by one (saturating at 0). Resets the
    /// region cursor so the new file's regions are shown from the top.
    pub fn move_up(&mut self) {
        if self.selected_file > 0 {
            self.selected_file -= 1;
            self.selected_region = 0;
        }
    }

    /// Move file selection down by one (saturating at len-1).
    pub fn move_down(&mut self) {
        if self.selected_file + 1 < self.files.len() {
            self.selected_file += 1;
            self.selected_region = 0;
        }
    }

    pub fn next_region(&mut self) {
        let n = self
            .current_file()
            .map(|f| f.conflict_regions().len())
            .unwrap_or(0);
        if n > 0 && self.selected_region + 1 < n {
            self.selected_region += 1;
        }
    }

    pub fn prev_region(&mut self) {
        if self.selected_region > 0 {
            self.selected_region -= 1;
        }
    }

    pub fn current_file(&self) -> Option<&FileEntry> {
        self.files.get(self.selected_file)
    }

    pub fn current_resolution(&self) -> Resolution {
        self.resolutions
            .get(self.selected_file)
            .cloned()
            .unwrap_or(Resolution::KeepCurrent)
    }

    pub fn set_current_resolution(&mut self, r: Resolution) {
        if self.read_only {
            return;
        }
        if let Some(slot) = self.resolutions.get_mut(self.selected_file) {
            *slot = r;
        }
    }

    pub fn accept_ours(&mut self) {
        self.set_current_resolution(Resolution::AcceptOurs);
    }
    pub fn accept_theirs(&mut self) {
        self.set_current_resolution(Resolution::AcceptTheirs);
    }
    pub fn keep_current(&mut self) {
        self.set_current_resolution(Resolution::KeepCurrent);
    }
    pub fn skip(&mut self) {
        self.set_current_resolution(Resolution::Skip);
    }
    pub fn quit(&mut self) {
        self.quitting = true;
    }

    /// Walk every file and write the chosen bytes. Returns
    /// `(written, skipped)`. Errors short-circuit — partial writes are
    /// possible. Caller is responsible for keeping the workdir clean
    /// across runs (the merge state file at `.levcs/MERGE_HEAD` etc.
    /// is left intact regardless of what we write here).
    pub fn apply(&self, workdir: &Path) -> std::io::Result<ApplyReport> {
        // Read-only mode (merge --explain) doesn't write anything —
        // count every file as skipped so the caller can still report
        // the totals it expects.
        if self.read_only {
            return Ok(ApplyReport {
                written: 0,
                skipped: self.files.len(),
            });
        }
        let chosen: Vec<(&str, &[u8])> = self
            .files
            .iter()
            .zip(&self.resolutions)
            .filter_map(|(entry, resolution)| {
                let bytes: &[u8] = match resolution {
                    Resolution::KeepCurrent | Resolution::Skip => return None,
                    Resolution::AcceptOurs => &entry.ours,
                    Resolution::AcceptTheirs => &entry.theirs,
                    Resolution::Edit { bytes } => bytes,
                };
                Some((entry.path.as_str(), bytes))
            })
            .collect();
        // Written through the working tree's descriptor, as a checkout is:
        // every path checked before the first write, no symlink followed,
        // and each file replaced by a rename (atomic from the working
        // tree's point of view, so a Ctrl-C part way never leaves a
        // half-written file). This used to join the merge record's paths
        // onto `workdir` and write by pathname.
        let wt = levcs_core::worktree::open(workdir).map_err(std::io::Error::other)?;
        wt.preflight(chosen.iter().map(|(path, _)| *path))
            .map_err(std::io::Error::other)?;
        for (path, bytes) in &chosen {
            wt.write_file(path, bytes, levcs_core::worktree::Perms::Keep)
                .map_err(std::io::Error::other)?;
        }
        Ok(ApplyReport {
            written: chosen.len(),
            skipped: self.files.len() - chosen.len(),
        })
    }

    /// Return a non-interactive textual summary of the resolutions —
    /// suitable for printing after a session ends, or driving the
    /// JSON reporter described in §6.7.
    pub fn summary(&self) -> Vec<(String, Resolution)> {
        self.files
            .iter()
            .zip(&self.resolutions)
            .map(|(f, r)| (f.path.clone(), r.clone()))
            .collect()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ApplyReport {
    pub written: usize,
    pub skipped: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Range;
    use std::path::PathBuf;

    fn entry(path: &str, regions: usize) -> FileEntry {
        let conflict_regions: Vec<ConflictRegion> = (0..regions)
            .map(|i| ConflictRegion {
                description: format!("region {i}"),
                base: Range {
                    start: i * 10,
                    end: i * 10 + 5,
                },
                ours: Range {
                    start: i * 10,
                    end: i * 10 + 7,
                },
                theirs: Range {
                    start: i * 10,
                    end: i * 10 + 6,
                },
            })
            .collect();
        let status = if regions == 0 {
            MergeStatus::Merged {
                content: b"ok".to_vec(),
                notes: vec![],
            }
        } else {
            MergeStatus::Conflict {
                regions: conflict_regions,
                partial: vec![],
            }
        };
        FileEntry {
            path: path.into(),
            status,
            current: format!("CURRENT-{path}").into_bytes(),
            ours: format!("OURS-{path}").into_bytes(),
            theirs: format!("THEIRS-{path}").into_bytes(),
            base: format!("BASE-{path}").into_bytes(),
            handler: "test-handler".into(),
            notes: String::new(),
        }
    }

    #[test]
    fn new_state_starts_at_zero_and_keep_current() {
        let s = ReviewState::new(vec![entry("a.txt", 0), entry("b.txt", 2)]);
        assert_eq!(s.selected_file, 0);
        assert_eq!(s.selected_region, 0);
        assert_eq!(s.current_resolution(), Resolution::KeepCurrent);
        assert!(!s.quitting);
    }

    #[test]
    fn move_up_down_clamps_at_bounds() {
        let mut s = ReviewState::new(vec![entry("a", 0), entry("b", 0), entry("c", 0)]);
        s.move_up();
        assert_eq!(s.selected_file, 0);
        s.move_down();
        s.move_down();
        s.move_down();
        assert_eq!(s.selected_file, 2, "must clamp at len-1");
        s.move_up();
        assert_eq!(s.selected_file, 1);
    }

    #[test]
    fn changing_file_resets_region_cursor() {
        let mut s = ReviewState::new(vec![entry("a", 3), entry("b", 3)]);
        s.next_region();
        s.next_region();
        assert_eq!(s.selected_region, 2);
        s.move_down();
        assert_eq!(s.selected_region, 0, "moving file must reset region cursor");
    }

    #[test]
    fn region_navigation_clamps_to_count() {
        let mut s = ReviewState::new(vec![entry("a", 2)]);
        s.next_region();
        assert_eq!(s.selected_region, 1);
        s.next_region();
        assert_eq!(s.selected_region, 1, "must clamp at count-1");
        s.prev_region();
        s.prev_region();
        assert_eq!(s.selected_region, 0, "must clamp at 0");
    }

    #[test]
    fn region_navigation_on_merged_file_is_noop() {
        let mut s = ReviewState::new(vec![entry("ok.txt", 0)]);
        s.next_region();
        s.next_region();
        assert_eq!(s.selected_region, 0, "no regions to navigate");
    }

    #[test]
    fn resolutions_track_per_file() {
        let mut s = ReviewState::new(vec![entry("a", 1), entry("b", 1), entry("c", 1)]);
        s.accept_ours();
        s.move_down();
        s.accept_theirs();
        s.move_down();
        s.skip();
        let summary = s.summary();
        assert_eq!(summary[0].1, Resolution::AcceptOurs);
        assert_eq!(summary[1].1, Resolution::AcceptTheirs);
        assert_eq!(summary[2].1, Resolution::Skip);
    }

    #[test]
    fn apply_writes_chosen_bytes_atomically() {
        let dir = tempdir();
        std::fs::write(dir.join("a.txt"), b"original-a").unwrap();
        std::fs::write(dir.join("b.txt"), b"original-b").unwrap();
        std::fs::write(dir.join("c.txt"), b"original-c").unwrap();

        let mut s = ReviewState::new(vec![
            entry("a.txt", 1),
            entry("b.txt", 1),
            entry("c.txt", 1),
        ]);
        s.accept_ours();
        s.move_down();
        s.accept_theirs();
        s.move_down();
        s.skip();

        let report = s.apply(&dir).unwrap();
        assert_eq!(report.written, 2);
        assert_eq!(report.skipped, 1);

        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"OURS-a.txt");
        assert_eq!(std::fs::read(dir.join("b.txt")).unwrap(), b"THEIRS-b.txt");
        // Skipped file untouched.
        assert_eq!(std::fs::read(dir.join("c.txt")).unwrap(), b"original-c");

        // No leftover temp files — atomic rename completed.
        for ent in std::fs::read_dir(&dir).unwrap() {
            let name = ent.unwrap().file_name().into_string().unwrap();
            assert!(
                !name.starts_with(".levcs-write"),
                "atomic temp leaked: {name}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_writes_edit_variant_bytes() {
        let dir = tempdir();
        std::fs::write(dir.join("a.txt"), b"original").unwrap();

        let mut s = ReviewState::new(vec![entry("a.txt", 1)]);
        s.set_current_resolution(Resolution::Edit {
            bytes: b"hand-edited".to_vec(),
        });
        let report = s.apply(&dir).unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(report.skipped, 0);
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"hand-edited");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_creates_parent_dirs_for_nested_paths() {
        let dir = tempdir();
        let mut s = ReviewState::new(vec![entry("nested/deep/leaf.txt", 1)]);
        s.accept_ours();
        let report = s.apply(&dir).unwrap();
        assert_eq!(report.written, 1);
        let p = dir.join("nested/deep/leaf.txt");
        assert!(p.is_file());
        assert_eq!(std::fs::read(&p).unwrap(), b"OURS-nested/deep/leaf.txt");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_only_blocks_resolution_changes() {
        let mut s = ReviewState::new_read_only(vec![entry("a", 1), entry("b", 1)]);
        assert!(s.read_only);
        // Every mutation method is a no-op.
        s.accept_ours();
        s.accept_theirs();
        s.skip();
        s.set_current_resolution(Resolution::Edit { bytes: b"x".into() });
        // KeepCurrent is the default and should still be the value.
        for r in &s.resolutions {
            assert_eq!(*r, Resolution::KeepCurrent);
        }
    }

    #[test]
    fn read_only_navigation_still_works() {
        let mut s = ReviewState::new_read_only(vec![entry("a", 2), entry("b", 1)]);
        s.move_down();
        assert_eq!(s.selected_file, 1);
        s.move_up();
        assert_eq!(s.selected_file, 0);
        s.next_region();
        assert_eq!(s.selected_region, 1);
    }

    #[test]
    fn read_only_apply_writes_nothing_and_reports_skipped() {
        let dir = tempdir();
        std::fs::write(dir.join("a.txt"), b"original").unwrap();
        let s = ReviewState::new_read_only(vec![entry("a.txt", 1)]);
        let r = s.apply(&dir).unwrap();
        assert_eq!(r.written, 0);
        assert_eq!(r.skipped, 1);
        // File on disk unchanged.
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"original");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn quit_sets_flag_without_changing_resolutions() {
        let mut s = ReviewState::new(vec![entry("a", 1)]);
        s.accept_ours();
        s.quit();
        assert!(s.quitting);
        assert_eq!(s.current_resolution(), Resolution::AcceptOurs);
    }

    /// Review application wrote the merge record's paths joined onto the
    /// working tree, through any symlinked directory, and stopped part way
    /// when one failed. Now every path is checked before the first write.
    #[cfg(unix)]
    #[test]
    fn apply_does_not_follow_symlinks_and_checks_before_writing() {
        let base = tempdir();
        let (dir, outside) = (base.join("w"), base.join("outside"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(dir.join("a.txt"), b"original-a").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("nested")).unwrap();

        let mut s = ReviewState::new(vec![entry("a.txt", 1), entry("nested/leaf.txt", 1)]);
        s.accept_ours();
        s.move_down();
        s.accept_ours();
        assert!(s.apply(&dir).is_err());
        assert!(
            !outside.join("leaf.txt").exists(),
            "written through the symlink"
        );
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"original-a");

        for bad in ["../escape.txt", ".levcs/config"] {
            let mut s = ReviewState::new(vec![entry(bad, 1)]);
            s.accept_ours();
            assert!(s.apply(&dir).is_err(), "{bad} accepted");
        }
        assert!(!base.join("escape.txt").exists());
        std::fs::remove_dir_all(&base).ok();
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("levcs-tui-{n}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
