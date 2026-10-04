//! Textual three-way merge handler. The universal fallback.
//!
//! The algorithm:
//!   1. Compute line-level diffs base→ours and base→theirs.
//!   2. Express each diff as a list of patches, where each patch replaces a
//!      contiguous range of base lines with new lines.
//!   3. Walk both patch lists in order. Non-overlapping patches apply
//!      independently. Overlapping patches form a conflict region; if both
//!      sides happen to make the *same* edit it auto-resolves.
//!
//! The output preserves base line endings: we keep each line including its
//! trailing `\n` (or the empty terminator at end of file) so the merged file
//! reproduces the original whitespace.

use std::path::Path;

use similar::{ChangeTag, TextDiff};

use crate::handler::{ConflictRegion, MergeHandler, MergeNote, MergeResult, MergeStatus};

#[derive(Clone, Debug)]
struct Patch {
    base_start: usize,
    base_end: usize,
    new_lines: Vec<String>,
}

/// Split a string into lines, preserving each line's terminator. Must
/// agree with `similar::TextDiff::from_lines` on what counts as a line —
/// otherwise the indices we walk in the diff will not line up with our
/// `base_lines` array, and we'll slice out of bounds. similar uses
/// universal newlines: `\n`, `\r\n`, and a bare `\r` are all line
/// terminators. We follow the same rule.
fn split_lines_keep(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        buf.push(ch);
        if ch == '\n' {
            out.push(std::mem::take(&mut buf));
        } else if ch == '\r' {
            // Bare CR is a terminator. CRLF: consume the following \n
            // into the same line so the terminator stays intact.
            if chars.peek() == Some(&'\n') {
                buf.push(chars.next().unwrap());
            }
            out.push(std::mem::take(&mut buf));
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

fn diff_to_patches(base_lines: &[String], other_lines: &[String]) -> Vec<Patch> {
    let base_joined: String = base_lines.concat();
    let other_joined: String = other_lines.concat();
    let diff = TextDiff::from_lines(&base_joined, &other_joined);

    let mut patches: Vec<Patch> = Vec::new();
    let mut base_idx = 0usize;
    let mut current: Option<Patch> = None;
    let flush = |cur: &mut Option<Patch>, out: &mut Vec<Patch>| {
        if let Some(p) = cur.take() {
            out.push(p);
        }
    };
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Equal => {
                flush(&mut current, &mut patches);
                base_idx += 1;
            }
            ChangeTag::Delete => {
                let p = current.get_or_insert_with(|| Patch {
                    base_start: base_idx,
                    base_end: base_idx,
                    new_lines: Vec::new(),
                });
                p.base_end = base_idx + 1;
                base_idx += 1;
            }
            ChangeTag::Insert => {
                let p = current.get_or_insert_with(|| Patch {
                    base_start: base_idx,
                    base_end: base_idx,
                    new_lines: Vec::new(),
                });
                p.new_lines.push(change.value().to_string());
            }
        }
    }
    flush(&mut current, &mut patches);
    patches
}

/// Result of merging two patch lists.
fn merge_patches(
    base_lines: &[String],
    ours: Vec<Patch>,
    theirs: Vec<Patch>,
) -> (Vec<String>, Vec<ConflictRegion>) {
    let mut output: Vec<String> = Vec::new();
    let mut conflicts: Vec<ConflictRegion> = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    let mut base_pos = 0usize;
    while i < ours.len() || j < theirs.len() {
        let next_o = ours.get(i).map(|p| p.base_start);
        let next_t = theirs.get(j).map(|p| p.base_start);
        let next = match (next_o, next_t) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => base_lines.len(),
        };
        // Copy unchanged base lines up to `next`.
        if base_pos < next {
            output.extend_from_slice(&base_lines[base_pos..next]);
            base_pos = next;
        }
        // Collect the patches that overlap starting here.
        let mut group_o: Vec<Patch> = Vec::new();
        let mut group_t: Vec<Patch> = Vec::new();
        let mut end = base_pos;
        loop {
            let mut grew = false;
            while let Some(p) = ours.get(i) {
                if p.base_start <= end {
                    end = end.max(p.base_end);
                    group_o.push(p.clone());
                    i += 1;
                    grew = true;
                } else {
                    break;
                }
            }
            while let Some(p) = theirs.get(j) {
                if p.base_start <= end {
                    end = end.max(p.base_end);
                    group_t.push(p.clone());
                    j += 1;
                    grew = true;
                } else {
                    break;
                }
            }
            if !grew {
                break;
            }
        }

        let resolved = resolve_group(base_pos, end, base_lines, &group_o, &group_t);
        match resolved {
            Resolution::Applied(lines) => output.extend(lines),
            Resolution::Conflict {
                ours_lines,
                theirs_lines,
                base_range,
            } => {
                let ours_start = output.len();
                output.extend(conflict_marker_ours());
                output.extend(ours_lines.clone());
                output.extend(conflict_marker_base());
                let mid = output.len();
                output.extend(base_lines[base_range.clone()].iter().cloned());
                output.extend(conflict_marker_theirs());
                let theirs_start = output.len();
                output.extend(theirs_lines.clone());
                output.extend(conflict_marker_end());
                let end_idx = output.len();
                conflicts.push(ConflictRegion {
                    description: format!(
                        "concurrent modifications to base lines {}..{}",
                        base_range.start, base_range.end
                    ),
                    base: base_range.clone(),
                    ours: ours_start..mid,
                    theirs: theirs_start..end_idx,
                });
            }
        }
        base_pos = end;
    }
    if base_pos < base_lines.len() {
        output.extend_from_slice(&base_lines[base_pos..]);
    }
    (output, conflicts)
}

enum Resolution {
    Applied(Vec<String>),
    Conflict {
        ours_lines: Vec<String>,
        theirs_lines: Vec<String>,
        base_range: std::ops::Range<usize>,
    },
}

fn apply_group(start: usize, end: usize, base: &[String], group: &[Patch]) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = start;
    for patch in group {
        if patch.base_start > p {
            out.extend_from_slice(&base[p..patch.base_start]);
        }
        out.extend_from_slice(&patch.new_lines);
        p = patch.base_end;
    }
    if p < end {
        out.extend_from_slice(&base[p..end]);
    }
    out
}

fn resolve_group(
    start: usize,
    end: usize,
    base: &[String],
    group_o: &[Patch],
    group_t: &[Patch],
) -> Resolution {
    let only_o = !group_o.is_empty() && group_t.is_empty();
    let only_t = !group_t.is_empty() && group_o.is_empty();
    if only_o {
        return Resolution::Applied(apply_group(start, end, base, group_o));
    }
    if only_t {
        return Resolution::Applied(apply_group(start, end, base, group_t));
    }
    let ours_lines = apply_group(start, end, base, group_o);
    let theirs_lines = apply_group(start, end, base, group_t);
    if ours_lines == theirs_lines {
        return Resolution::Applied(ours_lines);
    }
    Resolution::Conflict {
        ours_lines,
        theirs_lines,
        base_range: start..end,
    }
}

fn conflict_marker_ours() -> Vec<String> {
    vec!["<<<<<<< ours\n".to_string()]
}
fn conflict_marker_base() -> Vec<String> {
    vec!["||||||| base\n".to_string()]
}
fn conflict_marker_theirs() -> Vec<String> {
    vec!["=======\n".to_string()]
}
fn conflict_marker_end() -> Vec<String> {
    vec![">>>>>>> theirs\n".to_string()]
}

pub fn three_way_merge_lines(
    base: &str,
    ours: &str,
    theirs: &str,
) -> (String, Vec<ConflictRegion>) {
    let base_lines = split_lines_keep(base);
    let ours_lines = split_lines_keep(ours);
    let theirs_lines = split_lines_keep(theirs);
    if ours_lines == theirs_lines {
        return (ours, Vec::new()).map_first();
    }
    if base_lines == ours_lines {
        return (theirs, Vec::new()).map_first();
    }
    if base_lines == theirs_lines {
        return (ours, Vec::new()).map_first();
    }
    let p_ours = diff_to_patches(&base_lines, &ours_lines);
    let p_theirs = diff_to_patches(&base_lines, &theirs_lines);
    let (merged_lines, conflicts) = merge_patches(&base_lines, p_ours, p_theirs);
    (merged_lines.concat(), conflicts)
}

trait MapFirst<A, B> {
    fn map_first(self) -> (String, B);
}

impl<S: Into<String>, B> MapFirst<S, B> for (S, B) {
    fn map_first(self) -> (String, B) {
        (self.0.into(), self.1)
    }
}

/// Bytes no built-in handler may merge: not valid UTF-8, or containing NUL.
/// NUL is valid UTF-8, so the UTF-8 check alone let binary formats through
/// to a line merge, which inserted conflict markers into them or spliced
/// their bytes together and reported AUTO.
pub fn looks_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0) || std::str::from_utf8(bytes).is_err()
}

pub struct TextualHandler;

impl MergeHandler for TextualHandler {
    fn name(&self) -> &str {
        "textual"
    }

    fn applicable(&self, _path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> bool {
        // Text only: a line merge of binary content corrupts it.
        !looks_binary(base) && !looks_binary(ours) && !looks_binary(theirs)
    }

    fn merge(&self, _path: &Path, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
        let bs = std::str::from_utf8(base).unwrap_or("");
        let os = std::str::from_utf8(ours).unwrap_or("");
        let ts = std::str::from_utf8(theirs).unwrap_or("");
        let (merged, conflicts) = three_way_merge_lines(bs, os, ts);
        let status = if conflicts.is_empty() {
            MergeStatus::Merged {
                content: merged.into_bytes(),
                notes: vec![MergeNote {
                    message: "auto-merged via line-level three-way diff".into(),
                }],
            }
        } else {
            MergeStatus::Conflict {
                regions: conflicts,
                partial: merged.into_bytes(),
            }
        };
        MergeResult {
            handler: self.name().into(),
            status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_changes() {
        let s = "a\nb\nc\n";
        let (out, c) = three_way_merge_lines(s, s, s);
        assert_eq!(out, s);
        assert!(c.is_empty());
    }

    #[test]
    fn only_ours_changes() {
        let base = "a\nb\nc\n";
        let ours = "a\nB\nc\n";
        let theirs = "a\nb\nc\n";
        let (out, c) = three_way_merge_lines(base, ours, theirs);
        assert_eq!(out, ours);
        assert!(c.is_empty());
    }

    #[test]
    fn only_theirs_changes() {
        let base = "a\nb\nc\n";
        let ours = "a\nb\nc\n";
        let theirs = "a\nb\nC\n";
        let (out, c) = three_way_merge_lines(base, ours, theirs);
        assert_eq!(out, theirs);
        assert!(c.is_empty());
    }

    #[test]
    fn disjoint_changes_merge() {
        let base = "a\nb\nc\nd\n";
        let ours = "A\nb\nc\nd\n";
        let theirs = "a\nb\nc\nD\n";
        let (out, c) = three_way_merge_lines(base, ours, theirs);
        assert_eq!(out, "A\nb\nc\nD\n");
        assert!(c.is_empty());
    }

    #[test]
    fn same_change_both_sides_resolves() {
        let base = "a\nb\nc\n";
        let ours = "a\nB\nc\n";
        let theirs = "a\nB\nc\n";
        let (out, c) = three_way_merge_lines(base, ours, theirs);
        assert_eq!(out, "a\nB\nc\n");
        assert!(c.is_empty());
    }

    #[test]
    fn divergent_change_conflicts() {
        let base = "a\nb\nc\n";
        let ours = "a\nB1\nc\n";
        let theirs = "a\nB2\nc\n";
        let (_out, c) = three_way_merge_lines(base, ours, theirs);
        assert_eq!(c.len(), 1);
    }

    /// Regression: `similar::TextDiff::from_lines` treats bare CR as a
    /// line terminator (universal newlines). `split_lines_keep` must
    /// agree, otherwise the diff walker indexes past the end of
    /// `base_lines` and the slice access panics. Found by proptest
    /// shrinking to (base="\r¡", ours="", theirs="\0").
    #[test]
    fn cr_only_line_endings_do_not_panic() {
        let _ = three_way_merge_lines("\r¡", "", "\0");
        let _ = three_way_merge_lines("a\rb\rc\r", "a\rb\r", "a\rb\rC\r");
        let _ = three_way_merge_lines("a\r\nb\r\n", "a\r\nB\r\n", "a\r\n");
    }
}
