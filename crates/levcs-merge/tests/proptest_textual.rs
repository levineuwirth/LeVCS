//! Property tests for the textual three-way merge handler (§6.1, §8.2).
//!
//! The merge engine has the largest blast radius of any module — every
//! conflict resolution flows through it — and these properties pin down
//! invariants that any correct 3-way merge must satisfy regardless of
//! input content.

use levcs_merge::textual::three_way_merge_lines;
use proptest::collection::vec;
use proptest::prelude::*;

/// A line is one of a small alphabet plus a trailing '\n'. Restricting
/// the alphabet keeps the test fast and forces collisions where the
/// merge logic actually has interesting decisions to make. Bias toward
/// short alphabets means base/ours/theirs share lines often, which
/// exercises the equal-vs-changed branches.
fn line_strategy() -> impl Strategy<Value = String> {
    "[a-c]{0,3}".prop_map(|s| format!("{s}\n"))
}

fn document_strategy() -> impl Strategy<Value = String> {
    vec(line_strategy(), 0..10).prop_map(|lines| lines.concat())
}

proptest! {
    /// Identity: merging a document with itself on all three sides yields
    /// the document with no conflicts.
    #[test]
    fn merge_of_self_is_self(s in document_strategy()) {
        let (out, conflicts) = three_way_merge_lines(&s, &s, &s);
        prop_assert_eq!(out, s);
        prop_assert!(conflicts.is_empty());
    }

    /// One side unchanged: when ours == base, the merge equals theirs
    /// with no conflicts. Symmetric to the next property.
    #[test]
    fn ours_unchanged_yields_theirs(
        base in document_strategy(),
        theirs in document_strategy(),
    ) {
        let (out, conflicts) = three_way_merge_lines(&base, &base, &theirs);
        prop_assert_eq!(out, theirs);
        prop_assert!(conflicts.is_empty());
    }

    /// Symmetric: theirs == base means the merge is ours.
    #[test]
    fn theirs_unchanged_yields_ours(
        base in document_strategy(),
        ours in document_strategy(),
    ) {
        let (out, conflicts) = three_way_merge_lines(&base, &ours, &base);
        prop_assert_eq!(out, ours);
        prop_assert!(conflicts.is_empty());
    }

    /// Same-edit-on-both-sides auto-resolves: if ours == theirs (regardless
    /// of base), the merge equals that common edit with no conflicts. This
    /// is a frequent real-world case (two devs cherry-pick the same fix)
    /// and the false-conflict the spec calls out repeatedly.
    #[test]
    fn same_edit_auto_resolves(
        base in document_strategy(),
        edit in document_strategy(),
    ) {
        let (out, conflicts) = three_way_merge_lines(&base, &edit, &edit);
        prop_assert_eq!(out, edit);
        prop_assert!(conflicts.is_empty());
    }

    /// No panic on arbitrary text. Even text that is nominally garbage to
    /// a line-based merger (no newlines, embedded NULs, the empty string)
    /// must produce a string and a conflict list, never a panic.
    #[test]
    fn no_panic_on_arbitrary_inputs(
        base in ".{0,256}",
        ours in ".{0,256}",
        theirs in ".{0,256}",
    ) {
        let _ = three_way_merge_lines(&base, &ours, &theirs);
    }

    /// Conflict markers come in matched sets in the order
    /// `<<<<<<< ours` … `||||||| base` … `=======` … `>>>>>>> theirs`.
    /// Counting the four marker substrings in the merged output must
    /// give equal counts equal to `conflicts.len()`. (The marker
    /// strings are deliberately distinctive so they don't appear by
    /// chance in our `[a-c]{0,3}\n` line alphabet.)
    #[test]
    fn conflict_marker_counts_match_region_count(
        base in document_strategy(),
        ours in document_strategy(),
        theirs in document_strategy(),
    ) {
        let (out, conflicts) = three_way_merge_lines(&base, &ours, &theirs);
        let n = conflicts.len();
        prop_assert_eq!(out.matches("<<<<<<< ours\n").count(), n);
        prop_assert_eq!(out.matches("||||||| base\n").count(), n);
        prop_assert_eq!(out.matches("=======\n").count(), n);
        prop_assert_eq!(out.matches(">>>>>>> theirs\n").count(), n);
    }

    /// When the merge reports zero conflicts, the output must NOT contain
    /// any of the conflict-marker headers. This guards against a regression
    /// where markers leak into a "successfully merged" output.
    #[test]
    fn clean_merge_has_no_conflict_markers(
        base in document_strategy(),
        ours in document_strategy(),
        theirs in document_strategy(),
    ) {
        let (out, conflicts) = three_way_merge_lines(&base, &ours, &theirs);
        if conflicts.is_empty() {
            prop_assert!(!out.contains("<<<<<<< ours\n"));
            prop_assert!(!out.contains("||||||| base\n"));
            prop_assert!(!out.contains("=======\n"));
            prop_assert!(!out.contains(">>>>>>> theirs\n"));
        }
    }
}
