//! Property tests for object body codecs.
//!
//! Complements `fuzz.rs` (which throws random bytes at parsers and asserts
//! no panic) with structured round-trips: build valid objects by
//! construction, serialize, parse, and assert structural equality. When
//! a property fails, proptest shrinks toward a minimal failing case.

use levcs_core::object::RawObject;
use levcs_core::{
    Blob, Commit, CommitFlags, EntryType, FileMode, ObjectId, Tree, TreeEntry,
};
use proptest::collection::vec;
use proptest::prelude::*;

/// A name that satisfies `TreeEntry::validate_name` — non-empty, ≤255 bytes,
/// no '/' or NUL, not "." or "..". We restrict to ASCII letters/digits/
/// underscore so the proptest generator stays simple and the names are
/// trivially unique-able.
fn name_strategy() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_]{1,32}".prop_filter("reserved", |s| s != "." && s != "..")
}

fn object_id_strategy() -> impl Strategy<Value = ObjectId> {
    any::<[u8; 32]>().prop_map(ObjectId)
}

fn entry_type_strategy() -> impl Strategy<Value = EntryType> {
    prop_oneof![Just(EntryType::Blob), Just(EntryType::Tree)]
}

fn file_mode_strategy() -> impl Strategy<Value = FileMode> {
    (0u8..=0b11).prop_map(FileMode)
}

fn tree_entry_strategy() -> impl Strategy<Value = TreeEntry> {
    (
        name_strategy(),
        entry_type_strategy(),
        file_mode_strategy(),
        object_id_strategy(),
    )
        .prop_map(|(name, entry_type, mode, hash)| TreeEntry {
            name,
            entry_type,
            mode,
            hash,
        })
}

/// Tree with unique-by-name entries (validated trees can't have dupes).
fn tree_strategy() -> impl Strategy<Value = Tree> {
    vec(tree_entry_strategy(), 0..16).prop_map(|entries| {
        // Dedupe by name: keep first occurrence so the property domain
        // matches what `sort_and_validate` accepts.
        let mut seen = std::collections::HashSet::new();
        let unique: Vec<_> = entries
            .into_iter()
            .filter(|e| seen.insert(e.name.clone()))
            .collect();
        let mut t = Tree { entries: unique };
        t.sort_and_validate().unwrap();
        t
    })
}

fn commit_flags_strategy() -> impl Strategy<Value = CommitFlags> {
    (0u8..=0b11).prop_map(CommitFlags)
}

fn commit_strategy() -> impl Strategy<Value = Commit> {
    (
        object_id_strategy(),
        vec(object_id_strategy(), 0..8),
        object_id_strategy(),
        any::<[u8; 32]>(),
        any::<i64>(),
        commit_flags_strategy(),
        ".{0,256}",
    )
        .prop_map(
            |(tree, parents, authority, author_key, ts, flags, message)| Commit {
                tree,
                parents,
                authority,
                author_key,
                timestamp_micros: ts,
                flags,
                message,
            },
        )
}

proptest! {
    /// Tree::body → Tree::parse_body is a structural identity for any
    /// valid tree.
    #[test]
    fn tree_body_roundtrip(t in tree_strategy()) {
        let body = t.body();
        let t2 = Tree::parse_body(&body).expect("valid tree must parse");
        prop_assert_eq!(t.entries.len(), t2.entries.len());
        for (a, b) in t.entries.iter().zip(t2.entries.iter()) {
            prop_assert_eq!(&a.name, &b.name);
            prop_assert_eq!(a.entry_type as u8, b.entry_type as u8);
            prop_assert_eq!(a.mode.0, b.mode.0);
            prop_assert_eq!(a.hash, b.hash);
        }
    }

    /// Commit::body → Commit::parse_body is a structural identity for
    /// any valid commit. Exercises every field including the variable-
    /// length parents list and message.
    #[test]
    fn commit_body_roundtrip(c in commit_strategy()) {
        let body = c.body().expect("valid commit must serialize");
        let c2 = Commit::parse_body(&body).expect("valid commit must parse");
        prop_assert_eq!(c.tree, c2.tree);
        prop_assert_eq!(&c.parents, &c2.parents);
        prop_assert_eq!(c.authority, c2.authority);
        prop_assert_eq!(c.author_key, c2.author_key);
        prop_assert_eq!(c.timestamp_micros, c2.timestamp_micros);
        prop_assert_eq!(c.flags.0, c2.flags.0);
        prop_assert_eq!(c.message, c2.message);
    }

    /// Blob serialize → RawObject::parse → Blob::from_body round-trip.
    /// `Blob::serialize` wraps the bytes in an unsigned object frame, so
    /// the natural inverse is to parse the frame and reconstruct.
    #[test]
    fn blob_roundtrip(bytes in vec(any::<u8>(), 0..16_384)) {
        let blob = Blob::new(bytes.clone());
        let serialized = blob.serialize();
        let raw = RawObject::parse(&serialized).expect("valid blob frame must parse");
        let parsed = Blob::from_body(raw.body);
        prop_assert_eq!(parsed.bytes, bytes);
    }

    /// One-byte truncation of any valid tree body must not panic. The
    /// fuzz suite covers random truncation; this version focuses proptest
    /// shrinkage on the tightest failing case.
    #[test]
    fn tree_body_one_byte_short_does_not_panic(t in tree_strategy()) {
        let body = t.body();
        if !body.is_empty() {
            let short = &body[..body.len() - 1];
            let _ = Tree::parse_body(short);
        }
    }

    /// Same property for commits — truncate the body by one byte and
    /// require the parser to return an error rather than panic.
    #[test]
    fn commit_body_one_byte_short_does_not_panic(c in commit_strategy()) {
        let body = c.body().expect("valid commit must serialize");
        if !body.is_empty() {
            let short = &body[..body.len() - 1];
            let _ = Commit::parse_body(short);
        }
    }
}
