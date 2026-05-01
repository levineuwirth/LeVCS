//! Tree-construction helpers shared by authority-modifying commits and fork
//! commits.

use anyhow::Result;

use levcs_core::object::ObjectType;
use levcs_core::{EntryType, FileMode, ObjectId, Repository, Tree, TreeEntry};

/// Return a new tree ID with the path `.levcs/authority` set to point at the
/// (already-stored) new authority object. Per the v1.1 trust-root revision
/// §3.4.1, the entry's hash equals the authority object's hash.
///
/// `parent_tree_id` is the tree to mirror (e.g., HEAD's tree, or the source
/// commit's tree for a fork). If it is `ZERO_ID`, an empty tree is used.
pub fn put_authority_in_tree(
    repo: &Repository,
    parent_tree_id: ObjectId,
    new_authority_id: ObjectId,
) -> Result<ObjectId> {
    let mut top = if parent_tree_id.is_zero() {
        Tree::default()
    } else {
        let raw = repo.objects.read_typed(parent_tree_id, ObjectType::Tree)?;
        Tree::parse_body(&raw.body)?
    };
    let mut levcs_tree = if let Some(e) = top.find(".levcs") {
        if e.entry_type == EntryType::Tree {
            let raw = repo.objects.read_typed(e.hash, ObjectType::Tree)?;
            Tree::parse_body(&raw.body)?
        } else {
            Tree::default()
        }
    } else {
        Tree::default()
    };
    levcs_tree.entries.retain(|e| e.name != "authority");
    levcs_tree.entries.push(TreeEntry {
        name: "authority".into(),
        entry_type: EntryType::Blob,
        mode: FileMode::REGULAR,
        hash: new_authority_id,
    });
    levcs_tree.sort_and_validate()?;
    let levcs_tree_id = repo.objects.write_raw(&levcs_tree.serialize())?;
    top.entries.retain(|e| e.name != ".levcs");
    top.entries.push(TreeEntry {
        name: ".levcs".into(),
        entry_type: EntryType::Tree,
        mode: FileMode::REGULAR,
        hash: levcs_tree_id,
    });
    top.sort_and_validate()?;
    Ok(repo.objects.write_raw(&top.serialize())?)
}

/// Return a new tree ID with the path `.levcs/merge-record` set to a blob
/// containing the merge metadata TOML (§6.5). Mirrors `put_authority_in_tree`
/// but wraps the bytes in a `Blob` since merge-record is ordinary file
/// content.
pub fn put_merge_record_in_tree(
    repo: &Repository,
    parent_tree_id: ObjectId,
    record_blob_id: ObjectId,
) -> Result<ObjectId> {
    let mut top = if parent_tree_id.is_zero() {
        Tree::default()
    } else {
        let raw = repo.objects.read_typed(parent_tree_id, ObjectType::Tree)?;
        Tree::parse_body(&raw.body)?
    };
    let mut levcs_tree = if let Some(e) = top.find(".levcs") {
        if e.entry_type == EntryType::Tree {
            let raw = repo.objects.read_typed(e.hash, ObjectType::Tree)?;
            Tree::parse_body(&raw.body)?
        } else {
            Tree::default()
        }
    } else {
        Tree::default()
    };
    levcs_tree.entries.retain(|e| e.name != "merge-record");
    levcs_tree.entries.push(TreeEntry {
        name: "merge-record".into(),
        entry_type: EntryType::Blob,
        mode: FileMode::REGULAR,
        hash: record_blob_id,
    });
    levcs_tree.sort_and_validate()?;
    let levcs_tree_id = repo.objects.write_raw(&levcs_tree.serialize())?;
    top.entries.retain(|e| e.name != ".levcs");
    top.entries.push(TreeEntry {
        name: ".levcs".into(),
        entry_type: EntryType::Tree,
        mode: FileMode::REGULAR,
        hash: levcs_tree_id,
    });
    top.sort_and_validate()?;
    Ok(repo.objects.write_raw(&top.serialize())?)
}
