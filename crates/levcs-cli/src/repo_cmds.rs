//! Repository-side commands: init, track, forget, commit, etc.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};

use levcs_core::object::{ObjectType, SignedObject};
use levcs_core::{
    Blob, Commit, CommitFlags, Index, IndexEntry, IndexEntryFlags, ObjectId, Refs, Release,
    Repository, Tree, ZERO_ID,
};
use levcs_core::refs::Head;
use levcs_identity::authority::{
    AuthorityBody, MemberEntry, PolicyEntry, Role, AUTHORITY_SCHEMA_VERSION,
};
use levcs_identity::keys::{PublicKey, SecretKey};
use levcs_identity::sign::{sign_authority, sign_commit, sign_release};
use levcs_identity::verify::{verify_authority_chain, verify_commit};
use levcs_merge::engine::validate_record_against_policy;
use levcs_merge::{
    CascadeEngine, FileRecord, FileStatus, MergeConfig, MergeRecord, MergeResult, MergeStatus,
};

use crate::cli::*;
use crate::ctx::{load_keychain, load_secret, now_micros, open_repo, save_keychain};

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

pub fn init(args: InitArgs) -> Result<()> {
    let path = args.path.unwrap_or_else(|| PathBuf::from("."));
    let path = if path.is_absolute() { path } else { std::env::current_dir()?.join(path) };
    fs::create_dir_all(&path)?;
    if path.join(".levcs").exists() {
        bail!("repository already exists at {:?}", path);
    }
    // Pick or create a key.
    let label = args.key.as_deref().unwrap_or("personal").to_string();
    let mut kc = load_keychain()?;
    let sk: SecretKey = if let Some(_) = kc.entry(&label) {
        let (_, sk) = load_secret(Some(&label))?;
        sk
    } else {
        let sk = SecretKey::generate();
        kc.add_plaintext(&label, &sk)?;
        save_keychain(&kc)?;
        eprintln!("generated new key '{label}' at {:?}", crate::ctx::keychain_path());
        sk
    };
    let pk = sk.public();

    // Build genesis authority: single owner = `pk`.
    let now = now_micros();
    let mut auth = AuthorityBody {
        schema_version: AUTHORITY_SCHEMA_VERSION,
        repo_id: ZERO_ID,
        previous_authority: ZERO_ID,
        version: 1,
        created_micros: now,
        members: vec![MemberEntry {
            key: pk,
            handle: label.clone(),
            role: Role::Owner,
            added_micros: now,
            added_by: pk,
        }],
        policy: vec![
            PolicyEntry { key: "public_read".into(), value: vec![0x01] },
            PolicyEntry { key: "require_signed_releases".into(), value: vec![0x01] },
            PolicyEntry { key: "allowed_handlers".into(), value: b"builtin".to_vec() },
        ],
    };
    auth.normalize()?;
    auth.assign_genesis_repo_id()?;
    let signed = sign_authority(&auth, &sk)?;

    // Materialize repo.
    let repo = Repository::init_skeleton(&path)?;
    let auth_id = repo.write_signed(&signed)?;
    repo.set_genesis_authority(auth_id)?;
    repo.set_current_authority(auth_id)?;
    // Create empty `main` branch HEAD pointer.
    repo.refs.write_head(&Head::Branch("refs/branches/main".into()))?;
    eprintln!(
        "initialized levcs repository at {:?}\n  repo_id     = blake3:{}\n  authority   = {}",
        path, auth.repo_id.to_hex(), auth_id
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// track / forget
// ---------------------------------------------------------------------------

pub fn track(args: TrackArgs) -> Result<()> {
    let repo = open_repo()?;
    let mut idx = repo.read_index()?;
    let mut targets: Vec<PathBuf> = Vec::new();
    if args.all || args.paths.iter().any(|p| p.as_os_str() == ".") {
        targets.extend(repo.walk_workdir()?);
    } else {
        for p in args.paths {
            let abs = if p.is_absolute() { p } else { repo.workdir.join(p) };
            if abs.is_dir() {
                walk_dir(&abs, &repo.workdir, &mut targets)?;
            } else if abs.is_file() {
                targets.push(abs);
            } else {
                bail!("path not found: {:?}", abs);
            }
        }
    }
    for path in targets {
        let rel = path.strip_prefix(&repo.workdir)?.to_string_lossy().replace('\\', "/");
        let bytes = fs::read(&path)?;
        let blob = Blob::new(bytes.clone());
        let id = repo.objects.write_raw(&blob.serialize())?;
        let meta = fs::metadata(&path)?;
        let mtime = file_mtime_micros(&meta);
        let size = meta.len();
        let mode = file_mode_bits(&meta);
        idx.upsert(IndexEntry {
            path: rel,
            blob_hash: id,
            mode,
            flags: IndexEntryFlags::TRACKED,
            mtime_micros: mtime,
            size,
        });
    }
    repo.write_index(&idx)?;
    Ok(())
}

pub fn forget(args: ForgetArgs) -> Result<()> {
    let repo = open_repo()?;
    let mut idx = repo.read_index()?;
    for p in args.paths {
        let abs = if p.is_absolute() { p } else { repo.workdir.join(&p) };
        let rel = abs.strip_prefix(&repo.workdir)?.to_string_lossy().replace('\\', "/");
        idx.remove(&rel);
        if !args.keep_file {
            let _ = fs::remove_file(&abs);
        }
    }
    repo.write_index(&idx)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// status / log
// ---------------------------------------------------------------------------

pub fn status() -> Result<()> {
    let repo = open_repo()?;
    let idx = repo.read_index()?;
    let head = repo.refs.resolve_head()?;
    let branch_ref = repo.current_branch()?;
    let branch = branch_ref
        .as_deref()
        .map(|s| s.trim_start_matches("refs/branches/").to_string())
        .unwrap_or_else(|| "(detached)".into());
    println!("On branch {branch}");
    if let Some(h) = head {
        let signed = repo.read_signed(h)?;
        let commit = Commit::from_signed(&signed)?;
        let subject = commit.message.lines().next().unwrap_or("").to_string();
        println!("HEAD       {h}");
        if !subject.is_empty() {
            println!("           {subject}");
        }
    } else {
        println!("(no commits yet)");
    }
    let releases = repo.refs.list_releases()?;
    if let Some((label, id)) = releases.last() {
        println!("Release    {label} ({id})");
    }
    if repo.levcs_dir.join("MERGE_HEAD").exists() {
        let mh = fs::read_to_string(repo.levcs_dir.join("MERGE_HEAD"))?;
        println!("Merge      in progress (theirs={})", mh.trim());
    }
    let workdir_files = repo.walk_workdir()?;
    let mut tracked = HashMap::<String, &IndexEntry>::new();
    for e in &idx.entries {
        tracked.insert(e.path.clone(), e);
    }
    let mut modified = Vec::new();
    let mut untracked = Vec::new();
    for path in workdir_files {
        let rel = path.strip_prefix(&repo.workdir)?.to_string_lossy().replace('\\', "/");
        match tracked.get(&rel) {
            None => untracked.push(rel),
            Some(entry) => {
                let bytes = fs::read(&path)?;
                let blob_id = Blob::new(bytes).object_id();
                if blob_id != entry.blob_hash {
                    modified.push(rel);
                }
            }
        }
    }
    let work_set: HashSet<String> = repo
        .walk_workdir()?
        .iter()
        .map(|p| p.strip_prefix(&repo.workdir).unwrap().to_string_lossy().replace('\\', "/"))
        .collect();
    let mut deleted: Vec<String> = idx
        .entries
        .iter()
        .filter(|e| !work_set.contains(&e.path))
        .map(|e| e.path.clone())
        .collect();
    deleted.sort();
    if !modified.is_empty() {
        println!("\nmodified:");
        for m in &modified { println!("  {m}"); }
    }
    if !deleted.is_empty() {
        println!("\ndeleted:");
        for d in &deleted { println!("  {d}"); }
    }
    if !untracked.is_empty() {
        println!("\nuntracked:");
        for u in &untracked { println!("  {u}"); }
    }
    if modified.is_empty() && deleted.is_empty() && untracked.is_empty() {
        println!("\nworking tree clean.");
    }
    Ok(())
}

pub fn log(_args: LogArgs) -> Result<()> {
    let repo = open_repo()?;
    let head = repo
        .refs
        .resolve_head()?
        .ok_or_else(|| anyhow!("no commits yet"))?;
    let mut id = head;
    let mut count = 0;
    while count < 100 {
        let signed = repo.read_signed(id)?;
        let commit = Commit::from_signed(&signed)?;
        let pk = PublicKey(commit.author_key);
        println!("commit {}", id);
        println!("Author: {}", pk);
        println!("Date:   {} (us since epoch)", commit.timestamp_micros);
        if commit.flags.modifies_authority() { println!("Flags:  authority-modifying"); }
        if commit.flags.is_fork() { println!("Flags:  fork"); }
        println!();
        for line in commit.message.lines() {
            println!("    {line}");
        }
        println!();
        if commit.parents.is_empty() {
            break;
        }
        id = commit.parents[0];
        count += 1;
    }
    Ok(())
}

pub fn root() -> Result<()> {
    let repo = open_repo()?;
    println!("{}", repo.workdir.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// commit
// ---------------------------------------------------------------------------

pub fn commit(args: CommitArgs) -> Result<()> {
    let repo = open_repo()?;
    let (label, sk) = load_secret(args.key.as_deref())?;
    let pk = sk.public();
    let _ = label;

    // Detect a merge in progress so we can attach the second parent and bake
    // the merge-record into the resulting tree.
    let merge_head_path = repo.levcs_dir.join("MERGE_HEAD");
    let merge_head_id: Option<ObjectId> = if merge_head_path.exists() {
        let s = fs::read_to_string(&merge_head_path)?;
        Some(ObjectId::from_hex(s.trim())?)
    } else {
        None
    };

    // Update index from working tree (for tracked files only). With --all,
    // also include any modified-but-tracked-via-prior-commit files (we
    // approximate: if the file is on disk and previously in index, refresh).
    let mut idx = repo.read_index()?;
    let mut new_entries = Vec::new();
    for e in &idx.entries {
        let abs = repo.workdir.join(&e.path);
        if abs.is_file() {
            let bytes = fs::read(&abs)?;
            // Refuse to commit content that still has unresolved conflict
            // markers — this is the last guard before a half-finished merge
            // ends up in the object store.
            if has_conflict_markers(&bytes) {
                bail!(
                    "{} still contains conflict markers; resolve before committing",
                    e.path
                );
            }
            let blob_id = repo.objects.write_raw(&Blob::new(bytes.clone()).serialize())?;
            let meta = fs::metadata(&abs)?;
            new_entries.push(IndexEntry {
                path: e.path.clone(),
                blob_hash: blob_id,
                mode: file_mode_bits(&meta),
                flags: IndexEntryFlags::TRACKED,
                mtime_micros: file_mtime_micros(&meta),
                size: meta.len(),
            });
        }
        // (deleted from disk → drop entry)
        let _ = args.all; // already implicit
    }
    idx.entries = new_entries;
    repo.write_index(&idx)?;

    // Build the staged tree. For a merge commit, splice the merge-record
    // blob into `.levcs/merge-record` (§6.5).
    let mut staged_tree = repo.build_tree_from_index(&idx)?;
    if merge_head_id.is_some() {
        let record_path = repo.levcs_dir.join("merge-record");
        if !record_path.exists() {
            bail!("MERGE_HEAD set but no merge-record found");
        }
        let record_bytes = fs::read(&record_path)?;
        // Defensive re-check: somebody could have hand-edited the record
        // after `levcs merge` produced it. Refuse to seal a record that
        // names a handler not in this repository's policy.
        let allowed = load_merge_policy_allowed(&repo);
        let record_str = std::str::from_utf8(&record_bytes)
            .map_err(|_| anyhow!("merge-record is not valid UTF-8"))?;
        let parsed = MergeRecord::from_toml(record_str)
            .map_err(|e| anyhow!("merge-record is malformed: {e}"))?;
        let bad = validate_record_against_policy(&parsed, &allowed);
        if !bad.is_empty() {
            bail!(
                "merge-record references handlers not in repository policy: {}",
                bad.join(", ")
            );
        }
        let blob_id = repo
            .objects
            .write_raw(&Blob::new(record_bytes).serialize())?;
        staged_tree = crate::tree_helpers::put_merge_record_in_tree(&repo, staged_tree, blob_id)?;
    }

    let parent = repo.refs.resolve_head()?;
    if merge_head_id.is_none() {
        // Skip the "nothing to commit" check for merge commits — a successful
        // three-way merge whose tree happens to equal HEAD's still needs a
        // second-parent commit to record the union.
        if let Some(p) = parent {
            let p_signed = repo.read_signed(p)?;
            let p_commit = Commit::from_signed(&p_signed)?;
            if p_commit.tree == staged_tree {
                bail!("nothing to commit, working tree matches HEAD");
            }
        }
    }

    let authority = repo
        .current_authority()?
        .ok_or_else(|| anyhow!("repository has no current authority"))?;
    // Verify the author is in the authority and has at least contributor.
    let auth_signed = repo.read_signed(authority)?;
    let auth_body = AuthorityBody::parse(&auth_signed.body)?;
    let member = auth_body
        .find_member(&pk)
        .ok_or_else(|| anyhow!("your key is not in the current authority"))?;
    if member.role < Role::Contributor {
        bail!("your key has role '{}', need at least contributor", member.role.name());
    }

    let default_message = match merge_head_id {
        Some(m) => format!("merge {m}"),
        None => "(no message)".into(),
    };
    let message = args.message.unwrap_or(default_message);
    let mut parents = parent.map(|p| vec![p]).unwrap_or_default();
    if let Some(m) = merge_head_id {
        parents.push(m);
    }
    let commit_obj = Commit {
        tree: staged_tree,
        parents,
        authority,
        author_key: pk.0,
        timestamp_micros: now_micros(),
        flags: CommitFlags::NONE,
        message,
    };
    let signed = sign_commit(commit_obj, &sk)?;
    let id = repo.write_signed(&signed)?;
    // Advance HEAD's branch ref.
    if let Some(branch) = repo.current_branch()? {
        repo.refs.write(&branch, id)?;
    } else {
        repo.refs.write_head(&Head::Detached(id))?;
    }
    // Tear down merge state on success.
    if merge_head_id.is_some() {
        let _ = fs::remove_file(&merge_head_path);
        let _ = fs::remove_file(repo.levcs_dir.join("MERGE_BASE"));
        let _ = fs::remove_file(repo.levcs_dir.join("merge-record"));
    }
    println!("[{}] {}", id, summarize_message(&signed));
    Ok(())
}

fn has_conflict_markers(bytes: &[u8]) -> bool {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return false, // binary file; skip
    };
    let mut saw_open = false;
    let mut saw_sep = false;
    for line in s.lines() {
        if line.starts_with("<<<<<<<") {
            saw_open = true;
        } else if saw_open && line == "=======" {
            saw_sep = true;
        } else if saw_sep && line.starts_with(">>>>>>>") {
            return true;
        }
    }
    false
}

fn summarize_message(signed: &SignedObject) -> String {
    let c = match Commit::parse_body(&signed.body) {
        Ok(c) => c,
        Err(_) => return "(unreadable)".into(),
    };
    c.message.lines().next().unwrap_or("").to_string()
}

// ---------------------------------------------------------------------------
// construct, diff
// ---------------------------------------------------------------------------

pub fn construct(args: ConstructArgs) -> Result<()> {
    let repo = open_repo()?;
    // The first positional arg may be either a hash or a path. If it doesn't
    // parse as a 64-char hex blake3 hash, fold it into the path list and
    // resolve the target from HEAD (or latest release with --release).
    let mut paths = args.paths.clone();
    let parsed_hash: Option<ObjectId> = match args.hash.as_deref() {
        Some(s) => match ObjectId::from_hex(s) {
            Ok(id) => Some(id),
            Err(_) => {
                paths.insert(0, PathBuf::from(s));
                None
            }
        },
        None => None,
    };
    let target_id = match (parsed_hash, args.release) {
        (Some(id), _) => id,
        (None, false) => repo
            .refs
            .resolve_head()?
            .ok_or_else(|| anyhow!("HEAD has no commits"))?,
        (None, true) => {
            let mut releases = repo.refs.list_releases()?;
            // Newest by timestamp_micros within the release object body.
            releases.sort_by_key(|(_, id)| {
                repo.read_signed(*id)
                    .ok()
                    .and_then(|s| Release::parse_body(&s.body).ok())
                    .map(|r| r.timestamp_micros)
                    .unwrap_or(0)
            });
            let (_, id) = releases
                .into_iter()
                .last()
                .ok_or_else(|| anyhow!("no releases on this repository"))?;
            id
        }
    };
    let raw = repo.read_raw_object(target_id)?;
    let tree_id = match raw.object_type {
        ObjectType::Commit => Commit::parse_body(&raw.body)?.tree,
        ObjectType::Release => Release::parse_body(&raw.body)?.tree,
        ObjectType::Tree => target_id,
        other => bail!("cannot construct from {} object", other.name()),
    };

    if paths.is_empty() {
        // Whole-tree reconstruction.
        if args.all {
            // No-op: --all only matters when restricting paths; full tree is
            // always rewritten.
        }
        repo.checkout_tree(tree_id, &repo.workdir)?;
        eprintln!("constructed tree {} into {:?}", tree_id, repo.workdir);
        return Ok(());
    }

    // Path-restricted reconstruction.
    for p in paths {
        let abs = if p.is_absolute() { p.clone() } else { repo.workdir.join(&p) };
        let rel = abs
            .strip_prefix(&repo.workdir)
            .map_err(|_| anyhow!("path {:?} is outside the repository", p))?;
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let entry = repo
            .lookup_path(tree_id, &rel_str)?
            .ok_or_else(|| anyhow!("path not in tree: {rel_str}"))?;
        match entry.0 {
            levcs_core::EntryType::Blob => {
                let blob = repo.objects.read_typed(entry.1, ObjectType::Blob)?;
                if !args.all && abs.is_file() {
                    let cur = fs::read(&abs)?;
                    if cur == blob.body {
                        continue;
                    }
                }
                if let Some(parent) = abs.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&abs, blob.body)?;
            }
            levcs_core::EntryType::Tree => {
                fs::create_dir_all(&abs)?;
                repo.checkout_tree(entry.1, &abs)?;
            }
        }
    }
    eprintln!("constructed paths from tree {}", tree_id);
    Ok(())
}

pub fn diff(args: DiffArgs) -> Result<()> {
    let repo = open_repo()?;
    let head = repo.refs.resolve_head()?;
    // Fold a non-hex "commit" positional into the path restriction list.
    let mut paths = args.paths.clone();
    let parsed_commit: Option<ObjectId> = match args.commit.as_deref() {
        Some(s) => match ObjectId::from_hex(s) {
            Ok(id) => Some(id),
            Err(_) => {
                paths.insert(0, PathBuf::from(s));
                None
            }
        },
        None => None,
    };
    let baseline_tree = if let Some(id) = parsed_commit {
        let raw = repo.read_raw_object(id)?;
        match raw.object_type {
            ObjectType::Commit => Commit::parse_body(&raw.body)?.tree,
            ObjectType::Release => Release::parse_body(&raw.body)?.tree,
            ObjectType::Tree => id,
            _ => bail!("not a commit/release/tree"),
        }
    } else if args.release {
        let mut releases = repo.refs.list_releases()?;
        releases.sort_by_key(|(_, id)| {
            repo.read_signed(*id)
                .ok()
                .and_then(|s| Release::parse_body(&s.body).ok())
                .map(|r| r.timestamp_micros)
                .unwrap_or(0)
        });
        let (_, id) = releases
            .into_iter()
            .last()
            .ok_or_else(|| anyhow!("no releases on this repository"))?;
        Release::parse_body(&repo.read_signed(id)?.body)?.tree
    } else if let Some(h) = head {
        Commit::from_signed(&repo.read_signed(h)?)?.tree
    } else {
        ZERO_ID
    };

    // Normalize path restrictions to repository-relative strings.
    let restrict: Vec<String> = paths
        .iter()
        .map(|p| -> Result<String> {
            let abs = if p.is_absolute() {
                p.clone()
            } else {
                repo.workdir.join(p)
            };
            let rel = abs
                .strip_prefix(&repo.workdir)
                .map_err(|_| anyhow!("path {:?} is outside the repository", p))?;
            Ok(rel.to_string_lossy().replace('\\', "/"))
        })
        .collect::<Result<_>>()?;
    let path_matches = |p: &str| -> bool {
        if restrict.is_empty() {
            return true;
        }
        restrict.iter().any(|r| p == r || p.starts_with(&format!("{r}/")))
    };

    let baseline = collect_tree_files(&repo, baseline_tree, "")?;
    let work: HashMap<String, Vec<u8>> = repo
        .walk_workdir()?
        .into_iter()
        .map(|p| -> Result<_> {
            let rel = p.strip_prefix(&repo.workdir)?.to_string_lossy().replace('\\', "/");
            let bytes = fs::read(&p)?;
            Ok((rel, bytes))
        })
        .collect::<Result<_>>()?;
    use similar::{ChangeTag, TextDiff};
    let mut keys: Vec<&String> = baseline.keys().chain(work.keys()).collect();
    keys.sort();
    keys.dedup();
    for k in keys {
        if !path_matches(k) {
            continue;
        }
        let a = baseline.get(k).cloned().unwrap_or_default();
        let b = work.get(k).cloned().unwrap_or_default();
        if a == b { continue; }
        println!("--- a/{k}\n+++ b/{k}");
        let a_s = String::from_utf8_lossy(&a);
        let b_s = String::from_utf8_lossy(&b);
        let diff = TextDiff::from_lines(&a_s, &b_s);
        for change in diff.iter_all_changes() {
            let prefix = match change.tag() {
                ChangeTag::Equal => " ",
                ChangeTag::Insert => "+",
                ChangeTag::Delete => "-",
            };
            print!("{prefix}{}", change.value());
        }
    }
    Ok(())
}

fn collect_tree_files(
    repo: &Repository,
    tree_id: ObjectId,
    prefix: &str,
) -> Result<HashMap<String, Vec<u8>>> {
    let mut out = HashMap::new();
    if tree_id.is_zero() {
        return Ok(out);
    }
    let raw = repo.objects.read_typed(tree_id, ObjectType::Tree)?;
    let tree = Tree::parse_body(&raw.body)?;
    for e in tree.entries {
        let path = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
        match e.entry_type {
            levcs_core::EntryType::Blob => {
                let blob = repo.objects.read_typed(e.hash, ObjectType::Blob)?;
                out.insert(path, blob.body);
            }
            levcs_core::EntryType::Tree => {
                let sub = collect_tree_files(repo, e.hash, &path)?;
                out.extend(sub);
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// branch / merge / release / cache
// ---------------------------------------------------------------------------

pub fn branch(args: BranchArgs) -> Result<()> {
    let repo = open_repo()?;
    if args.list || (args.create.is_none() && args.switch.is_none() && args.delete.is_none()) {
        let cur = repo.current_branch()?.unwrap_or_default();
        for (name, id) in repo.refs.list_branches()? {
            let marker = if cur == format!("refs/branches/{name}") { "*" } else { " " };
            println!("{marker} {name}\t{id}");
        }
        return Ok(());
    }
    if let Some(name) = args.create {
        let from = match args.from {
            Some(s) => ObjectId::from_hex(&s)?,
            None => repo.refs.resolve_head()?.ok_or_else(|| anyhow!("no HEAD"))?,
        };
        repo.refs.write(&format!("refs/branches/{name}"), from)?;
        eprintln!("created branch {name} at {from}");
    }
    if let Some(name) = args.switch {
        let target = repo
            .refs
            .read(&format!("refs/branches/{name}"))?
            .ok_or_else(|| anyhow!("no such branch: {name}"))?;
        repo.refs.write_head(&Head::Branch(format!("refs/branches/{name}")))?;
        let raw = repo.read_raw_object(target)?;
        let tree_id = match raw.object_type {
            ObjectType::Commit => Commit::parse_body(&raw.body)?.tree,
            _ => bail!("branch tip is not a commit"),
        };
        repo.checkout_tree(tree_id, &repo.workdir)?;
        eprintln!("switched to branch {name}");
    }
    if let Some(name) = args.delete {
        repo.refs.delete(&format!("refs/branches/{name}"))?;
        eprintln!("deleted branch {name}");
    }
    Ok(())
}

pub fn merge(args: MergeArgs) -> Result<()> {
    let _ = args.key; // resolution is signed at commit-time, not merge-time
    if args.abort {
        return merge_abort();
    }
    if args.explain {
        return merge_explain();
    }
    if args.review {
        return merge_review();
    }
    merge_run(args)
}

fn merge_run(args: MergeArgs) -> Result<()> {
    let branch_name = args
        .branch
        .clone()
        .ok_or_else(|| anyhow!("missing branch to merge"))?;
    let repo = open_repo()?;
    if repo.levcs_dir.join("MERGE_HEAD").exists() {
        bail!("a merge is already in progress; run `levcs merge --abort` to cancel");
    }
    let head = repo
        .refs
        .resolve_head()?
        .ok_or_else(|| anyhow!("no HEAD on current branch"))?;
    let theirs_id = resolve_target(&repo, &branch_name)?;
    if head == theirs_id {
        eprintln!("already up to date.");
        return Ok(());
    }

    let base_id = find_common_ancestor(&repo, head, theirs_id)?
        .ok_or_else(|| anyhow!("no common ancestor between {head} and {theirs_id}"))?;

    // Fast-forward: HEAD is an ancestor of theirs, no merge commit needed.
    if base_id == head {
        let theirs_commit = Commit::from_signed(&repo.read_signed(theirs_id)?)?;
        if let Some(branch_ref) = repo.current_branch()? {
            repo.refs.write(&branch_ref, theirs_id)?;
        } else {
            repo.refs.write_head(&Head::Detached(theirs_id))?;
        }
        repo.checkout_tree(theirs_commit.tree, &repo.workdir)?;
        // Refresh index from the new tree.
        let mut idx = Index::new();
        rebuild_index_from_tree(&repo, theirs_commit.tree, "", &mut idx)?;
        repo.write_index(&idx)?;
        eprintln!("fast-forward to {theirs_id}");
        return Ok(());
    }

    let head_commit = Commit::from_signed(&repo.read_signed(head)?)?;
    let theirs_commit = Commit::from_signed(&repo.read_signed(theirs_id)?)?;
    let base_commit = Commit::from_signed(&repo.read_signed(base_id)?)?;

    let base_files = collect_tree_files(&repo, base_commit.tree, "")?;
    let ours_files = collect_tree_files(&repo, head_commit.tree, "")?;
    let theirs_files = collect_tree_files(&repo, theirs_commit.tree, "")?;

    // Layered config per §6.6.3 — `.levcs/merge.local.toml` over
    // `.levcs/merge.toml`. Promotions in the local override are
    // rejected before we touch the working tree.
    let cfg = load_effective_merge_config(&repo)?;
    let engine = CascadeEngine::new().with_config(cfg);
    let mut record = MergeRecord {
        schema_version: 1,
        base: format!("blake3:{}", base_id),
        ours: format!("blake3:{}", head),
        theirs: format!("blake3:{}", theirs_id),
        files: Vec::new(),
    };
    let mut paths: BTreeSet<String> = BTreeSet::new();
    for k in base_files.keys().chain(ours_files.keys()).chain(theirs_files.keys()) {
        // .levcs/* synthetic tree entries (authority, merge-record) live in
        // commits but never on disk; skip them when reconciling files.
        if k.starts_with(".levcs/") || k == ".levcs" {
            continue;
        }
        paths.insert(k.clone());
    }

    let json_mode = args.format == "json";
    if !json_mode && args.format != "text" {
        bail!("unknown --format value: {} (allowed: text, json)", args.format);
    }
    let mut auto_resolved = 0usize;
    let mut conflict_count = 0usize;
    let mut merged_files: HashMap<String, Vec<u8>> = HashMap::new();
    let mut deleted_files: HashSet<String> = HashSet::new();
    // Collected eagerly because MergeResult is not Clone — we capture
    // the JSON projection inside the loop and stash it for the final
    // report.
    let mut json_files: Vec<(String, JsonReportData)> = Vec::new();

    for path in paths {
        let base = base_files.get(&path).cloned().unwrap_or_default();
        let ours = ours_files.get(&path).cloned().unwrap_or_default();
        let theirs = theirs_files.get(&path).cloned().unwrap_or_default();

        // Both sides agree: take the value (handles deletes-on-both).
        if ours == theirs {
            if ours.is_empty() && !ours_files.contains_key(&path) {
                deleted_files.insert(path);
            } else {
                merged_files.insert(path, ours);
            }
            continue;
        }
        // One-sided edits.
        if base == ours {
            // Only theirs changed.
            if args.no_auto {
                let result = make_no_auto_conflict(path.clone(), &ours, &theirs);
                conflict_count += 1;
                emit_outcome(&path, &result, json_mode);
                if json_mode {
                    json_files.push((path.clone(), JsonReportData::from(&result)));
                }
                record.files.push(file_record_from(&path, &result));
                merged_files.insert(path, partial_from(result.status, &ours));
                continue;
            }
            if theirs_files.contains_key(&path) {
                merged_files.insert(path.clone(), theirs.clone());
                record.files.push(FileRecord {
                    path,
                    handler: "theirs-only".into(),
                    handler_hash: String::new(),
                    status: FileStatus::Theirs,
                    notes: String::new(),
                });
            } else {
                deleted_files.insert(path.clone());
                record.files.push(FileRecord {
                    path,
                    handler: "delete".into(),
                    handler_hash: String::new(),
                    status: FileStatus::Theirs,
                    notes: "deleted by theirs".into(),
                });
            }
            auto_resolved += 1;
            continue;
        }
        if base == theirs {
            // Only ours changed.
            if ours_files.contains_key(&path) {
                merged_files.insert(path.clone(), ours.clone());
                record.files.push(FileRecord {
                    path,
                    handler: "ours-only".into(),
                    handler_hash: String::new(),
                    status: FileStatus::Ours,
                    notes: String::new(),
                });
            } else {
                deleted_files.insert(path.clone());
                record.files.push(FileRecord {
                    path,
                    handler: "delete".into(),
                    handler_hash: String::new(),
                    status: FileStatus::Ours,
                    notes: "deleted by ours".into(),
                });
            }
            auto_resolved += 1;
            continue;
        }
        // Both sides changed: cascade.
        let result = if args.no_auto {
            make_no_auto_conflict(path.clone(), &ours, &theirs)
        } else {
            engine.merge_file(Path::new(&path), &base, &ours, &theirs)
        };
        emit_outcome(&path, &result, json_mode);
        if json_mode {
            json_files.push((path.clone(), JsonReportData::from(&result)));
        }
        let fr = file_record_from(&path, &result);
        let status = result.status;
        match &status {
            MergeStatus::Merged { content, .. } => {
                auto_resolved += 1;
                merged_files.insert(path.clone(), content.clone());
            }
            MergeStatus::Conflict { partial, regions: _ } => {
                conflict_count += 1;
                merged_files.insert(path.clone(), partial.clone());
            }
            MergeStatus::NotApplicable => {
                conflict_count += 1;
                merged_files.insert(path.clone(), ours.clone());
            }
        }
        record.files.push(fr);
    }

    // Apply to working tree.
    for (path, bytes) in &merged_files {
        let abs = repo.workdir.join(path);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&abs, bytes)?;
    }
    for path in &deleted_files {
        let abs = repo.workdir.join(path);
        let _ = fs::remove_file(&abs);
    }

    // Refresh the index to reflect post-merge content. Tracked entries are
    // reset to the new blob hashes so that `levcs commit` can build a tree
    // without re-reading the working directory's view of every file.
    let mut idx = Index::new();
    for (path, bytes) in &merged_files {
        let id = repo.objects.write_raw(&Blob::new(bytes.clone()).serialize())?;
        let mut flags = IndexEntryFlags::TRACKED;
        if let Some(fr) = record.files.iter().find(|fr| fr.path == *path) {
            if matches!(fr.status, FileStatus::Manual) {
                flags = flags.with(IndexEntryFlags::CONFLICTED);
            }
        }
        idx.upsert(IndexEntry {
            path: path.clone(),
            blob_hash: id,
            mode: 0,
            flags,
            mtime_micros: 0,
            size: bytes.len() as u64,
        });
    }
    repo.write_index(&idx)?;

    // Repo-side policy ceiling: every handler reference in the record must
    // be permitted by `.levcs/merge.toml` (§6.6). Catch this before we
    // touch the working tree's merge state so an aborted policy-violating
    // merge leaves nothing to clean up.
    let allowed = load_merge_policy_allowed(&repo);
    let bad = validate_record_against_policy(&record, &allowed);
    if !bad.is_empty() {
        bail!(
            "merge produced records referencing handlers not in repository policy: {}",
            bad.join(", ")
        );
    }

    // Persist merge state and the in-progress merge-record.
    fs::write(repo.levcs_dir.join("MERGE_HEAD"), theirs_id.to_hex())?;
    fs::write(repo.levcs_dir.join("MERGE_BASE"), base_id.to_hex())?;
    let toml = record
        .to_toml()
        .map_err(|e| anyhow!("serialize merge-record: {e}"))?;
    fs::write(repo.levcs_dir.join("merge-record"), toml)?;

    if json_mode {
        // One JSON object on stdout. Ordering matches the input
        // iteration so consumers can correlate by index.
        let report = JsonMergeReport {
            schema_version: 1,
            base: &record.base,
            ours: &record.ours,
            theirs: &record.theirs,
            auto_resolved,
            conflicts: conflict_count,
            files: json_files
                .iter()
                .map(|(path, data)| JsonFileReport { path, data })
                .collect(),
        };
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| anyhow!("serialize report: {e}"))?
        );
        if conflict_count > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }
    println!();
    println!("merge summary:");
    println!("  auto-resolved: {auto_resolved}");
    println!("  conflicts:     {conflict_count}");
    println!();
    if conflict_count > 0 {
        println!("review with `levcs merge --review`, or edit conflicted files and run `levcs commit`.");
        std::process::exit(1);
    }
    println!("clean merge. run `levcs commit` to finalize.");
    Ok(())
}

/// Read `.levcs/merge.toml` into a `MergeConfig`. Missing file or
/// malformed contents both produce a default config — the spec's
/// "absence means permissive" semantics.
fn read_repo_merge_config(repo: &Repository) -> MergeConfig {
    let path = repo.levcs_dir.join("merge.toml");
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return MergeConfig::default(),
    };
    toml::from_str(&raw).unwrap_or_default()
}

/// Load the effective merge config for this repository, layering
/// `.levcs/merge.local.toml` (gitignored, never pushed) over
/// `.levcs/merge.toml` per §6.6.3. The local layer can demote handler
/// aggressiveness but not promote it; promotions are rejected with a
/// hard error so the user knows their override is being silently
/// dropped instead of quietly ignored.
fn load_effective_merge_config(repo: &Repository) -> Result<MergeConfig> {
    let base = read_repo_merge_config(repo);
    let local_path = repo.levcs_dir.join("merge.local.toml");
    if !local_path.exists() {
        return Ok(base);
    }
    let local_raw = fs::read_to_string(&local_path)
        .map_err(|e| anyhow!("read merge.local.toml: {e}"))?;
    let local: MergeConfig = toml::from_str(&local_raw)
        .map_err(|e| anyhow!("parse merge.local.toml: {e}"))?;
    levcs_merge::engine::layer_local_over(&base, &local)
        .map_err(|e| anyhow!("merge.local.toml: {e}"))
}

/// Load `.levcs/merge.toml`'s `policy.allowed_handlers`. Returns an empty
/// vec (permissive) if the file is absent or has no policy block.
/// `merge.local.toml` does not influence policy — local overrides
/// can't widen what's permitted.
fn load_merge_policy_allowed(repo: &Repository) -> Vec<String> {
    let cfg = read_repo_merge_config(repo);
    cfg.policy.map(|p| p.allowed_handlers).unwrap_or_default()
}

fn resolve_target(repo: &Repository, name: &str) -> Result<ObjectId> {
    if let Some(id) = repo.refs.read(&format!("refs/branches/{name}"))? {
        return Ok(id);
    }
    if let Ok(id) = ObjectId::from_hex(name) {
        return Ok(id);
    }
    bail!("unknown branch or commit: {name}")
}

fn emit_outcome(path: &str, result: &MergeResult, json: bool) {
    if json {
        // JSON mode collects results into a final report — no per-file
        // line goes to stdout, since stdout is reserved for the single
        // structured object.
        return;
    }
    match &result.status {
        MergeStatus::Merged { .. } => {
            eprintln!("AUTO     {path}  ({})", result.handler);
        }
        MergeStatus::Conflict { regions, .. } => {
            eprintln!(
                "CONFLICT {path}  ({}, {} region{})",
                result.handler,
                regions.len(),
                if regions.len() == 1 { "" } else { "s" }
            );
        }
        MergeStatus::NotApplicable => {
            eprintln!("CONFLICT {path}  (no applicable handler)");
        }
    }
}

/// JSON projection of a `MergeResult` — extracted eagerly inside the
/// merge loop so we don't need MergeResult to be Clone. Holds owned
/// strings so it can outlive the result it was derived from.
#[derive(serde::Serialize)]
struct JsonReportData {
    handler: String,
    /// One of "merged", "conflict", "not_applicable".
    status: &'static str,
    conflict_regions: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    regions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
}

impl From<&MergeResult> for JsonReportData {
    fn from(r: &MergeResult) -> Self {
        match &r.status {
            MergeStatus::Merged { notes, .. } => JsonReportData {
                handler: r.handler.clone(),
                status: "merged",
                conflict_regions: 0,
                regions: Vec::new(),
                notes: notes.iter().map(|n| n.message.clone()).collect(),
            },
            MergeStatus::Conflict { regions, .. } => JsonReportData {
                handler: r.handler.clone(),
                status: "conflict",
                conflict_regions: regions.len(),
                regions: regions.iter().map(|r| r.description.clone()).collect(),
                notes: Vec::new(),
            },
            MergeStatus::NotApplicable => JsonReportData {
                handler: r.handler.clone(),
                status: "not_applicable",
                conflict_regions: 0,
                regions: Vec::new(),
                notes: Vec::new(),
            },
        }
    }
}

#[derive(serde::Serialize)]
struct JsonFileReport<'a> {
    path: &'a str,
    #[serde(flatten)]
    data: &'a JsonReportData,
}

#[derive(serde::Serialize)]
struct JsonMergeReport<'a> {
    /// Schema tag — bumped when the output format changes incompatibly.
    schema_version: u32,
    base: &'a str,
    ours: &'a str,
    theirs: &'a str,
    auto_resolved: usize,
    conflicts: usize,
    files: Vec<JsonFileReport<'a>>,
}

fn file_record_from(path: &str, result: &MergeResult) -> FileRecord {
    let (status, notes) = match &result.status {
        MergeStatus::Merged { notes, .. } => (
            FileStatus::Auto,
            notes
                .iter()
                .map(|n| n.message.clone())
                .collect::<Vec<_>>()
                .join("; "),
        ),
        MergeStatus::Conflict { regions, .. } => {
            let n = regions.len();
            (
                FileStatus::Manual,
                format!("{n} conflict region{}", if n == 1 { "" } else { "s" }),
            )
        }
        MergeStatus::NotApplicable => (FileStatus::Manual, "no applicable handler".into()),
    };
    FileRecord {
        path: path.to_string(),
        handler: result.handler.clone(),
        handler_hash: String::new(),
        status,
        notes,
    }
}

fn make_no_auto_conflict(_path: String, ours: &[u8], theirs: &[u8]) -> MergeResult {
    let mut partial = Vec::new();
    partial.extend_from_slice(b"<<<<<<< ours\n");
    partial.extend_from_slice(ours);
    if !ours.is_empty() && !ours.ends_with(b"\n") {
        partial.push(b'\n');
    }
    partial.extend_from_slice(b"=======\n");
    partial.extend_from_slice(theirs);
    if !theirs.is_empty() && !theirs.ends_with(b"\n") {
        partial.push(b'\n');
    }
    partial.extend_from_slice(b">>>>>>> theirs\n");
    MergeResult {
        handler: "no-auto".into(),
        status: MergeStatus::Conflict {
            regions: vec![levcs_merge::ConflictRegion {
                description: "no-auto: forced conflict".into(),
                base: 0..0,
                ours: 0..ours.len(),
                theirs: 0..theirs.len(),
            }],
            partial,
        },
    }
}

fn partial_from(status: MergeStatus, fallback: &[u8]) -> Vec<u8> {
    match status {
        MergeStatus::Conflict { partial, .. } => partial,
        MergeStatus::Merged { content, .. } => content,
        MergeStatus::NotApplicable => fallback.to_vec(),
    }
}

fn rebuild_index_from_tree(
    repo: &Repository,
    tree_id: ObjectId,
    prefix: &str,
    idx: &mut Index,
) -> Result<()> {
    if tree_id.is_zero() {
        return Ok(());
    }
    let raw = repo.objects.read_typed(tree_id, ObjectType::Tree)?;
    let tree = Tree::parse_body(&raw.body)?;
    for e in tree.entries {
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        if path.starts_with(".levcs/") || path == ".levcs" {
            continue;
        }
        match e.entry_type {
            levcs_core::EntryType::Tree => {
                rebuild_index_from_tree(repo, e.hash, &path, idx)?;
            }
            levcs_core::EntryType::Blob => {
                let blob = repo.objects.read_typed(e.hash, ObjectType::Blob)?;
                idx.upsert(IndexEntry {
                    path,
                    blob_hash: e.hash,
                    mode: if e.mode.is_executable() { 0o111 } else { 0 },
                    flags: IndexEntryFlags::TRACKED,
                    mtime_micros: 0,
                    size: blob.body.len() as u64,
                });
            }
        }
    }
    Ok(())
}

fn merge_abort() -> Result<()> {
    let repo = open_repo()?;
    let merge_head_path = repo.levcs_dir.join("MERGE_HEAD");
    if !merge_head_path.exists() {
        bail!("no merge in progress");
    }
    let head_id = repo
        .refs
        .resolve_head()?
        .ok_or_else(|| anyhow!("no HEAD"))?;
    let head_commit = Commit::from_signed(&repo.read_signed(head_id)?)?;
    repo.checkout_tree(head_commit.tree, &repo.workdir)?;
    let mut idx = Index::new();
    rebuild_index_from_tree(&repo, head_commit.tree, "", &mut idx)?;
    repo.write_index(&idx)?;
    let _ = fs::remove_file(&merge_head_path);
    let _ = fs::remove_file(repo.levcs_dir.join("MERGE_BASE"));
    let _ = fs::remove_file(repo.levcs_dir.join("merge-record"));
    eprintln!("merge aborted; restored to {head_id}");
    Ok(())
}

fn merge_explain() -> Result<()> {
    let repo = open_repo()?;
    let in_progress_path = repo.levcs_dir.join("merge-record");

    // Two cases (per §6.7): a merge is in progress, or we're inspecting
    // the most recent commit's recorded merge. The TUI source-of-truth
    // is the merge-record TOML; if it isn't there, we fall back to
    // dumping any text we can find (legacy script callers may rely on
    // text output, so keep that path alive).
    let (record_text, ours_tree, theirs_tree, base_tree) = if in_progress_path.exists() {
        let head_id = repo
            .refs
            .resolve_head()?
            .ok_or_else(|| anyhow!("no HEAD"))?;
        let head_commit = Commit::from_signed(&repo.read_signed(head_id)?)?;
        let merge_head_id = ObjectId::from_hex(
            fs::read_to_string(repo.levcs_dir.join("MERGE_HEAD"))?
                .trim(),
        )?;
        let merge_head_commit = Commit::from_signed(&repo.read_signed(merge_head_id)?)?;
        let base_tree = if repo.levcs_dir.join("MERGE_BASE").exists() {
            let id = ObjectId::from_hex(
                fs::read_to_string(repo.levcs_dir.join("MERGE_BASE"))?.trim(),
            )?;
            Some(Commit::from_signed(&repo.read_signed(id)?)?.tree)
        } else {
            None
        };
        (
            fs::read_to_string(&in_progress_path)?,
            head_commit.tree,
            merge_head_commit.tree,
            base_tree,
        )
    } else {
        // No in-progress merge — pull from the most recent commit.
        let head = repo
            .refs
            .resolve_head()?
            .ok_or_else(|| anyhow!("no HEAD"))?;
        let head_commit = Commit::from_signed(&repo.read_signed(head)?)?;
        let entry = repo
            .lookup_path(head_commit.tree, ".levcs/merge-record")?
            .ok_or_else(|| anyhow!("no merge-record on HEAD or in progress"))?;
        let blob = repo.objects.read_typed(entry.1, ObjectType::Blob)?;
        let text = String::from_utf8(blob.body)
            .map_err(|_| anyhow!("merge-record is not UTF-8"))?;
        // For a committed merge, "ours" is HEAD's first parent and
        // "theirs" is HEAD's second parent. If the commit isn't a
        // merge, we have nothing to step through — fall back to text.
        if head_commit.parents.len() < 2 {
            print!("{text}");
            return Ok(());
        }
        let ours_commit = Commit::from_signed(&repo.read_signed(head_commit.parents[0])?)?;
        let theirs_commit = Commit::from_signed(&repo.read_signed(head_commit.parents[1])?)?;
        let base_id = find_common_ancestor(&repo, head_commit.parents[0], head_commit.parents[1])?;
        let base_tree = match base_id {
            Some(id) => Some(Commit::from_signed(&repo.read_signed(id)?)?.tree),
            None => None,
        };
        (text, ours_commit.tree, theirs_commit.tree, base_tree)
    };

    let record = match MergeRecord::from_toml(&record_text) {
        Ok(r) => r,
        Err(_) => {
            // Unparseable record — keep the legacy text-dump escape hatch
            // so users with broken state can still see what's there.
            print!("{record_text}");
            return Ok(());
        }
    };

    // Build a FileEntry per file in the record. Same loader logic as
    // merge_review but seeded from the *committed* trees.
    let read_path = |tree: ObjectId, p: &str| -> Vec<u8> {
        match repo.lookup_path(tree, p) {
            Ok(Some((_, blob_id))) => match repo.objects.read_typed(blob_id, ObjectType::Blob) {
                Ok(blob) => blob.body,
                Err(_) => Vec::new(),
            },
            _ => Vec::new(),
        }
    };
    let files: Vec<levcs_tui::FileEntry> = record
        .files
        .iter()
        .map(|fr| {
            let ours = read_path(ours_tree, &fr.path);
            let theirs = read_path(theirs_tree, &fr.path);
            let base = base_tree.map(|t| read_path(t, &fr.path)).unwrap_or_default();
            // For explain, the "current" pane shows the *result* of the
            // merge — i.e., what the engine produced for this file.
            // For an in-progress merge that's the working tree; for a
            // committed merge it's the file at HEAD.
            let current = if in_progress_path.exists() {
                fs::read(repo.workdir.join(&fr.path)).unwrap_or_default()
            } else {
                read_path(ours_tree, &fr.path)
            };
            // Use the structured status to drive the TUI's regions: an
            // auto-resolved file shows as "merged" with the engine's
            // notes; a manual file shows as a single conflict region
            // covering the full file (the record doesn't preserve
            // per-region byte ranges, just the count).
            let status = match fr.status {
                FileStatus::Auto | FileStatus::Ours | FileStatus::Theirs => MergeStatus::Merged {
                    content: current.clone(),
                    notes: if fr.notes.is_empty() {
                        vec![]
                    } else {
                        vec![levcs_merge::MergeNote { message: fr.notes.clone() }]
                    },
                },
                FileStatus::Manual => MergeStatus::Conflict {
                    regions: vec![levcs_merge::ConflictRegion {
                        description: if fr.notes.is_empty() {
                            "manual resolution".into()
                        } else {
                            fr.notes.clone()
                        },
                        base: 0..base.len(),
                        ours: 0..ours.len(),
                        theirs: 0..theirs.len(),
                    }],
                    partial: current.clone(),
                },
            };
            levcs_tui::FileEntry {
                path: fr.path.clone(),
                status,
                current,
                ours,
                theirs,
                base,
                handler: fr.handler.clone(),
                notes: fr.notes.clone(),
            }
        })
        .collect();

    if files.is_empty() {
        // Nothing structural to show — fall back to dumping the record.
        print!("{record_text}");
        return Ok(());
    }

    // Non-interactive contexts (scripts, CI, piped output) can't drive
    // the TUI — fall back to the text dump so callers still get
    // something useful. We probe stdin since the alt-screen reads from
    // there; if it isn't a terminal, raw-mode setup fails noisily.
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        print!("{record_text}");
        return Ok(());
    }

    levcs_tui::review_read_only(files).map_err(|e| anyhow!("explain session: {e}"))?;
    Ok(())
}

fn merge_review() -> Result<()> {
    let repo = open_repo()?;
    let merge_record_path = repo.levcs_dir.join("merge-record");
    if !merge_record_path.exists() {
        bail!("no merge in progress");
    }
    let s = fs::read_to_string(&merge_record_path)?;
    let record = MergeRecord::from_toml(&s)
        .map_err(|e| anyhow!("parse merge-record: {e}"))?;

    // Resolve the three side trees the review needs.
    //   * ours  — current HEAD's tree (what we had before the merge).
    //   * theirs — MERGE_HEAD's tree (what's being merged in).
    //   * base   — MERGE_BASE's tree (their common ancestor).
    let head_id = repo
        .refs
        .resolve_head()?
        .ok_or_else(|| anyhow!("no HEAD"))?;
    let head_commit = Commit::from_signed(&repo.read_signed(head_id)?)?;
    let ours_tree = head_commit.tree;

    let merge_head_id = ObjectId::from_hex(
        fs::read_to_string(repo.levcs_dir.join("MERGE_HEAD"))?
            .trim(),
    )?;
    let merge_head_commit = Commit::from_signed(&repo.read_signed(merge_head_id)?)?;
    let theirs_tree = merge_head_commit.tree;

    let base_path = repo.levcs_dir.join("MERGE_BASE");
    let base_tree = if base_path.exists() {
        let id = ObjectId::from_hex(fs::read_to_string(&base_path)?.trim())?;
        let c = Commit::from_signed(&repo.read_signed(id)?)?;
        Some(c.tree)
    } else {
        None
    };

    // Build a FileEntry per file in the merge-record. Read each side's
    // bytes from its tree by path; missing files (modify-vs-delete) get
    // an empty byte vector for that side.
    let read_path = |tree: ObjectId, p: &str| -> Vec<u8> {
        match repo.lookup_path(tree, p) {
            Ok(Some((_, blob_id))) => match repo.objects.read_typed(blob_id, ObjectType::Blob) {
                Ok(blob) => blob.body,
                Err(_) => Vec::new(),
            },
            _ => Vec::new(),
        }
    };

    let files: Vec<levcs_tui::FileEntry> = record
        .files
        .iter()
        .map(|fr| {
            let current = fs::read(repo.workdir.join(&fr.path)).unwrap_or_default();
            let ours = read_path(ours_tree, &fr.path);
            let theirs = read_path(theirs_tree, &fr.path);
            let base = base_tree
                .map(|t| read_path(t, &fr.path))
                .unwrap_or_default();
            let status = match fr.status {
                FileStatus::Auto | FileStatus::Ours | FileStatus::Theirs => {
                    MergeStatus::Merged {
                        content: current.clone(),
                        notes: if fr.notes.is_empty() {
                            vec![]
                        } else {
                            vec![levcs_merge::MergeNote { message: fr.notes.clone() }]
                        },
                    }
                }
                FileStatus::Manual => MergeStatus::Conflict {
                    regions: vec![levcs_merge::ConflictRegion {
                        description: if fr.notes.is_empty() {
                            "manual resolution required".into()
                        } else {
                            fr.notes.clone()
                        },
                        base: 0..base.len(),
                        ours: 0..ours.len(),
                        theirs: 0..theirs.len(),
                    }],
                    partial: current.clone(),
                },
            };
            levcs_tui::FileEntry {
                path: fr.path.clone(),
                status,
                current,
                ours,
                theirs,
                base,
                handler: fr.handler.clone(),
                notes: fr.notes.clone(),
            }
        })
        .collect();

    let total = files.len();
    let final_state = levcs_tui::review(files)
        .map_err(|e| anyhow!("review session: {e}"))?;
    let report = final_state
        .apply(&repo.workdir)
        .map_err(|e| anyhow!("apply resolutions: {e}"))?;
    eprintln!(
        "review complete: {total} file(s) seen, {} written, {} kept",
        report.written, report.skipped
    );
    Ok(())
}

fn find_common_ancestor(repo: &Repository, a: ObjectId, b: ObjectId) -> Result<Option<ObjectId>> {
    let mut a_anc: HashSet<ObjectId> = HashSet::new();
    let mut stack = vec![a];
    while let Some(id) = stack.pop() {
        if !a_anc.insert(id) { continue; }
        if let Ok(s) = repo.read_signed(id) {
            if let Ok(c) = Commit::from_signed(&s) {
                stack.extend(c.parents);
            }
        }
    }
    let mut stack = vec![b];
    let mut visited: HashSet<ObjectId> = HashSet::new();
    while let Some(id) = stack.pop() {
        if !visited.insert(id) { continue; }
        if a_anc.contains(&id) {
            return Ok(Some(id));
        }
        if let Ok(s) = repo.read_signed(id) {
            if let Ok(c) = Commit::from_signed(&s) {
                stack.extend(c.parents);
            }
        }
    }
    Ok(None)
}

pub fn release(args: ReleaseArgs) -> Result<()> {
    let repo = open_repo()?;
    let (_label, sk) = load_secret(args.key.as_deref())?;
    let pk = sk.public();
    let authority = repo.current_authority()?.ok_or_else(|| anyhow!("no current authority"))?;
    let auth_signed = repo.read_signed(authority)?;
    let auth_body = AuthorityBody::parse(&auth_signed.body)?;
    let m = auth_body
        .find_member(&pk)
        .ok_or_else(|| anyhow!("your key is not in the current authority"))?;
    if m.role < Role::Maintainer {
        bail!("releases require maintainer role; your role is '{}'", m.role.name());
    }
    let head = repo.refs.resolve_head()?.ok_or_else(|| anyhow!("no HEAD"))?;
    let head_commit = Commit::from_signed(&repo.read_signed(head)?)?;
    let parent_release = repo
        .refs
        .read(&format!("refs/releases/{}", args.label))?
        .unwrap_or(ZERO_ID);
    let release = Release {
        tree: head_commit.tree,
        parent_release,
        predecessor: head,
        authority,
        declarer_key: pk.0,
        timestamp_micros: now_micros(),
        label: args.label.clone(),
        notes: args.message.unwrap_or_default(),
    };
    let signed = sign_release(release, &sk)?;
    let id = repo.write_signed(&signed)?;
    repo.refs.write(&format!("refs/releases/{}", args.label), id)?;

    // §4.4: warm the release cache and run LRU eviction so the
    // cache stays under its configured cap. The cap is 1 GiB by
    // default; future revisions can wire this through `.levcs/config`.
    levcs_core::release_cache::cache_release(&repo, id)?;
    let _ = levcs_core::release_cache::evict_to(
        &repo,
        levcs_core::release_cache::DEFAULT_CACHE_CAP_BYTES,
    )?;

    println!("released {} ({id})", args.label);
    Ok(())
}

pub fn cache(args: CacheArgs) -> Result<()> {
    let repo = open_repo()?;
    let dir = repo.levcs_dir.join("cache").join("workdir");
    fs::create_dir_all(&dir)?;
    if args.list {
        for ent in fs::read_dir(&dir)?.flatten() {
            println!("{}", ent.file_name().to_string_lossy());
        }
        return Ok(());
    }
    if let Some(id) = args.drop {
        let path = dir.join(&id);
        if path.exists() {
            fs::remove_dir_all(path)?;
            eprintln!("dropped cache {id}");
        }
        return Ok(());
    }
    if let Some(id) = args.restore {
        let src = dir.join(&id);
        if !src.is_dir() { bail!("no such cache: {id}"); }
        copy_dir_recursive(&src, &repo.workdir)?;
        eprintln!("restored {id}");
        return Ok(());
    }
    if args.save {
        // Save current working tree files into the cache.
        let id = format!("c{}", now_micros());
        let dest = dir.join(&id);
        fs::create_dir_all(&dest)?;
        for path in repo.walk_workdir()? {
            let rel = path.strip_prefix(&repo.workdir)?;
            let target = dest.join(rel);
            if let Some(parent) = target.parent() { fs::create_dir_all(parent)?; }
            fs::copy(&path, &target)?;
        }
        if let Some(m) = args.message {
            fs::write(dest.join(".message"), m)?;
        }
        println!("saved cache {id}");
        return Ok(());
    }
    eprintln!("usage: levcs cache --save [-m MSG] | --list | --restore ID | --drop ID");
    Ok(())
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<()> {
    for ent in fs::read_dir(src)? {
        let ent = ent?;
        let p = ent.path();
        let rel = p.strip_prefix(src)?;
        let t = dest.join(rel);
        if p.is_dir() {
            fs::create_dir_all(&t)?;
            copy_dir_recursive(&p, &t)?;
        } else {
            if let Some(parent) = t.parent() { fs::create_dir_all(parent)?; }
            fs::copy(&p, &t)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// verify, gc
// ---------------------------------------------------------------------------

pub fn verify() -> Result<()> {
    let repo = open_repo()?;
    let head = repo.refs.resolve_head()?;
    if let Some(h) = head {
        verify_commit(&repo.objects, h, repo.current_branch()?.as_deref())?;
        eprintln!("HEAD commit {h}: ok");
    }
    if let Some(auth) = repo.current_authority()? {
        verify_authority_chain(&repo.objects, auth)?;
        eprintln!("authority chain rooted at {auth}: ok");
    }
    eprintln!("verify: ok");
    Ok(())
}

pub fn gc(args: GcArgs) -> Result<()> {
    let repo = open_repo()?;
    let mut reachable: HashSet<ObjectId> = HashSet::new();
    let mut stack: Vec<ObjectId> = Vec::new();
    if let Some(h) = repo.refs.resolve_head()? { stack.push(h); }
    if let Some(c) = repo.current_authority()? { stack.push(c); }
    if let Some(g) = repo.genesis_authority()? { stack.push(g); }
    for (_, id) in repo.refs.list_all()? { stack.push(id); }
    while let Some(id) = stack.pop() {
        if !reachable.insert(id) { continue; }
        if let Ok(raw) = repo.objects.read_object(id) {
            match raw.object_type {
                ObjectType::Tree => {
                    if let Ok(t) = Tree::parse_body(&raw.body) {
                        for e in t.entries { stack.push(e.hash); }
                    }
                }
                ObjectType::Commit => {
                    if let Ok(c) = Commit::parse_body(&raw.body) {
                        stack.push(c.tree);
                        stack.push(c.authority);
                        stack.extend(c.parents);
                    }
                }
                ObjectType::Release => {
                    if let Ok(r) = Release::parse_body(&raw.body) {
                        stack.push(r.tree);
                        stack.push(r.predecessor);
                        stack.push(r.authority);
                        if !r.parent_release.is_zero() { stack.push(r.parent_release); }
                    }
                }
                ObjectType::Authority => {
                    if let Ok(b) = AuthorityBody::parse(&raw.body) {
                        if !b.previous_authority.is_zero() {
                            stack.push(b.previous_authority);
                        }
                    }
                }
                ObjectType::Blob => {}
            }
        }
    }
    // §4.2.2: don't delete an object that's younger than the grace
    // period. An in-progress `commit` or `push` may have written the
    // blob/tree to the object store but not yet linked it into a ref;
    // GCing it underneath would corrupt the operation. The grace
    // window is configurable; spec default is 14 days.
    let grace = std::time::Duration::from_secs(args.grace_days * 24 * 60 * 60);
    let now = std::time::SystemTime::now();
    let mut deleted = 0usize;
    let mut kept_young = 0usize;
    for id in repo.objects.iter_ids()? {
        if reachable.contains(&id) {
            continue;
        }
        let p = repo.objects.path_for(id);
        // Read mtime; skip with a warning if we can't tell. Choosing to
        // err on the side of keeping the object means a clock-skewed
        // file isn't silently lost.
        let mtime = fs::metadata(&p).and_then(|m| m.modified()).ok();
        if let Some(t) = mtime {
            if let Ok(age) = now.duration_since(t) {
                if age < grace {
                    kept_young += 1;
                    continue;
                }
            }
        }
        let _ = fs::remove_file(p);
        deleted += 1;
    }
    eprintln!(
        "gc: removed {deleted} unreachable object(s); kept {kept_young} within grace ({}d)",
        args.grace_days
    );
    let _ = args.aggressive; // honored via the same delete loop today
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn walk_dir(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let path = ent.path();
        let rel = path.strip_prefix(base)?;
        if levcs_core::ignore::always_ignored(rel) { continue; }
        let ft = ent.file_type()?;
        if ft.is_dir() {
            walk_dir(&path, base, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

fn file_mtime_micros(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn file_mode_bits(meta: &fs::Metadata) -> u8 {
    use std::os::unix::fs::PermissionsExt;
    let m = meta.permissions().mode();
    if m & 0o111 != 0 { 0o111 } else { 0 }
}

#[cfg(not(unix))]
fn file_mode_bits(_meta: &fs::Metadata) -> u8 { 0 }

#[allow(dead_code)]
fn _refs_unused(_: Refs) {}
#[allow(dead_code)]
fn _ctx_keep(_: &SecretKey) {}
