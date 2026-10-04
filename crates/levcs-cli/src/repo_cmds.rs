//! Repository-side commands: init, track, forget, commit, etc.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use levcs_core::object::{ObjectType, SignedObject};
use levcs_core::refs::Head;
use levcs_core::{
    Blob, Commit, CommitFlags, Index, IndexEntry, IndexEntryFlags, ObjectId, Refs, Release,
    Repository, Tree, ZERO_ID,
};
use levcs_identity::authority::{
    AuthorityBody, MemberEntry, PolicyEntry, Role, AUTHORITY_SCHEMA_VERSION,
};
use levcs_identity::keys::{PublicKey, SecretKey};
use levcs_identity::sign::{sign_authority, sign_commit, sign_release};
use levcs_merge::engine::validate_record_against_policy;
use levcs_merge::{
    CascadeEngine, FileRecord, FileStatus, MergeConfig, MergeRecord, MergeResult, MergeStatus,
};

use crate::cli::*;
use crate::ctx::{
    load_keychain, load_secret, lock_repo, now_micros, open_repo, open_repo_locked, save_keychain,
};

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

pub fn init(args: InitArgs) -> Result<()> {
    let path = args.path.unwrap_or_else(|| PathBuf::from("."));
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    fs::create_dir_all(&path)?;
    if path.join(".levcs").exists() {
        bail!("repository already exists at {:?}", path);
    }
    // Pick or create the key that will own the repository. A named label is
    // used, or generated if new. Unnamed: an empty keychain gets a new
    // `personal` key, and a keychain with one key uses it. With several,
    // refuse. This used to default to `personal` whenever it existed, so a
    // keychain holding the owner's `personal` and an agent's key made the
    // owner the genesis Owner of a repository an agent created.
    let mut kc = load_keychain()?;
    let label = match args.key.as_deref() {
        Some(l) => l.to_string(),
        None => match kc.keys.len() {
            0 => "personal".to_string(),
            1 => kc.keys[0].label.clone(),
            _ => {
                let labels: Vec<&str> = kc.keys.iter().map(|k| k.label.as_str()).collect();
                bail!(
                    "the keychain holds several keys ({}); name the one that will own \
                     the new repository with --key <label>",
                    labels.join(", ")
                );
            }
        },
    };
    let sk: SecretKey = if let Some(_) = kc.entry(&label) {
        let (_, sk) = load_secret(Some(&label))?;
        sk
    } else {
        let sk = SecretKey::generate();
        kc.add_plaintext(&label, &sk)?;
        save_keychain(&kc)?;
        eprintln!(
            "generated new key '{label}' at {:?}",
            crate::ctx::keychain_path()
        );
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
            PolicyEntry {
                key: "public_read".into(),
                value: vec![0x01],
            },
            PolicyEntry {
                key: "require_signed_releases".into(),
                value: vec![0x01],
            },
            PolicyEntry {
                key: "allowed_handlers".into(),
                value: b"builtin".to_vec(),
            },
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
    repo.refs
        .write_head(&Head::Branch("refs/branches/main".into()))?;
    eprintln!(
        "initialized levcs repository at {:?}\n  repo_id     = blake3:{}\n  authority   = {}",
        path,
        auth.repo_id.to_hex(),
        auth_id
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// track / forget
// ---------------------------------------------------------------------------

pub fn track(args: TrackArgs) -> Result<()> {
    let (repo, _lock) = open_repo_locked()?;
    let root = repo_root(&repo);
    let mut idx = load_index(&repo)?;
    let restrict = normalize_paths(&repo, &args.paths)?;

    // The repository's own walk is the only place `.levcsignore` is applied,
    // so a directory argument is filtered out of it rather than walked
    // separately. `track sub/`, `track .` from inside `sub/`, and
    // `track --all` then cannot disagree about what is ignored — they did,
    // because each rolled its own descent.
    let walked = repo.walk_workdir()?;
    let mut targets: Vec<PathBuf> = Vec::new();
    // Files named one by one. Only these can mark a conflict resolved:
    // `track --all` or a directory would otherwise resolve every conflict
    // under it, including ones with no markers that nobody looked at.
    let mut named: HashSet<String> = HashSet::new();

    // An empty restriction is the repository root: `track .` at the top.
    if args.all || restrict.iter().any(|r| r.is_empty()) {
        targets.extend(walked);
    } else {
        for r in &restrict {
            let abs = root.join(r);
            if abs.is_dir() {
                let before = targets.len();
                for p in &walked {
                    if path_under(std::slice::from_ref(r), &rel_of(&root, p)) {
                        targets.push(p.clone());
                    }
                }
                if targets.len() == before {
                    bail!("nothing to track under '{r}'; everything there is ignored");
                }
            } else if abs.is_file() {
                // An explicitly named file is tracked even where
                // `.levcsignore` would skip it. Naming it is the override.
                named.insert(r.to_string());
                targets.push(abs);
            } else {
                bail!("path not found: {r}");
            }
        }
    }
    for path in targets {
        let rel = path
            .strip_prefix(&repo.workdir)?
            .to_string_lossy()
            .replace('\\', "/");
        // What checkout would refuse to write is refused here, so that no
        // commit holds a tree its own checkout cannot materialise. A named
        // `.levcs/config` used to be tracked.
        levcs_core::worktree::components(&rel).map_err(|e| anyhow!("refusing to track: {e}"))?;
        let bytes = fs::read(&path)?;
        let blob = Blob::new(bytes.clone());
        let id = repo.objects.write_raw(&blob.serialize())?;
        let meta = fs::metadata(&path)?;
        let mtime = file_mtime_micros(&meta);
        let size = meta.len();
        let mode = file_mode_bits(&meta);
        let was_conflicted = idx
            .entries
            .iter()
            .any(|e| e.path == rel && e.flags.is_conflicted());
        let mut flags = IndexEntryFlags::TRACKED;
        if was_conflicted {
            if named.contains(&rel) {
                println!("resolved   {rel}");
            } else {
                flags = flags.with(IndexEntryFlags::CONFLICTED);
                println!("conflicted {rel}  (still unresolved; name it to mark it resolved)");
            }
        }
        idx.upsert(IndexEntry {
            path: rel,
            blob_hash: id,
            mode,
            flags,
            mtime_micros: mtime,
            size,
        });
    }
    repo.write_index(&idx)?;
    Ok(())
}

/// Stop tracking files.
///
/// `forget` means stop remembering, and that is now all it does by default;
/// `--delete` opts into removing the file as well. It used to be the other
/// way round, and the flag was not the real defect. The verb was unbounded:
/// it acted on the filesystem rather than on the repository, so
/// `levcs forget notes.txt` on a file the repository had never tracked
/// deleted it — exit 0, no output, and nothing in the object store to
/// restore from. A tool whose claim is that history is a verifiable record
/// of what happened must not be able to destroy something it never recorded,
/// because the hole that leaves is one history cannot describe.
///
/// So the verb is bounded to the index. Only tracked paths can be named, a
/// directory expands to the tracked files beneath it, and a path matching
/// nothing tracked is refused. `--delete` is therefore safe by construction
/// rather than by analysis: everything it can reach has a blob in the store,
/// and the alternative — deleting by default and refusing when the content
/// is not already in a commit — would require the tool to answer "is this
/// recoverable?" correctly on every call, with deletion as the price of
/// being wrong.
pub fn forget(args: ForgetArgs) -> Result<()> {
    let (repo, _lock) = open_repo_locked()?;
    let mut idx = load_index(&repo)?;
    let restrict = normalize_paths(&repo, &args.paths)?;
    if restrict.is_empty() {
        bail!("name at least one tracked path to forget");
    }

    let mut targets: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for r in &restrict {
        let matched: Vec<&IndexEntry> = idx
            .entries
            .iter()
            .filter(|e| path_under(std::slice::from_ref(r), &e.path))
            .collect();
        if matched.is_empty() {
            bail!("nothing tracked at '{r}'; forget acts only on tracked files");
        }
        for e in matched {
            // Forgetting a conflicted file resolves its conflict by deletion,
            // so it must be named, not swept up by a directory.
            if e.flags.is_conflicted() && e.path != *r {
                skipped.push(e.path.clone());
            } else {
                targets.push(e.path.clone());
            }
        }
    }
    for path in &skipped {
        println!("conflicted {path}  (not forgotten; name it to resolve it by deletion)");
    }
    targets.sort();
    targets.dedup();

    let wt = levcs_core::worktree::open(&repo.workdir)?;
    // Untrack first and persist that, so the reported state is the state on
    // disk even if a delete then fails. The index write is the part that must
    // not be left inconsistent.
    for path in &targets {
        idx.remove(path);
    }
    repo.write_index(&idx)?;

    let mut failed: Vec<String> = Vec::new();
    for path in &targets {
        if args.delete {
            // Through the working tree's descriptor: a directory on the
            // way that had become a symlink used to send the delete to a
            // file outside the repository.
            if let Err(e) = wt.remove_file(path) {
                failed.push(format!("{path}: {e}"));
                continue;
            }
        }
        println!(
            "{} {path}",
            if args.delete {
                "deleted  "
            } else {
                "untracked"
            }
        );
    }
    if !failed.is_empty() {
        bail!("untracked, but could not delete: {}", failed.join(", "));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// status / log
// ---------------------------------------------------------------------------

pub fn status() -> Result<()> {
    let repo = open_repo()?;
    let idx = load_index(&repo)?;
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
        if stale_merge_head(&repo)?.is_some() {
            println!(
                "Merge      already committed in HEAD (theirs={}); the next commit or merge clears its leftover state",
                mh.trim()
            );
        } else {
            println!("Merge      in progress (theirs={})", mh.trim());
        }
    }
    let workdir_files = repo.walk_workdir()?;
    let mut tracked = HashMap::<String, &IndexEntry>::new();
    for e in &idx.entries {
        tracked.insert(e.path.clone(), e);
    }
    let mut modified = Vec::new();
    let mut untracked = Vec::new();
    for path in workdir_files {
        let rel = path
            .strip_prefix(&repo.workdir)?
            .to_string_lossy()
            .replace('\\', "/");
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
        .map(|p| {
            p.strip_prefix(&repo.workdir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    let mut deleted: Vec<String> = idx
        .entries
        .iter()
        .filter(|e| !work_set.contains(&e.path))
        .map(|e| e.path.clone())
        .collect();
    deleted.sort();
    // Conflicts first: some have no markers, and nothing else shows them.
    let mut conflicted: Vec<&str> = idx
        .entries
        .iter()
        .filter(|e| e.flags.is_conflicted())
        .map(|e| e.path.as_str())
        .collect();
    conflicted.sort();
    if !conflicted.is_empty() {
        println!("\nunresolved conflicts (commit refuses until each is resolved):");
        for c in &conflicted {
            println!("  {c}");
        }
        println!("\n{RESOLVE_HELP}");
    }
    if !modified.is_empty() {
        println!("\nmodified:");
        for m in &modified {
            println!("  {m}");
        }
    }
    if !deleted.is_empty() {
        println!("\ndeleted:");
        for d in &deleted {
            println!("  {d}");
        }
    }
    if !untracked.is_empty() {
        println!("\nuntracked:");
        for u in &untracked {
            println!("  {u}");
        }
    }
    if modified.is_empty() && deleted.is_empty() && untracked.is_empty() && conflicted.is_empty() {
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
        if commit.flags.modifies_authority() {
            println!("Flags:  authority-modifying");
        }
        if commit.flags.is_fork() {
            println!("Flags:  fork");
        }
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

/// Resolve `.` and `..` without touching the filesystem.
///
/// Lexical on purpose: a path argument may name something that does not
/// exist — a file already deleted, or a typo that should be reported as one
/// — and `canonicalize` cannot normalize a path it cannot open.
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The repository root, with any `.` component removed.
///
/// `init` records the workdir as `<path>/.`, which survives into every join
/// and every `strip_prefix` built from it.
fn repo_root(repo: &Repository) -> PathBuf {
    lexical_normalize(&repo.workdir)
}

fn rel_of(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .map(|r| r.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default()
}

/// Resolve path arguments to repository-relative strings.
///
/// **A relative path resolves against the current directory**, which is what
/// every other version control tool does and what a shell's tab-completion
/// produces. It used to resolve against the repository root, and the reason
/// that mattered is not ergonomics: from a subdirectory, `commit README.md`
/// selected the *root* `README.md`, committed it, printed success, and left
/// the file actually named still modified. A signature over a file the
/// signer did not name is the failure this whole system exists to preclude.
///
/// The two resolutions fail differently, and that asymmetry is the argument.
/// Resolved against the current directory, a name can only ever miss — and a
/// miss is caught, because every command that takes paths now refuses one
/// that matches nothing. Resolved against the root, a name that exists at
/// both levels silently selects the wrong file.
///
/// Output stays repository-relative. You type `c.txt` in `sub/` and `status`,
/// `diff` and `commit`'s `scoped to` line all say `sub/c.txt`, which is both
/// the canonical form for a record and a free confirmation of what your
/// argument resolved to.
fn normalize_paths(repo: &Repository, paths: &[PathBuf]) -> Result<Vec<String>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let root = repo_root(repo);
    // Compare in the same world the current directory is expressed in: a
    // repository reached through a symlink would otherwise strip_prefix
    // against a path that never matches.
    let root_real = root.canonicalize().unwrap_or_else(|_| root.clone());
    let cwd = std::env::current_dir()?;
    let cwd_real = cwd.canonicalize().unwrap_or(cwd);

    paths
        .iter()
        .map(|p| -> Result<String> {
            let abs = if p.is_absolute() {
                p.clone()
            } else {
                cwd_real.join(p)
            };
            let abs = lexical_normalize(&abs);
            let rel = abs
                .strip_prefix(&root_real)
                .or_else(|_| abs.strip_prefix(&root))
                .map_err(|_| anyhow!("path {:?} is outside the repository", p))?;
            Ok(rel
                .to_string_lossy()
                .replace('\\', "/")
                .trim_end_matches('/')
                .to_string())
        })
        .collect()
}

/// Whether a repository-relative path falls under a path restriction.
///
/// An empty restriction means everything, so the unrestricted case needs no
/// separate branch at any call site. A restriction naming a directory takes
/// everything beneath it.
///
/// `commit` and `diff` share this and `normalize_paths` deliberately: a scope
/// is only useful if `levcs diff <paths>` is an exact preview of
/// `levcs commit <paths>`, and two copies of a prefix rule would not stay
/// exact for long.
fn path_under(restrict: &[String], p: &str) -> bool {
    if restrict.is_empty() {
        return true;
    }
    restrict
        .iter()
        .any(|r| r.is_empty() || r == "." || p == r || p.starts_with(&format!("{r}/")))
}

pub fn commit(args: CommitArgs) -> Result<()> {
    let repo = open_repo()?;
    let (label, sk) = load_secret(args.key.as_deref())?;
    let pk = sk.public();
    let _ = label;
    // Everything from here to the ref write reads and writes shared state.
    let _lock = lock_repo(&repo)?;

    // Authority is checked BEFORE the index is written. It used to be checked
    // after, which meant a rejected commit still persisted the staged index:
    // `status` then compared the working tree against that index and reported
    // "working tree clean" while `diff` still showed the change against HEAD.
    // A repository that reports clean while holding uncommitted work is worse
    // than one that refuses loudly, so nothing is written until the author is
    // known to be allowed to write it.
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
        bail!(
            "your key has role '{}', need at least contributor",
            member.role.name()
        );
    }

    // A merge commit that was published but not cleaned up leaves MERGE_HEAD
    // behind; clear it first, or this commit would be a second merge.
    clear_stale_merge_state(&repo)?;
    // Detect a merge in progress so we can attach the second parent and bake
    // the merge-record into the resulting tree.
    let merge_head_path = repo.levcs_dir.join("MERGE_HEAD");
    let merge_head_id: Option<ObjectId> = if merge_head_path.exists() {
        let s = fs::read_to_string(&merge_head_path)?;
        Some(ObjectId::from_hex(s.trim())?)
    } else {
        None
    };

    // Update index from working tree, for tracked files only. A lost index
    // is HEAD with nothing staged (see `load_index`), never an empty tree.
    let mut idx = load_index(&repo)?;

    // A commit may be scoped to paths. Entries outside the scope are carried
    // through untouched — neither refreshed from the working tree nor dropped
    // when the file is gone — so the staged tree differs from HEAD in exactly
    // the named files, and the rest of a dirty working tree stays dirty.
    //
    // This is what makes "commit in coherent units" achievable when a working
    // tree holds more than one piece of work, which in a repository written by
    // several hands at once is the ordinary case and not the awkward one.
    // Attribution is the entire point of signing a commit, and a commit that
    // had to sweep up someone else's unfinished edits in order to exist
    // attributes their work to you.
    let restrict = normalize_paths(&repo, &args.paths)?;
    for r in &restrict {
        // A path matching nothing tracked is an error rather than an empty
        // scope. A mistyped path that quietly commits nothing is the same
        // class of failure as a repository that reports clean while holding
        // uncommitted work.
        if !idx
            .entries
            .iter()
            .any(|e| path_under(std::slice::from_ref(r), &e.path))
        {
            bail!("nothing tracked at '{r}'; `levcs track` it first");
        }
    }
    let _ = args.all; // the explicit spelling of the default; clap bars it with paths

    // A merge is finalized as a whole. Scoping would carry every conflict
    // outside the named paths through the per-file marker check below
    // unexamined, seal it into a merge commit, and clear MERGE_HEAD.
    if merge_head_id.is_some() && !restrict.is_empty() {
        bail!("a merge is in progress; resolve it and commit without paths");
    }

    // Every file a merge left conflicted must be resolved explicitly before
    // anything is committed: edited and tracked, or forgotten. Checked here,
    // under the lock and before the refresh below rewrites the entries. The
    // marker scan further down cannot see conflicts that have no markers: a
    // binary file, a file deleted on one side, a structural handler's
    // conflict. A JSON conflict used to be committable for that reason.
    let conflicted: Vec<&str> = idx
        .entries
        .iter()
        .filter(|e| e.flags.is_conflicted())
        .map(|e| e.path.as_str())
        .collect();
    if !conflicted.is_empty() {
        bail!(
            "unresolved conflicts in: {}\n{}",
            conflicted.join(", "),
            RESOLVE_HELP
        );
    }

    let mut new_entries = Vec::new();
    for e in &idx.entries {
        if !path_under(&restrict, &e.path) {
            new_entries.push(e.clone());
            continue;
        }
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
            let blob_id = repo
                .objects
                .write_raw(&Blob::new(bytes.clone()).serialize())?;
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
        // (deleted from disk, and in scope → drop entry)
    }
    idx.entries = new_entries;
    // The refreshed index is written only after the commit is on its ref.
    // Written here, a refusal or failure below would leave the index saying
    // the work was committed, and `status` would report a clean tree.

    // Build the staged tree. For a merge commit, splice the merge-record
    // blob into `.levcs/merge-record` (§6.5).
    //
    // Under a scope the tree is HEAD's plus the named paths, not the index:
    // the index also holds changes the commit was not asked to take (a file
    // tracked since, a file forgotten since), and those stay staged for a
    // later commit instead of being sealed under this one's signature.
    let parent = repo.refs.resolve_head()?;
    let mut staged_tree = if restrict.is_empty() {
        repo.build_tree_from_index(&idx)?
    } else {
        let mut scoped = Index::default();
        if let Some(p) = parent {
            let head_tree = Commit::from_signed(&repo.read_signed(p)?)?.tree;
            for e in tree_index_entries(&repo, head_tree, "")? {
                if !path_under(&restrict, &e.path) {
                    scoped.entries.push(e);
                }
            }
        }
        scoped.entries.extend(
            idx.entries
                .iter()
                .filter(|e| path_under(&restrict, &e.path))
                .cloned(),
        );
        repo.build_tree_from_index(&scoped)?
    };
    if merge_head_id.is_some() {
        let record_path = repo.levcs_dir.join("merge-record");
        if !record_path.exists() {
            bail!("MERGE_HEAD set but no merge-record found");
        }
        let record_bytes = fs::read(&record_path)?;
        // Defensive re-check: somebody could have hand-edited the record
        // after `levcs merge` produced it. Refuse to seal a record that
        // names a handler not in this repository's policy.
        let allowed = load_merge_policy_allowed(&repo)?;
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

    if merge_head_id.is_none() {
        // Skip the "nothing to commit" check for merge commits — a successful
        // three-way merge whose tree happens to equal HEAD's still needs a
        // second-parent commit to record the union.
        if let Some(p) = parent {
            let p_signed = repo.read_signed(p)?;
            let p_commit = Commit::from_signed(&p_signed)?;
            // A merge commit's tree carries `.levcs/merge-record`, which no
            // later commit does; compare without it, or the first commit after
            // a merge always differs from HEAD, even with nothing changed.
            if tree_without_levcs(&repo, p_commit.tree)? == staged_tree {
                // Say which thing matched HEAD. Under a scope the working
                // tree very often does not, and claiming it did would send
                // someone looking for a bug that is not there.
                if restrict.is_empty() {
                    bail!("nothing to commit, working tree matches HEAD");
                }
                bail!("nothing to commit in the named paths; they match HEAD");
            }
        }
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
    // Advance HEAD's branch ref, but only from the parent this commit was
    // built on. Under the lock nothing cooperating moves it. The check also
    // catches most moves by a writer that skips the lock, but not one that
    // lands between the comparison and the rename (see `compare_and_write`).
    if let Some(branch) = repo.current_branch()? {
        repo.refs.compare_and_write(&branch, parent, id)?;
    } else {
        if repo.refs.resolve_head()? != parent {
            bail!("HEAD moved while this commit was being built; nothing was committed");
        }
        repo.refs.write_head(&Head::Detached(id))?;
    }
    // The commit is published from here on. Say so first, so that whatever
    // fails below is reported against a commit that exists.
    println!("[{}] {}", id, summarize_message(&signed));
    if !restrict.is_empty() {
        // A partial commit that does not announce itself is a footgun: the
        // next `status` will still be dirty, and the reason should already
        // have been said.
        println!("scoped to {}", restrict.join(", "));
    }
    // Merge state goes before the index: left behind, it would make the next
    // commit a second merge; a stale index only makes `status` overstate.
    let mut problems = Vec::new();
    if merge_head_id.is_some() {
        for name in MERGE_STATE {
            match fs::remove_file(repo.levcs_dir.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => problems.push(format!("removing .levcs/{name}: {e}")),
            }
        }
    }
    if let Err(e) = repo.write_index(&idx) {
        problems.push(format!("writing the index: {e}"));
    }
    if !problems.is_empty() {
        return Err(PublishedIncomplete { id, problems }.into());
    }
    Ok(())
}

/// The files of a tree as index entries, for building a tree that mixes
/// HEAD's content with staged content. `.levcs/` is skipped: an index never
/// holds it, so an unscoped commit's tree does not either.
fn tree_index_entries(
    repo: &Repository,
    tree_id: ObjectId,
    prefix: &str,
) -> Result<Vec<IndexEntry>> {
    let mut out = Vec::new();
    if tree_id.is_zero() {
        return Ok(out);
    }
    let raw = repo.objects.read_typed(tree_id, ObjectType::Tree)?;
    for e in Tree::parse_body(&raw.body)?.entries {
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        if path == ".levcs" {
            continue;
        }
        match e.entry_type {
            levcs_core::EntryType::Blob => out.push(IndexEntry {
                path,
                blob_hash: e.hash,
                mode: if e.mode.is_executable() { 0o111 } else { 0 },
                flags: IndexEntryFlags::TRACKED,
                mtime_micros: 0,
                size: 0,
            }),
            levcs_core::EntryType::Tree => out.extend(tree_index_entries(repo, e.hash, &path)?),
        }
    }
    Ok(out)
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
    let (repo, _lock) = open_repo_locked()?;
    // The first positional arg may be either a hash or a path. If it doesn't
    // parse as a 64-char hex blake3 hash, fold it into the path list and
    // resolve the target from HEAD (or latest release with --release).
    let mut paths = args.paths.clone();
    let parsed_hash: Option<ObjectId> = match args.hash.as_deref() {
        Some(s) => match crate::rev::try_resolve_rev(&repo, s)? {
            Some(id) => Some(id),
            None => {
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

    // Path-restricted reconstruction. The whole selection is listed and
    // checked before anything is written, as a checkout is, and written
    // through the working tree's own descriptor: a directory on the way that
    // is a symlink is refused, and a file that is one is replaced, not
    // written through. Each path used to be checked and written in turn, by
    // joined pathname, so `construct a.txt dir/b.txt` overwrote `a.txt`
    // before finding `dir` was a symlink.
    let mut files: Vec<levcs_core::repo::TreeFile> = Vec::new();
    for rel_str in normalize_paths(&repo, &paths)? {
        let entry = repo
            .lookup_entry(tree_id, &rel_str)?
            .ok_or_else(|| anyhow!("path not in tree: {rel_str}"))?;
        match entry.entry_type {
            levcs_core::EntryType::Blob => files.push(levcs_core::repo::TreeFile {
                path: rel_str,
                blob: entry.hash,
                executable: entry.mode.is_executable(),
            }),
            levcs_core::EntryType::Tree => files.extend(repo.tree_files(entry.hash, &rel_str)?),
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files.dedup_by(|a, b| a.path == b.path);
    if !args.all {
        // A file is left alone only if it is a regular file that already
        // holds the blob, with the mode the tree gives it. Comparing
        // contents alone left a mode-only change unrestored, reported as
        // done.
        let wt = levcs_core::worktree::open(&repo.workdir)?;
        let mut stale = Vec::with_capacity(files.len());
        for f in files {
            let blob = repo.objects.read_typed(f.blob, ObjectType::Blob)?;
            if !wt.holds(&f.path, &blob.body, f.perms())? {
                stale.push(f);
            }
        }
        files = stale;
    }
    repo.checkout_files(&files, &repo.workdir)?;
    eprintln!("constructed paths from tree {}", tree_id);
    Ok(())
}

pub fn diff(args: DiffArgs) -> Result<()> {
    let repo = open_repo()?;
    let head = repo.refs.resolve_head()?;
    // Fold a non-hex "commit" positional into the path restriction list.
    let mut paths = args.paths.clone();
    let parsed_commit: Option<ObjectId> = match args.commit.as_deref() {
        Some(s) => match crate::rev::try_resolve_rev(&repo, s)? {
            Some(id) => Some(id),
            None => {
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

    // The same normalization and the same prefix rule `commit` uses, so that
    // `levcs diff <paths>` is an exact preview of `levcs commit <paths>`.
    let restrict = normalize_paths(&repo, &paths)?;
    let path_matches = |p: &str| -> bool { path_under(&restrict, p) };

    let baseline = collect_tree_files(&repo, baseline_tree, "")?;
    let work: HashMap<String, Vec<u8>> = repo
        .walk_workdir()?
        .into_iter()
        .map(|p| -> Result<_> {
            let rel = p
                .strip_prefix(&repo.workdir)?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&p)?;
            Ok((rel, bytes))
        })
        .collect::<Result<_>>()?;
    // A restriction that matches nothing at all is a mistake, not an empty
    // diff. Printing nothing and exiting 0 says "no changes" about a path the
    // repository has never heard of, which is the same silent-success shape
    // as a commit that reports clean while holding work.
    for r in &restrict {
        if !baseline
            .keys()
            .chain(work.keys())
            .any(|k| path_under(std::slice::from_ref(r), k))
        {
            bail!("nothing at '{r}' in the working tree or the baseline");
        }
    }

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
        if a == b {
            continue;
        }
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
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
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
    let (repo, _lock) = open_repo_locked()?;
    if args.list || (args.create.is_none() && args.switch.is_none() && args.delete.is_none()) {
        let cur = repo.current_branch()?.unwrap_or_default();
        for (name, id) in repo.refs.list_branches()? {
            let marker = if cur == format!("refs/branches/{name}") {
                "*"
            } else {
                " "
            };
            println!("{marker} {name}\t{id}");
        }
        return Ok(());
    }
    if let Some(name) = args.create {
        let from = match args.from {
            Some(s) => crate::rev::resolve_rev(&repo, &s)?,
            None => repo
                .refs
                .resolve_head()?
                .ok_or_else(|| anyhow!("no HEAD"))?,
        };
        repo.refs.write(&format!("refs/branches/{name}"), from)?;
        eprintln!("created branch {name} at {from}");
    }
    if let Some(name) = args.switch {
        // State a published merge left behind (its cleanup failed, exit 3)
        // is cleared here, under the lock. Carried onto another branch, it
        // made the next ordinary commit a merge, with the old merge's record
        // and two identical parents. If it cannot be cleared, refuse.
        clear_stale_merge_state(&repo)?;
        // A switch rewrites HEAD, the working tree and the index. During a
        // merge it would wipe the conflict flags and keep MERGE_HEAD, so the
        // next commit sealed the conflicts unresolved, even when switching
        // to the branch already checked out. Refuse before changing anything.
        if repo.levcs_dir.join("MERGE_HEAD").exists() && stale_merge_head(&repo)?.is_none() {
            bail!(
                "a merge is in progress; commit it or run `levcs merge --abort` \
                 before switching branches"
            );
        }
        let target = repo
            .refs
            .read(&format!("refs/branches/{name}"))?
            .ok_or_else(|| anyhow!("no such branch: {name}"))?;
        let raw = repo.read_raw_object(target)?;
        let tree_id = match raw.object_type {
            ObjectType::Commit => Commit::parse_body(&raw.body)?.tree,
            _ => bail!("branch tip is not a commit"),
        };
        // Materialize first: checkout validates the whole tree and refuses
        // before writing anything it cannot write safely. HEAD and the
        // index move only once the files are in place, so a refused switch
        // leaves the repository where it was. HEAD used to move first.
        repo.checkout_tree(tree_id, &repo.workdir)?;
        repo.refs
            .write_head(&Head::Branch(format!("refs/branches/{name}")))?;
        // Refresh the index from the new tree. Without this the index
        // keeps the previous branch's blob hashes — invisible to most
        // workflows because the next `commit` rebuilds the index from
        // the working tree, but visible to anything that compares
        // index-vs-workdir (e.g., the merge command's dirty-tree
        // precondition, which would otherwise false-positive on every
        // branch switch).
        let mut idx = Index::new();
        rebuild_index_from_tree(&repo, tree_id, "", &mut idx)?;
        repo.write_index(&idx)?;
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

/// Return the list of tracked paths whose working-tree contents differ from
/// the index, including paths that are tracked but missing from disk. Used
/// as a precondition for any operation that overwrites the working tree
/// (currently: `merge`, both fast-forward and three-way). Callers should
/// refuse to proceed when the returned list is non-empty so users don't
/// silently lose uncommitted work.
fn dirty_tracked_paths(repo: &Repository) -> Result<Vec<String>> {
    let idx = load_index(repo)?;
    let mut workdir_set: HashSet<String> = HashSet::new();
    for path in repo.walk_workdir()? {
        let rel = path
            .strip_prefix(&repo.workdir)?
            .to_string_lossy()
            .replace('\\', "/");
        workdir_set.insert(rel);
    }
    let mut dirty = Vec::new();
    for entry in &idx.entries {
        if !entry.flags.is_tracked() {
            continue;
        }
        let abs = repo.workdir.join(&entry.path);
        if !workdir_set.contains(&entry.path) {
            // Tracked file removed from working tree without `levcs commit`
            // — counts as dirty for merge purposes since the merge would
            // resurrect it (or compute against stale on-disk state).
            dirty.push(entry.path.clone());
            continue;
        }
        let bytes = match fs::read(&abs) {
            Ok(b) => b,
            Err(_) => {
                dirty.push(entry.path.clone());
                continue;
            }
        };
        let id = Blob::new(bytes).object_id();
        if id != entry.blob_hash {
            dirty.push(entry.path.clone());
        }
    }
    dirty.sort();
    Ok(dirty)
}

fn merge_run(args: MergeArgs) -> Result<()> {
    let branch_name = args
        .branch
        .clone()
        .ok_or_else(|| anyhow!("missing branch to merge"))?;
    let (repo, _lock) = open_repo_locked()?;
    clear_stale_merge_state(&repo)?;
    if repo.levcs_dir.join("MERGE_HEAD").exists() {
        bail!("a merge is already in progress; run `levcs merge --abort` to cancel");
    }
    // Refuse to start a merge when tracked files have uncommitted changes —
    // both the fast-forward and three-way paths overwrite the working
    // tree, and silently clobbering local edits is the kind of bug that
    // costs users hours of work. Mirrors git's `Your local changes to
    // the following files would be overwritten by merge` precondition.
    let dirty = dirty_tracked_paths(&repo)?;
    if !dirty.is_empty() {
        let listing = dirty
            .iter()
            .take(10)
            .map(|p| format!("  {p}"))
            .collect::<Vec<_>>()
            .join("\n");
        let more = if dirty.len() > 10 {
            format!("\n  ... and {} more", dirty.len() - 10)
        } else {
            String::new()
        };
        bail!(
            "uncommitted changes to tracked files would be overwritten by merge:\n{listing}{more}\n\
             commit them (or revert to HEAD) before merging — see `levcs status`."
        );
    }
    let head = repo
        .refs
        .resolve_head()?
        .ok_or_else(|| anyhow!("no HEAD on current branch"))?;
    let theirs_id = crate::rev::resolve_rev(&repo, &branch_name)?;
    if head == theirs_id {
        eprintln!("already up to date.");
        return Ok(());
    }

    let base_id = find_common_ancestor(&repo, head, theirs_id)?
        .ok_or_else(|| anyhow!("no common ancestor between {head} and {theirs_id}"))?;

    // Fast-forward: HEAD is an ancestor of theirs, no merge commit needed.
    if base_id == head {
        let theirs_commit = Commit::from_signed(&repo.read_signed(theirs_id)?)?;
        // Files first, then the ref, then the index: a refused checkout
        // must not leave the branch moved over a working tree it never
        // reached. The ref used to move first.
        repo.checkout_tree(theirs_commit.tree, &repo.workdir)?;
        if let Some(branch_ref) = repo.current_branch()? {
            repo.refs
                .compare_and_write(&branch_ref, Some(head), theirs_id)?;
        } else {
            repo.refs.write_head(&Head::Detached(theirs_id))?;
        }
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
    let engine = load_merge_engine(&repo)?;
    let mut record = MergeRecord {
        schema_version: 1,
        base: format!("blake3:{}", base_id),
        ours: format!("blake3:{}", head),
        theirs: format!("blake3:{}", theirs_id),
        files: Vec::new(),
    };
    let mut paths: BTreeSet<String> = BTreeSet::new();
    for k in base_files
        .keys()
        .chain(ours_files.keys())
        .chain(theirs_files.keys())
    {
        // .levcs/* synthetic tree entries (authority, merge-record) live in
        // commits but never on disk; skip them when reconciling files.
        if k.starts_with(".levcs/") || k == ".levcs" {
            continue;
        }
        paths.insert(k.clone());
    }

    let json_mode = args.format == "json";
    if !json_mode && args.format != "text" {
        bail!(
            "unknown --format value: {} (allowed: text, json)",
            args.format
        );
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
        // Each side as present-with-content or absent. Comparing bytes alone
        // made a deleted file equal to an empty one: deleting an empty file
        // while the other side edited it, or deleting a file while the other
        // side truncated it, merged "cleanly" to whichever side the shortcuts
        // below happened to reach first.
        let base_side = base_files.get(&path);
        let ours_side = ours_files.get(&path);
        let theirs_side = theirs_files.get(&path);
        let base = base_side.cloned().unwrap_or_default();
        let ours = ours_side.cloned().unwrap_or_default();
        let theirs = theirs_side.cloned().unwrap_or_default();

        // Both sides agree: take the value (handles deletes-on-both).
        if ours_side == theirs_side {
            if ours_side.is_none() {
                deleted_files.insert(path);
            } else {
                merged_files.insert(path, ours);
            }
            continue;
        }
        // One-sided edits.
        if base_side == ours_side {
            // Only theirs changed.
            if args.no_auto {
                let result = make_no_auto_conflict(path.clone(), &base, &ours, &theirs);
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
        if base_side == theirs_side {
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
        // Both sides changed, and one of them deleted the file: a conflict,
        // never a merge. Handing the deleted side to a handler as empty
        // content produced fragments of the other side, reported as AUTO.
        // The edited version stays in the working tree, unmarked; the
        // resolution is `levcs track` to keep it or `levcs forget` to
        // delete it.
        let in_ours = ours_files.contains_key(&path);
        let in_theirs = theirs_files.contains_key(&path);
        if in_ours != in_theirs {
            let (kept, who_kept, who_deleted) = if in_ours {
                (ours.clone(), "ours", "theirs")
            } else {
                (theirs.clone(), "theirs", "ours")
            };
            conflict_count += 1;
            let notes = format!("modified by {who_kept}, deleted by {who_deleted}");
            if json_mode {
                let result = MergeResult {
                    handler: "none".into(),
                    status: MergeStatus::Conflict {
                        regions: vec![],
                        partial: kept.clone(),
                    },
                };
                json_files.push((path.clone(), JsonReportData::from(&result)));
            } else {
                eprintln!("CONFLICT {path}  ({notes})");
            }
            record.files.push(FileRecord {
                path: path.clone(),
                handler: "none".into(),
                handler_hash: String::new(),
                status: FileStatus::Manual,
                notes,
            });
            merged_files.insert(path, kept);
            continue;
        }
        // Both sides changed: the handler the configuration selects, which
        // is textual unless `.levcs/merge.toml` opts this path into a
        // structural one. A local override that would do anything else
        // stops the merge here, before anything is written.
        if !args.no_auto {
            engine
                .select(Path::new(&path))
                .map_err(|e| anyhow!("{e}"))?;
        }
        let result = if args.no_auto {
            make_no_auto_conflict(path.clone(), &base, &ours, &theirs)
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
            MergeStatus::Conflict {
                partial,
                regions: _,
            } => {
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

    // Repo-side policy ceiling: every handler reference in the record must
    // be permitted by `.levcs/merge.toml` (§6.6). This used to run *after*
    // we applied the merge to the working tree, which left the user's
    // files clobbered when the policy check then bailed. Validate up
    // front, before any disk write, so a rejected merge leaves the
    // working tree exactly as we found it.
    let allowed = load_merge_policy_allowed(&repo)?;
    let bad = validate_record_against_policy(&record, &allowed);
    if !bad.is_empty() {
        bail!(
            "merge produced records referencing handlers not in repository policy: {}",
            bad.join(", ")
        );
    }

    // Apply to the working tree through its own descriptor: every path is
    // checked, and every existing directory on the way confirmed real,
    // before the first write. Writes never follow a symlink, and replace
    // rather than write through a linked file. These used to be
    // `fs::write` and `fs::remove_file` on joined paths, so a symlinked
    // directory in the working tree sent merge output outside it.
    let mut writes: Vec<(&String, &Vec<u8>)> = merged_files.iter().collect();
    writes.sort();
    let mut deletes: Vec<&String> = deleted_files.iter().collect();
    deletes.sort();
    let wt = levcs_core::worktree::open(&repo.workdir)?;
    wt.preflight(
        writes
            .iter()
            .map(|(p, _)| p.as_str())
            .chain(deletes.iter().map(|p| p.as_str())),
    )?;
    for (path, bytes) in writes {
        wt.write_file(path, bytes, levcs_core::worktree::Perms::Keep)?;
    }
    for path in deletes {
        wt.remove_file(path)?;
    }

    // Refresh the index to reflect post-merge content. Tracked entries are
    // reset to the new blob hashes so that `levcs commit` can build a tree
    // without re-reading the working directory's view of every file.
    let mut idx = Index::new();
    for (path, bytes) in &merged_files {
        let id = repo
            .objects
            .write_raw(&Blob::new(bytes.clone()).serialize())?;
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
        println!("{}", RESOLVE_HELP);
        std::process::exit(1);
    }
    println!("clean merge. run `levcs commit` to finalize.");
    Ok(())
}

/// How to finish a merge that left conflicts. `commit` refuses while any
/// file is still marked conflicted, so every conflict needs one of these.
const RESOLVE_HELP: &str = "\
to resolve each conflicted file:
  edit it, then mark it resolved:    levcs track <path>
  or delete it and mark that:        levcs forget --delete <path>
then commit the merge:               levcs commit -m <message>
to step through conflicts:           levcs merge --review
to give up on the merge:             levcs merge --abort
a conflict may have no conflict markers (binary files, a file deleted on one
side), so name each conflicted path; `levcs status` lists them.";

/// Read a merge config from `.levcs/<name>`. An absent file is the default
/// config. An unreadable or malformed one is an error: it used to be read
/// as the default, which silently turned off both the repository's rules
/// and its `allowed_handlers` policy.
fn read_merge_config_file(repo: &Repository, name: &str) -> Result<Option<MergeConfig>> {
    let path = repo.levcs_dir.join(name);
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("cannot read .levcs/{name}: {e}")),
    };
    toml::from_str(&raw)
        .map(Some)
        .map_err(|e| anyhow!(".levcs/{name} is malformed: {e}"))
}

fn read_repo_merge_config(repo: &Repository) -> Result<MergeConfig> {
    Ok(read_merge_config_file(repo, "merge.toml")?.unwrap_or_default())
}

/// The merge engine for this repository. Without rules, every file merges
/// textually. `.levcs/merge.toml` may opt paths into structural handlers.
/// `.levcs/merge.local.toml` (per user, never pushed) may only keep those
/// choices or choose textual (§6.6.3). Every rule must name an available
/// handler.
fn load_merge_engine(repo: &Repository) -> Result<CascadeEngine> {
    let base = read_repo_merge_config(repo)?;
    let mut engine = CascadeEngine::new().with_config(base.clone());
    if let Some(local) = read_merge_config_file(repo, "merge.local.toml")? {
        engine = engine
            .with_local_overrides(&base, &local)
            .map_err(|e| anyhow!("{e}"))?;
    }
    engine.validate().map_err(|e| anyhow!("{e}"))?;
    Ok(engine)
}

/// Load `.levcs/merge.toml`'s `policy.allowed_handlers`: empty (permissive)
/// if the file is absent or has no policy block, an error if it is
/// malformed. `merge.local.toml` does not influence policy; local overrides
/// can't widen what's permitted.
fn load_merge_policy_allowed(repo: &Repository) -> Result<Vec<String>> {
    let cfg = read_repo_merge_config(repo)?;
    Ok(cfg.policy.map(|p| p.allowed_handlers).unwrap_or_default())
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

fn make_no_auto_conflict(_path: String, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeResult {
    // Binary content gets no markers here either: `--no-auto` used to wrap
    // it in them, changing the working bytes of NUL-containing and
    // non-UTF-8 files. Like the engine's binary guard, keep ours unchanged
    // and leave the resolution to an explicit `track` or `forget`.
    if [base, ours, theirs]
        .iter()
        .any(|b| levcs_merge::textual::looks_binary(b))
    {
        return MergeResult {
            handler: "no-auto".into(),
            status: MergeStatus::Conflict {
                regions: vec![],
                partial: ours.to_vec(),
            },
        };
    }
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

/// The outcome of a commit whose branch ref moved but whose later cleanup
/// failed. The commit is published: it is on its branch and signed. Reporting
/// it as a failure, with no id, invited a retry, and a retry with merge state
/// still present made a second merge commit. `main` reports this outcome
/// with its own exit status (3) so a caller can tell it from a commit that
/// did not happen.
#[derive(Debug)]
pub struct PublishedIncomplete {
    pub id: ObjectId,
    pub problems: Vec<String>,
}

impl std::fmt::Display for PublishedIncomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "commit {} is published, but cleanup after it did not finish: {}",
            self.id,
            self.problems.join("; ")
        )
    }
}

impl std::error::Error for PublishedIncomplete {}

const MERGE_STATE: [&str; 3] = ["MERGE_HEAD", "MERGE_BASE", "merge-record"];

/// The commit MERGE_HEAD names, if HEAD already has it as a parent: the merge
/// was committed, and the files left in `.levcs/` are stale.
fn stale_merge_head(repo: &Repository) -> Result<Option<ObjectId>> {
    let Ok(s) = fs::read_to_string(repo.levcs_dir.join("MERGE_HEAD")) else {
        return Ok(None);
    };
    let Ok(theirs) = ObjectId::from_hex(s.trim()) else {
        return Ok(None);
    };
    let Some(head) = repo.refs.resolve_head()? else {
        return Ok(None);
    };
    let c = Commit::from_signed(&repo.read_signed(head)?)?;
    Ok((c.parents.len() > 1 && c.parents[1..].contains(&theirs)).then_some(theirs))
}

/// Remove merge state that a published merge commit left behind, so it
/// cannot turn the next commit into a second merge. Call under the lock.
fn clear_stale_merge_state(repo: &Repository) -> Result<()> {
    if let Some(theirs) = stale_merge_head(repo)? {
        for name in MERGE_STATE {
            match fs::remove_file(repo.levcs_dir.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("removing .levcs/{name}")),
            }
        }
        eprintln!(
            "levcs: the merge with {theirs} is already committed in HEAD; \
             cleared the merge state it left behind"
        );
    }
    Ok(())
}

/// `tree_id` without its top-level `.levcs` entry, as the id that tree
/// would have. Only merge commits put anything there (the merge record).
fn tree_without_levcs(repo: &Repository, tree_id: ObjectId) -> Result<ObjectId> {
    if tree_id.is_zero() {
        return Ok(tree_id);
    }
    let raw = repo.objects.read_typed(tree_id, ObjectType::Tree)?;
    let mut tree = Tree::parse_body(&raw.body)?;
    let before = tree.entries.len();
    tree.entries.retain(|e| e.name != ".levcs");
    if tree.entries.len() == before {
        return Ok(tree_id);
    }
    Ok(tree.object_id())
}

/// The index, for any command that reads it. When the file is missing and
/// HEAD exists, the index is HEAD's files with nothing staged.
///
/// A missing index used to read as empty. `track` would then write back an
/// index holding only the new file, and the next commit deleted every other
/// file from HEAD. Treating a lost index as "nothing staged" can drop a
/// staged change, which stays on disk, but it never deletes committed files.
fn load_index(repo: &Repository) -> Result<Index> {
    if repo.index_exists() {
        return repo.read_index().with_context(|| {
            format!(
                "reading {}; if it cannot be repaired, delete it and levcs will \
                 rebuild it from HEAD with nothing staged",
                repo.index_path().display()
            )
        });
    }
    // During a merge the index holds the merged files and which of them are
    // still conflicted. Rebuilt from HEAD it would hold neither, and the
    // next commit would seal unresolved conflicts and drop files the merge
    // added. Refuse instead; abort and merge again rebuilds both.
    if repo.levcs_dir.join("MERGE_HEAD").exists() && stale_merge_head(repo)?.is_none() {
        bail!(
            "{} is missing while a merge is in progress, and with it the record of \
             which files are still conflicted; run `levcs merge --abort`, then merge again",
            repo.index_path().display()
        );
    }
    let mut idx = Index::new();
    if let Some(head) = repo.refs.resolve_head()? {
        let tree = Commit::from_signed(&repo.read_signed(head)?)?.tree;
        rebuild_index_from_tree(repo, tree, "", &mut idx)?;
        eprintln!(
            "levcs: {} is missing; using HEAD's files with nothing staged",
            repo.index_path().display()
        );
    }
    Ok(idx)
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
    let (repo, _lock) = open_repo_locked()?;
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
        let merge_head_id =
            ObjectId::from_hex(fs::read_to_string(repo.levcs_dir.join("MERGE_HEAD"))?.trim())?;
        let merge_head_commit = Commit::from_signed(&repo.read_signed(merge_head_id)?)?;
        let base_tree = if repo.levcs_dir.join("MERGE_BASE").exists() {
            let id =
                ObjectId::from_hex(fs::read_to_string(repo.levcs_dir.join("MERGE_BASE"))?.trim())?;
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
        let text =
            String::from_utf8(blob.body).map_err(|_| anyhow!("merge-record is not UTF-8"))?;
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
            let base = base_tree
                .map(|t| read_path(t, &fr.path))
                .unwrap_or_default();
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
                        vec![levcs_merge::MergeNote {
                            message: fr.notes.clone(),
                        }]
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
    let (repo, _lock) = open_repo_locked()?;
    let merge_record_path = repo.levcs_dir.join("merge-record");
    if !merge_record_path.exists() {
        bail!("no merge in progress");
    }
    let s = fs::read_to_string(&merge_record_path)?;
    let record = MergeRecord::from_toml(&s).map_err(|e| anyhow!("parse merge-record: {e}"))?;

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

    let merge_head_id =
        ObjectId::from_hex(fs::read_to_string(repo.levcs_dir.join("MERGE_HEAD"))?.trim())?;
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
                FileStatus::Auto | FileStatus::Ours | FileStatus::Theirs => MergeStatus::Merged {
                    content: current.clone(),
                    notes: if fr.notes.is_empty() {
                        vec![]
                    } else {
                        vec![levcs_merge::MergeNote {
                            message: fr.notes.clone(),
                        }]
                    },
                },
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
    let final_state = levcs_tui::review(files).map_err(|e| anyhow!("review session: {e}"))?;
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
        if !a_anc.insert(id) {
            continue;
        }
        if let Ok(s) = repo.read_signed(id) {
            if let Ok(c) = Commit::from_signed(&s) {
                stack.extend(c.parents);
            }
        }
    }
    let mut stack = vec![b];
    let mut visited: HashSet<ObjectId> = HashSet::new();
    while let Some(id) = stack.pop() {
        if !visited.insert(id) {
            continue;
        }
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
    // Locked after the key, so a passphrase prompt holds no other writer.
    let _lock = crate::ctx::lock_repo(&repo)?;
    let pk = sk.public();
    let authority = repo
        .current_authority()?
        .ok_or_else(|| anyhow!("no current authority"))?;
    let auth_signed = repo.read_signed(authority)?;
    let auth_body = AuthorityBody::parse(&auth_signed.body)?;
    let m = auth_body
        .find_member(&pk)
        .ok_or_else(|| anyhow!("your key is not in the current authority"))?;
    if m.role < Role::Maintainer {
        bail!(
            "releases require maintainer role; your role is '{}'",
            m.role.name()
        );
    }
    let head = repo
        .refs
        .resolve_head()?
        .ok_or_else(|| anyhow!("no HEAD"))?;
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
    repo.refs
        .write(&format!("refs/releases/{}", args.label), id)?;

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
    let (repo, _lock) = open_repo_locked()?;
    let dir = repo.levcs_dir.join("cache").join("workdir");
    fs::create_dir_all(&dir)?;
    if args.list {
        for ent in fs::read_dir(&dir)?.flatten() {
            println!("{}", ent.file_name().to_string_lossy());
        }
        return Ok(());
    }
    // An id names one entry of the cache directory. `--drop ../..` used to
    // remove `.levcs` itself.
    for id in [&args.drop, &args.restore].into_iter().flatten() {
        if id.is_empty() || id == "." || id == ".." || id.contains(['/', '\\', '\0']) {
            bail!("no such cache: {id:?}");
        }
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
        if !src.is_dir() {
            bail!("no such cache: {id}");
        }
        // Listed and checked in full, then written through the working
        // tree's descriptor like a checkout. This used to copy by joined
        // pathname, through any symlinked directory in the working tree,
        // and copied the cache's own `.message` into it.
        let mut files = Vec::new();
        cached_files(&src, "", &mut files)?;
        let wt = levcs_core::worktree::open(&repo.workdir)?;
        wt.preflight(files.iter().map(|(rel, _, _)| rel.as_str()))?;
        for (rel, path, perms) in &files {
            wt.write_file(rel, &fs::read(path)?, *perms)?;
        }
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
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
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

/// The files of a saved cache, as (working-tree path, cache path, perms).
/// `save` writes regular files only, so anything else is refused.
fn cached_files(
    dir: &Path,
    prefix: &str,
    out: &mut Vec<(String, PathBuf, levcs_core::worktree::Perms)>,
) -> Result<()> {
    use levcs_core::worktree::Perms;
    for ent in fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow!("cache entry {:?} is not UTF-8", ent.path()))?;
        if prefix.is_empty() && name == ".message" {
            continue;
        }
        let rel = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let meta = fs::symlink_metadata(ent.path())?;
        if meta.is_dir() {
            cached_files(&ent.path(), &rel, out)?;
        } else if meta.is_file() {
            // The mode `save` copied, so a private file comes back private.
            // Only the executable bit used to be carried.
            #[cfg(unix)]
            let perms = Perms::Exact(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()));
            #[cfg(not(unix))]
            let perms = Perms::Regular;
            out.push((rel, ent.path(), perms));
        } else {
            bail!("cache entry {:?} is not a regular file", ent.path());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// verify, gc
// ---------------------------------------------------------------------------

/// `verify`'s outcome when all history is valid but some commits cite an
/// authority incomparable with this repository's current one (decision D2 in
/// `doc/authority-semantics.md`): a detected disagreement between replicas,
/// not a forgery. `main` gives it exit status 4.
#[derive(Debug)]
pub struct ConflictingLineage(pub usize);

impl std::fmt::Display for ConflictingLineage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} commit(s) are valid but cite an authority lineage that conflicts \
             with this repository's current authority",
            self.0
        )
    }
}

impl std::error::Error for ConflictingLineage {}

/// The roots of everything a repository keeps: every ref, a detached HEAD,
/// and the commits a merge in progress names.
fn reachability_roots(repo: &Repository) -> Result<Vec<(String, ObjectId)>> {
    let mut roots = repo.refs.list_all()?;
    if let Some(Head::Detached(id)) = repo.refs.read_head()? {
        roots.push(("HEAD".into(), id));
    }
    // A marker that is absent is no root; one that exists but cannot be read
    // or parsed is an error. Ignoring it would let `gc` delete the commits a
    // merge in progress holds.
    for name in ["MERGE_HEAD", "MERGE_BASE"] {
        let path = repo.levcs_dir.join(name);
        let s = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(anyhow!("cannot read .levcs/{name}: {e}")),
        };
        let id =
            ObjectId::from_hex(s.trim()).map_err(|e| anyhow!(".levcs/{name} is malformed: {e}"))?;
        roots.push((name.to_string(), id));
    }
    Ok(roots)
}

/// Check everything the repository keeps, not just HEAD: every object
/// reachable from any ref is hash-checked, and every commit and release is
/// checked under the authority rules (Rule H) against the pinned genesis.
/// This used to check HEAD's signature and the current authority chain and
/// print "verify: ok" with hundreds of corrupt objects behind HEAD.
pub fn verify() -> Result<()> {
    let repo = open_repo()?;
    let genesis = repo
        .genesis_authority()?
        .ok_or_else(|| anyhow!("no refs/authority/genesis to verify against"))?;
    let current = repo.current_authority()?;
    let roots = reachability_roots(&repo)?;
    let r = levcs_identity::history::verify_history(&repo.objects, genesis, current, &roots);
    let foreign = if r.foreign_commits > 0 {
        format!(", {} fork-source commits", r.foreign_commits)
    } else {
        String::new()
    };
    eprintln!(
        "checked {} refs: {} commits, {} trees, {} blobs, {} releases, {} authorities{foreign}; \
         every object hash-checked",
        r.roots, r.commits, r.trees, r.blobs, r.releases, r.authorities
    );
    const SHOW: usize = 50;
    for p in r.problems.iter().take(SHOW) {
        let label = if p.integrity { "damaged" } else { "invalid" };
        eprintln!("{label:<9} {}: {}", p.object, p.what);
    }
    if r.problems.len() > SHOW {
        eprintln!("          … and {} more", r.problems.len() - SHOW);
    }
    for p in r.conflicting.iter().take(SHOW) {
        eprintln!("conflict  {}: {}", p.object, p.what);
    }
    if r.conflicting.len() > SHOW {
        eprintln!("          … and {} more", r.conflicting.len() - SHOW);
    }
    if !r.problems.is_empty() {
        bail!("verify failed: {} problem(s)", r.problems.len());
    }
    if !r.conflicting.is_empty() {
        return Err(ConflictingLineage(r.conflicting.len()).into());
    }
    eprintln!("verify: ok");
    Ok(())
}

pub fn gc(args: GcArgs) -> Result<()> {
    let (repo, _lock) = open_repo_locked()?;
    // What gc keeps is exactly what `verify`'s typed walk reaches, from the
    // same roots and through the same links, each checked for its type. Any
    // damage on the way stops gc before it deletes anything: an unreadable
    // or mis-typed object hides everything behind it, and gc used to delete
    // that history as unreachable (on a copy of a vault with 400 corrupt
    // objects, 1,243 sound ones, with exit 0). Rule violations in intact
    // history do not stop it; they cannot be repaired by deleting.
    let genesis = repo
        .genesis_authority()?
        .ok_or_else(|| anyhow!("no refs/authority/genesis; refusing to collect"))?;
    let current = repo.current_authority()?;
    let roots = reachability_roots(&repo)?;
    let report = levcs_identity::history::verify_history(&repo.objects, genesis, current, &roots);
    if let Some(p) = report.problems.iter().find(|p| p.integrity) {
        bail!(
            "{} is damaged ({}); refusing to delete anything. Run `levcs verify` \
             to see what is damaged.",
            p.object,
            p.what
        );
    }
    let reachable = report.reachable;
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
    if m & 0o111 != 0 {
        0o111
    } else {
        0
    }
}

#[cfg(not(unix))]
fn file_mode_bits(_meta: &fs::Metadata) -> u8 {
    0
}

#[allow(dead_code)]
fn _refs_unused(_: Refs) {}
#[allow(dead_code)]
fn _ctx_keep(_: &SecretKey) {}
