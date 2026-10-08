//! Publication from the command line: `doc/authority-semantics.md`, Rule P.
//!
//! Without an instance, a repository's authoritative state is its own
//! branch, release and authority refs. So every local command that moves one
//! of them publishes:
//! - `commit` on a branch, including a merge's commit;
//! - a fast-forward `merge`;
//! - `branch --create` and `--delete`;
//! - `release`;
//! - `authority add`, `remove` and `promote`;
//! - `fork`'s first branch.
//!
//! None of these checked Rule P. `branch --create` or a fast-forward could
//! publish history that was only received, and an authority change on a
//! detached HEAD moved `current` with no boundary commit on any ref.
//!
//! Each now goes through here, in two calls:
//! - [`prepare`] runs admission against the state read under the repository
//!   lock, before anything is written.
//! - [`Prepared::apply`] moves the refs by compare-and-swap after any working
//!   tree is written, as one transaction. If any write fails, every ref it
//!   reached is put back, `current` included, and reported as it reads back.
//!
//! A repository whose own `.levcs/config` names an instance is a workspace
//! of it (see [`mode`]). Its refs are not authoritative: the instance applies Rule P when
//! the work is pushed, against its own published history. Admission is
//! skipped there, and the refs still move only by compare-and-swap.

use anyhow::{anyhow, bail, Result};

use levcs_core::ref_tx::{self, RefChange};
use levcs_core::{ObjectId, Repository};
use levcs_identity::admission::{admit, PreState, RefUpdate, Refused, Transaction};
use levcs_identity::keys::PublicKey;

/// Whether this repository's refs are its published state.
pub enum Mode {
    /// They are, and every move of them is admitted here.
    Standalone,
    /// It is a workspace of an instance, which admits the work on push.
    Workspace,
}

/// The file that marks a repository as having been a workspace.
const WORKSPACE_MARK: &str = "workspace";

/// A workspace's refs move without admission. If the repository later
/// stopped naming its instance, those refs would become its published
/// state, unchecked: once a config failed to parse, a ref moved in
/// workspace mode was published. So becoming a workspace is recorded in
/// `.levcs/workspace`, and a repository marked so but naming no instance
/// publishes nothing. Accepting its refs as published would need an owner
/// to accept them, the decision deferred as D6 for a replica `dial`
/// receives.
const FORMER_WORKSPACE: &str = "this repository has been a workspace of an instance \
    (.levcs/workspace), and its .levcs/config no longer names one. Its refs moved \
    without admission while it was a workspace, so they are not published history \
    here, and it cannot publish as a standalone repository: that would need an owner \
    to accept its state, which has no defined form yet (D6, deferred). Name the \
    instance again (`levcs instance --set <url>`) to go on working as its workspace";

/// Record, durably, that this repository is a workspace. Never undone by
/// levcs: see [`FORMER_WORKSPACE`]. A workspace's refs move only after this
/// succeeds, so an unchecked move never becomes durable without the mark
/// that keeps it from being taken for published history. A mark already
/// present is synced again, with its directory, every time: an earlier
/// attempt whose sync failed left a file that may not be durable.
pub fn mark_workspace(repo: &Repository) -> Result<()> {
    let path = repo.levcs_dir.join(WORKSPACE_MARK);
    if path.exists() {
        std::fs::File::open(&path)?.sync_all()?;
        levcs_core::fsutil::fsync_dir(&repo.levcs_dir)?;
    } else {
        levcs_core::fsutil::replace_file_staged(
            &path,
            b"This repository has been a workspace of an instance. Its refs moved without \
              admission, so levcs will not publish from it as a standalone repository \
              (doc/authority-semantics.md, D6).\n",
            &repo.levcs_dir.join("tmp"),
        )?;
    }
    Ok(())
}

/// Whether this repository is standalone or a workspace, failing closed: a
/// config that cannot be read is an error, and a repository that has been
/// a workspace but names no instance is refused.
pub fn mode(repo: &Repository) -> Result<Mode> {
    let url = crate::fed_cmds::read_instance_url(repo)?;
    let marked = repo.levcs_dir.join(WORKSPACE_MARK).exists();
    match (url, marked) {
        (Some(_), _) => Ok(Mode::Workspace),
        (None, false) => Ok(Mode::Standalone),
        (None, true) => bail!(FORMER_WORKSPACE),
    }
}

/// `S0`: the genesis, the current authority, and the branch and release
/// refs. Never `refs/remote/…`: received refs are records of another
/// replica's state, not this one's.
fn pre_state(repo: &Repository) -> Result<PreState> {
    let genesis = repo
        .genesis_authority()?
        .ok_or_else(|| anyhow!("this repository has no genesis authority"))?;
    let current = repo.current_authority()?;
    let refs = repo
        .refs
        .list_all()?
        .into_iter()
        .filter(|(n, _)| n.starts_with("refs/branches/") || n.starts_with("refs/releases/"))
        .collect();
    Ok(PreState {
        genesis,
        current,
        refs,
    })
}

/// A transaction that admission accepted, or a workspace's, waiting to be
/// applied.
#[must_use = "nothing is published until `apply`"]
pub struct Prepared {
    updates: Vec<RefUpdate>,
    /// `(A0, A1)`, when `current` moves.
    current: Option<(Option<ObjectId>, ObjectId)>,
}

/// Check a publication. `signer` is the key the command acts under; its
/// secret has been loaded, which is as much as a local command can show.
/// Call under the repository lock, and apply under the same lock.
pub fn prepare(
    repo: &Repository,
    signer: Option<&PublicKey>,
    updates: Vec<RefUpdate>,
    authority_update: Option<ObjectId>,
) -> Result<Prepared> {
    let a0 = repo.current_authority()?;
    if let Mode::Workspace = mode(repo)? {
        // A workspace that predates the mark is marked on its first move.
        mark_workspace(repo)?;
    } else {
        let signer = signer
            .ok_or_else(|| anyhow!("publishing here needs a key; name it with --key <label>"))?;
        let s0 = pre_state(repo)?;
        let tx = Transaction {
            signer: *signer,
            updates: updates.clone(),
            authority_update,
        };
        if let Err(r) = admit(&repo.objects, &s0, &tx) {
            let what = match r.kind {
                Refused::Stale => "the repository changed while this was prepared",
                Refused::NotFastForward => "it would rewrite published history",
                Refused::Unauthorized => "the key lacks the role it needs",
                Refused::Invalid => "Rule P forbids it",
            };
            let mut msg = format!("not published: {what}");
            for reason in &r.reasons {
                msg.push_str("\n  ");
                msg.push_str(reason);
            }
            bail!(msg);
        }
    }
    Ok(Prepared {
        updates,
        current: authority_update.map(|a1| (a0, a1)),
    })
}

/// The signer a local publication needs: none in a workspace, otherwise
/// the key `label` names, or the keychain's only key.
pub fn signer_for(repo: &Repository, label: Option<&str>) -> Result<Option<PublicKey>> {
    if let Mode::Workspace = mode(repo)? {
        return Ok(None);
    }
    Ok(Some(crate::ctx::load_secret(label)?.1.public()))
}

impl Prepared {
    /// Move the refs, then `current`, each only from what it held when the
    /// transaction was checked, as one transaction. If any write fails,
    /// every ref it reached is read back and put back, `current` included:
    /// a write can land and still fail. The error says which refs read
    /// back as they were and which do not.
    pub fn apply(self, repo: &Repository) -> Result<()> {
        let mut changes: Vec<RefChange> = self
            .updates
            .into_iter()
            .map(|u| RefChange {
                name: u.name,
                expected: u.expected,
                new: u.new,
            })
            .collect();
        if let Some((a0, a1)) = self.current {
            changes.push(RefChange {
                name: "refs/authority/current".into(),
                expected: a0,
                new: Some(a1),
            });
        }
        ref_tx::apply(&repo.refs, &changes).map_err(|e| anyhow!("not published: {e}"))
    }
}

/// One ref update.
pub fn update(name: String, expected: Option<ObjectId>, new: Option<ObjectId>) -> RefUpdate {
    RefUpdate {
        name,
        expected,
        new,
        force: false,
    }
}
