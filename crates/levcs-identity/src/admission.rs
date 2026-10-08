//! Admission: `doc/authority-semantics.md`, Rule P.
//!
//! Publication changes a repository's authoritative state. That is a push to
//! its instance or, for a repository with no instance, any local command
//! that moves a branch, release or authority ref. Each publication is
//! checked here against one pre-transaction state `S0`. The caller reads it
//! under the lock it will write under, and nothing in the transaction can
//! change it.
//!
//! - **`A0` and `R0`.** `A0` is the current authority. `R0` is the commits
//!   and releases the authoritative refs already reach. An object merely
//!   present in the store, or reached only by `refs/remote/…`, is not in
//!   `R0`, so it cannot grandfather itself.
//! - **P.1.** The transaction's signer holds at least `Contributor` in `A0`.
//!   An authority the request names is never used.
//! - **P.2.** Every newly exposed commit and release passes Rule H and cites
//!   `A0` exactly. Newly exposed means reached by a new ref value and not in
//!   `R0`, however it got into the store.
//!   - The one exception is a single boundary commit. It cites `A0` and
//!     installs a direct successor `A1`.
//!   - Nothing else in the transaction may cite or install `A1`.
//!   - Work made under another authority needs adoption (D1). Adoption's
//!     record has no defined format yet, so that work is refused.
//! - **P.3.** `current` moves only with that boundary, from `A0` to `A1`. A
//!   transaction cannot express any other change to `refs/authority/*`.
//! - **P.4.** A protected branch needs `Maintainer`. A non-fast-forward
//!   update needs `Maintainer` and must be forced. Ancestry is walked only
//!   over objects read and hash-checked here.
//! - **Completeness.** Newly exposed history must be complete. Every object
//!   its trees reach, and its parents' trees do not, must be present,
//!   intact and of the right type.
//!
//! A fork commit is accepted only as a repository's first publication: one
//! create-only branch, into an empty repository whose current authority is
//! still its genesis. That genesis is the authority the fork cites and
//! installs. The source history behind it is checked under Rule H against
//! the source's own genesis. This is the v1 form of the frozen v2
//! contract's `ForkProofV2` path.
//!
//! Admission only decides. The caller applies the updates if it returns
//! `Ok`, still under the lock it read `S0` under, and moves `current` by
//! compare-and-swap from `A0` to [`Admitted::new_current`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use levcs_core::object::{ObjectType, SignedObject};
use levcs_core::{Commit, EntryType, ObjectId, RawObject, Release, Tree};

use crate::authority::Role;
use crate::history::Walker;
use crate::keys::PublicKey;
use crate::verify::{locate_new_authority, ObjectSource};

/// The authoritative state before the transaction, `S0`.
#[derive(Clone, Debug)]
pub struct PreState {
    /// The genesis that `repo_id` pins.
    pub genesis: ObjectId,
    /// `A0`, `refs/authority/current`. With none, nothing can be published.
    /// A replica received under v1 has none until an owner of the received
    /// authority accepts the bootstrap, and that statement has no defined
    /// format yet (D6, deferred).
    pub current: Option<ObjectId>,
    /// The authoritative branch and release refs, by full name. Never
    /// `refs/remote/…`.
    pub refs: BTreeMap<String, ObjectId>,
}

/// One ref change, compared against `S0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefUpdate {
    /// `refs/branches/<name>` or `refs/releases/<name>`.
    pub name: String,
    /// What the ref held when the transaction was made. `None` creates it.
    pub expected: Option<ObjectId>,
    /// What it will hold. `None` deletes it.
    pub new: Option<ObjectId>,
    /// Allows a non-fast-forward update, which also needs `Maintainer`.
    pub force: bool,
}

#[derive(Clone, Debug)]
pub struct Transaction {
    /// The key the transaction is made under: a push's signer, or a local
    /// command's key, whose secret the command has loaded.
    pub signer: PublicKey,
    pub updates: Vec<RefUpdate>,
    /// `A1`, when the transaction moves `current`.
    pub authority_update: Option<ObjectId>,
}

/// Why a transaction was refused, by what a caller can do about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A ref was not where the transaction expected: `S0` has moved.
    Stale,
    /// A non-fast-forward update that was not forced.
    NotFastForward,
    /// The signer lacks a role the transaction needs, or there is no
    /// current authority to hold one in.
    Unauthorized,
    /// The transaction would publish what Rule P forbids, or history that
    /// is invalid, incomplete or damaged.
    Invalid,
}

#[derive(Clone, Debug)]
pub struct Refusal {
    pub kind: Refused,
    pub reasons: Vec<String>,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reasons.join("; "))
    }
}

impl std::error::Error for Refusal {}

/// What an admitted transaction publishes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Admitted {
    /// Newly exposed commits of this repository's own history.
    pub commits: usize,
    /// Newly exposed commits behind a fork boundary, checked against the
    /// source's genesis.
    pub foreign_commits: usize,
    pub releases: usize,
    /// `A1`, which `current` moves to by compare-and-swap from `A0`.
    pub new_current: Option<ObjectId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kind {
    Commit,
    Release,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Commit => "commit",
            Kind::Release => "release",
        }
    }
}

/// What a ref of this name must point at. Only branches and releases can be
/// updated. `refs/authority/*` moves only through `authority_update`.
fn ref_kind(name: &str) -> Option<Kind> {
    let (kind, rest) = match name.strip_prefix("refs/branches/") {
        Some(r) => (Kind::Commit, r),
        None => (Kind::Release, name.strip_prefix("refs/releases/")?),
    };
    if levcs_core::refs::validate_ref_name(name).is_err()
        || rest
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return None;
    }
    Some(kind)
}

fn refuse<T>(kind: Refused, reasons: Vec<String>) -> Result<T, Refusal> {
    Err(Refusal { kind, reasons })
}

/// An object, read and checked against its id.
fn read<S: ObjectSource>(src: &S, id: ObjectId) -> Result<(Vec<u8>, RawObject), String> {
    let bytes = src
        .read_raw(id)
        .map_err(|e| format!("{id} cannot be read: {e}"))?;
    if *blake3::hash(&bytes).as_bytes() != id.0 {
        return Err(format!("{id}: its stored bytes do not hash to its id"));
    }
    let raw = RawObject::parse(&bytes).map_err(|e| format!("{id} is malformed: {e}"))?;
    Ok((bytes, raw))
}

enum Node {
    Commit(Commit),
    Release(Release),
}

impl Node {
    /// Where history continues from this object.
    fn links(&self) -> Vec<(ObjectId, Kind)> {
        match self {
            Node::Commit(c) => c.parents.iter().map(|p| (*p, Kind::Commit)).collect(),
            Node::Release(r) => {
                let mut v = vec![(r.predecessor, Kind::Commit)];
                if !r.parent_release.is_zero() {
                    v.push((r.parent_release, Kind::Release));
                }
                v
            }
        }
    }
}

fn node<S: ObjectSource>(src: &S, id: ObjectId, want: Kind) -> Result<Node, String> {
    let (bytes, raw) = read(src, id)?;
    let signed = || SignedObject::parse(&bytes).map_err(|e| format!("{id} is malformed: {e}"));
    match (want, raw.object_type) {
        (Kind::Commit, ObjectType::Commit) => Commit::from_signed(&signed()?)
            .map(Node::Commit)
            .map_err(|e| format!("{id} is a malformed commit: {e}")),
        (Kind::Release, ObjectType::Release) => Release::from_signed(&signed()?)
            .map(Node::Release)
            .map_err(|e| format!("{id} is a malformed release: {e}")),
        (_, t) => Err(format!(
            "{id} is a {}, where a {} is required",
            t.name(),
            want.name()
        )),
    }
}

/// Whether `from` reaches `to` along the links recorded while walking.
fn reaches(links: &HashMap<ObjectId, Vec<ObjectId>>, from: ObjectId, to: ObjectId) -> bool {
    let mut stack = vec![from];
    let mut seen = HashSet::new();
    while let Some(id) = stack.pop() {
        if id == to {
            return true;
        }
        if seen.insert(id) {
            if let Some(next) = links.get(&id) {
                stack.extend(next.iter().copied());
            }
        }
    }
    false
}

/// What a tree link requires of the object it names. Where a tree sits
/// decides what `authority` in it must be: an authority under a root
/// tree's `.levcs`, a blob anywhere else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum At {
    Root,
    Levcs,
    Plain,
    Blob,
    Authority,
}

/// Objects found complete, by what their link required and the genesis of
/// the history they belong to: an id alone says neither. An object is
/// entered only once everything it reaches has been checked, so a result
/// is never reused before its dependencies are validated. `failed` holds
/// those found wanting, whose problem is already reported, so that a tree
/// naming one many times is not checked many times.
#[derive(Default)]
struct Done {
    ok: HashSet<(ObjectId, At, ObjectId)>,
    failed: HashSet<(ObjectId, At, ObjectId)>,
}

impl Done {
    fn settled(&self, key: &(ObjectId, At, ObjectId)) -> bool {
        self.ok.contains(key) || self.failed.contains(key)
    }
}

/// Check that tree `root`, in history `domain`, and everything it reaches
/// are present, intact, of the type each link requires, and that every
/// authority it holds is valid and of this history: what `verify` checks
/// of the same objects.
///
/// `base` is the same directory in a tree known complete: one in published
/// history, or one already validated here. Entries it shares are skipped.
/// It is never a tree still being checked, so a skip never rests on an
/// unchecked result.
///
/// The walk keeps its own stack: a tree nested thousands deep, which
/// `verify` walks, used to exhaust the process stack here.
fn check_tree<S: ObjectSource>(
    w: &mut Walker<S>,
    root: ObjectId,
    domain: ObjectId,
    base: Option<ObjectId>,
    done: &mut Done,
    problems: &mut Vec<String>,
) {
    enum Step {
        /// Check a tree, with the same directory of a complete tree.
        Enter(ObjectId, At, Option<ObjectId>),
        /// Every entry of the tree has been checked. `usize` is how many
        /// problems there were when it was entered; `bool`, whether an
        /// entry had already failed elsewhere.
        Leave(ObjectId, At, usize, bool),
    }
    let src = w.source();
    let mut steps = vec![Step::Enter(root, At::Root, base)];
    while let Some(step) = steps.pop() {
        let (id, at, base) = match step {
            Step::Leave(id, at, before, tainted) => {
                if !tainted && problems.len() == before {
                    done.ok.insert((id, at, domain));
                } else {
                    done.failed.insert((id, at, domain));
                }
                continue;
            }
            Step::Enter(id, at, base) => (id, at, base),
        };
        if done.settled(&(id, at, domain)) {
            continue;
        }
        let before = problems.len();
        let tree = match read(src, id) {
            Ok((_, raw)) if raw.object_type == ObjectType::Tree => {
                match Tree::parse_body(&raw.body) {
                    Ok(t) => t,
                    Err(e) => {
                        problems.push(format!("tree {id} is malformed: {e}"));
                        done.failed.insert((id, at, domain));
                        continue;
                    }
                }
            }
            Ok((_, raw)) => {
                problems.push(format!(
                    "{id} is a {}, where a tree is required",
                    raw.object_type.name()
                ));
                done.failed.insert((id, at, domain));
                continue;
            }
            Err(e) => {
                problems.push(e);
                done.failed.insert((id, at, domain));
                continue;
            }
        };
        let base: HashMap<String, (EntryType, ObjectId)> = base
            .and_then(|b| read(src, b).ok())
            .filter(|(_, raw)| raw.object_type == ObjectType::Tree)
            .and_then(|(_, raw)| Tree::parse_body(&raw.body).ok())
            .map(|t| {
                t.entries
                    .into_iter()
                    .map(|e| (e.name, (e.entry_type, e.hash)))
                    .collect()
            })
            .unwrap_or_default();
        let mut children = Vec::new();
        let mut tainted = false;
        for e in &tree.entries {
            let old = base.get(&e.name).copied();
            if old == Some((e.entry_type, e.hash)) {
                continue;
            }
            let next = match (at, e.name.as_str(), e.entry_type) {
                (At::Root, ".levcs", EntryType::Tree) => At::Levcs,
                (_, _, EntryType::Tree) => At::Plain,
                (At::Levcs, "authority", EntryType::Blob) => At::Authority,
                (_, _, EntryType::Blob) => At::Blob,
            };
            if done.ok.contains(&(e.hash, next, domain)) {
                continue;
            }
            if done.failed.contains(&(e.hash, next, domain)) {
                tainted = true;
                continue;
            }
            if matches!(next, At::Levcs | At::Plain | At::Root) {
                let old_tree = old.filter(|(t, _)| *t == EntryType::Tree).map(|(_, h)| h);
                children.push(Step::Enter(e.hash, next, old_tree));
                continue;
            }
            let want = if next == At::Authority {
                ObjectType::Authority
            } else {
                ObjectType::Blob
            };
            let found = match read(src, e.hash) {
                Ok((_, raw)) if raw.object_type != want => Err(format!(
                    "{} is a {}, where a {} is required",
                    e.hash,
                    raw.object_type.name(),
                    want.name()
                )),
                Ok(_) if next == At::Authority => match w.genesis_of(e.hash) {
                    Ok(g) if g == domain => Ok(()),
                    Ok(g) => Err(format!(
                        "authority {} descends from another genesis ({g})",
                        e.hash
                    )),
                    Err(err) => Err(format!("authority {}: {err}", e.hash)),
                },
                Ok(_) => Ok(()),
                Err(err) => Err(err),
            };
            match found {
                Ok(()) => {
                    done.ok.insert((e.hash, next, domain));
                }
                Err(why) => {
                    problems.push(why);
                    done.failed.insert((e.hash, next, domain));
                }
            }
        }
        // Left only after every subtree below it, which is pushed after.
        steps.push(Step::Leave(id, at, before, tainted));
        steps.extend(children);
    }
}

/// Decide whether `tx` may be published over `s0`.
pub fn admit<S: ObjectSource>(
    src: &S,
    s0: &PreState,
    tx: &Transaction,
) -> Result<Admitted, Refusal> {
    // The transaction's shape. Only branch and release refs can be named.
    let mut shape = Vec::new();
    let mut names = HashSet::new();
    for u in &tx.updates {
        if ref_kind(&u.name).is_none() {
            shape.push(format!(
                "{} cannot be published: only refs/branches/* and refs/releases/* can, and \
                 refs/authority/current moves only with its boundary commit (P.3)",
                u.name
            ));
        }
        if !names.insert(u.name.as_str()) {
            shape.push(format!("{} is updated twice", u.name));
        }
        if u.new.is_none() && u.expected.is_none() {
            shape.push(format!("deleting {} must name what it holds", u.name));
        }
    }
    if !shape.is_empty() {
        return refuse(Refused::Invalid, shape);
    }

    // Every comparison against S0, before anything else is looked at.
    let stale: Vec<String> = tx
        .updates
        .iter()
        .filter_map(|u| {
            let actual = s0.refs.get(&u.name).copied();
            (actual != u.expected).then(|| {
                let show = |v: Option<ObjectId>| v.map_or("nothing".to_string(), |i| i.to_hex());
                format!(
                    "{} holds {}, not {}: it changed since the transaction was made",
                    u.name,
                    show(actual),
                    show(u.expected)
                )
            })
        })
        .collect();
    if !stale.is_empty() {
        return refuse(Refused::Stale, stale);
    }

    // A0, pinned to this repository's genesis.
    let Some(a0) = s0.current else {
        return refuse(
            Refused::Unauthorized,
            vec![
                "this repository has no current authority, so nothing can be published \
                 from it. A replica received under v1 keeps that history under \
                 refs/remote/… until an owner of the received authority accepts the \
                 bootstrap, and that statement has no defined format yet (D6, deferred)"
                    .into(),
            ],
        );
    };
    let mut w = Walker::new(src);
    // A0 and the authorities before it: the only ones newly exposed history
    // may carry, outside an authority change's boundary commit.
    let (a0_body, a0_lineage): (_, HashSet<ObjectId>) = match w.authority(a0) {
        Ok(a) if *a.chain.last().unwrap() == s0.genesis => {
            (a.body.clone(), a.chain.iter().copied().collect())
        }
        Ok(_) => {
            return refuse(
                Refused::Invalid,
                vec![format!(
                    "the current authority {a0} does not descend from this repository's \
                     genesis {}",
                    s0.genesis
                )],
            )
        }
        Err(e) => {
            return refuse(
                Refused::Invalid,
                vec![format!("the current authority {a0}: {e}")],
            )
        }
    };

    // P.1.
    let role = match a0_body.find_member(&tx.signer) {
        Some(m) if m.role >= Role::Contributor => m.role,
        Some(m) => {
            return refuse(
                Refused::Unauthorized,
                vec![format!(
                    "{} is a {} of the current authority; publishing needs a contributor",
                    tx.signer,
                    m.role.name()
                )],
            )
        }
        None => {
            return refuse(
                Refused::Unauthorized,
                vec![format!(
                    "{} is not a member of the current authority {a0}",
                    tx.signer
                )],
            )
        }
    };

    // R0: everything the authoritative refs already reach, each object
    // with the type its link requires and the genesis of the history it
    // belongs to. Behind a fork commit that is the source's genesis, read
    // from the authority the parent cites (`None` until it is read).
    // `links` records every edge walked here and below, so that ancestry
    // is decided only over objects read and checked. The trees of published
    // commits and releases are complete by admission, and serve as bases.
    let mut links: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
    let mut r0: HashSet<(ObjectId, Kind, ObjectId)> = HashSet::new();
    let mut r0_trees: HashMap<(ObjectId, ObjectId), ObjectId> = HashMap::new();
    {
        let mut stack: Vec<(ObjectId, Kind, Option<ObjectId>)> = Vec::new();
        for (name, id) in &s0.refs {
            match ref_kind(name) {
                Some(k) => stack.push((*id, k, Some(s0.genesis))),
                None => {
                    return refuse(
                        Refused::Invalid,
                        vec![format!(
                            "{name} is not an authoritative branch or release ref"
                        )],
                    )
                }
            }
        }
        let damaged = |e: String| -> Result<Admitted, Refusal> {
            refuse(
                Refused::Invalid,
                vec![format!(
                    "the published history is damaged ({e}); nothing can be published \
                     over it until it is repaired"
                )],
            )
        };
        while let Some((id, kind, domain)) = stack.pop() {
            if domain.is_some_and(|d| r0.contains(&(id, kind, d))) {
                continue;
            }
            let n = match node(src, id, kind) {
                Ok(n) => n,
                Err(e) => return damaged(e),
            };
            let domain = match (domain, &n) {
                (Some(d), _) => d,
                (None, Node::Commit(c)) => match w.genesis_of(c.authority) {
                    Ok(g) => g,
                    Err(e) => return damaged(format!("fork source {id}: {e}")),
                },
                (None, Node::Release(_)) => unreachable!("only a commit's parent is foreign"),
            };
            if !r0.insert((id, kind, domain)) {
                continue;
            }
            let next = n.links();
            links.insert(id, next.iter().map(|(i, _)| *i).collect());
            let behind = match &n {
                Node::Commit(c) if c.flags.is_fork() => None,
                _ => Some(domain),
            };
            match &n {
                Node::Commit(c) => r0_trees.insert((id, domain), c.tree),
                Node::Release(r) => r0_trees.insert((id, domain), r.tree),
            };
            stack.extend(next.into_iter().map(|(i, k)| (i, k, behind)));
        }
    }

    // Newly exposed: reached by a new ref value, as a link of the type it
    // requires in the history it belongs to, and not in R0 as that.
    let mut exposed_commits: HashMap<(ObjectId, ObjectId), Commit> = HashMap::new();
    let mut exposed_releases: Vec<(ObjectId, Release)> = Vec::new();
    {
        let mut missing = Vec::new();
        let mut stack: Vec<(ObjectId, Kind, Option<ObjectId>)> = Vec::new();
        for u in &tx.updates {
            if let Some(n) = u.new {
                stack.push((n, ref_kind(&u.name).unwrap(), Some(s0.genesis)));
            }
        }
        let mut seen: HashSet<(ObjectId, Kind, ObjectId)> = HashSet::new();
        while let Some((id, kind, domain)) = stack.pop() {
            if domain.is_some_and(|d| r0.contains(&(id, kind, d)) || seen.contains(&(id, kind, d)))
            {
                continue;
            }
            let n = match node(src, id, kind) {
                Ok(n) => n,
                Err(e) => {
                    missing.push(e);
                    continue;
                }
            };
            let domain = match (domain, &n) {
                (Some(d), _) => d,
                (None, Node::Commit(c)) => match w.genesis_of(c.authority) {
                    Ok(g) => g,
                    Err(e) => {
                        missing.push(format!("fork source commit {id}: {e}"));
                        continue;
                    }
                },
                (None, Node::Release(_)) => unreachable!("only a commit's parent is foreign"),
            };
            if r0.contains(&(id, kind, domain)) || !seen.insert((id, kind, domain)) {
                continue;
            }
            let next = n.links();
            links.insert(id, next.iter().map(|(i, _)| *i).collect());
            match n {
                Node::Commit(c) => {
                    let behind = if c.flags.is_fork() {
                        None
                    } else {
                        Some(domain)
                    };
                    stack.extend(next.into_iter().map(|(i, k)| (i, k, behind)));
                    exposed_commits.insert((id, domain), c);
                }
                Node::Release(r) => {
                    stack.extend(next.into_iter().map(|(i, k)| (i, k, Some(domain))));
                    exposed_releases.push((id, r));
                }
            }
        }
        if !missing.is_empty() {
            missing.insert(
                0,
                "the history this would publish is incomplete or damaged".into(),
            );
            return refuse(Refused::Invalid, missing);
        }
    }

    // P.4, over the post-transaction refs.
    let mut post = s0.refs.clone();
    for u in &tx.updates {
        match u.new {
            Some(n) => post.insert(u.name.clone(), n),
            None => post.remove(&u.name),
        };
    }
    let protected = a0_body.protected_branches();
    let mut unforced = Vec::new();
    let mut denied = Vec::new();
    for u in &tx.updates {
        if let Some(branch) = u.name.strip_prefix("refs/branches/") {
            let hit = protected.iter().any(|pat| {
                glob::Pattern::new(pat)
                    .map(|p| p.matches(branch) || p.matches(&u.name))
                    .unwrap_or(false)
            });
            if hit && role < Role::Maintainer {
                denied.push(format!(
                    "{} is protected: updating it needs a maintainer, and the signer is a {}",
                    u.name,
                    role.name()
                ));
            }
        }
        let rewrite = match (u.expected, u.new) {
            (Some(old), Some(new)) if old != new && !reaches(&links, new, old) => Some(format!(
                "{} would move from {old} to {new}, which does not descend from it",
                u.name
            )),
            (Some(old), None) if !post.values().any(|v| reaches(&links, *v, old)) => Some(format!(
                "deleting {} would unpublish {old}, which no remaining ref reaches",
                u.name
            )),
            _ => None,
        };
        if let Some(what) = rewrite {
            if !u.force {
                unforced.push(format!("{what}; it must be forced"));
            } else if role < Role::Maintainer {
                denied.push(format!(
                    "{what}; a forced update needs a maintainer, and the signer is a {}",
                    role.name()
                ));
            }
        }
    }
    if !unforced.is_empty() {
        return refuse(Refused::NotFastForward, unforced);
    }
    if !denied.is_empty() {
        return refuse(Refused::Unauthorized, denied);
    }

    // P.2 and Rule H, for every newly exposed commit and release, parents
    // first: a commit's tree is checked against its first parent's only
    // once that tree is known complete.
    let mut problems: Vec<String> = Vec::new();
    let a1 = tx.authority_update;
    let mut admitted = Admitted::default();
    let mut boundaries: Vec<(ObjectId, Option<ObjectId>)> = Vec::new();
    let mut forks: Vec<(ObjectId, Commit)> = Vec::new();
    let mut done = Done::default();
    // An authority a tree carries that is not A0 or one before it. Only the
    // boundary may introduce one, and only A1 (the v2 contract, §6.1): an
    // authority descending from A1 references it too, so a check for A1
    // alone let one through on a side branch.
    let beyond_a0 = |tree: ObjectId| -> Option<ObjectId> {
        locate_new_authority(src, tree)
            .ok()
            .filter(|x| !a0_lineage.contains(x))
    };
    // The tree of commit `p` in history `domain`, if it is known complete.
    let complete_tree = |p: ObjectId,
                         domain: ObjectId,
                         exposed: &HashMap<(ObjectId, ObjectId), Commit>,
                         done: &Done|
     -> Option<ObjectId> {
        if let Some(t) = r0_trees.get(&(p, domain)) {
            return Some(*t);
        }
        exposed
            .get(&(p, domain))
            .map(|c| c.tree)
            .filter(|t| done.ok.contains(&(*t, At::Root, domain)))
    };
    let mut order: Vec<(ObjectId, ObjectId)> = Vec::new();
    {
        let mut state: HashMap<(ObjectId, ObjectId), bool> = HashMap::new();
        let mut keys: Vec<(ObjectId, ObjectId)> = exposed_commits.keys().copied().collect();
        keys.sort();
        for root in keys {
            let mut stack = vec![(root, false)];
            while let Some((key, expanded)) = stack.pop() {
                if expanded {
                    if state.insert(key, true) != Some(true) {
                        order.push(key);
                    }
                    continue;
                }
                if state.contains_key(&key) {
                    continue;
                }
                state.insert(key, false);
                stack.push((key, true));
                let c = &exposed_commits[&key];
                for p in &c.parents {
                    let pk = if c.flags.is_fork() {
                        exposed_commits.keys().find(|(i, _)| i == p).copied()
                    } else {
                        Some((*p, key.1))
                    };
                    if let Some(pk) = pk.filter(|pk| exposed_commits.contains_key(pk)) {
                        if !state.contains_key(&pk) {
                            stack.push((pk, false));
                        }
                    }
                }
            }
        }
    }
    for (id, domain) in order {
        let c = exposed_commits[&(id, domain)].clone();
        let mut here = Vec::new();
        let base = if c.flags.is_fork() {
            None
        } else {
            c.parents
                .first()
                .and_then(|p| complete_tree(*p, domain, &exposed_commits, &done))
        };
        check_tree(&mut w, c.tree, domain, base, &mut done, &mut here);
        let (cited, installed) = w.check_commit(id, domain, &mut here);
        if domain != s0.genesis {
            // Behind a fork boundary: the source's history, under Rule H
            // against the source's genesis. It was published there.
            admitted.foreign_commits += 1;
        } else {
            admitted.commits += 1;
            if let Some(other) = cited.filter(|c| *c != a0) {
                here.push(format!(
                    "cites authority {other}, not the current authority {a0}. Work made \
                     under another authority is published only by adoption (D1), and \
                     adoption's record has no defined format yet, so it cannot be published"
                ));
            }
            if c.flags.is_fork() {
                forks.push((id, c.clone()));
            } else if c.flags.modifies_authority() {
                boundaries.push((id, installed));
            } else if let Some(x) = beyond_a0(c.tree) {
                here.push(format!(
                    "carries authority {x}, which is not the current authority or one \
                     before it; only an authority change's boundary commit introduces an \
                     authority"
                ));
            }
        }
        problems.extend(here.into_iter().map(|p| format!("commit {id}: {p}")));
    }
    for (id, r) in &exposed_releases {
        let mut here = Vec::new();
        let base = complete_tree(r.predecessor, s0.genesis, &exposed_commits, &done);
        check_tree(&mut w, r.tree, s0.genesis, base, &mut done, &mut here);
        let cited = w.check_release(*id, s0.genesis, &mut here);
        admitted.releases += 1;
        if let Some(other) = cited.filter(|c| *c != a0) {
            here.push(format!(
                "cites authority {other}, not the current authority {a0}. Releases are \
                 published under the current authority only"
            ));
        }
        if let Some(x) = beyond_a0(r.tree) {
            here.push(format!(
                "carries authority {x}, which is not the current authority or one before it"
            ));
        }
        problems.extend(here.into_iter().map(|p| format!("release {id}: {p}")));
    }

    // P.3: current moves with exactly one boundary, to what it installs.
    match (a1, boundaries.as_slice()) {
        (None, []) => {}
        (None, bs) => {
            for (b, installed) in bs {
                problems.push(format!(
                    "commit {b} changes the authority{}, but the transaction does not move \
                     current with it",
                    installed.map_or(String::new(), |i| format!(" to {i}"))
                ));
            }
        }
        (Some(a1), []) => problems.push(format!(
            "current would move to {a1}, but no commit in the transaction installs it; \
             current moves only with its boundary commit (P.3)"
        )),
        (Some(a1), [(b, installed)]) => {
            if *installed != Some(a1) {
                problems.push(format!(
                    "current would move to {a1}, but its boundary commit {b} installs {}",
                    installed.map_or("nothing valid".to_string(), |i| i.to_hex())
                ));
            }
        }
        (Some(_), bs) => problems.push(format!(
            "{} commits change the authority; a transaction publishes one boundary",
            bs.len()
        )),
    }
    admitted.new_current = a1;

    // A fork is the destination's first publication, and only that.
    match forks.as_slice() {
        [] => {}
        [(id, c)] => {
            let first = s0.refs.is_empty()
                && a0 == s0.genesis
                && a1.is_none()
                && matches!(tx.updates.as_slice(), [u] if u.expected.is_none()
                    && u.new.is_some() && u.name.starts_with("refs/branches/"));
            if !first {
                problems.push(format!(
                    "fork commit {id} can be published only as the first, create-only \
                     branch of an empty repository whose current authority is its genesis"
                ));
            }
            match locate_new_authority(src, c.tree) {
                Ok(g) if g == s0.genesis => {}
                _ => problems.push(format!(
                    "fork commit {id} must install this repository's genesis {}",
                    s0.genesis
                )),
            }
            // The v2 contract's fork rule: the transaction is the fork
            // commit's signer's, an owner of this repository's genesis.
            if c.author_key != tx.signer.0 {
                problems.push(format!(
                    "fork commit {id} is published only by its signer, {}",
                    PublicKey(c.author_key)
                ));
            }
            if role != Role::Owner {
                problems.push(format!(
                    "fork commit {id} is published only by an owner; the signer is a {}",
                    role.name()
                ));
            }
        }
        fs => problems.push(format!(
            "{} fork commits; a repository begins with one",
            fs.len()
        )),
    }

    if !problems.is_empty() {
        return refuse(Refused::Invalid, problems);
    }
    Ok(admitted)
}
