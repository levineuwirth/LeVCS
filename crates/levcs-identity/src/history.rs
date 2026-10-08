//! Whole-history verification: `doc/authority-semantics.md`, Rule H.
//!
//! `levcs verify` used to check one commit (HEAD) and the current authority
//! chain, and printed `verify: ok` over a store with hundreds of corrupt
//! objects behind HEAD. This walks everything the given roots reach and
//! checks every object.
//!
//! **Integrity.**
//! - Every object's bytes must hash to its id.
//! - Every link must point at the type it names. A branch names a commit, a
//!   commit's tree slot a tree, a `Blob` tree entry a blob. The one
//!   exception is `.levcs/authority`, a `Blob` entry that holds an authority.
//!
//! **Authorities.** Every reachable authority is checked: its chain back to
//! genesis, every signature on it, and that its genesis is the genesis of
//! the history it was reached through.
//!
//! **Rule H**, for every commit:
//! - **H.1:** it is signed by a member of the authority it cites, holding
//!   `Owner` if it changes authority and `Contributor` otherwise. There is no
//!   protected-ref check, because a commit does not record its ref.
//! - **H.2:** that authority's chain ends at the genesis of the history it
//!   belongs to.
//! - **H.3:** for every parent, the cited authority equals or descends from
//!   the authority in effect after that parent. After an authority-changing
//!   parent, that is the successor the parent installs.
//! - **H.4:** a root commit cites the genesis.
//! - **H.5:** an installed successor is a valid direct successor with at
//!   least one `Owner`.
//!
//! **Releases.** A release's declarer holds `Maintainer` in the authority it
//! cites, and that authority equals or descends from the one in effect after
//! its predecessor (D5).
//!
//! **Forks.** A fork commit's parent begins another repository's history.
//! The walk carries that repository's genesis across the boundary, taken
//! from the authority the parent cites, and applies the same rules to the
//! source history against the source's genesis.
//!
//! **Conflicting lineages (D2).** Every authority this repository's history
//! cites or installs, and every authority its releases cite, is classified
//! against the canonical lineage ending at `refs/authority/current`.

use std::collections::{HashMap, HashSet};

use levcs_core::object::{ObjectType, SignedObject};
use levcs_core::{Commit, ObjectId, RawObject, Release, Tree};

use crate::authority::{AuthorityBody, Role};
use crate::keys::PublicKey;
use crate::verify::{
    self, locate_new_authority, read_signed, verify_authority_step, verify_signed_object,
    ObjectSource, VerifyError,
};

#[derive(Clone, Debug)]
pub struct Problem {
    pub object: ObjectId,
    pub what: String,
    /// Damage to the store or its links: unreadable, malformed or
    /// mis-typed objects and refs. Anything else is a rule violation in
    /// intact history. `gc` refuses on damage, because damage makes
    /// reachability unknowable; it does not refuse on rule violations,
    /// which cannot be repaired without rewriting history.
    pub integrity: bool,
}

#[derive(Debug, Default)]
pub struct HistoryReport {
    pub roots: usize,
    pub commits: usize,
    pub trees: usize,
    pub blobs: usize,
    pub releases: usize,
    pub authorities: usize,
    /// Commits behind a fork boundary, checked against the source's genesis.
    pub foreign_commits: usize,
    /// Invalid: missing, unreadable or malformed objects, bad hashes or
    /// signatures, wrong object types, unauthorized roles, broken or foreign
    /// chains, Rule H.
    pub problems: Vec<Problem>,
    /// Valid, but citing or installing an authority incomparable with the
    /// canonical lineage.
    pub conflicting: Vec<Problem>,
    /// Every object the typed walk reached, read, and found to be of the
    /// type its link requires. `gc` keeps exactly these.
    pub reachable: HashSet<ObjectId>,
}

impl HistoryReport {
    /// Valid, with nothing on a conflicting lineage.
    pub fn ok(&self) -> bool {
        self.problems.is_empty() && self.conflicting.is_empty()
    }
}

/// The type a link requires of the object it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Expect {
    Commit,
    Release,
    Authority,
    Blob,
    /// A commit's or release's root tree, where `.levcs` may appear.
    RootTree,
    /// The `.levcs` directory, where `authority` names an authority.
    LevcsTree,
    Tree,
}

impl Expect {
    fn admits(self, t: ObjectType) -> bool {
        matches!(
            (self, t),
            (Expect::Commit, ObjectType::Commit)
                | (Expect::Release, ObjectType::Release)
                | (Expect::Authority, ObjectType::Authority)
                | (Expect::Blob, ObjectType::Blob)
                | (Expect::RootTree, ObjectType::Tree)
                | (Expect::LevcsTree, ObjectType::Tree)
                | (Expect::Tree, ObjectType::Tree)
        )
    }

    fn name(self) -> &'static str {
        match self {
            Expect::Commit => "commit",
            Expect::Release => "release",
            Expect::Authority => "authority",
            Expect::Blob => "blob",
            Expect::RootTree | Expect::LevcsTree | Expect::Tree => "tree",
        }
    }

    /// What a ref of this name must point at, by the namespace's structure:
    /// `refs/{branches,releases}/<name>`, `refs/authority/<name>`, and the
    /// remote copies `refs/remote/<remote>/{branches,releases}/<name>`. A
    /// name's own components never decide it: a release called `branches`
    /// is still a release.
    fn for_ref(name: &str) -> Option<Expect> {
        if matches!(name, "HEAD" | "MERGE_HEAD" | "MERGE_BASE") {
            return Some(Expect::Commit);
        }
        let parts: Vec<&str> = name.split('/').collect();
        let kind = |ns: &str| match ns {
            "branches" => Some(Expect::Commit),
            "releases" => Some(Expect::Release),
            _ => None,
        };
        match parts.as_slice() {
            ["refs", "authority", _] => Some(Expect::Authority),
            ["refs", "remote", _, ns, rest @ ..] if !rest.is_empty() => kind(ns),
            ["refs", ns, rest @ ..] if !rest.is_empty() && *ns != "remote" => kind(ns),
            _ => None,
        }
    }
}

/// A verified authority and its chain, newest first, ending at its genesis.
pub(crate) struct Auth {
    pub(crate) body: AuthorityBody,
    pub(crate) chain: Vec<ObjectId>,
}

/// Rule H, object by object, with the authority chains and effective
/// authorities it needs memoized. Shared with admission, so that a commit
/// is held to exactly the same rules when it is published as when the
/// history holding it is verified.
pub(crate) struct Walker<'a, S: ObjectSource> {
    src: &'a S,
    auth: HashMap<ObjectId, Result<Auth, String>>,
    effective: HashMap<ObjectId, Result<ObjectId, String>>,
}

impl<'a, S: ObjectSource> Walker<'a, S> {
    pub(crate) fn new(src: &'a S) -> Self {
        Walker {
            src,
            auth: HashMap::new(),
            effective: HashMap::new(),
        }
    }

    /// The objects it reads.
    pub(crate) fn source(&self) -> &'a S {
        self.src
    }

    /// `id`'s chain back to a genesis, verified and memoized per authority:
    /// every step, every signature on every authority in it.
    pub(crate) fn authority(&mut self, id: ObjectId) -> Result<&Auth, String> {
        if !self.auth.contains_key(&id) {
            let r = self.verify_chain(id);
            self.auth.insert(id, r);
        }
        self.auth[&id].as_ref().map_err(|e| e.clone())
    }

    fn verify_chain(&mut self, id: ObjectId) -> Result<Auth, String> {
        let mut path: Vec<(ObjectId, SignedObject, AuthorityBody)> = Vec::new();
        let mut cur = id;
        let mut seen = HashSet::new();
        let base: Option<Vec<ObjectId>> = loop {
            if !seen.insert(cur) {
                return Err(format!("authority chain through {cur} loops"));
            }
            if let Some(Ok(known)) = self.auth.get(&cur) {
                break Some(known.chain.clone());
            }
            let signed = read_signed(self.src, cur).map_err(|e| e.to_string())?;
            if signed.object_type != ObjectType::Authority {
                return Err(format!(
                    "{cur} is a {}, not an authority",
                    signed.object_type.name()
                ));
            }
            // Every signature on it, not only the one owner signature a
            // step needs.
            verify_signed_object(&signed)
                .map_err(|e| format!("authority {cur} carries an invalid signature: {e}"))?;
            let body = AuthorityBody::parse(&signed.body).map_err(|e| e.to_string())?;
            let prev = body.previous_authority;
            path.push((cur, signed, body));
            if prev.is_zero() {
                break None;
            }
            cur = prev;
        };
        let mut chain: Vec<ObjectId> = base.clone().unwrap_or_default();
        let mut prev_body: Option<AuthorityBody> = None;
        if base.is_some() {
            prev_body = Some(self.auth[&chain[0]].as_ref().unwrap().body.clone());
        }
        // `path` is newest first; verify from the oldest step forward.
        for (aid, signed, body) in path.iter().rev() {
            match &prev_body {
                None => {
                    verify::verify_genesis(signed).map_err(|e| e.to_string())?;
                }
                Some(pb) => {
                    verify_authority_step(signed, body, pb, chain[0]).map_err(|e| e.to_string())?;
                    // D4, for every successor, cited or installed: an
                    // ownerless authority can never be succeeded.
                    if !body.members.iter().any(|m| m.role == Role::Owner) {
                        return Err(format!(
                            "authority {aid} has no owner; it could never be changed again"
                        ));
                    }
                }
            }
            chain.insert(0, *aid);
            prev_body = Some(body.clone());
        }
        let body = path
            .first()
            .map(|(_, _, b)| b.clone())
            .or(prev_body)
            .ok_or_else(|| format!("empty authority chain at {id}"))?;
        Ok(Auth { body, chain })
    }

    pub(crate) fn genesis_of(&mut self, id: ObjectId) -> Result<ObjectId, String> {
        self.authority(id).map(|a| *a.chain.last().unwrap())
    }

    fn descends(&mut self, newer: ObjectId, older: ObjectId) -> bool {
        match self.authority(newer) {
            Ok(a) => a.chain.contains(&older),
            Err(_) => false,
        }
    }

    /// The authority in effect after commit `id`, memoized.
    fn effective(&mut self, id: ObjectId) -> Result<ObjectId, String> {
        if let Some(r) = self.effective.get(&id) {
            return r.clone();
        }
        let r = (|| {
            let signed = read_signed(self.src, id).map_err(|e| e.to_string())?;
            let c = Commit::from_signed(&signed).map_err(|e| e.to_string())?;
            if c.flags.modifies_authority() {
                locate_new_authority(self.src, c.tree).map_err(|e| e.to_string())
            } else {
                Ok(c.authority)
            }
        })();
        self.effective.insert(id, r.clone());
        r
    }

    /// Rule H for one commit of the history whose genesis is `genesis`.
    /// Returns the authority it cites and, if it changes authority, the one
    /// it installs.
    pub(crate) fn check_commit(
        &mut self,
        id: ObjectId,
        genesis: ObjectId,
        problems: &mut Vec<String>,
    ) -> (Option<ObjectId>, Option<ObjectId>) {
        let signed = match read_signed(self.src, id) {
            Ok(s) => s,
            Err(e) => {
                problems.push(e.to_string());
                return (None, None);
            }
        };
        let c = match Commit::from_signed(&signed) {
            Ok(c) => c,
            Err(e) => {
                problems.push(format!("malformed commit: {e}"));
                return (None, None);
            }
        };
        if signed.signatures.len() != 1 {
            problems.push(format!(
                "has {} signatures, needs exactly 1",
                signed.signatures.len()
            ));
            return (None, None);
        }
        let sig = signed.signatures[0];
        if sig.public_key != c.author_key {
            problems.push("signed by a key other than its author".into());
            return (None, None);
        }
        let author = PublicKey(sig.public_key);
        if author
            .verify(signed.signing_hash().as_bytes(), &sig.signature)
            .is_err()
        {
            problems.push("signature is invalid".into());
            return (None, None);
        }
        let fork = c.flags.is_fork();
        let (body, ends_at) = match self.authority(c.authority) {
            Ok(a) => (a.body.clone(), *a.chain.last().unwrap()),
            Err(e) => {
                problems.push(format!("cites authority {}: {e}", c.authority));
                return (None, None);
            }
        };
        if ends_at != genesis {
            problems.push(format!(
                "cites authority {} whose chain ends at a different genesis ({ends_at})",
                c.authority
            ));
            return (None, None);
        }
        let required = if c.flags.modifies_authority() || fork {
            Role::Owner
        } else {
            Role::Contributor
        };
        match body.find_member(&author) {
            None => problems.push(format!(
                "author is not a member of the authority it cites ({})",
                c.authority
            )),
            Some(m) if m.role < required => problems.push(format!(
                "author has role {}, needs {}",
                m.role.name(),
                required.name()
            )),
            Some(_) => {}
        }
        if fork {
            // The fork's own rules (read authorization at the source, the new
            // genesis in its tree) stay as implemented. Its parent's history
            // is checked separately, against the source's genesis.
            if let Err(e) = verify::verify_commit(self.src, id, None) {
                problems.push(format!("fork commit: {e}"));
            }
            return (Some(c.authority), None);
        }
        if c.parents.is_empty() && c.authority != genesis {
            problems.push("a root commit must cite the genesis authority".into());
        }
        let mut effects = Vec::new();
        for p in &c.parents {
            match self.effective(*p) {
                Ok(e) => effects.push((*p, e)),
                Err(e) => problems.push(format!("parent {p}: {e}")),
            }
        }
        for i in 0..effects.len() {
            for j in i + 1..effects.len() {
                let (a, b) = (effects[i].1, effects[j].1);
                if !self.descends(a, b) && !self.descends(b, a) {
                    problems.push(format!(
                        "merges incomparable authority lineages ({a} after parent {}, \
                         {b} after parent {}): a hard conflict",
                        effects[i].0, effects[j].0
                    ));
                }
            }
        }
        for (p, e) in &effects {
            if !self.descends(c.authority, *e) {
                problems.push(format!(
                    "cites authority {}, which does not equal or descend from {e}, \
                     the authority in effect after parent {p}",
                    c.authority
                ));
            }
        }
        let mut installed = None;
        if c.flags.modifies_authority() {
            let found = locate_new_authority(self.src, c.tree)
                .and_then(|n| Ok((n, read_signed(self.src, n)?)));
            match found {
                Err(e) => problems.push(format!("authority change: {e}")),
                Ok((new_id, new_signed)) => {
                    installed = Some(new_id);
                    match AuthorityBody::parse(&new_signed.body) {
                        Err(e) => problems.push(format!("installed authority: {e}")),
                        Ok(new_body) => {
                            if let Err(e) = verify::verify_successor(
                                &new_signed,
                                &new_body,
                                c.authority,
                                &body,
                                author,
                            ) {
                                problems.push(format!("installed authority {new_id}: {e}"));
                            }
                            // Cryptographic validity of the whole chain,
                            // which `verify_successor` does not check.
                            if let Err(e) = self.authority(new_id) {
                                problems.push(format!("installed authority {new_id}: {e}"));
                            }
                        }
                    }
                }
            }
        }
        (Some(c.authority), installed)
    }

    /// D5 for one release; returns the authority it cites.
    pub(crate) fn check_release(
        &mut self,
        id: ObjectId,
        genesis: ObjectId,
        problems: &mut Vec<String>,
    ) -> Option<ObjectId> {
        if let Err(e) = verify::verify_release(self.src, id) {
            problems.push(e.to_string());
            return None;
        }
        let r = match read_signed(self.src, id)
            .and_then(|s| Release::from_signed(&s).map_err(VerifyError::from))
        {
            Ok(r) => r,
            Err(e) => {
                problems.push(e.to_string());
                return None;
            }
        };
        let (body, ends_at) = match self.authority(r.authority) {
            Ok(a) => (a.body.clone(), *a.chain.last().unwrap()),
            Err(e) => {
                problems.push(format!("cites authority {}: {e}", r.authority));
                return None;
            }
        };
        if ends_at != genesis {
            problems.push(format!(
                "cites authority {} whose chain ends at a different genesis",
                r.authority
            ));
        }
        match body.find_member(&PublicKey(r.declarer_key)) {
            Some(m) if m.role >= Role::Maintainer => {}
            Some(m) => problems.push(format!(
                "declared by a {}; releases need a maintainer or owner",
                m.role.name()
            )),
            None => problems.push("declarer is not a member of the authority it cites".into()),
        }
        match self.effective(r.predecessor) {
            Ok(e) if self.descends(r.authority, e) => {}
            Ok(e) => problems.push(format!(
                "cites authority {}, which does not equal or descend from {e}, the \
                 authority in effect after its predecessor",
                r.authority
            )),
            Err(e) => problems.push(format!("predecessor {}: {e}", r.predecessor)),
        }
        Some(r.authority)
    }
}

/// Verify everything reachable from `roots` (ref names and ids) against the
/// pinned `genesis`. `current` is `refs/authority/current`, if any.
pub fn verify_history<S: ObjectSource>(
    src: &S,
    genesis: ObjectId,
    current: Option<ObjectId>,
    roots: &[(String, ObjectId)],
) -> HistoryReport {
    let mut report = HistoryReport {
        roots: roots.len(),
        ..Default::default()
    };
    let mut w = Walker::new(src);
    let flag = |report: &mut HistoryReport, object: ObjectId, what: String| {
        report.problems.push(Problem {
            object,
            what,
            integrity: false,
        });
    };
    let damage = |report: &mut HistoryReport, object: ObjectId, what: String| {
        report.problems.push(Problem {
            object,
            what,
            integrity: true,
        });
    };

    // The pin itself, and current's place on it.
    if let Err(e) = read_signed(src, genesis).and_then(|g| verify::verify_genesis(&g)) {
        flag(
            &mut report,
            genesis,
            format!("pinned genesis is invalid: {e}"),
        );
    }
    let canonical: Option<HashSet<ObjectId>> = match current {
        None => None,
        Some(cur) => match w.authority(cur) {
            Ok(a) if *a.chain.last().unwrap() == genesis => Some(a.chain.iter().copied().collect()),
            Ok(_) => {
                flag(
                    &mut report,
                    cur,
                    "current authority does not descend from the genesis".into(),
                );
                None
            }
            Err(e) => {
                flag(&mut report, cur, format!("current authority: {e}"));
                None
            }
        },
    };

    // Each stack entry: an object, the type its link requires, and the
    // genesis of the history it belongs to (`genesis` here; a fork source's
    // across a fork boundary).
    let mut stack: Vec<(ObjectId, Expect, ObjectId)> = Vec::new();
    for (name, id) in roots {
        match Expect::for_ref(name) {
            Some(e) => stack.push((*id, e, genesis)),
            None => damage(
                &mut report,
                *id,
                format!("ref {name} is in no recognized namespace"),
            ),
        }
    }
    let mut visited: HashSet<(ObjectId, Expect, ObjectId)> = HashSet::new();
    let mut counted: HashSet<ObjectId> = HashSet::new();
    let mut commits: Vec<(ObjectId, ObjectId)> = Vec::new();
    let mut releases: Vec<(ObjectId, ObjectId)> = Vec::new();
    while let Some((id, expect, domain)) = stack.pop() {
        if !visited.insert((id, expect, domain)) {
            continue;
        }
        let bytes = match src.read_raw(id) {
            Ok(b) => b,
            Err(e) => {
                damage(&mut report, id, format!("cannot be read: {e}"));
                continue;
            }
        };
        if *blake3::hash(&bytes).as_bytes() != id.0 {
            damage(
                &mut report,
                id,
                "stored bytes do not hash to the object's id".into(),
            );
            continue;
        }
        let raw = match RawObject::parse(&bytes) {
            Ok(r) => r,
            Err(e) => {
                damage(&mut report, id, format!("malformed object: {e}"));
                continue;
            }
        };
        if !expect.admits(raw.object_type) {
            damage(
                &mut report,
                id,
                format!(
                    "is a {} where a {} is required",
                    raw.object_type.name(),
                    expect.name()
                ),
            );
            continue;
        }
        let first = counted.insert(id);
        report.reachable.insert(id);
        match raw.object_type {
            ObjectType::Blob => {
                if first {
                    report.blobs += 1;
                }
            }
            ObjectType::Tree => {
                if first {
                    report.trees += 1;
                }
                let t = match Tree::parse_body(&raw.body) {
                    Ok(t) => t,
                    Err(e) => {
                        damage(&mut report, id, format!("malformed tree: {e}"));
                        continue;
                    }
                };
                for e in &t.entries {
                    let next = match (expect, e.name.as_str(), e.entry_type) {
                        (Expect::RootTree, ".levcs", levcs_core::EntryType::Tree) => {
                            Expect::LevcsTree
                        }
                        (Expect::LevcsTree, "authority", levcs_core::EntryType::Blob) => {
                            Expect::Authority
                        }
                        (_, _, levcs_core::EntryType::Tree) => Expect::Tree,
                        (_, _, levcs_core::EntryType::Blob) => Expect::Blob,
                    };
                    stack.push((e.hash, next, domain));
                }
            }
            ObjectType::Commit => {
                let c = match SignedObject::parse(&bytes)
                    .map_err(|e| e.to_string())
                    .and_then(|s| Commit::from_signed(&s).map_err(|e| e.to_string()))
                {
                    Ok(c) => c,
                    Err(e) => {
                        damage(&mut report, id, format!("malformed commit: {e}"));
                        continue;
                    }
                };
                stack.push((c.tree, Expect::RootTree, domain));
                stack.push((c.authority, Expect::Authority, domain));
                for p in &c.parents {
                    if !c.flags.is_fork() {
                        stack.push((*p, Expect::Commit, domain));
                        continue;
                    }
                    // A fork's parent begins the source's history: carry
                    // the source's genesis, from the authority it cites.
                    let source = read_signed(src, *p)
                        .map_err(|e| e.to_string())
                        .and_then(|s| Commit::from_signed(&s).map_err(|e| e.to_string()))
                        .and_then(|pc| w.genesis_of(pc.authority));
                    match source {
                        Ok(g) => stack.push((*p, Expect::Commit, g)),
                        Err(e) => {
                            // Still walk it: what lies behind must stay
                            // reachable, whatever is wrong with its authority.
                            flag(&mut report, id, format!("fork source {p}: {e}"));
                            stack.push((*p, Expect::Commit, domain));
                        }
                    }
                }
                commits.push((id, domain));
            }
            ObjectType::Release => {
                if first {
                    report.releases += 1;
                }
                match SignedObject::parse(&bytes)
                    .map_err(|e| e.to_string())
                    .and_then(|s| Release::from_signed(&s).map_err(|e| e.to_string()))
                {
                    Ok(r) => {
                        stack.push((r.tree, Expect::RootTree, domain));
                        stack.push((r.predecessor, Expect::Commit, domain));
                        stack.push((r.authority, Expect::Authority, domain));
                        if !r.parent_release.is_zero() {
                            stack.push((r.parent_release, Expect::Release, domain));
                        }
                        releases.push((id, domain));
                    }
                    Err(e) => damage(&mut report, id, format!("malformed release: {e}")),
                }
            }
            ObjectType::Authority => {
                if first {
                    report.authorities += 1;
                }
                // Decode first, through the damage path like every other
                // kind: an authority that cannot be decoded hides its
                // predecessor, so gc must not proceed past it. Skipping it
                // silently let gc delete the predecessor.
                let body = match SignedObject::parse(&bytes)
                    .map_err(|e| e.to_string())
                    .and_then(|_| AuthorityBody::parse(&raw.body).map_err(|e| e.to_string()))
                {
                    Ok(b) => b,
                    Err(e) => {
                        damage(&mut report, id, format!("malformed authority: {e}"));
                        continue;
                    }
                };
                if !body.previous_authority.is_zero() {
                    stack.push((body.previous_authority, Expect::Authority, domain));
                }
                // Then the rules, on fully decoded history: the chain, every
                // signature on it, and a genesis that is this history's.
                match w.genesis_of(id) {
                    Ok(g) if g == domain => {}
                    Ok(g) => flag(
                        &mut report,
                        id,
                        format!("authority descends from a different genesis ({g})"),
                    ),
                    Err(e) => flag(&mut report, id, format!("invalid authority: {e}")),
                }
            }
        }
    }

    let classify = |w: &mut Walker<S>, report: &mut HistoryReport, object, a, what: &str| {
        if let Some(canon) = &canonical {
            let ahead = current.is_some_and(|cur| w.descends(a, cur));
            if !canon.contains(&a) && !ahead {
                report.conflicting.push(Problem {
                    object,
                    integrity: false,
                    what: format!(
                        "valid, but {what} authority {a}, which is incomparable with this \
                         replica's current authority"
                    ),
                });
            }
        }
    };
    let mut seen_commits = HashSet::new();
    for (id, domain) in commits {
        if !seen_commits.insert((id, domain)) {
            continue;
        }
        if domain == genesis {
            report.commits += 1;
        } else {
            report.foreign_commits += 1;
        }
        let mut problems = Vec::new();
        let (cited, installed) = w.check_commit(id, domain, &mut problems);
        if problems.is_empty() && domain == genesis {
            if let Some(a) = cited {
                classify(&mut w, &mut report, id, a, "cites");
            }
            if let Some(a) = installed {
                classify(&mut w, &mut report, id, a, "installs");
            }
        }
        for what in problems {
            flag(&mut report, id, what);
        }
    }
    let mut seen_releases = HashSet::new();
    for (id, domain) in releases {
        if !seen_releases.insert((id, domain)) {
            continue;
        }
        let mut problems = Vec::new();
        let cited = w.check_release(id, domain, &mut problems);
        if problems.is_empty() && domain == genesis {
            if let Some(a) = cited {
                classify(&mut w, &mut report, id, a, "cites");
            }
        }
        for what in problems {
            flag(&mut report, id, what);
        }
    }
    report
}
