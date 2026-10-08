//! Rule P of `doc/authority-semantics.md`, case by case, through `admit`.
//! Histories are built object by object, as for Rule H, because most of
//! these cannot be made with an honest `levcs`.

use std::collections::BTreeMap;
use std::rc::Rc;

use levcs_core::{
    Blob, Commit, CommitFlags, EntryType, FileMode, ObjectId, Release, SignedObject, Tree,
    TreeEntry, ZERO_ID,
};
use levcs_identity::admission::{admit, Admitted, PreState, RefUpdate, Refused, Transaction};
use levcs_identity::authority::{
    AuthorityBody, MemberEntry, PolicyEntry, Role, AUTHORITY_SCHEMA_VERSION,
};
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::{sign_authority, sign_commit, sign_release};
use levcs_identity::verify::MemorySource;

struct Repo {
    src: MemorySource,
    owner: Rc<SecretKey>,
    empty_tree: ObjectId,
    t: i64,
}

type Auth = (ObjectId, AuthorityBody);

impl Repo {
    fn new() -> Self {
        let mut src = MemorySource(Default::default());
        let empty = Tree::default();
        let empty_tree = empty.object_id();
        src.0.insert(empty_tree, empty.serialize());
        Repo {
            src,
            owner: Rc::new(SecretKey::generate()),
            empty_tree,
            t: 1,
        }
    }

    fn put(&mut self, o: &SignedObject) -> ObjectId {
        let id = o.object_id();
        self.src.0.insert(id, o.serialize());
        id
    }

    fn members(&self, others: &[(&SecretKey, Role)]) -> Vec<MemberEntry> {
        let mut m = vec![MemberEntry {
            key: self.owner.public(),
            handle: "owner".into(),
            role: Role::Owner,
            added_micros: 1,
            added_by: self.owner.public(),
        }];
        for (i, (k, role)) in others.iter().enumerate() {
            m.push(MemberEntry {
                key: k.public(),
                handle: format!("m{i}"),
                role: *role,
                added_micros: 1,
                added_by: self.owner.public(),
            });
        }
        m
    }

    fn genesis(&mut self, others: &[(&SecretKey, Role)], policy: Vec<PolicyEntry>) -> Auth {
        let mut body = AuthorityBody {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            repo_id: ZERO_ID,
            previous_authority: ZERO_ID,
            version: 1,
            created_micros: 1,
            members: self.members(others),
            policy,
        };
        body.normalize().unwrap();
        body.assign_genesis_repo_id().unwrap();
        let s = sign_authority(&body, &self.owner).unwrap();
        (self.put(&s), body)
    }

    fn successor(&mut self, prev: &Auth, members: Vec<MemberEntry>) -> Auth {
        let mut body = prev.1.clone();
        body.previous_authority = prev.0;
        body.version += 1;
        body.created_micros += 1;
        body.members = members;
        body.normalize().unwrap();
        let s = sign_authority(&body, &self.owner).unwrap();
        (self.put(&s), body)
    }

    fn commit(&mut self, authority: ObjectId, parents: &[ObjectId], by: &SecretKey) -> ObjectId {
        self.commit_with(authority, parents, by, self.empty_tree, CommitFlags::NONE)
    }

    fn commit_with(
        &mut self,
        authority: ObjectId,
        parents: &[ObjectId],
        by: &SecretKey,
        tree: ObjectId,
        flags: CommitFlags,
    ) -> ObjectId {
        self.t += 1;
        let c = Commit {
            tree,
            parents: parents.to_vec(),
            authority,
            author_key: by.public().0,
            timestamp_micros: self.t,
            flags,
            message: format!("c{}", self.t),
        };
        let s = sign_commit(c, by).unwrap();
        self.put(&s)
    }

    /// A root tree holding `.levcs/authority = new`.
    fn authority_tree(&mut self, new: ObjectId) -> ObjectId {
        let inner = self.tree(vec![("authority", EntryType::Blob, new)]);
        self.tree(vec![(".levcs", EntryType::Tree, inner)])
    }

    fn tree(&mut self, entries: Vec<(&str, EntryType, ObjectId)>) -> ObjectId {
        let mut t = Tree {
            entries: entries
                .into_iter()
                .map(|(name, entry_type, hash)| TreeEntry {
                    name: name.into(),
                    entry_type,
                    mode: FileMode::REGULAR,
                    hash,
                })
                .collect(),
        };
        t.sort_and_validate().unwrap();
        let id = t.object_id();
        self.src.0.insert(id, t.serialize());
        id
    }

    fn blob(&mut self, bytes: &[u8]) -> ObjectId {
        let b = Blob::new(bytes.to_vec()).serialize();
        let id = levcs_core::blake3_hash(&b);
        self.src.0.insert(id, b);
        id
    }

    /// A commit that cites `cites` and installs `new`, by `by`.
    fn change_authority_by(
        &mut self,
        cites: ObjectId,
        parents: &[ObjectId],
        new: ObjectId,
        by: &SecretKey,
    ) -> ObjectId {
        let tree = self.authority_tree(new);
        self.commit_with(cites, parents, by, tree, CommitFlags::MODIFIES_AUTHORITY)
    }

    fn change_authority(
        &mut self,
        cites: ObjectId,
        parents: &[ObjectId],
        new: ObjectId,
    ) -> ObjectId {
        let owner = self.owner.clone();
        self.change_authority_by(cites, parents, new, &owner)
    }

    fn release(
        &mut self,
        authority: ObjectId,
        predecessor: ObjectId,
        parent_release: ObjectId,
        by: &SecretKey,
    ) -> ObjectId {
        self.t += 1;
        let r = Release {
            tree: self.empty_tree,
            parent_release,
            predecessor,
            authority,
            declarer_key: by.public().0,
            timestamp_micros: self.t,
            label: "v1".into(),
            notes: String::new(),
        };
        let s = sign_release(r, by).unwrap();
        self.put(&s)
    }

    /// Admission, and whenever it admits, `verify` over the state it
    /// leaves: admission must never accept what verification rejects.
    fn admit(&self, s0: &PreState, tx: &Transaction) -> Result<Admitted, (Refused, String)> {
        let a = admit(&self.src, s0, tx).map_err(|r| (r.kind, r.reasons.join("\n")))?;
        let mut post = s0.refs.clone();
        for u in &tx.updates {
            match u.new {
                Some(n) => post.insert(u.name.clone(), n),
                None => post.remove(&u.name),
            };
        }
        let current = a.new_current.or(s0.current);
        let roots: Vec<(String, ObjectId)> = post.into_iter().collect();
        let report =
            levcs_identity::history::verify_history(&self.src, s0.genesis, current, &roots);
        assert!(
            report.ok(),
            "admitted, but verify rejects the result:\n{}",
            report
                .problems
                .iter()
                .chain(&report.conflicting)
                .map(|p| format!("{}: {}", p.object, p.what))
                .collect::<Vec<_>>()
                .join("\n")
        );
        Ok(a)
    }
}

fn s0(genesis: ObjectId, current: ObjectId, refs: &[(&str, ObjectId)]) -> PreState {
    PreState {
        genesis,
        current: Some(current),
        refs: refs
            .iter()
            .map(|(n, id)| (n.to_string(), *id))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn set(name: &str, expected: Option<ObjectId>, new: ObjectId) -> RefUpdate {
    RefUpdate {
        name: name.into(),
        expected,
        new: Some(new),
        force: false,
    }
}

fn tx(signer: &SecretKey, updates: Vec<RefUpdate>) -> Transaction {
    Transaction {
        signer: signer.public(),
        updates,
        authority_update: None,
    }
}

fn refused(r: Result<Admitted, (Refused, String)>, kind: Refused, needle: &str) {
    match r {
        Ok(a) => panic!("admitted ({a:?}); expected {kind:?} mentioning {needle:?}"),
        Err((k, why)) => {
            assert_eq!(k, kind, "{why}");
            assert!(why.contains(needle), "expected {needle:?} in:\n{why}");
        }
    }
}

const MAIN: &str = "refs/branches/main";

/// v1 with `x` as a contributor, `main` at one owner commit.
fn base() -> (Repo, Auth, ObjectId, SecretKey) {
    let mut r = Repo::new();
    let x = SecretKey::generate();
    let v1 = r.genesis(&[(&x, Role::Contributor)], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    (r, v1, c1, x)
}

#[test]
fn a_contributor_publishes_work_citing_the_current_authority() {
    let (mut r, v1, c1, x) = base();
    let c2 = r.commit(v1.0, &[c1], &x);
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);
    let a = r
        .admit(&state, &tx(&x, vec![set(MAIN, Some(c1), c2)]))
        .unwrap();
    assert_eq!((a.commits, a.releases, a.new_current), (1, 0, None));
}

/// The specification's first Rule P case: an unpublished v1 commit by a
/// still-current member, after v2.
#[test]
fn work_made_under_an_older_authority_is_refused_without_adoption() {
    let (mut r, v1, c1, x) = base();
    let members = r.members(&[(&x, Role::Contributor)]);
    let v2 = r.successor(&v1, members);
    let boundary = r.change_authority(v1.0, &[c1], v2.0);
    let offline = r.commit(v1.0, &[c1], &x);
    let state = s0(v1.0, v2.0, &[(MAIN, boundary)]);
    refused(
        r.admit(&state, &tx(&x, vec![set("refs/branches/x", None, offline)])),
        Refused::Invalid,
        "adoption (D1)",
    );
}

/// `R0` is fixed from `S0`: a ref in the transaction, or presence in the
/// store, or a remote ref, does not make history already published.
#[test]
fn an_incoming_ref_cannot_grandfather_its_own_commits() {
    let (mut r, v1, c1, x) = base();
    let members = r.members(&[(&x, Role::Contributor)]);
    let v2 = r.successor(&v1, members);
    let boundary = r.change_authority(v1.0, &[c1], v2.0);
    let stale = r.commit(v1.0, &[c1], &x);
    let on_top = r.commit(v2.0, &[stale, boundary], &x);
    // `stale` is in the store and under a remote ref, but not in S0.
    let state = s0(v1.0, v2.0, &[(MAIN, boundary)]);
    refused(
        r.admit(
            &state,
            &tx(
                &x,
                vec![
                    set("refs/branches/a", None, stale),
                    set(MAIN, Some(boundary), on_top),
                ],
            ),
        ),
        Refused::Invalid,
        &format!("commit {stale}: cites authority {}", v1.0),
    );
}

/// Every newly exposed ancestor is checked, not only the tip: a revoked
/// author's commit buried under a valid one is still refused.
#[test]
fn every_newly_exposed_ancestor_is_checked_not_only_the_tip() {
    let (mut r, v1, c1, x) = base();
    let y = SecretKey::generate();
    let buried = r.commit(v1.0, &[c1], &y); // y is not a member
    let tip = r.commit(v1.0, &[buried], &x);
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, Some(c1), tip)])),
        Refused::Invalid,
        &format!("commit {buried}: author is not a member"),
    );
}

/// The specification's membership case: a change and commits citing it,
/// in one transaction.
#[test]
fn an_incoming_membership_change_cannot_authorize_its_own_submission() {
    let (mut r, v1, c1, _x) = base();
    let y = SecretKey::generate();
    let with_y = r.members(&[(&y, Role::Contributor)]);
    let v2 = r.successor(&v1, with_y);
    let boundary = r.change_authority(v1.0, &[c1], v2.0);
    let by_y = r.commit(v2.0, &[boundary], &y);
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);
    let owner = r.owner.clone();
    let mut both = tx(&owner, vec![set(MAIN, Some(c1), by_y)]);
    both.authority_update = Some(v2.0);
    refused(
        r.admit(&state, &both),
        Refused::Invalid,
        &format!("commit {by_y}: cites authority {}", v2.0),
    );

    // The boundary alone is admitted and moves current; y's commit follows
    // in a later transaction, whose A0 is v2.
    let mut alone = tx(&owner, vec![set(MAIN, Some(c1), boundary)]);
    alone.authority_update = Some(v2.0);
    let a = r.admit(&state, &alone).unwrap();
    assert_eq!(a.new_current, Some(v2.0));
    let later = s0(v1.0, v2.0, &[(MAIN, boundary)]);
    r.admit(&later, &tx(&y, vec![set(MAIN, Some(boundary), by_y)]))
        .unwrap();
}

#[test]
fn current_moves_only_with_exactly_one_boundary_to_what_it_installs() {
    let (mut r, v1, c1, x) = base();
    let owner = r.owner.clone();
    let members = r.members(&[]);
    let v2 = r.successor(&v1, members.clone());
    let other = {
        let mut b = v1.1.clone();
        b.previous_authority = v1.0;
        b.version += 1;
        b.created_micros += 7;
        b.members = members;
        b.normalize().unwrap();
        let s = sign_authority(&b, &owner).unwrap();
        r.put(&s)
    };
    let boundary = r.change_authority(v1.0, &[c1], v2.0);
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);

    // A boundary without the move of current.
    refused(
        r.admit(&state, &tx(&owner, vec![set(MAIN, Some(c1), boundary)])),
        Refused::Invalid,
        "does not move current with it",
    );
    // A move of current without a boundary: a plain commit.
    let plain = r.commit(v1.0, &[c1], &x);
    let mut no_boundary = tx(&owner, vec![set(MAIN, Some(c1), plain)]);
    no_boundary.authority_update = Some(v2.0);
    refused(
        r.admit(&state, &no_boundary),
        Refused::Invalid,
        "no commit in the transaction installs it",
    );
    // A move to an authority other than the one installed.
    let mut wrong = tx(&owner, vec![set(MAIN, Some(c1), boundary)]);
    wrong.authority_update = Some(other);
    refused(r.admit(&state, &wrong), Refused::Invalid, "installs");
    // Two boundaries, on two refs.
    let second = r.change_authority(v1.0, &[c1], other);
    let mut two = tx(
        &owner,
        vec![
            set(MAIN, Some(c1), boundary),
            set("refs/branches/b", None, second),
        ],
    );
    two.authority_update = Some(v2.0);
    refused(
        r.admit(&state, &two),
        Refused::Invalid,
        "publishes one boundary",
    );
    // A side branch carrying the successor without being its boundary.
    let carrier = {
        let t = r.authority_tree(v2.0);
        r.commit_with(v1.0, &[c1], &owner, t, CommitFlags::NONE)
    };
    let mut side = tx(
        &owner,
        vec![
            set(MAIN, Some(c1), boundary),
            set("refs/branches/side", None, carrier),
        ],
    );
    side.authority_update = Some(v2.0);
    refused(
        r.admit(&state, &side),
        Refused::Invalid,
        "only an authority change's boundary commit introduces an authority",
    );
}

/// The specification's rollback case, and a boundary that names an older
/// authority or is not signed by an owner.
#[test]
fn current_cannot_roll_back_or_be_changed_by_a_non_owner() {
    let mut r = Repo::new();
    let x = SecretKey::generate();
    let v1 = r.genesis(&[(&x, Role::Contributor)], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let members = r.members(&[(&x, Role::Contributor)]);
    let v2 = r.successor(&v1, members);
    let boundary = r.change_authority(v1.0, &[c1], v2.0);
    let state = s0(v1.0, v2.0, &[(MAIN, boundary)]);

    let back = r.change_authority(v2.0, &[boundary], v1.0);
    let mut rollback = tx(&owner, vec![set(MAIN, Some(boundary), back)]);
    rollback.authority_update = Some(v1.0);
    refused(
        r.admit(&state, &rollback),
        Refused::Invalid,
        "installed authority",
    );

    // refs/authority/* cannot be named as a ref at all.
    refused(
        r.admit(
            &state,
            &tx(
                &owner,
                vec![set("refs/authority/current", Some(v2.0), v1.0)],
            ),
        ),
        Refused::Invalid,
        "P.3",
    );

    let v3 = r.successor(&v2, r.members(&[(&x, Role::Owner)]));
    let by_x = r.change_authority_by(v2.0, &[boundary], v3.0, &x);
    let mut not_owner = tx(&x, vec![set(MAIN, Some(boundary), by_x)]);
    not_owner.authority_update = Some(v3.0);
    refused(r.admit(&state, &not_owner), Refused::Invalid, "needs owner");
}

/// The specification's protected-ref case.
#[test]
fn a_protected_branch_needs_a_maintainer() {
    let mut r = Repo::new();
    let x = SecretKey::generate();
    let m = SecretKey::generate();
    let policy = vec![PolicyEntry {
        key: "protected_branches".into(),
        value: b"main,rel-*".to_vec(),
    }];
    let v1 = r.genesis(&[(&x, Role::Contributor), (&m, Role::Maintainer)], policy);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let c2 = r.commit(v1.0, &[c1], &x);
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, Some(c1), c2)])),
        Refused::Unauthorized,
        "is protected",
    );
    refused(
        r.admit(&state, &tx(&x, vec![set("refs/branches/rel-2", None, c2)])),
        Refused::Unauthorized,
        "is protected",
    );
    // A contributor's commit is still historically valid on a protected
    // branch: the maintainer publishes it.
    r.admit(&state, &tx(&m, vec![set(MAIN, Some(c1), c2)]))
        .unwrap();
    r.admit(&state, &tx(&x, vec![set("refs/branches/topic", None, c2)]))
        .unwrap();
}

#[test]
fn a_rewrite_must_be_forced_by_a_maintainer() {
    let mut r = Repo::new();
    let x = SecretKey::generate();
    let m = SecretKey::generate();
    let v1 = r.genesis(&[(&x, Role::Contributor), (&m, Role::Maintainer)], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let c2 = r.commit(v1.0, &[c1], &x);
    let elsewhere = r.commit(v1.0, &[c1], &x);
    let state = s0(v1.0, v1.0, &[(MAIN, c2)]);
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, Some(c2), elsewhere)])),
        Refused::NotFastForward,
        "must be forced",
    );
    let mut forced = set(MAIN, Some(c2), elsewhere);
    forced.force = true;
    refused(
        r.admit(&state, &tx(&x, vec![forced.clone()])),
        Refused::Unauthorized,
        "needs a maintainer",
    );
    r.admit(&state, &tx(&m, vec![forced])).unwrap();
}

/// A deletion that leaves its tip published elsewhere unpublishes nothing;
/// one that would is a rewrite.
#[test]
fn deleting_a_ref_that_unpublishes_history_is_a_rewrite() {
    let (mut r, v1, c1, x) = base();
    let c2 = r.commit(v1.0, &[c1], &x);
    let state = s0(
        v1.0,
        v1.0,
        &[
            (MAIN, c2),
            ("refs/branches/merged", c1),
            ("refs/branches/only", c2),
        ],
    );
    let del = |name: &str, old| RefUpdate {
        name: name.into(),
        expected: Some(old),
        new: None,
        force: false,
    };
    r.admit(&state, &tx(&x, vec![del("refs/branches/merged", c1)]))
        .unwrap();
    // c2 stays reachable from main.
    r.admit(&state, &tx(&x, vec![del("refs/branches/only", c2)]))
        .unwrap();
    refused(
        r.admit(
            &state,
            &tx(&x, vec![del("refs/branches/only", c2), del(MAIN, c2)]),
        ),
        Refused::NotFastForward,
        "would unpublish",
    );
}

#[test]
fn a_stale_comparison_refuses_the_whole_batch() {
    let (mut r, v1, c1, x) = base();
    let c2 = r.commit(v1.0, &[c1], &x);
    let state = s0(v1.0, v1.0, &[(MAIN, c2)]);
    refused(
        r.admit(
            &state,
            &tx(
                &x,
                vec![
                    set("refs/branches/fresh", None, c2),
                    set(MAIN, Some(c1), c2),
                ],
            ),
        ),
        Refused::Stale,
        "changed since the transaction was made",
    );
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, None, c2)])),
        Refused::Stale,
        "changed since",
    );
}

#[test]
fn the_signer_must_be_a_contributor_of_the_current_authority() {
    let mut r = Repo::new();
    let reader = SecretKey::generate();
    let x = SecretKey::generate();
    let v1 = r.genesis(&[(&reader, Role::Reader)], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let c2 = r.commit(v1.0, &[c1], &owner);
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);
    refused(
        r.admit(&state, &tx(&reader, vec![set(MAIN, Some(c1), c2)])),
        Refused::Unauthorized,
        "needs a contributor",
    );
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, Some(c1), c2)])),
        Refused::Unauthorized,
        "is not a member",
    );

    // An authority from another repository is never A0.
    let mut other = Repo::new();
    other.owner = owner.clone();
    let foreign = other.genesis(&[], vec![]);
    r.src.0.extend(other.src.0);
    let wrong = s0(v1.0, foreign.0, &[(MAIN, c1)]);
    refused(
        r.admit(&wrong, &tx(&owner, vec![set(MAIN, Some(c1), c2)])),
        Refused::Invalid,
        "does not descend from this repository's genesis",
    );
}

/// Deferred D6: a v1 replica has no current authority and publishes
/// nothing until an owner's bootstrap statement exists.
#[test]
fn without_a_current_authority_nothing_is_published() {
    let (mut r, v1, c1, x) = base();
    let c2 = r.commit(v1.0, &[c1], &x);
    let state = PreState {
        genesis: v1.0,
        current: None,
        refs: BTreeMap::new(),
    };
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, None, c2)])),
        Refused::Unauthorized,
        "D6, deferred",
    );
}

#[test]
fn releases_cite_the_current_authority_and_need_a_maintainer() {
    let mut r = Repo::new();
    let x = SecretKey::generate();
    let m = SecretKey::generate();
    let v1 = r.genesis(&[(&x, Role::Contributor), (&m, Role::Maintainer)], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let members = r.members(&[(&x, Role::Contributor), (&m, Role::Maintainer)]);
    let v2 = r.successor(&v1, members);
    let boundary = r.change_authority(v1.0, &[c1], v2.0);
    let state = s0(v1.0, v2.0, &[(MAIN, boundary)]);
    const REL: &str = "refs/releases/v1";

    let good = r.release(v2.0, boundary, ZERO_ID, &m);
    r.admit(&state, &tx(&m, vec![set(REL, None, good)]))
        .unwrap();

    let by_contributor = r.release(v2.0, boundary, ZERO_ID, &x);
    refused(
        r.admit(&state, &tx(&x, vec![set(REL, None, by_contributor)])),
        Refused::Invalid,
        "releases need a maintainer",
    );
    let old_authority = r.release(v1.0, c1, ZERO_ID, &m);
    refused(
        r.admit(&state, &tx(&m, vec![set(REL, None, old_authority)])),
        Refused::Invalid,
        "not the current authority",
    );
    // A release newly exposes its predecessor, which must pass too.
    let stale = r.commit(v1.0, &[c1], &x);
    let on_stale = r.release(v2.0, stale, ZERO_ID, &m);
    refused(
        r.admit(&state, &tx(&m, vec![set(REL, None, on_stale)])),
        Refused::Invalid,
        &format!("commit {stale}: cites authority"),
    );
    // A branch names a commit and a release ref a release.
    refused(
        r.admit(&state, &tx(&m, vec![set(MAIN, Some(boundary), good)])),
        Refused::Invalid,
        "where a commit is required",
    );
}

#[test]
fn newly_exposed_history_must_be_complete() {
    let (mut r, v1, c1, x) = base();
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);
    let missing = ObjectId([9; 32]);

    let no_parent = r.commit(v1.0, &[missing], &x);
    refused(
        r.admit(
            &state,
            &tx(&x, vec![set("refs/branches/a", None, no_parent)]),
        ),
        Refused::Invalid,
        "incomplete or damaged",
    );
    let no_blob = {
        let t = r.tree(vec![("f.txt", EntryType::Blob, missing)]);
        r.commit_with(v1.0, &[c1], &x, t, CommitFlags::NONE)
    };
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, Some(c1), no_blob)])),
        Refused::Invalid,
        "cannot be read",
    );
    let mistyped = {
        let t = r.tree(vec![("f.txt", EntryType::Blob, v1.0)]);
        r.commit_with(v1.0, &[c1], &x, t, CommitFlags::NONE)
    };
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, Some(c1), mistyped)])),
        Refused::Invalid,
        "where a blob is required",
    );
    // A complete tree is fine.
    let ok = {
        let b = r.blob(b"hello");
        let t = r.tree(vec![("f.txt", EntryType::Blob, b)]);
        r.commit_with(v1.0, &[c1], &x, t, CommitFlags::NONE)
    };
    r.admit(&state, &tx(&x, vec![set(MAIN, Some(c1), ok)]))
        .unwrap();
}

#[test]
fn only_branch_and_release_refs_can_be_published() {
    let (mut r, v1, c1, x) = base();
    let c2 = r.commit(v1.0, &[c1], &x);
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);
    for name in [
        "refs/authority/genesis",
        "HEAD",
        "refs/remote/origin/branches/main",
        "refs/branches/../authority/current",
        "config",
    ] {
        refused(
            r.admit(&state, &tx(&x, vec![set(name, None, c2)])),
            Refused::Invalid,
            "cannot be published",
        );
    }
    refused(
        r.admit(
            &state,
            &tx(&x, vec![set(MAIN, Some(c1), c2), set(MAIN, Some(c1), c2)]),
        ),
        Refused::Invalid,
        "updated twice",
    );
}

/// A fork is admitted as the first publication of an empty repository, with
/// the source history behind it checked against the source's genesis.
#[test]
fn a_fork_is_admitted_only_as_a_first_publication() {
    let fork_of = |revoked: bool| {
        let mut source = Repo::new();
        let x = SecretKey::generate();
        let v1 = source.genesis(&[(&x, Role::Contributor)], vec![]);
        let owner = source.owner.clone();
        let base = source.commit(v1.0, &[], &owner);
        let v2 = source.successor(&v1, source.members(&[]));
        let revoke = source.change_authority(v1.0, &[base], v2.0);
        let tip = if revoked {
            source.commit(v1.0, &[revoke], &x)
        } else {
            source.commit(v2.0, &[revoke], &owner)
        };
        let mut dest = Repo::new();
        dest.owner = owner.clone();
        let genesis = dest.genesis(&[], vec![]);
        let tree = dest.authority_tree(genesis.0);
        let flags = CommitFlags(CommitFlags::FORK.0 | CommitFlags::MODIFIES_AUTHORITY.0);
        let fork = dest.commit_with(genesis.0, &[tip], &owner, tree, flags);
        dest.src.0.extend(source.src.0);
        (dest, genesis, fork, tip, owner)
    };
    let (dest, genesis, fork, _, owner) = fork_of(false);
    let empty = s0(genesis.0, genesis.0, &[]);
    let a = dest
        .admit(&empty, &tx(&owner, vec![set(MAIN, None, fork)]))
        .unwrap();
    assert_eq!(a.commits, 1);
    assert!(a.foreign_commits >= 3, "{a:?}");

    let (dest, genesis, fork, tip, owner) = fork_of(true);
    refused(
        dest.admit(
            &s0(genesis.0, genesis.0, &[]),
            &tx(&owner, vec![set(MAIN, None, fork)]),
        ),
        Refused::Invalid,
        &format!("commit {tip}: cites authority"),
    );

    // The fork cites the destination's genesis but installs another
    // authority: the destination would begin under something else.
    let (mut dest, genesis, fork, tip, owner) = fork_of(false);
    let _ = fork;
    let elsewhere = {
        let mut other = Repo::new();
        other.owner = owner.clone();
        let stranger = SecretKey::generate();
        let g = other.genesis(&[(&stranger, Role::Reader)], vec![]);
        assert_ne!(g.0, genesis.0);
        dest.src.0.extend(other.src.0);
        g.0
    };
    let tree = dest.authority_tree(elsewhere);
    let flags = CommitFlags(CommitFlags::FORK.0 | CommitFlags::MODIFIES_AUTHORITY.0);
    let wrong = dest.commit_with(genesis.0, &[tip], &owner, tree, flags);
    refused(
        dest.admit(
            &s0(genesis.0, genesis.0, &[]),
            &tx(&owner, vec![set(MAIN, None, wrong)]),
        ),
        Refused::Invalid,
        "must install this repository's genesis",
    );

    let (mut dest, genesis, fork, _, owner) = fork_of(false);
    let c1 = dest.commit(genesis.0, &[], &owner);
    refused(
        dest.admit(
            &s0(genesis.0, genesis.0, &[(MAIN, c1)]),
            &tx(&owner, vec![set("refs/branches/f", None, fork)]),
        ),
        Refused::Invalid,
        "first, create-only branch of an empty repository",
    );
}

#[test]
fn objects_merely_present_are_not_published_history() {
    // A history received and stored, never published: building on it
    // exposes all of it.
    let (mut r, v1, c1, x) = base();
    let members = r.members(&[(&x, Role::Contributor)]);
    let v2 = r.successor(&v1, members);
    let boundary = r.change_authority(v1.0, &[c1], v2.0);
    let received = r.commit(v1.0, &[c1], &x);
    let merge = r.commit(v2.0, &[boundary, received], &x);
    let state = s0(v1.0, v2.0, &[(MAIN, boundary)]);
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, Some(boundary), merge)])),
        Refused::Invalid,
        &format!("commit {received}: cites authority {}", v1.0),
    );
}

// Cases from the review of 2026-10-05: shortcuts that skipped a check on
// the strength of a result that had not been, or could not be, validated.

/// Two newly exposed commits share a tree with a missing blob. Checking the
/// descendant against its parent's tree skipped every entry, and marked
/// the tree complete; the parent's check then skipped it whole.
#[test]
fn a_tree_shared_between_new_commits_cannot_hide_a_missing_object() {
    let (mut r, v1, c1, x) = base();
    let missing = ObjectId([123; 32]);
    let tree = r.tree(vec![("absent.txt", EntryType::Blob, missing)]);
    let c2 = r.commit_with(v1.0, &[c1], &x, tree, CommitFlags::NONE);
    let c3 = r.commit_with(v1.0, &[c2], &x, tree, CommitFlags::NONE);
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, Some(c1), c3)])),
        Refused::Invalid,
        &missing.to_hex(),
    );
}

/// Published as a release is not published as a commit: a branch must
/// name a commit, whatever R0 holds under that id.
#[test]
fn a_published_release_cannot_be_a_branch_tip() {
    let (mut r, v1, c1, x) = base();
    let owner = r.owner.clone();
    let rel = r.release(v1.0, c1, ZERO_ID, &owner);
    let state = s0(v1.0, v1.0, &[(MAIN, c1), ("refs/releases/v1", rel)]);
    refused(
        r.admit(&state, &tx(&x, vec![set("refs/branches/wrong", None, rel)])),
        Refused::Invalid,
        "where a commit is required",
    );
}

/// One object reached as a tree and as a blob: each link's requirement is
/// checked, not the first one met.
#[test]
fn an_object_checked_as_a_tree_is_not_thereby_a_blob() {
    let (mut r, v1, c1, x) = base();
    let inner = r.tree(vec![]);
    let root = r.tree(vec![
        ("a", EntryType::Tree, inner),
        ("b", EntryType::Blob, inner),
    ]);
    let c2 = r.commit_with(v1.0, &[c1], &x, root, CommitFlags::NONE);
    refused(
        r.admit(
            &s0(v1.0, v1.0, &[(MAIN, c1)]),
            &tx(&x, vec![set(MAIN, Some(c1), c2)]),
        ),
        Refused::Invalid,
        "where a blob is required",
    );
    // The same, with the tree use validated first, in an earlier commit:
    // the blob use in its child must still be checked as a blob.
    let x_blob = r.blob(b"x");
    let inner = r.tree(vec![("x", EntryType::Blob, x_blob)]);
    let as_tree = r.tree(vec![("a", EntryType::Tree, inner)]);
    let as_blob = r.tree(vec![("b", EntryType::Blob, inner)]);
    let c2 = r.commit_with(v1.0, &[c1], &x, as_tree, CommitFlags::NONE);
    let c3 = r.commit_with(v1.0, &[c2], &x, as_blob, CommitFlags::NONE);
    refused(
        r.admit(
            &s0(v1.0, v1.0, &[(MAIN, c1)]),
            &tx(&x, vec![set(MAIN, Some(c1), c3)]),
        ),
        Refused::Invalid,
        "where a blob is required",
    );
}

/// The source history behind a published fork is published as the
/// source's, not as this repository's: a branch naming it is newly
/// exposed in this repository's history, and checked against its genesis.
#[test]
fn fork_source_history_cannot_become_a_native_branch() {
    let (mut source, srcgen, tip, _) = base();
    let owner = source.owner.clone();
    let mut dest = Repo::new();
    dest.owner = owner.clone();
    let stranger = SecretKey::generate();
    let dstgen = dest.genesis(&[(&stranger, Role::Reader)], vec![]);
    let tree = dest.authority_tree(dstgen.0);
    let flags = CommitFlags(CommitFlags::FORK.0 | CommitFlags::MODIFIES_AUTHORITY.0);
    let fork = dest.commit_with(dstgen.0, &[tip], &owner, tree, flags);
    dest.src.0.extend(source.src.0.drain());
    assert_ne!(dstgen.0, srcgen.0);
    dest.admit(
        &s0(dstgen.0, dstgen.0, &[]),
        &tx(&owner, vec![set(MAIN, None, fork)]),
    )
    .unwrap();
    refused(
        dest.admit(
            &s0(dstgen.0, dstgen.0, &[(MAIN, fork)]),
            &tx(&owner, vec![set("refs/branches/source", None, tip)]),
        ),
        Refused::Invalid,
        "different genesis",
    );
}

/// Every authority a newly exposed tree holds is verified, as `verify`
/// verifies it: chain, signatures and genesis, not only its type.
#[test]
fn an_unsigned_authority_in_a_tree_is_refused_as_verify_refuses_it() {
    let (mut r, v1, c1, x) = base();
    let members = r.members(&[(&x, Role::Contributor)]);
    let v2 = r.successor(&v1, members);
    let mut unsigned = SignedObject::parse(&r.src.0[&v2.0]).unwrap();
    unsigned.signatures.clear();
    let bad = r.put(&unsigned);
    let tree = r.authority_tree(bad);
    let c2 = r.commit_with(v1.0, &[c1], &x, tree, CommitFlags::NONE);
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);
    let roots = vec![(MAIN.to_string(), c2)];
    let report = levcs_identity::history::verify_history(&r.src, v1.0, Some(v1.0), &roots);
    assert!(
        !report.ok(),
        "control: verify rejects the unsigned authority"
    );
    refused(
        r.admit(&state, &tx(&x, vec![set(MAIN, Some(c1), c2)])),
        Refused::Invalid,
        &format!("authority {bad}"),
    );
}

// Cases from the review's second round (2026-10-05).

/// A tree nested thousands deep, which `verify` walks, is admitted: the
/// check used to recurse once per level and exhaust the process stack.
#[test]
fn a_deep_tree_is_checked_without_exhausting_the_stack() {
    let (mut r, v1, c1, x) = base();
    let mut tree = r.tree(vec![]);
    for _ in 0..4000 {
        tree = r.tree(vec![("d", EntryType::Tree, tree)]);
    }
    let c2 = r.commit_with(v1.0, &[c1], &x, tree, CommitFlags::NONE);
    r.admit(
        &s0(v1.0, v1.0, &[(MAIN, c1)]),
        &tx(&x, vec![set(MAIN, Some(c1), c2)]),
    )
    .unwrap();
    // And a missing object at the bottom is still found.
    let mut tree = r.tree(vec![("gone", EntryType::Blob, ObjectId([77; 32]))]);
    for _ in 0..4000 {
        tree = r.tree(vec![("d", EntryType::Tree, tree)]);
    }
    let c3 = r.commit_with(v1.0, &[c1], &x, tree, CommitFlags::NONE);
    refused(
        r.admit(
            &s0(v1.0, v1.0, &[(MAIN, c1)]),
            &tx(&x, vec![set(MAIN, Some(c1), c3)]),
        ),
        Refused::Invalid,
        &ObjectId([77; 32]).to_hex(),
    );
}

/// The v2 contract's fork rule: the fork is published by its own signer,
/// an owner of the destination's genesis. A contributor, and a different
/// owner, could publish it.
#[test]
fn a_fork_is_published_only_by_its_signer_as_an_owner() {
    let (mut source, srcgen, tip, _) = base();
    let owner = source.owner.clone();
    let mut dest = Repo::new();
    dest.owner = owner.clone();
    let contributor = SecretKey::generate();
    let other_owner = SecretKey::generate();
    let genesis = dest.genesis(
        &[
            (&contributor, Role::Contributor),
            (&other_owner, Role::Owner),
        ],
        vec![],
    );
    assert_ne!(srcgen.0, genesis.0);
    let tree = dest.authority_tree(genesis.0);
    let flags = CommitFlags(CommitFlags::FORK.0 | CommitFlags::MODIFIES_AUTHORITY.0);
    let fork = dest.commit_with(genesis.0, &[tip], &owner, tree, flags);
    dest.src.0.extend(source.src.0.drain());
    let state = s0(genesis.0, genesis.0, &[]);
    dest.admit(&state, &tx(&owner, vec![set(MAIN, None, fork)]))
        .unwrap();
    refused(
        dest.admit(&state, &tx(&contributor, vec![set(MAIN, None, fork)])),
        Refused::Invalid,
        "published only by an owner",
    );
    refused(
        dest.admit(&state, &tx(&other_owner, vec![set(MAIN, None, fork)])),
        Refused::Invalid,
        "published only by its signer",
    );
}

/// Only the boundary may reference the successor, and an authority that
/// descends from it references it: a side branch carrying A2, signed by an
/// owner A1 introduced, alongside the A0 to A1 boundary.
#[test]
fn an_authority_descending_from_the_successor_is_refused_off_the_boundary() {
    let (mut r, v1, c1, _) = base();
    let owner = r.owner.clone();
    let incoming_owner = SecretKey::generate();
    let v2 = r.successor(
        &v1,
        vec![MemberEntry {
            key: incoming_owner.public(),
            handle: "incoming-owner".into(),
            role: Role::Owner,
            added_micros: 2,
            added_by: owner.public(),
        }],
    );
    let mut next = v2.1.clone();
    next.previous_authority = v2.0;
    next.version += 1;
    next.created_micros += 1;
    let signed = sign_authority(&next, &incoming_owner).unwrap();
    let v3 = r.put(&signed);
    let boundary = r.change_authority(v1.0, &[c1], v2.0);
    let tree = r.authority_tree(v3);
    let side = r.commit_with(v1.0, &[c1], &owner, tree, CommitFlags::NONE);
    let state = s0(v1.0, v1.0, &[(MAIN, c1)]);
    let mut t = tx(
        &owner,
        vec![
            set(MAIN, Some(c1), boundary),
            set("refs/branches/side", None, side),
        ],
    );
    t.authority_update = Some(v2.0);
    refused(
        r.admit(&state, &t),
        Refused::Invalid,
        &format!("carries authority {v3}"),
    );
}

/// Behind a fork, the source's history is not held to this repository's
/// authorities, so only verifying every authority its trees carry stops an
/// unsigned one there.
#[test]
fn an_unsigned_authority_in_fork_source_history_is_refused() {
    let (mut source, srcgen, c1, x) = base();
    let members = source.members(&[(&x, Role::Contributor)]);
    let v2 = source.successor(&srcgen, members);
    let mut unsigned = SignedObject::parse(&source.src.0[&v2.0]).unwrap();
    unsigned.signatures.clear();
    let bad = source.put(&unsigned);
    let tree = source.authority_tree(bad);
    let tip = source.commit_with(srcgen.0, &[c1], &x, tree, CommitFlags::NONE);
    let owner = source.owner.clone();
    let mut dest = Repo::new();
    dest.owner = owner.clone();
    let stranger = SecretKey::generate();
    let genesis = dest.genesis(&[(&stranger, Role::Reader)], vec![]);
    let fork_tree = dest.authority_tree(genesis.0);
    let flags = CommitFlags(CommitFlags::FORK.0 | CommitFlags::MODIFIES_AUTHORITY.0);
    let fork = dest.commit_with(genesis.0, &[tip], &owner, fork_tree, flags);
    dest.src.0.extend(source.src.0.drain());
    refused(
        dest.admit(
            &s0(genesis.0, genesis.0, &[]),
            &tx(&owner, vec![set(MAIN, None, fork)]),
        ),
        Refused::Invalid,
        &format!("authority {bad}: "),
    );
}
