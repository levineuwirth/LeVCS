//! Rule H of `doc/authority-semantics.md`, case by case, through
//! `verify_history`. Every history here is built object by object, because
//! most of these cannot be made with the CLI: an honest `levcs` always cites
//! the current authority and refuses keys that are not in it.

use levcs_core::{
    Commit, CommitFlags, EntryType, FileMode, ObjectId, Release, SignedObject, Tree, TreeEntry,
    ZERO_ID,
};
use levcs_identity::authority::{
    AuthorityBody, MemberEntry, PolicyEntry, Role, AUTHORITY_SCHEMA_VERSION,
};
use levcs_identity::history::{verify_history, HistoryReport};
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::{sign_authority, sign_commit, sign_release};
use levcs_identity::verify::MemorySource;
use std::rc::Rc;

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

    /// A successor of `prev` with exactly `members`, signed by the owner.
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

    /// A commit that cites `cites` and installs `new` at `.levcs/authority`.
    fn change_authority(
        &mut self,
        cites: ObjectId,
        parents: &[ObjectId],
        new: ObjectId,
    ) -> ObjectId {
        let mut inner = Tree {
            entries: vec![TreeEntry {
                name: "authority".into(),
                entry_type: EntryType::Blob,
                mode: FileMode::REGULAR,
                hash: new,
            }],
        };
        inner.sort_and_validate().unwrap();
        let inner_id = inner.object_id();
        self.src.0.insert(inner_id, inner.serialize());
        let mut outer = Tree {
            entries: vec![TreeEntry {
                name: ".levcs".into(),
                entry_type: EntryType::Tree,
                mode: FileMode::REGULAR,
                hash: inner_id,
            }],
        };
        outer.sort_and_validate().unwrap();
        let outer_id = outer.object_id();
        self.src.0.insert(outer_id, outer.serialize());
        let owner = self.owner.clone();
        self.commit_with(
            cites,
            parents,
            &owner,
            outer_id,
            CommitFlags::MODIFIES_AUTHORITY,
        )
    }

    fn release(&mut self, authority: ObjectId, predecessor: ObjectId, by: &SecretKey) -> ObjectId {
        let r = Release {
            tree: self.empty_tree,
            parent_release: ZERO_ID,
            predecessor,
            authority,
            declarer_key: by.public().0,
            timestamp_micros: 100,
            label: "v1".into(),
            notes: String::new(),
        };
        let s = sign_release(r, by).unwrap();
        self.put(&s)
    }

    fn verify_release(&self, genesis: ObjectId, current: ObjectId, rel: ObjectId) -> HistoryReport {
        verify_history(
            &self.src,
            genesis,
            Some(current),
            &[("refs/releases/v1".to_string(), rel)],
        )
    }

    fn verify(&self, genesis: ObjectId, current: ObjectId, tips: &[ObjectId]) -> HistoryReport {
        let roots: Vec<(String, ObjectId)> = tips
            .iter()
            .enumerate()
            .map(|(i, t)| (format!("refs/branches/b{i}"), *t))
            .collect();
        verify_history(&self.src, genesis, Some(current), &roots)
    }
}

fn problems(r: &HistoryReport) -> String {
    r.problems
        .iter()
        .map(|p| format!("{}: {}", p.object, p.what))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn a_linear_history_with_a_membership_change_is_valid() {
    let mut r = Repo::new();
    let x = SecretKey::generate();
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let add_x = r.members(&[(&x, Role::Contributor)]);
    let v2 = r.successor(&v1, add_x);
    let change = r.change_authority(v1.0, &[c1], v2.0);
    let c3 = r.commit(v2.0, &[change], &x);
    let report = r.verify(v1.0, v2.0, &[c3]);
    assert!(report.ok(), "{}", problems(&report));
    assert_eq!(report.commits, 3);
    assert_eq!(report.authorities, 2);
}

#[test]
fn a_revoked_author_cannot_extend_history_that_contains_the_revocation() {
    // The audit's revocation case: X's commit sits directly on the commit that
    // removed X and cites the authority that commit itself cites. Comparing
    // cited authorities alone would pass it.
    let mut r = Repo::new();
    let x = SecretKey::generate();
    let v1 = r.genesis(&[(&x, Role::Contributor)], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let without_x = r.members(&[]);
    let v2 = r.successor(&v1, without_x);
    let revoke = r.change_authority(v1.0, &[c1], v2.0);
    let by_x = r.commit(v1.0, &[revoke], &x);
    let report = r.verify(v1.0, v2.0, &[by_x]);
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.object == by_x && p.what.contains("in effect after parent")),
        "{}",
        problems(&report)
    );
}

#[test]
fn a_branch_that_never_saw_the_revocation_stays_historically_valid() {
    // What Rule H cannot do without a clock: X extending a branch made before
    // the removal is valid history. Publishing it is Rule P's question.
    let mut r = Repo::new();
    let x = SecretKey::generate();
    let v1 = r.genesis(&[(&x, Role::Contributor)], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let without_x = r.members(&[]);
    let v2 = r.successor(&v1, without_x);
    let revoke = r.change_authority(v1.0, &[c1], v2.0);
    let stale = r.commit(v1.0, &[c1], &x);
    let report = r.verify(v1.0, v2.0, &[revoke, stale]);
    assert!(report.problems.is_empty(), "{}", problems(&report));
}

#[test]
fn a_merge_of_incomparable_authority_lineages_is_a_hard_conflict() {
    let mut r = Repo::new();
    let (y, z) = (SecretKey::generate(), SecretKey::generate());
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let with_y = r.members(&[(&y, Role::Contributor)]);
    let with_z = r.members(&[(&z, Role::Contributor)]);
    let v2a = r.successor(&v1, with_y);
    let v2b = r.successor(&v1, with_z);
    let ra = r.change_authority(v1.0, &[c1], v2a.0);
    let rb = r.change_authority(v1.0, &[c1], v2b.0);
    let merge = r.commit(v2a.0, &[ra, rb], &owner);
    let report = r.verify(v1.0, v2a.0, &[merge]);
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.object == merge && p.what.contains("incomparable")),
        "{}",
        problems(&report)
    );
}

#[test]
fn a_merge_of_comparable_authorities_must_cite_the_newer() {
    let mut r = Repo::new();
    let y = SecretKey::generate();
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let with_y = r.members(&[(&y, Role::Contributor)]);
    let v2 = r.successor(&v1, with_y);
    let change = r.change_authority(v1.0, &[c1], v2.0);
    let side = r.commit(v1.0, &[c1], &owner);
    let good = r.commit(v2.0, &[change, side], &owner);
    let stale = r.commit(v1.0, &[change, side], &owner);
    let report = r.verify(v1.0, v2.0, &[good]);
    assert!(report.ok(), "{}", problems(&report));
    let report = r.verify(v1.0, v2.0, &[stale]);
    assert!(
        report.problems.iter().any(|p| p.object == stale),
        "a merge citing the older authority passed"
    );
}

#[test]
fn a_contributor_commit_under_a_protected_branch_policy_is_historically_valid() {
    // H.1 is intrinsic: a commit does not record the ref it was made for, so a
    // protected-branch rule cannot be applied to history.
    let mut r = Repo::new();
    let c = SecretKey::generate();
    let policy = vec![PolicyEntry {
        key: "protected_branches".into(),
        value: b"main".to_vec(),
    }];
    let v1 = r.genesis(&[(&c, Role::Contributor)], policy);
    let owner = r.owner.clone();
    let root = r.commit(v1.0, &[], &owner);
    let by_c = r.commit(v1.0, &[root], &c);
    let report = r.verify(v1.0, v1.0, &[by_c]);
    assert!(report.ok(), "{}", problems(&report));
}

#[test]
fn a_release_declared_by_a_reader_is_invalid() {
    let mut r = Repo::new();
    let reader = SecretKey::generate();
    let v1 = r.genesis(&[(&reader, Role::Reader)], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let rel = r.release(v1.0, c1, &reader);
    let report = r.verify_release(v1.0, v1.0, rel);
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.object == rel && p.what.contains("maintainer")),
        "{}",
        problems(&report)
    );
    let good = r.release(v1.0, c1, &owner);
    let report = r.verify_release(v1.0, v1.0, good);
    assert!(report.ok(), "{}", problems(&report));
}

#[test]
fn installing_an_ownerless_authority_is_invalid() {
    let mut r = Repo::new();
    let x = SecretKey::generate();
    let v1 = r.genesis(&[(&x, Role::Maintainer)], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let mut only_x = r.members(&[(&x, Role::Maintainer)]);
    only_x.retain(|m| m.role != Role::Owner);
    let v2 = r.successor(&v1, only_x);
    let change = r.change_authority(v1.0, &[c1], v2.0);
    let report = r.verify(v1.0, v1.0, &[change]);
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.object == change && p.what.contains("no owner")),
        "{}",
        problems(&report)
    );
}

#[test]
fn a_conflicting_lineage_is_reported_apart_from_invalid_history() {
    // Two replicas each accepted a different successor of v1. History on the
    // other one is valid, but in disagreement with this replica (D2).
    let mut r = Repo::new();
    let (y, z) = (SecretKey::generate(), SecretKey::generate());
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let with_y = r.members(&[(&y, Role::Contributor)]);
    let with_z = r.members(&[(&z, Role::Contributor)]);
    let v2a = r.successor(&v1, with_y);
    let v2b = r.successor(&v1, with_z);
    let ra = r.change_authority(v1.0, &[c1], v2a.0);
    let rb = r.change_authority(v1.0, &[c1], v2b.0);
    let theirs = r.commit(v2b.0, &[rb], &z);
    let report = r.verify(v1.0, v2a.0, &[ra, theirs]);
    assert!(report.problems.is_empty(), "{}", problems(&report));
    assert!(
        report.conflicting.iter().any(|p| p.object == theirs),
        "a commit on the other lineage was not reported as conflicting"
    );
    assert!(!report.ok());
}

#[test]
fn history_under_a_foreign_genesis_is_invalid() {
    let mut r = Repo::new();
    let v1 = r.genesis(&[], vec![]);
    let mut other = Repo::new();
    let foreign = other.genesis(&[], vec![]);
    for (k, v) in other.src.0.drain() {
        r.src.0.insert(k, v);
    }
    let theirs = other.owner.clone();
    let c = r.commit(foreign.0, &[], &theirs);
    let report = r.verify(v1.0, v1.0, &[c]);
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.object == c && p.what.contains("different genesis")),
        "{}",
        problems(&report)
    );
}

#[test]
fn missing_and_corrupt_objects_are_invalid() {
    let mut r = Repo::new();
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let c1 = r.commit(v1.0, &[], &owner);
    let c2 = r.commit(v1.0, &[c1], &owner);
    // c1 corrupt, and a parent that does not exist at all.
    r.src.0.insert(c1, b"garbage".to_vec());
    let ghost = r.commit(v1.0, &[ObjectId([7; 32])], &owner);
    let report = r.verify(v1.0, v1.0, &[c2, ghost]);
    for want in [c1, ObjectId([7; 32])] {
        assert!(
            report.problems.iter().any(|p| p.object == want),
            "{want} not reported:\n{}",
            problems(&report)
        );
    }
}

// Cases from the second review of this verifier (2026-10-04): each passed the
// first version.

fn flagged(report: &HistoryReport, object: ObjectId) -> bool {
    report.problems.iter().any(|p| p.object == object)
}

#[test]
fn an_installed_authority_with_an_invalid_signature_is_invalid() {
    // Nothing cites the installed authority, so only checking every reachable
    // authority's signatures catches it.
    let mut r = Repo::new();
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let base = r.commit(v1.0, &[], &owner);
    let members = r.members(&[]);
    let v2 = r.successor(&v1, members);
    let mut bad = SignedObject::parse(&r.src.0[&v2.0]).unwrap();
    bad.signatures[0].signature = [0; 64];
    let bad_id = r.put(&bad);
    let boundary = r.change_authority(v1.0, &[base], bad_id);
    let report = r.verify(v1.0, v1.0, &[boundary]);
    assert!(
        flagged(&report, bad_id) || flagged(&report, boundary),
        "{}",
        problems(&report)
    );
}

#[test]
fn every_link_names_the_type_it_requires() {
    let mut r = Repo::new();
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let blob = levcs_core::Blob::new(b"not a tree, not a commit".to_vec());
    let blob_id = blob.object_id();
    r.src.0.insert(blob_id, blob.serialize());
    let c = r.commit_with(v1.0, &[], &owner, blob_id, CommitFlags::NONE);
    let report = r.verify(v1.0, v1.0, &[c]);
    assert!(
        flagged(&report, blob_id),
        "a blob passed as a commit's tree"
    );
    let report = r.verify(v1.0, v1.0, &[blob_id]);
    assert!(flagged(&report, blob_id), "a blob passed as a branch tip");
}

#[test]
fn a_split_between_installed_authorities_is_a_conflict() {
    // Both boundary commits cite their common predecessor, so classifying
    // only cited authorities saw nothing.
    let mut r = Repo::new();
    let (y, z) = (SecretKey::generate(), SecretKey::generate());
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let base = r.commit(v1.0, &[], &owner);
    let ym = r.members(&[(&y, Role::Contributor)]);
    let zm = r.members(&[(&z, Role::Contributor)]);
    let v2a = r.successor(&v1, ym);
    let v2b = r.successor(&v1, zm);
    let ra = r.change_authority(v1.0, &[base], v2a.0);
    let rb = r.change_authority(v1.0, &[base], v2b.0);
    let report = r.verify(v1.0, v2a.0, &[ra, rb]);
    assert!(report.problems.is_empty(), "{}", problems(&report));
    assert!(report.conflicting.iter().any(|p| p.object == rb));
    assert!(!report.conflicting.iter().any(|p| p.object == ra));
}

#[test]
fn a_release_on_a_conflicting_lineage_is_a_conflict() {
    let mut r = Repo::new();
    let (y, z) = (SecretKey::generate(), SecretKey::generate());
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let base = r.commit(v1.0, &[], &owner);
    let ym = r.members(&[(&y, Role::Contributor)]);
    let zm = r.members(&[(&z, Role::Contributor)]);
    let v2a = r.successor(&v1, ym);
    let v2b = r.successor(&v1, zm);
    let rel = r.release(v2b.0, base, &owner);
    let report = r.verify_release(v1.0, v2a.0, rel);
    assert!(report.problems.is_empty(), "{}", problems(&report));
    assert!(report.conflicting.iter().any(|p| p.object == rel));
}

/// A source history with a revoked author's commit on the revoking commit,
/// and a destination repository forked from `tip`, as `levcs fork` does.
fn fork_of(revoked_tip: bool) -> (Repo, Auth, ObjectId, ObjectId) {
    let mut source = Repo::new();
    let x = SecretKey::generate();
    let v1 = source.genesis(&[(&x, Role::Contributor)], vec![]);
    let owner = source.owner.clone();
    let base = source.commit(v1.0, &[], &owner);
    let members = source.members(&[]);
    let v2 = source.successor(&v1, members);
    let revoke = source.change_authority(v1.0, &[base], v2.0);
    let tip = if revoked_tip {
        source.commit(v1.0, &[revoke], &x)
    } else {
        source.commit(v2.0, &[revoke], &owner)
    };
    let mut dest = Repo::new();
    dest.owner = owner.clone();
    let genesis = dest.genesis(&[], vec![]);
    let boundary = dest.change_authority(genesis.0, &[tip], genesis.0);
    let tree = Commit::from_signed(&SignedObject::parse(&dest.src.0[&boundary]).unwrap())
        .unwrap()
        .tree;
    let flags = CommitFlags(CommitFlags::FORK.0 | CommitFlags::MODIFIES_AUTHORITY.0);
    let fork = dest.commit_with(genesis.0, &[tip], &owner, tree, flags);
    dest.src.0.extend(source.src.0);
    (dest, genesis, fork, tip)
}

#[test]
fn a_fork_carries_the_source_genesis_into_its_history() {
    let (dest, genesis, fork, tip) = fork_of(true);
    let report = dest.verify(genesis.0, genesis.0, &[fork]);
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.object == tip && p.what.contains("in effect after parent")),
        "a revoked author's source commit passed behind a fork:\n{}",
        problems(&report)
    );

    // Control: valid source history behind the same fork passes.
    let (dest, genesis, fork, _) = fork_of(false);
    let report = dest.verify(genesis.0, genesis.0, &[fork]);
    assert!(report.problems.is_empty(), "{}", problems(&report));
    assert!(report.foreign_commits >= 3, "{report:?}");
}

// Cases from the third review round (2026-10-04).

#[test]
fn an_ownerless_successor_is_invalid_even_when_only_cited() {
    // D4 used to be checked only on a transition commit. With no boundary
    // commit in sight, an ownerless authority passed as current.
    let mut r = Repo::new();
    let c = SecretKey::generate();
    let v1 = r.genesis(&[(&c, Role::Contributor)], vec![]);
    let owner = r.owner.clone();
    let root = r.commit(v1.0, &[], &owner);
    let mut members = r.members(&[(&c, Role::Contributor)]);
    members.retain(|m| m.role != Role::Owner);
    let v2 = r.successor(&v1, members);
    let by_c = r.commit(v2.0, &[root], &c);
    let report = r.verify(v1.0, v2.0, &[by_c]);
    assert!(
        report.problems.iter().any(|p| p.what.contains("no owner")),
        "{}",
        problems(&report)
    );
}

#[test]
fn ref_namespaces_are_decided_by_structure_not_by_name() {
    let mut r = Repo::new();
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let root = r.commit(v1.0, &[], &owner);
    let rel = r.release(v1.0, root, &owner);
    let roots: Vec<(String, ObjectId)> = vec![
        ("refs/releases/branches".into(), rel),
        ("refs/branches/releases".into(), root),
        ("refs/remote/origin/branches/main".into(), root),
        ("refs/remote/origin/releases/v1".into(), rel),
        ("refs/authority/current".into(), v1.0),
    ];
    let report = verify_history(&r.src, v1.0, Some(v1.0), &roots);
    assert!(report.ok(), "{}", problems(&report));

    for (bad, id) in [
        ("refs/branches", root),
        ("refs/remote/origin/main", root),
        ("refs/elsewhere/x", root),
    ] {
        let report = verify_history(&r.src, v1.0, Some(v1.0), &[(bad.to_string(), id)]);
        assert!(
            report.problems.iter().any(|p| p.integrity),
            "{bad} was accepted as a ref namespace"
        );
    }
}

// Fourth review round (2026-10-04).

/// A correctly hashed and signed authority whose body is truncated, cited as
/// current, with a sound predecessor behind it.
fn malformed_authority(r: &mut Repo) -> (ObjectId, ObjectId, ObjectId, ObjectId) {
    let v1 = r.genesis(&[], vec![]);
    let owner = r.owner.clone();
    let root = r.commit(v1.0, &[], &owner);
    let members = r.members(&[]);
    let v2 = r.successor(&v1, members);
    let mut body = v2.1.clone();
    body.previous_authority = v2.0;
    body.version += 1;
    let mut bad = sign_authority(&body, &owner).unwrap();
    bad.body.pop();
    bad.signatures[0].signature = owner.sign(bad.signing_hash().as_bytes());
    let bad_id = r.put(&bad);
    (v1.0, root, v2.0, bad_id)
}

#[test]
fn an_undecodable_authority_is_damage_not_a_rule_violation() {
    // Only fully decoded history can be a rule violation; anything else hides
    // what lies behind it, and gc must not proceed past it.
    let mut r = Repo::new();
    let (genesis, root, _, bad) = malformed_authority(&mut r);
    let report = verify_history(
        &r.src,
        genesis,
        Some(bad),
        &[
            ("refs/authority/genesis".into(), genesis),
            ("refs/authority/current".into(), bad),
            ("refs/branches/main".into(), root),
        ],
    );
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.object == bad && p.integrity),
        "{}",
        problems(&report)
    );
}
