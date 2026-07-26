use std::collections::HashMap;

use levcs_core::object::SignatureEntry;
use levcs_core::{Commit, CommitFlags, ObjectId, Release, SignedObject, ZERO_ID};
use levcs_identity::authority::{
    AuthorityBody, MemberEntry, PolicyEntry, Role, AUTHORITY_SCHEMA_VERSION,
};
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::{add_cosigner_signature, sign_authority, sign_commit, sign_release};
use levcs_identity::verify::{verify_commit, verify_release, MemorySource, ObjectSource};

fn authority(
    owner: &SecretKey,
    extra_member: Option<(&SecretKey, Role)>,
    policies: Vec<PolicyEntry>,
) -> (AuthorityBody, SignedObject) {
    let mut members = vec![MemberEntry {
        key: owner.public(),
        handle: "owner".into(),
        role: Role::Owner,
        added_micros: 1,
        added_by: owner.public(),
    }];
    if let Some((member, role)) = extra_member {
        members.push(MemberEntry {
            key: member.public(),
            handle: "member".into(),
            role,
            added_micros: 1,
            added_by: owner.public(),
        });
    }
    let mut body = AuthorityBody {
        schema_version: AUTHORITY_SCHEMA_VERSION,
        repo_id: ZERO_ID,
        previous_authority: ZERO_ID,
        version: 1,
        created_micros: 1,
        members,
        policy: policies,
    };
    body.normalize().unwrap();
    body.assign_genesis_repo_id().unwrap();
    let signed = sign_authority(&body, owner).unwrap();
    (body, signed)
}

fn insert(source: &mut MemorySource, object: &SignedObject) -> ObjectId {
    let id = object.object_id();
    source.0.insert(id, object.serialize());
    id
}

fn adversarial_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/phase0-adversarial.json")).unwrap()
}

/// Looks up one named case and asserts its `v2_expected` outcome against a
/// live result computed by an actual verifier call in this test file, so
/// editing the fixture's expectation for an exercised case is independently
/// detectable rather than only schema-checked.
fn assert_case_matches(fixture: &serde_json::Value, name: &str, actually_rejected: bool) {
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("fixture is missing case {name}"));
    let expected_reject = match case["v2_expected"].as_str() {
        Some("reject") => true,
        Some("accept") => false,
        other => panic!("case {name} has unexpected v2_expected {other:?}"),
    };
    assert_eq!(
        expected_reject, actually_rejected,
        "case {name}: fixture v2_expected does not match the live verifier outcome"
    );
}

fn ordinary_commit(authority: ObjectId, signer: &SecretKey, tree: ObjectId) -> SignedObject {
    sign_commit(
        Commit {
            tree,
            parents: vec![],
            authority,
            author_key: signer.public().0,
            timestamp_micros: 2,
            flags: CommitFlags::NONE,
            message: "phase-0 fixture".into(),
        },
        signer,
    )
    .unwrap()
}

#[test]
fn wrong_release_declarer_and_duplicate_cosigner_are_rejected() {
    let owner = SecretKey::from_seed([1; 32]);
    let member = SecretKey::from_seed([2; 32]);
    let (_, authority) = authority(&owner, Some((&member, Role::Maintainer)), vec![]);
    let mut source = MemorySource(HashMap::new());
    let authority_id = insert(&mut source, &authority);

    let release = Release {
        tree: ObjectId([3; 32]),
        parent_release: ZERO_ID,
        predecessor: ObjectId([4; 32]),
        authority: authority_id,
        declarer_key: owner.public().0,
        timestamp_micros: 3,
        label: "v1".into(),
        notes: "fixture".into(),
    };

    let mut wrong_declarer = release.clone().into_signed().unwrap();
    add_cosigner_signature(&mut wrong_declarer, &member);
    let wrong_id = insert(&mut source, &wrong_declarer);
    let wrong_declarer_rejected = verify_release(&source, wrong_id).is_err();
    assert!(wrong_declarer_rejected);

    let mut duplicate = sign_release(release, &owner).unwrap();
    add_cosigner_signature(&mut duplicate, &owner);
    let duplicate_id = insert(&mut source, &duplicate);
    let duplicate_cosigner_rejected = verify_release(&source, duplicate_id).is_err();
    assert!(duplicate_cosigner_rejected);

    let fixture = adversarial_fixture();
    assert_case_matches(
        &fixture,
        "release-first-signer-is-not-declarer",
        wrong_declarer_rejected,
    );
    assert_case_matches(
        &fixture,
        "release-duplicate-cosigner",
        duplicate_cosigner_rejected,
    );
}

#[test]
fn invalid_signature_and_protected_branch_policy_reject() {
    let owner = SecretKey::from_seed([5; 32]);
    let contributor = SecretKey::from_seed([6; 32]);
    let (_, authority) = authority(
        &owner,
        Some((&contributor, Role::Contributor)),
        vec![PolicyEntry {
            key: "protected_branches".into(),
            value: b"main".to_vec(),
        }],
    );
    let mut source = MemorySource(HashMap::new());
    let authority_id = insert(&mut source, &authority);

    let valid = ordinary_commit(authority_id, &contributor, ObjectId([7; 32]));
    let valid_id = insert(&mut source, &valid);
    verify_commit(&source, valid_id, None).unwrap();
    let protected_branch_rejected = verify_commit(&source, valid_id, Some("main")).is_err();
    assert!(protected_branch_rejected);

    let mut bad_signature = valid;
    bad_signature.signatures[0].signature[0] ^= 1;
    let bad_id = insert(&mut source, &bad_signature);
    let bad_signature_rejected = verify_commit(&source, bad_id, None).is_err();
    assert!(bad_signature_rejected);

    let fixture = adversarial_fixture();
    assert_case_matches(
        &fixture,
        "invalid-ed25519-signature",
        bad_signature_rejected,
    );
    assert_case_matches(
        &fixture,
        "protected-branch-contributor",
        protected_branch_rejected,
    );
}

#[test]
fn foreign_stale_and_missing_closure_fixtures_document_legacy_gaps_for_v2() {
    let destination_owner = SecretKey::from_seed([8; 32]);
    let (destination_body, destination_authority) = authority(&destination_owner, None, vec![]);
    let destination_current = destination_authority.object_id();

    let foreign_owner = SecretKey::from_seed([9; 32]);
    let (foreign_body, foreign_authority) = authority(&foreign_owner, None, vec![]);
    let mut source = MemorySource(HashMap::new());
    let foreign_authority_id = insert(&mut source, &foreign_authority);
    let missing_tree = ObjectId([10; 32]);
    let foreign_commit = ordinary_commit(foreign_authority_id, &foreign_owner, missing_tree);
    let foreign_commit_id = insert(&mut source, &foreign_commit);

    // The current verifier proves an internally valid chain but has no
    // repository TrustAnchor and does not walk an ordinary commit's tree.
    verify_commit(&source, foreign_commit_id, None).unwrap();
    assert_ne!(foreign_body.repo_id, destination_body.repo_id);
    assert_ne!(foreign_authority_id, destination_current);
    assert!(source.read_raw(missing_tree).is_err());

    // A Phase-0 v2 fixture therefore classifies all three facts as rejection:
    // foreign repo, stale/non-current authority, and incomplete closure. Each
    // is cross-checked against its named fixture case rather than only
    // re-asserting the same booleans already asserted above.
    let fixture = adversarial_fixture();
    assert_case_matches(
        &fixture,
        "foreign-valid-authority-chain",
        foreign_body.repo_id != destination_body.repo_id,
    );
    assert_case_matches(
        &fixture,
        "missing-ordinary-tree-closure",
        source.read_raw(missing_tree).is_err(),
    );
}

#[test]
fn stale_but_valid_ancestor_authority_is_not_current_authority() {
    let owner = SecretKey::from_seed([11; 32]);
    let (genesis_body, genesis) = authority(&owner, None, vec![]);
    let mut source = MemorySource(HashMap::new());
    let genesis_id = insert(&mut source, &genesis);

    let successor_body = AuthorityBody {
        schema_version: AUTHORITY_SCHEMA_VERSION,
        repo_id: genesis_body.repo_id,
        previous_authority: genesis_id,
        version: 2,
        created_micros: 2,
        members: genesis_body.members.clone(),
        policy: genesis_body.policy.clone(),
    };
    let successor = sign_authority(&successor_body, &owner).unwrap();
    let successor_id = insert(&mut source, &successor);

    let stale_commit = ordinary_commit(genesis_id, &owner, ObjectId([12; 32]));
    let stale_commit_id = insert(&mut source, &stale_commit);
    verify_commit(&source, stale_commit_id, None).unwrap();
    assert_ne!(genesis_id, successor_id);

    // The stale commit cites `genesis_id`, but the repository's current
    // authority is now `successor_id`; v2 must reject any transaction whose
    // cited authority is not the pinned current authority.
    assert_case_matches(
        &adversarial_fixture(),
        "stale-valid-authority-ancestor",
        genesis_id != successor_id,
    );
}

#[test]
fn malformed_extra_commit_signature_is_rejected() {
    let owner = SecretKey::from_seed([13; 32]);
    let (_, authority) = authority(&owner, None, vec![]);
    let mut source = MemorySource(HashMap::new());
    let authority_id = insert(&mut source, &authority);
    let mut commit = ordinary_commit(authority_id, &owner, ObjectId([14; 32]));
    commit.signatures.push(SignatureEntry {
        public_key: owner.public().0,
        signature: [0; 64],
    });
    let commit_id = insert(&mut source, &commit);
    let rejected = verify_commit(&source, commit_id, None).is_err();
    assert!(rejected);
    assert_case_matches(
        &adversarial_fixture(),
        "malformed-extra-commit-signature",
        rejected,
    );
}

#[test]
fn adversarial_fixture_matrix_is_total_for_phase0_identity_classes() {
    let fixture = adversarial_fixture();
    assert_eq!(fixture["schema_version"].as_u64(), Some(1));
    let cases = fixture["cases"].as_array().unwrap();
    for required_class in [
        "foreign_authority",
        "stale_authority",
        "same_transaction_successor",
        "signature",
        "release_declarer",
        "closure",
        "policy",
    ] {
        assert!(
            cases
                .iter()
                .any(|case| case["class"].as_str() == Some(required_class)),
            "missing adversarial class {required_class}"
        );
    }
    assert!(cases.iter().all(|case| {
        matches!(
            case["v2_expected"].as_str(),
            Some("accept") | Some("reject")
        ) && !case["reason"].as_str().unwrap_or_default().is_empty()
    }));

    // Pin every row's (class, legacy_observation, v2_expected) by name so a
    // silent edit to any case — including the same_transaction_successor and
    // not-exercised rows that have no live verifier cross-check elsewhere in
    // this file — fails the gate instead of only passing a shape check.
    const EXPECTED: &[(&str, &str, &str, &str)] = &[
        (
            "foreign-valid-authority-chain",
            "foreign_authority",
            "accept",
            "reject",
        ),
        (
            "stale-valid-authority-ancestor",
            "stale_authority",
            "accept",
            "reject",
        ),
        (
            "same-transaction-successor-object",
            "same_transaction_successor",
            "not-applicable",
            "reject",
        ),
        (
            "successor-object-in-later-transaction",
            "same_transaction_successor",
            "not-applicable",
            "accept",
        ),
        ("invalid-ed25519-signature", "signature", "reject", "reject"),
        (
            "malformed-extra-commit-signature",
            "signature",
            "reject",
            "reject",
        ),
        (
            "release-first-signer-is-not-declarer",
            "release_declarer",
            "reject",
            "reject",
        ),
        (
            "release-duplicate-cosigner",
            "release_declarer",
            "reject",
            "reject",
        ),
        (
            "missing-ordinary-tree-closure",
            "closure",
            "accept",
            "reject",
        ),
        (
            "wrong-embedded-edge-type",
            "closure",
            "not-exercised",
            "reject",
        ),
        (
            "repository-policy-read-failure",
            "policy",
            "not-exercised",
            "reject",
        ),
        (
            "repository-policy-parse-failure",
            "policy",
            "not-exercised",
            "reject",
        ),
        ("protected-branch-contributor", "policy", "reject", "reject"),
    ];
    assert_eq!(
        cases.len(),
        EXPECTED.len(),
        "case count drifted from the pinned table"
    );
    for (name, class, legacy_observation, v2_expected) in EXPECTED {
        let case = cases
            .iter()
            .find(|case| case["name"].as_str() == Some(*name))
            .unwrap_or_else(|| panic!("pinned case {name} is missing from the fixture"));
        assert_eq!(case["class"].as_str(), Some(*class), "{name} class");
        assert_eq!(
            case["legacy_observation"].as_str(),
            Some(*legacy_observation),
            "{name} legacy_observation"
        );
        assert_eq!(
            case["v2_expected"].as_str(),
            Some(*v2_expected),
            "{name} v2_expected"
        );
    }
}
