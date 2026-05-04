//! Verification algorithm from the v1.1 trust-root revision §3.6.
//!
//! Provides:
//!   - `verify_signed_object`: per-object signature check.
//!   - `verify_genesis`: validates a candidate genesis authority.
//!   - `verify_authority_chain`: walks back to genesis verifying each step.
//!   - `verify_commit`: full commit verification including authority chain.
//!
//! The verifier accepts any object source that implements `ObjectSource` so
//! the same logic works against an `ObjectStore`, an in-memory map, or a
//! remote-fetching shim.

use std::collections::HashMap;
use std::sync::Arc;

use thiserror::Error;

use levcs_core::object::{ObjectType, SignatureEntry, SignedObject};
use levcs_core::{ObjectId, RawObject, Tree};

use crate::authority::{AuthorityBody, Role};
use crate::error::IdentityError;
use crate::keys::PublicKey;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("object {hash}: {kind}")]
    Object { hash: String, kind: String },

    #[error("authority chain: {0}")]
    Authority(String),

    #[error("commit {hash}: {reason}")]
    Commit { hash: String, reason: String },

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error(transparent)]
    Core(#[from] levcs_core::Error),

    #[error("missing object: {0}")]
    Missing(String),
}

pub type Verification<T> = std::result::Result<T, VerifyError>;

/// Trait implemented by anything that can supply objects by hash.
pub trait ObjectSource {
    fn read_raw(&self, id: ObjectId) -> Verification<Vec<u8>>;
}

impl ObjectSource for levcs_core::ObjectStore {
    fn read_raw(&self, id: ObjectId) -> Verification<Vec<u8>> {
        Ok(self.read_raw(id)?)
    }
}

/// In-memory object source for unit tests.
pub struct MemorySource(pub HashMap<ObjectId, Vec<u8>>);

impl ObjectSource for MemorySource {
    fn read_raw(&self, id: ObjectId) -> Verification<Vec<u8>> {
        self.0
            .get(&id)
            .cloned()
            .ok_or_else(|| VerifyError::Missing(id.to_hex()))
    }
}

fn read_signed<S: ObjectSource>(src: &S, id: ObjectId) -> Verification<SignedObject> {
    let bytes = src.read_raw(id)?;
    Ok(
        SignedObject::parse(&bytes).map_err(|e| VerifyError::Object {
            hash: id.to_hex(),
            kind: e.to_string(),
        })?,
    )
}

/// Verify the signature(s) on a SignedObject. Each signature in the trailer
/// is checked against `BLAKE3(header || body)`. Returns Ok if every
/// signature is valid; the policy (role checks, count constraints) is
/// enforced by the caller.
pub fn verify_signed_object(signed: &SignedObject) -> Verification<()> {
    let h = signed.signing_hash();
    for s in &signed.signatures {
        let pk = PublicKey(s.public_key);
        pk.verify(h.as_bytes(), &s.signature)
            .map_err(IdentityError::from)?;
    }
    Ok(())
}

/// Verify that `genesis` is a well-formed genesis authority object, including
/// repo_id derivation and self-signature by an owner.
pub fn verify_genesis(genesis: &SignedObject) -> Verification<AuthorityBody> {
    if genesis.object_type != ObjectType::Authority {
        return Err(VerifyError::Authority(format!(
            "expected authority object, got {}",
            genesis.object_type.name()
        )));
    }
    let body =
        AuthorityBody::parse(&genesis.body).map_err(|e| VerifyError::Authority(e.to_string()))?;
    if !body.previous_authority.is_zero() {
        return Err(VerifyError::Authority(
            "genesis must have zero previous_authority".into(),
        ));
    }
    if body.version != 1 {
        return Err(VerifyError::Authority("genesis version must be 1".into()));
    }
    let zeroed = body
        .encode_with_repo_id_zero()
        .map_err(|e| VerifyError::Authority(e.to_string()))?;
    let derived = ObjectId(*blake3::hash(&zeroed).as_bytes());
    if derived != body.repo_id {
        return Err(VerifyError::Authority(format!(
            "repo_id derivation invalid: derived {}, body says {}",
            derived, body.repo_id
        )));
    }
    // Genesis must be self-signed by an owner.
    let h = genesis.signing_hash();
    let mut found = false;
    for s in &genesis.signatures {
        let pk = PublicKey(s.public_key);
        let member = match body.find_member(&pk) {
            Some(m) => m,
            None => continue,
        };
        if member.role == Role::Owner && pk.verify(h.as_bytes(), &s.signature).is_ok() {
            found = true;
            break;
        }
    }
    if !found {
        return Err(VerifyError::Authority(
            "no valid owner self-signature on genesis".into(),
        ));
    }
    Ok(body)
}

fn verify_authority_step(
    new_signed: &SignedObject,
    new_body: &AuthorityBody,
    prev_body: &AuthorityBody,
    prev_id: ObjectId,
) -> Verification<()> {
    if new_body.repo_id != prev_body.repo_id {
        return Err(VerifyError::Authority("repo_id mismatch".into()));
    }
    if new_body.version != prev_body.version + 1 {
        return Err(VerifyError::Authority(format!(
            "version not sequential: prev {} -> next {}",
            prev_body.version, new_body.version
        )));
    }
    if new_body.previous_authority != prev_id {
        return Err(VerifyError::Authority(
            "previous_authority does not match predecessor hash".into(),
        ));
    }
    // At least one signature on the new authority must be by an owner of prev.
    let h = new_signed.signing_hash();
    let mut found = false;
    for s in &new_signed.signatures {
        let pk = PublicKey(s.public_key);
        let member = match prev_body.find_member(&pk) {
            Some(m) => m,
            None => continue,
        };
        if member.role == Role::Owner && pk.verify(h.as_bytes(), &s.signature).is_ok() {
            found = true;
            break;
        }
    }
    if !found {
        return Err(VerifyError::Authority(
            "no valid owner signature on successor authority".into(),
        ));
    }
    Ok(())
}

/// Walk an authority back to genesis, verifying each step. Returns the body
/// of the genesis authority on success.
///
/// Standalone calls allocate a fresh verifier each time. Callers that
/// verify many tips in a loop (mirror sync, push handler iterating
/// commits) should use `ChainVerifier` directly so the chain walk can be
/// shared — without it, verifying N commits that all cite the same
/// authority is O(N × chain_depth).
pub fn verify_authority_chain<S: ObjectSource>(
    src: &S,
    start: ObjectId,
) -> Verification<AuthorityBody> {
    let mut v = ChainVerifier::new();
    let body = v.verify_chain(src, start)?;
    Ok((*body).clone())
}

/// Caches authority chains that have been fully verified back to genesis.
/// Hand the same verifier to a sequence of `verify_chain` / `verify_commit`
/// / `verify_release` calls and the per-call cost drops from O(chain
/// depth) to O(1) once an ancestor has been seen.
///
/// The cache is keyed by authority id, which is a BLAKE3 of the signed
/// object — collisions are infeasible — so a hit is sound: the underlying
/// bytes are guaranteed identical to whatever produced the original
/// success. Insertions are atomic per call: a partial walk that fails
/// midway leaves the cache untouched.
///
/// Not internally synchronized. Callers that share a verifier across
/// threads should wrap it in `Mutex<_>`.
#[derive(Default)]
pub struct ChainVerifier {
    /// Maps any id along a verified chain → the chain's genesis body.
    /// The same `Arc<AuthorityBody>` is shared across every entry that
    /// belongs to one chain, so memory cost scales with the number of
    /// distinct chains, not with the number of authorities.
    verified: HashMap<ObjectId, Arc<AuthorityBody>>,
}

impl ChainVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify the authority chain rooted at `start` back to genesis.
    /// On a cache hit (any id along a previously-verified chain), returns
    /// the cached genesis body in O(1). On a cache miss, walks the chain,
    /// verifies each step, and on full success records every walked id
    /// against a single shared genesis body.
    pub fn verify_chain<S: ObjectSource>(
        &mut self,
        src: &S,
        start: ObjectId,
    ) -> Verification<Arc<AuthorityBody>> {
        if let Some(g) = self.verified.get(&start) {
            return Ok(g.clone());
        }
        // Walk back, accumulating the path. We don't insert anything into
        // the cache until the entire walk succeeds — a partial walk that
        // errors out must not leave half-trusted ids cached.
        let mut walked: Vec<ObjectId> = Vec::new();
        let mut cur_id = start;
        let mut cur_signed = read_signed(src, cur_id)?;
        let mut cur_body = AuthorityBody::parse(&cur_signed.body)
            .map_err(|e| VerifyError::Authority(e.to_string()))?;
        let genesis: Arc<AuthorityBody> = loop {
            walked.push(cur_id);
            if cur_body.previous_authority.is_zero() {
                break Arc::new(verify_genesis(&cur_signed)?);
            }
            let prev_id = cur_body.previous_authority;
            // Cache hit on the predecessor: we still need to verify the
            // step from cur → prev (because the *step's* signature isn't
            // covered by prev being known-good), but the rest of the
            // chain back to genesis is already trusted.
            if let Some(g) = self.verified.get(&prev_id).cloned() {
                let prev_signed = read_signed(src, prev_id)?;
                let prev_body = AuthorityBody::parse(&prev_signed.body)
                    .map_err(|e| VerifyError::Authority(e.to_string()))?;
                verify_authority_step(&cur_signed, &cur_body, &prev_body, prev_id)?;
                break g;
            }
            let prev_signed = read_signed(src, prev_id)?;
            let prev_body = AuthorityBody::parse(&prev_signed.body)
                .map_err(|e| VerifyError::Authority(e.to_string()))?;
            verify_authority_step(&cur_signed, &cur_body, &prev_body, prev_id)?;
            cur_signed = prev_signed;
            cur_body = prev_body;
            cur_id = prev_id;
        };
        for id in walked {
            self.verified.insert(id, genesis.clone());
        }
        Ok(genesis)
    }

    /// Cache-aware variant of `verify_commit`. Identical semantics; the
    /// only behavioural difference is that authority chains visited in
    /// prior calls don't get re-walked.
    pub fn verify_commit<S: ObjectSource>(
        &mut self,
        src: &S,
        commit_id: ObjectId,
        target_ref: Option<&str>,
    ) -> Verification<()> {
        verify_commit_inner(src, commit_id, target_ref, self)
    }

    /// Cache-aware variant of `verify_release`.
    pub fn verify_release<S: ObjectSource>(
        &mut self,
        src: &S,
        release_id: ObjectId,
    ) -> Verification<()> {
        verify_release_inner(src, release_id, self)
    }

    #[cfg(test)]
    pub(crate) fn cache_size(&self) -> usize {
        self.verified.len()
    }
}

/// Verify a successor authority object against `A_old`, given the signer key
/// that will be checked. The signer must be an owner of `A_old` AND must
/// appear among `A_new`'s signatures.
pub fn verify_successor(
    a_new: &SignedObject,
    a_new_body: &AuthorityBody,
    a_old_id: ObjectId,
    a_old_body: &AuthorityBody,
    signer: PublicKey,
) -> Verification<()> {
    if a_new_body.previous_authority != a_old_id {
        return Err(VerifyError::Authority(
            "successor previous_authority != hash(A_old)".into(),
        ));
    }
    if a_new_body.version != a_old_body.version + 1 {
        return Err(VerifyError::Authority("version not sequential".into()));
    }
    if a_new_body.repo_id != a_old_body.repo_id {
        return Err(VerifyError::Authority("repo_id mismatch".into()));
    }
    let m = a_old_body
        .find_member(&signer)
        .ok_or_else(|| VerifyError::Authority("signer not in predecessor authority".into()))?;
    if m.role < Role::Owner {
        return Err(VerifyError::Authority(
            "signer must hold owner role in predecessor".into(),
        ));
    }
    let found_in_new = a_new.signatures.iter().any(|s| s.public_key == signer.0);
    if !found_in_new {
        return Err(VerifyError::Authority(
            "predecessor owner must also sign the new authority".into(),
        ));
    }
    Ok(())
}

/// Verify a fork-genesis authority pair (per §3.5). `a_source_body` is the
/// source repository's authority at the parent commit; `a_new` is the fork's
/// new genesis.
pub fn verify_fork(
    fork_author: PublicKey,
    a_source_body: &AuthorityBody,
    a_new: &SignedObject,
    a_new_body: &AuthorityBody,
) -> Verification<()> {
    let _ = verify_genesis(a_new)?;
    if a_new_body.repo_id == a_source_body.repo_id {
        return Err(VerifyError::Authority("fork must have new repo_id".into()));
    }
    if a_source_body.public_read() {
        return Ok(());
    }
    let m = a_source_body.find_member(&fork_author).ok_or_else(|| {
        VerifyError::Authority("fork author not authorized to read source".into())
    })?;
    if m.role < Role::Reader {
        return Err(VerifyError::Authority(
            "fork author lacks reader role".into(),
        ));
    }
    Ok(())
}

/// Determine the role required for a commit given the active authority. In
/// v1.1 this is:
///   - Owner if the commit modifies authority (flag bit 0 or fork bit).
///   - Maintainer if the target ref matches a `protected_branches` glob.
///   - Contributor otherwise.
pub fn role_for_commit(
    flags: levcs_core::CommitFlags,
    authority: &AuthorityBody,
    target_ref: Option<&str>,
) -> Role {
    if flags.modifies_authority() || flags.is_fork() {
        return Role::Owner;
    }
    if let Some(name) = target_ref {
        for pat in authority.protected_branches() {
            if glob::Pattern::new(&pat)
                .map(|p| p.matches(name))
                .unwrap_or(false)
            {
                return Role::Maintainer;
            }
        }
    }
    Role::Contributor
}

/// Full commit verification per §3.6 algorithm. `target_ref` is the ref the
/// commit is being applied to (used for protected-branch role checks); pass
/// `None` if not applicable (e.g., during walking).
///
/// Each call walks the authority chain from scratch. To share that work
/// across many commits — e.g., during a mirror sync that verifies a
/// branch's worth of tips — use `ChainVerifier::verify_commit` instead.
pub fn verify_commit<S: ObjectSource>(
    src: &S,
    commit_id: ObjectId,
    target_ref: Option<&str>,
) -> Verification<()> {
    verify_commit_inner(src, commit_id, target_ref, &mut ChainVerifier::new())
}

fn verify_commit_inner<S: ObjectSource>(
    src: &S,
    commit_id: ObjectId,
    target_ref: Option<&str>,
    verifier: &mut ChainVerifier,
) -> Verification<()> {
    let bytes = src.read_raw(commit_id)?;
    let actual = blake3::hash(&bytes);
    if *actual.as_bytes() != commit_id.0 {
        return Err(VerifyError::Object {
            hash: commit_id.to_hex(),
            kind: "stored bytes do not match expected hash".into(),
        });
    }
    let signed = SignedObject::parse(&bytes).map_err(|e| VerifyError::Object {
        hash: commit_id.to_hex(),
        kind: e.to_string(),
    })?;
    if signed.object_type != ObjectType::Commit {
        return Err(VerifyError::Commit {
            hash: commit_id.to_hex(),
            reason: format!("expected commit, got {}", signed.object_type.name()),
        });
    }
    if signed.signatures.len() != 1 {
        return Err(VerifyError::Commit {
            hash: commit_id.to_hex(),
            reason: format!(
                "commit must have 1 signature, got {}",
                signed.signatures.len()
            ),
        });
    }
    let sig = signed.signatures[0];
    let commit = levcs_core::Commit::from_signed(&signed).map_err(|e| VerifyError::Commit {
        hash: commit_id.to_hex(),
        reason: e.to_string(),
    })?;
    if sig.public_key != commit.author_key {
        return Err(VerifyError::Commit {
            hash: commit_id.to_hex(),
            reason: "author_key does not match trailer signature key".into(),
        });
    }
    let pk = PublicKey(sig.public_key);
    pk.verify(signed.signing_hash().as_bytes(), &sig.signature)
        .map_err(|_| VerifyError::Commit {
            hash: commit_id.to_hex(),
            reason: "Ed25519 signature invalid".into(),
        })?;
    // Verify authority chain.
    let auth_signed = read_signed(src, commit.authority)?;
    let auth_body = AuthorityBody::parse(&auth_signed.body)
        .map_err(|e| VerifyError::Authority(e.to_string()))?;
    let _ = verifier.verify_chain(src, commit.authority)?;
    let member = auth_body
        .find_member(&pk)
        .ok_or_else(|| VerifyError::Commit {
            hash: commit_id.to_hex(),
            reason: "author not in authority".into(),
        })?;
    let required = role_for_commit(commit.flags, &auth_body, target_ref);
    if member.role < required {
        return Err(VerifyError::Commit {
            hash: commit_id.to_hex(),
            reason: format!(
                "insufficient role: have {}, need {}",
                member.role.name(),
                required.name()
            ),
        });
    }
    if commit.flags.modifies_authority() || commit.flags.is_fork() {
        // The new authority must be reachable via the tree at .levcs/authority.
        let new_auth_id = locate_new_authority(src, commit.tree)?;
        let new_signed = read_signed(src, new_auth_id)?;
        let new_body = AuthorityBody::parse(&new_signed.body)
            .map_err(|e| VerifyError::Authority(e.to_string()))?;
        verify_signed_object(&new_signed)?;
        if commit.flags.is_fork() {
            // Per §3.5.3, fork-commit signature is verified against the new
            // genesis authority (already done above via auth_body, which for
            // fork commits is the new authority since C.body.authority points
            // to the new genesis). For *read authorization* against the
            // source, look up the parent commit's authority.
            if commit.parents.len() != 1 {
                return Err(VerifyError::Commit {
                    hash: commit_id.to_hex(),
                    reason: format!(
                        "fork commit must have exactly 1 parent, got {}",
                        commit.parents.len()
                    ),
                });
            }
            let parent_signed = read_signed(src, commit.parents[0])?;
            let parent_commit = levcs_core::Commit::from_signed(&parent_signed).map_err(|e| {
                VerifyError::Commit {
                    hash: commit_id.to_hex(),
                    reason: e.to_string(),
                }
            })?;
            let source_auth_signed = read_signed(src, parent_commit.authority)?;
            let source_auth_body = AuthorityBody::parse(&source_auth_signed.body)
                .map_err(|e| VerifyError::Authority(e.to_string()))?;
            verify_fork(pk, &source_auth_body, &new_signed, &new_body)?;
        } else {
            verify_successor(&new_signed, &new_body, commit.authority, &auth_body, pk)?;
        }
    }
    Ok(())
}

/// Verify a release object: check stored bytes hash to the claimed id,
/// validate the signed envelope, parse the release body, walk the
/// authority chain it cites back to genesis, and confirm every signing
/// key is a member of that authority.
///
/// Releases (§4.1) don't have an "author key" trailer the way commits do;
/// the signers are simply the authority members who minted it. So the
/// membership check loops over `signed.signatures` and pins each one
/// against the authority body. A release with no listed members signing
/// it is rejected.
pub fn verify_release<S: ObjectSource>(src: &S, release_id: ObjectId) -> Verification<()> {
    verify_release_inner(src, release_id, &mut ChainVerifier::new())
}

fn verify_release_inner<S: ObjectSource>(
    src: &S,
    release_id: ObjectId,
    verifier: &mut ChainVerifier,
) -> Verification<()> {
    let bytes = src.read_raw(release_id)?;
    let actual = blake3::hash(&bytes);
    if *actual.as_bytes() != release_id.0 {
        return Err(VerifyError::Object {
            hash: release_id.to_hex(),
            kind: "stored bytes do not match expected hash".into(),
        });
    }
    let signed = SignedObject::parse(&bytes).map_err(|e| VerifyError::Object {
        hash: release_id.to_hex(),
        kind: e.to_string(),
    })?;
    if signed.object_type != ObjectType::Release {
        return Err(VerifyError::Object {
            hash: release_id.to_hex(),
            kind: format!("expected release, got {}", signed.object_type.name()),
        });
    }
    if signed.signatures.is_empty() {
        return Err(VerifyError::Object {
            hash: release_id.to_hex(),
            kind: "release has no signatures".into(),
        });
    }
    verify_signed_object(&signed)?;
    let release =
        levcs_core::Release::parse_body(&signed.body).map_err(|e| VerifyError::Object {
            hash: release_id.to_hex(),
            kind: e.to_string(),
        })?;
    let _ = verifier.verify_chain(src, release.authority)?;
    let auth_signed = read_signed(src, release.authority)?;
    let auth_body = AuthorityBody::parse(&auth_signed.body)
        .map_err(|e| VerifyError::Authority(e.to_string()))?;
    for s in &signed.signatures {
        let pk = PublicKey(s.public_key);
        if auth_body.find_member(&pk).is_none() {
            return Err(VerifyError::Object {
                hash: release_id.to_hex(),
                kind: "release signed by key not in authority".into(),
            });
        }
    }
    Ok(())
}

fn locate_new_authority<S: ObjectSource>(src: &S, tree_id: ObjectId) -> Verification<ObjectId> {
    let raw = parse_raw(src, tree_id, ObjectType::Tree)?;
    let tree = Tree::parse_body(&raw.body).map_err(|e| VerifyError::Object {
        hash: tree_id.to_hex(),
        kind: e.to_string(),
    })?;
    let levcs_dir = tree.find(".levcs").ok_or_else(|| VerifyError::Commit {
        hash: tree_id.to_hex(),
        reason: "tree has no .levcs directory".into(),
    })?;
    if levcs_dir.entry_type != levcs_core::EntryType::Tree {
        return Err(VerifyError::Commit {
            hash: tree_id.to_hex(),
            reason: ".levcs is not a tree".into(),
        });
    }
    let inner = parse_raw(src, levcs_dir.hash, ObjectType::Tree)?;
    let inner_tree = Tree::parse_body(&inner.body).map_err(|e| VerifyError::Object {
        hash: levcs_dir.hash.to_hex(),
        kind: e.to_string(),
    })?;
    let auth = inner_tree
        .find("authority")
        .ok_or_else(|| VerifyError::Commit {
            hash: levcs_dir.hash.to_hex(),
            reason: "tree has no .levcs/authority entry".into(),
        })?;
    Ok(auth.hash)
}

fn parse_raw<S: ObjectSource>(
    src: &S,
    id: ObjectId,
    expect: ObjectType,
) -> Verification<RawObject> {
    let bytes = src.read_raw(id)?;
    let actual = blake3::hash(&bytes);
    if *actual.as_bytes() != id.0 {
        return Err(VerifyError::Object {
            hash: id.to_hex(),
            kind: "hash mismatch".into(),
        });
    }
    let raw = RawObject::parse(&bytes).map_err(|e| VerifyError::Object {
        hash: id.to_hex(),
        kind: e.to_string(),
    })?;
    if raw.object_type != expect {
        return Err(VerifyError::Object {
            hash: id.to_hex(),
            kind: format!("expected {}, got {}", expect.name(), raw.object_type.name()),
        });
    }
    Ok(raw)
}

/// Used by the trailer count check at object boundaries.
#[allow(dead_code)]
pub(crate) fn entry_eq(a: &SignatureEntry, b: &SignatureEntry) -> bool {
    a.public_key == b.public_key && a.signature == b.signature
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SecretKey;
    use crate::sign::sign_authority;

    #[test]
    fn genesis_verifies() {
        let sk = SecretKey::generate();
        let pk = sk.public();
        let mut body = AuthorityBody {
            schema_version: 1,
            repo_id: ObjectId([0u8; 32]),
            previous_authority: ObjectId([0u8; 32]),
            version: 1,
            created_micros: 1_700_000_000_000_000,
            members: vec![crate::authority::MemberEntry {
                key: pk,
                handle: "alice".into(),
                role: Role::Owner,
                added_micros: 1_700_000_000_000_000,
                added_by: pk,
            }],
            policy: vec![crate::authority::PolicyEntry {
                key: "public_read".into(),
                value: vec![0x01],
            }],
        };
        body.assign_genesis_repo_id().unwrap();
        let signed = sign_authority(&body, &sk).unwrap();
        verify_signed_object(&signed).unwrap();
        let body2 = verify_genesis(&signed).unwrap();
        assert_eq!(body, body2);
    }

    #[test]
    fn fork_against_public_source_succeeds() {
        // Source authority: public_read = true, alice owns it.
        let alice = SecretKey::generate();
        let alice_pk = alice.public();
        let now = 1_700_000_000_000_000;
        let mut source = AuthorityBody {
            schema_version: 1,
            repo_id: ObjectId([0u8; 32]),
            previous_authority: ObjectId([0u8; 32]),
            version: 1,
            created_micros: now,
            members: vec![crate::authority::MemberEntry {
                key: alice_pk,
                handle: "alice".into(),
                role: Role::Owner,
                added_micros: now,
                added_by: alice_pk,
            }],
            policy: vec![crate::authority::PolicyEntry {
                key: "public_read".into(),
                value: vec![0x01],
            }],
        };
        source.normalize().unwrap();
        source.assign_genesis_repo_id().unwrap();

        // Bob (a stranger) creates a fork-genesis.
        let bob = SecretKey::generate();
        let bob_pk = bob.public();
        let mut fork = AuthorityBody {
            schema_version: 1,
            repo_id: ObjectId([0u8; 32]),
            previous_authority: ObjectId([0u8; 32]),
            version: 1,
            created_micros: now,
            members: vec![crate::authority::MemberEntry {
                key: bob_pk,
                handle: "bob".into(),
                role: Role::Owner,
                added_micros: now,
                added_by: bob_pk,
            }],
            policy: vec![],
        };
        fork.normalize().unwrap();
        fork.assign_genesis_repo_id().unwrap();
        assert_ne!(fork.repo_id, source.repo_id);
        let fork_signed = crate::sign::sign_authority(&fork, &bob).unwrap();
        verify_fork(bob_pk, &source, &fork_signed, &fork).unwrap();
    }

    #[test]
    fn fork_against_private_source_blocks_strangers() {
        let alice = SecretKey::generate();
        let alice_pk = alice.public();
        let now = 1_700_000_000_000_000;
        let mut source = AuthorityBody {
            schema_version: 1,
            repo_id: ObjectId([0u8; 32]),
            previous_authority: ObjectId([0u8; 32]),
            version: 1,
            created_micros: now,
            members: vec![crate::authority::MemberEntry {
                key: alice_pk,
                handle: "alice".into(),
                role: Role::Owner,
                added_micros: now,
                added_by: alice_pk,
            }],
            policy: vec![crate::authority::PolicyEntry {
                key: "public_read".into(),
                value: vec![0x00],
            }],
        };
        source.normalize().unwrap();
        source.assign_genesis_repo_id().unwrap();

        let bob = SecretKey::generate();
        let bob_pk = bob.public();
        let mut fork = AuthorityBody {
            schema_version: 1,
            repo_id: ObjectId([0u8; 32]),
            previous_authority: ObjectId([0u8; 32]),
            version: 1,
            created_micros: now,
            members: vec![crate::authority::MemberEntry {
                key: bob_pk,
                handle: "bob".into(),
                role: Role::Owner,
                added_micros: now,
                added_by: bob_pk,
            }],
            policy: vec![],
        };
        fork.normalize().unwrap();
        fork.assign_genesis_repo_id().unwrap();
        let fork_signed = crate::sign::sign_authority(&fork, &bob).unwrap();
        let res = verify_fork(bob_pk, &source, &fork_signed, &fork);
        assert!(
            res.is_err(),
            "stranger should not be able to fork private source"
        );
    }

    #[test]
    fn fork_with_colliding_repo_id_rejected() {
        let alice = SecretKey::generate();
        let alice_pk = alice.public();
        let now = 1_700_000_000_000_000;
        let mut source = AuthorityBody {
            schema_version: 1,
            repo_id: ObjectId([0u8; 32]),
            previous_authority: ObjectId([0u8; 32]),
            version: 1,
            created_micros: now,
            members: vec![crate::authority::MemberEntry {
                key: alice_pk,
                handle: "alice".into(),
                role: Role::Owner,
                added_micros: now,
                added_by: alice_pk,
            }],
            policy: vec![crate::authority::PolicyEntry {
                key: "public_read".into(),
                value: vec![0x01],
            }],
        };
        source.normalize().unwrap();
        source.assign_genesis_repo_id().unwrap();
        // Pretend the fork derived the same repo_id (impossible in practice
        // without a BLAKE3 collision, but the verifier must still reject).
        let mut fork = source.clone();
        let fork_signed = crate::sign::sign_authority(&fork, &alice).unwrap();
        let _ = fork.assign_genesis_repo_id();
        let res = verify_fork(alice_pk, &source, &fork_signed, &fork);
        assert!(res.is_err(), "colliding repo_id must be rejected");
    }

    #[test]
    fn tampered_genesis_rejected() {
        let sk = SecretKey::generate();
        let pk = sk.public();
        let mut body = AuthorityBody {
            schema_version: 1,
            repo_id: ObjectId([0u8; 32]),
            previous_authority: ObjectId([0u8; 32]),
            version: 1,
            created_micros: 1_700_000_000_000_000,
            members: vec![crate::authority::MemberEntry {
                key: pk,
                handle: "alice".into(),
                role: Role::Owner,
                added_micros: 1_700_000_000_000_000,
                added_by: pk,
            }],
            policy: vec![],
        };
        body.assign_genesis_repo_id().unwrap();
        let mut signed = sign_authority(&body, &sk).unwrap();
        signed.body[0] ^= 0xFF; // tamper
        assert!(verify_signed_object(&signed).is_err());
    }

    /// `ObjectSource` wrapper that counts each `read_raw` call. Lets us
    /// assert exactly how many bytes the verifier actually fetched, which
    /// is the only direct way to observe a chain-cache hit.
    struct CountingSource<'a> {
        inner: &'a MemorySource,
        reads: std::cell::Cell<usize>,
    }
    impl<'a> CountingSource<'a> {
        fn new(inner: &'a MemorySource) -> Self {
            Self {
                inner,
                reads: std::cell::Cell::new(0),
            }
        }
        fn reads(&self) -> usize {
            self.reads.get()
        }
    }
    impl<'a> ObjectSource for CountingSource<'a> {
        fn read_raw(&self, id: ObjectId) -> Verification<Vec<u8>> {
            self.reads.set(self.reads.get() + 1);
            self.inner.read_raw(id)
        }
    }

    /// Build a chain of `length` authorities — genesis at index 0, each
    /// later entry a properly-signed successor of the previous — backed
    /// by `alice` (an Owner) for the whole walk. Returns the
    /// `MemorySource` plus the list of authority ids in order.
    fn build_chain(length: usize, alice: &SecretKey) -> (MemorySource, Vec<ObjectId>) {
        assert!(length >= 1);
        let alice_pk = alice.public();
        let now = 1_700_000_000_000_000;
        let mut genesis = AuthorityBody {
            schema_version: 1,
            repo_id: ObjectId([0u8; 32]),
            previous_authority: ObjectId([0u8; 32]),
            version: 1,
            created_micros: now,
            members: vec![crate::authority::MemberEntry {
                key: alice_pk,
                handle: "alice".into(),
                role: Role::Owner,
                added_micros: now,
                added_by: alice_pk,
            }],
            policy: vec![crate::authority::PolicyEntry {
                key: "public_read".into(),
                value: vec![0x01],
            }],
        };
        genesis.normalize().unwrap();
        genesis.assign_genesis_repo_id().unwrap();
        let genesis_signed = sign_authority(&genesis, alice).unwrap();
        let genesis_id = ObjectId(*blake3::hash(&genesis_signed.serialize()).as_bytes());

        let mut store: HashMap<ObjectId, Vec<u8>> = HashMap::new();
        let mut ids = vec![genesis_id];
        store.insert(genesis_id, genesis_signed.serialize());

        let mut prev_id = genesis_id;
        let mut prev_body = genesis;
        for v in 2..=length as u32 {
            let mut body = AuthorityBody {
                schema_version: prev_body.schema_version,
                repo_id: prev_body.repo_id,
                previous_authority: prev_id,
                version: v,
                created_micros: now + v as i64 * 1_000_000,
                members: prev_body.members.clone(),
                policy: prev_body.policy.clone(),
            };
            body.normalize().unwrap();
            let signed = sign_authority(&body, alice).unwrap();
            let id = ObjectId(*blake3::hash(&signed.serialize()).as_bytes());
            store.insert(id, signed.serialize());
            ids.push(id);
            prev_id = id;
            prev_body = body;
        }
        (MemorySource(store), ids)
    }

    /// Verifying a chain of length N from the tip touches every
    /// authority object exactly once. A second verification of the same
    /// tip — using the same `ChainVerifier` — must perform zero reads.
    /// This is the user-visible win: O(N²) → O(N) total work for N
    /// commits citing the same chain.
    #[test]
    fn chain_verifier_caches_walked_authorities() {
        let alice = SecretKey::generate();
        let (mem, ids) = build_chain(5, &alice);
        let src = CountingSource::new(&mem);
        let mut verifier = ChainVerifier::new();

        let _ = verifier.verify_chain(&src, *ids.last().unwrap()).unwrap();
        let first_pass_reads = src.reads();
        assert!(
            first_pass_reads >= 5,
            "first verification must read every authority at least once; got {first_pass_reads}"
        );
        // Every walked authority should now sit in the cache pointing
        // at the same shared genesis body.
        assert_eq!(verifier.cache_size(), ids.len());

        let before = src.reads();
        let _ = verifier.verify_chain(&src, *ids.last().unwrap()).unwrap();
        assert_eq!(
            src.reads(),
            before,
            "cached re-verification must perform zero reads"
        );
    }

    /// Verifying an *ancestor* after the tip must also be a cache hit —
    /// this is the practical case during a sync where one tip points at
    /// `A_n` and a second tip points at `A_{n-1}`.
    #[test]
    fn chain_verifier_serves_ancestors_from_cache() {
        let alice = SecretKey::generate();
        let (mem, ids) = build_chain(4, &alice);
        let src = CountingSource::new(&mem);
        let mut verifier = ChainVerifier::new();
        let _ = verifier.verify_chain(&src, *ids.last().unwrap()).unwrap();
        let after_tip = src.reads();
        // Ask for A_2 — should be a hit.
        let _ = verifier.verify_chain(&src, ids[1]).unwrap();
        assert_eq!(
            src.reads(),
            after_tip,
            "ancestor verification must hit cache, not re-walk"
        );
    }

    /// A failing verification must NOT pollute the cache. The test
    /// rebuilds a chain, corrupts the bytes of the most recent
    /// authority, and checks that (a) verification fails, (b) the
    /// cache stays empty, and (c) a follow-up valid lookup still walks
    /// the chain rather than serving a phantom hit.
    #[test]
    fn chain_verifier_does_not_cache_on_failure() {
        let alice = SecretKey::generate();
        let (mut mem, ids) = build_chain(3, &alice);
        let tip_id = *ids.last().unwrap();
        // Mutate the byte at offset 12 of the tip's signed bytes — that
        // sits inside the authority body, so the recorded BLAKE3 hash
        // will no longer match the id that names it. The verifier reads
        // by id and re-hashes the bytes; mismatched bytes propagate as
        // a `repo_id derivation invalid` or a parse-time error depending
        // on the offset, but in either case the chain walk fails.
        let bytes = mem.0.get(&tip_id).unwrap().clone();
        let mut bad = bytes.clone();
        bad[12] ^= 0xFF;
        mem.0.insert(tip_id, bad);

        let src = CountingSource::new(&mem);
        let mut verifier = ChainVerifier::new();
        assert!(
            verifier.verify_chain(&src, tip_id).is_err(),
            "corrupted tip must fail verification"
        );
        assert_eq!(
            verifier.cache_size(),
            0,
            "failed verification must leave the cache empty"
        );
    }
}
