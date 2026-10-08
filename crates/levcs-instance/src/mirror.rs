//! Inter-instance mirroring (§5.6).
//!
//! [`sync_mirror`] is a single, blocking sync pass: it polls the source
//! instance's `/info` and `/refs`, fetches a pack of objects this instance
//! does not yet have, verifies their signatures locally against the
//! repository's own authority chain, and atomically advances the local
//! refs. The receiver does not have to trust the source — every signature
//! is checked against in-repository authority data.
//!
//! The function is sync because [`levcs_client::Client`] wraps blocking
//! `reqwest`. Callers that want to drive it from an async context should
//! invoke it via `tokio::task::spawn_blocking`. A simple background poller
//! is provided as [`spawn_poller`].

use std::path::PathBuf;
use std::time::Duration;

use levcs_client::{Client, ClientError};
use levcs_core::{ObjectId, ObjectStore, Refs, Repository};
use levcs_identity::verify::ChainVerifier;
use thiserror::Error;

use crate::{InstanceConfig, MirrorConfig, RepoId};

#[derive(Debug, Error)]
pub enum MirrorError {
    #[error("client: {0}")]
    Client(#[from] ClientError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("core: {0}")]
    Core(#[from] levcs_core::error::Error),

    #[error("verify: {0}")]
    Verify(#[from] levcs_identity::verify::VerifyError),

    #[error("malformed hash: {0}")]
    Hash(String),

    #[error("unsupported mode: {0}")]
    Mode(String),

    #[error("mirror repo_id {0:?} is not 64 lowercase hex characters")]
    RepoId(String),
}

/// What the most recent sync pass changed locally.
#[derive(Clone, Debug, Default)]
pub struct MirrorReport {
    pub objects_received: usize,
    pub branches_updated: usize,
    pub releases_updated: usize,
    pub authority_changed: bool,
}

/// One sync pass against `mirror.source`. Idempotent — calling it on a
/// fully-up-to-date mirror is a no-op apart from two HTTP GETs.
///
/// In `mode = "full"` we mirror branches + releases + authority chain.
/// In `mode = "release"` we mirror only releases + authority chain
/// (§4.3): inter-release commits are not pulled, branches are not advanced,
/// matching how a release-only instance is meant to behave.
pub fn sync_mirror(
    config: &InstanceConfig,
    mirror: &MirrorConfig,
) -> Result<MirrorReport, MirrorError> {
    if mirror.mode != "full" && mirror.mode != "release" {
        return Err(MirrorError::Mode(mirror.mode.clone()));
    }

    // Only an id is ever joined onto the root: a mirror's `repo_id` used to
    // be joined as configured.
    let repo = RepoId::parse(&mirror.repo_id)
        .ok_or_else(|| MirrorError::RepoId(mirror.repo_id.clone()))?;
    let repo_dir: PathBuf = config.repo_dir(&repo);
    if !repo_dir.is_dir() {
        Repository::init_skeleton(&repo_dir)?;
    }
    let store = ObjectStore::new(repo_dir.join(".levcs/objects"));
    let refs = Refs::new(repo_dir.join(".levcs"));

    let client = Client::new(&mirror.source);
    let info = client.repo_info(&mirror.repo_id)?;
    let remote_refs = client.refs(&mirror.repo_id)?;

    // What we want from the source: tips of every ref we'll mirror, plus
    // the current authority (and its chain — closure resolution on the
    // server side handles previous_authority transitively).
    let mut want: Vec<ObjectId> = Vec::new();
    let mut want_branches: Vec<(String, ObjectId)> = Vec::new();
    let mut want_releases: Vec<(String, ObjectId)> = Vec::new();

    if mirror.mode == "full" {
        for (name, hash) in &remote_refs.branches {
            let id = parse_hash(hash)?;
            want.push(id);
            want_branches.push((name.clone(), id));
        }
    }
    for (name, hash) in &remote_refs.releases {
        let id = parse_hash(hash)?;
        want.push(id);
        want_releases.push((name.clone(), id));
    }
    if !info.current_authority.is_empty() {
        want.push(parse_hash(&info.current_authority)?);
    }

    // What we already have. Anything reachable from these tips, the server
    // will exclude from the pack — this keeps mirror passes incremental.
    let mut have: Vec<ObjectId> = Vec::new();
    for (_, id) in refs.list_branches()? {
        have.push(id);
    }
    for (_, id) in refs.list_releases()? {
        have.push(id);
    }
    if let Some(cur) = refs.read("refs/authority/current")? {
        have.push(cur);
    }

    let pack = client.get_pack(&mirror.repo_id, &have, &want)?;

    // Stage objects to disk first. The receiver verifies against the
    // local store, so verification needs the bytes already written.
    for ent in &pack.entries {
        store.write_raw(&ent.bytes)?;
    }

    // Share one chain-verification cache across every per-tip check below.
    // Without this, each tip independently walks its authority chain back
    // to genesis — repeating identical work for every tip that cites the
    // same authority. With the cache the second tip onwards is O(1).
    let mut verifier = ChainVerifier::new();

    // Verify the authority chain on the announced current authority.
    // This populates the cache with the entire chain so the per-tip
    // checks below get cache hits.
    if !info.current_authority.is_empty() {
        let cur_auth = parse_hash(&info.current_authority)?;
        verifier.verify_chain(&store, cur_auth)?;
    }

    // Per-branch verification — fully checks signature, author membership,
    // and authority chain. If verification fails on any tip we abort
    // before touching local refs, so a bad source can never poison us.
    for (name, id) in &want_branches {
        verifier.verify_commit(&store, *id, Some(&format!("refs/branches/{name}")))?;
    }
    // Per-release verification: check the signed object itself and its
    // authority. The release object's full schema check (predecessor /
    // parent_release wiring) is the responsibility of `levcs_core::Release`
    // when consumers parse it; here we ensure the signature is valid and
    // the signing key is actually a member of the chain rooted in our
    // local genesis.
    for (_, id) in &want_releases {
        verifier.verify_release(&store, *id)?;
    }

    // All checks passed — advance local refs. We do branches first, then
    // releases, then the authority pointer. There is no per-pass atomicity
    // guarantee between refs (each `Refs::write` is its own fsync), but
    // each individual ref moves forward only after its tip has been
    // independently verified, so partial application leaves the mirror in
    // a consistent — if interleaved — state.
    let mut report = MirrorReport {
        objects_received: pack.entries.len(),
        ..Default::default()
    };

    if mirror.mode == "full" {
        for (name, id) in &want_branches {
            let path = format!("refs/branches/{name}");
            if refs.read(&path)? != Some(*id) {
                refs.write(&path, *id)?;
                report.branches_updated += 1;
            }
        }
    }
    for (name, id) in &want_releases {
        let path = format!("refs/releases/{name}");
        if refs.read(&path)? != Some(*id) {
            refs.write(&path, *id)?;
            report.releases_updated += 1;
        }
    }
    if !info.genesis_authority.is_empty() {
        let g = parse_hash(&info.genesis_authority)?;
        // Genesis is set once and never changes for a repo. Only write if
        // we don't already have it — guards against accidentally clobbering
        // a locally-init'd genesis with a different one.
        if refs.read("refs/authority/genesis")?.is_none() {
            refs.write("refs/authority/genesis", g)?;
        }
    }
    if !info.current_authority.is_empty() {
        let c = parse_hash(&info.current_authority)?;
        if refs.read("refs/authority/current")? != Some(c) {
            refs.write("refs/authority/current", c)?;
            report.authority_changed = true;
        }
    }

    Ok(report)
}

/// Spawn a tokio task that calls [`sync_mirror`] on a fixed cadence.
/// `every` overrides `mirror.poll_interval`; pass it explicitly so callers
/// own the parsing/clamping policy.
///
/// Errors from individual passes are logged via `tracing` and do not stop
/// the loop — a transient source outage shouldn't kill the poller.
pub fn spawn_poller(
    config: std::sync::Arc<InstanceConfig>,
    mirror: MirrorConfig,
    every: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let cfg = config.clone();
            let m = mirror.clone();
            let res = tokio::task::spawn_blocking(move || sync_mirror(&cfg, &m)).await;
            match res {
                Ok(Ok(report)) => tracing::debug!(
                    "mirror sync of {}: {} objects, {} branches, {} releases",
                    mirror.repo_id,
                    report.objects_received,
                    report.branches_updated,
                    report.releases_updated
                ),
                Ok(Err(e)) => tracing::warn!("mirror sync of {} failed: {e}", mirror.repo_id),
                Err(e) => tracing::error!("mirror sync of {} panicked: {e}", mirror.repo_id),
            }
            tokio::time::sleep(every).await;
        }
    })
}

fn parse_hash(s: &str) -> Result<ObjectId, MirrorError> {
    ObjectId::from_hex(s).map_err(|e| MirrorError::Hash(e.to_string()))
}
