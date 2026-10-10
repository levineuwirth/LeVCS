//! Receiving published history from an instance: `clone`, `pull` and the
//! read side of `fork` (`doc/authority-semantics.md`, Rule R).
//!
//! Each used to write whatever it was sent: `pull` recorded refs to objects
//! it never received, and `fork` took its source tip on the instance's word
//! (audit H3). Now what an instance sends is held in memory and checked in
//! full before any of it is written:
//! - The genesis is the one the repository's id pins: it verifies as a
//!   genesis, and the id it derives is the id asked for.
//! - Every object the received refs reach is present, hashes to its id and
//!   is of the type its link requires, and every commit and release passes
//!   Rule H against that genesis, on the lineage of the instance's current
//!   authority: `levcs verify`'s walk. No membership is asked of the
//!   receiver, and history by since-revoked authors is accepted (R.2, R.3).
//! - Where this repository already holds an object, its own copy is what is
//!   checked, not what was sent: the store keeps the copy it has, so that
//!   copy is what the received refs will reach. A damaged one used to pass,
//!   checked as the instance's copy, and then be read as damaged.
//! - Only what the received refs reach is kept.
//!
//! A transfer that fails any of this writes nothing.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};

use levcs_client::Client;
use levcs_core::object::SignedObject;
use levcs_core::{blake3_hash, ObjectId, ObjectStore};
use levcs_identity::history::{verify_history, HistoryReport};
use levcs_identity::verify::{verify_genesis, ObjectSource, Verification, VerifyError};

/// What an instance sent, checked, and not yet written.
pub struct Received {
    /// What the received refs reach, less what was already here.
    objects: Vec<Vec<u8>>,
}

impl Received {
    /// How many objects it adds.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Write it into `store`.
    pub fn write(&self, store: &ObjectStore) -> Result<()> {
        for bytes in &self.objects {
            store.write_raw(bytes)?;
        }
        Ok(())
    }
}

/// Fetch the history of `roots` (ref names as they will be written here,
/// and the ids they will hold) from repository `repo_id`, with `genesis`
/// and the instance's `current` authority, and check it. `have` is what
/// this side already holds, which the instance need not send; `local` is
/// where it is held.
pub fn receive(
    client: &Client,
    repo_id: &str,
    genesis: ObjectId,
    current: ObjectId,
    roots: &[(String, ObjectId)],
    have: &[ObjectId],
    local: Option<&ObjectStore>,
) -> Result<Received> {
    let mut want: Vec<ObjectId> = roots.iter().map(|(_, id)| *id).collect();
    want.extend([genesis, current]);
    want.sort();
    want.dedup();
    let pack = client.get_pack(repo_id, have, &want)?;
    let sent: HashMap<ObjectId, Vec<u8>> = pack
        .entries
        .into_iter()
        .map(|e| (blake3_hash(&e.bytes), e.bytes))
        .collect();
    let src = Sent { sent: &sent, local };

    let pinned = src
        .read_raw(genesis)
        .and_then(|bytes| {
            SignedObject::parse(&bytes).map_err(|e| VerifyError::Object {
                hash: genesis.to_hex(),
                kind: e.to_string(),
            })
        })
        .and_then(|g| verify_genesis(&g))
        .map_err(|e| anyhow!("the instance's genesis authority {genesis}: {e}"))?;
    if pinned.repo_id.to_hex() != repo_id {
        bail!(
            "the instance's genesis authority {genesis} is repository {}, not {repo_id}; \
             nothing was written",
            pinned.repo_id
        );
    }

    let report = verify_history(&src, genesis, Some(current), roots);
    if !report.ok() {
        return Err(refused(&report, local));
    }
    let objects = report
        .reachable
        .iter()
        .filter(|id| !local.is_some_and(|store| store.contains(**id)))
        .filter_map(|id| sent.get(id).cloned())
        .collect();
    Ok(Received { objects })
}

/// What is already held here, then what the instance sent.
struct Sent<'a> {
    sent: &'a HashMap<ObjectId, Vec<u8>>,
    local: Option<&'a ObjectStore>,
}

impl ObjectSource for Sent<'_> {
    fn read_raw(&self, id: ObjectId) -> Verification<Vec<u8>> {
        if let Some(store) = self.local.filter(|store| store.contains(id)) {
            return Ok(store.read_raw(id)?);
        }
        self.sent
            .get(&id)
            .cloned()
            .ok_or_else(|| VerifyError::Missing(id.to_hex()))
    }
}

/// The refusal of a transfer that failed its check, naming what failed,
/// and which of it is this repository's own copy.
fn refused(report: &HistoryReport, local: Option<&ObjectStore>) -> anyhow::Error {
    const SHOW: usize = 10;
    let mut msg = format!(
        "refused what the instance sent, and wrote nothing: {} problem(s)",
        report.problems.len() + report.conflicting.len()
    );
    for p in report.problems.iter().take(SHOW) {
        let label = if p.integrity { "damaged" } else { "invalid" };
        let whose = if local.is_some_and(|store| store.contains(p.object)) {
            " (this repository's own copy)"
        } else {
            ""
        };
        msg.push_str(&format!("\n  {label} {}{whose}: {}", p.object, p.what));
    }
    for p in report.conflicting.iter().take(SHOW) {
        msg.push_str(&format!("\n  conflict {}: {}", p.object, p.what));
    }
    anyhow!(msg)
}
