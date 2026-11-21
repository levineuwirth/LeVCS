//! Rule R's receiver, run for real, over the scenarios of the executable
//! specification in `authority-spec/`.
//!
//! `levcs-identity`'s side of the specification
//! (`crates/levcs-identity/tests/spec_support`) decides a transfer from the
//! report of `verify_history`, as `receive` does, without running `receive`:
//! that crate cannot depend on this one. Here the function itself is run,
//! the one `clone`, `pull` and `fork` call (`src/receive.rs`), and its
//! answer takes the place of the report's. Everything else in a response,
//! the verdicts on history and on transactions, is answered there as before.
//!
//! The source is an instance that will say anything. It claims whatever
//! genesis and current authority the scenario gives it, and sends every
//! object of the scenario whatever was asked for, or all but the ones it is
//! told here to withhold. A real instance would not: it sends what the
//! wanted objects reach, and serves no one from a repository whose current
//! authority it cannot prove. So this is the receiver's own defence that is
//! compared, which is what R.1 and R.3 are about, and not the instance's.
//!
//! Beyond the answer, each transfer is held to what any transfer must do,
//! and a failure of these is an error and not an answer.
//!
//! Of every call:
//! - it asks the repository expected, for exactly the roots, the genesis
//!   and the current authority it was given, and tells it exactly what the
//!   receiver was said to have;
//! - a refusal over intact objects must report no damage;
//! - a successful transfer is written into its destination. Its final IDs
//!   and bytes must include precisely the objects already held and the
//!   closure of the roots, using the references each object was built with.
//!
//! Of every transfer, kept or refused:
//! - asked for as `clone` asks, with the genesis and the current authority
//!   as roots of their own, it is kept or refused the same;
//! - asked for as `pull` asks, under the names of copies of a remote's
//!   branches and by a receiver that holds the genesis, the same again.
//!   `pull` asks for branches only, so this is tried where every root is a
//!   commit.
//!
//! Of every transfer that is kept:
//! - by a receiver that holds all of it, from a source that sends none of
//!   what that receiver has, it is accepted and adds nothing;
//! - by a receiver that holds what the first root reaches, from a source
//!   that sends the rest, it is accepted and adds the rest. Tried where
//!   there is more than one root;
//! - asked of a repository with another id, with the same genesis offered,
//!   it is refused: the genesis is not that repository's;
//! - by a receiver whose own copy of the first root is damaged, it is
//!   refused: that copy is the one the refs would reach. A transfer of no
//!   roots has none to damage, and this is not tried on it.
//!
//! Shared by `examples/spec_receive_oracle.rs`, which the Haskell
//! differential run drives, and `tests/spec_receive.rs`, which replays the
//! committed corpus.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use levcs_client::{Client, ClientError};
use levcs_core::{ObjectId, ObjectStore};
use levcs_protocol::Pack;
use serde_json::{json, Value};
use tempfile::TempDir;

#[path = "../../src/receive.rs"]
mod receive;
#[path = "../../../levcs-identity/tests/spec_support/mod.rs"]
pub mod spec_support;

use spec_support::Transfer;

type Res<T> = Result<T, String>;

/// What the source will send next, and what it was last asked.
#[derive(Default)]
struct Said {
    pack: Vec<u8>,
    asked: Option<String>,
}

/// An instance that answers every request with the pack it was last given.
struct Source {
    base: String,
    said: Arc<Mutex<Said>>,
}

impl Source {
    fn start() -> Source {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port to serve transfers from");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let said = Arc::new(Mutex::new(Said::default()));
        let shared = said.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                // A request cut short is the client's to report: it gets
                // no answer, and the transfer fails as a fault of the
                // harness, never as a refusal.
                let Ok(mut stream) = stream else { continue };
                let Ok(reading) = stream.try_clone() else {
                    continue;
                };
                let mut reader = BufReader::new(reading);
                let mut request = String::new();
                if reader.read_line(&mut request).is_err() {
                    continue;
                }
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(n) if n > 0 && line != "\r\n" => {}
                        _ => break,
                    }
                }
                let pack = {
                    let mut said = shared.lock().unwrap();
                    said.asked = Some(request);
                    said.pack.clone()
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\
                     Content-Type: application/octet-stream\r\n\r\n",
                    pack.len()
                );
                let _ = stream.write_all(&pack);
            }
        });
        Source { base, said }
    }
}

/// Where a receiver keeps the objects it writes, for as long as one transfer
/// takes: `LEVCS_SPEC_SCRATCH` if that is set, memory if the system offers
/// it as a directory, and the temporary directory if not.
///
/// The object store makes every write durable, which nothing here needs,
/// and on a disk that is most of what a run costs: 20,000 scenarios took 35
/// minutes with these on btrfs.
fn scratch_parent() -> PathBuf {
    match std::env::var_os("LEVCS_SPEC_SCRATCH") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => {
            let memory = PathBuf::from("/dev/shm");
            if memory.is_dir() {
                memory
            } else {
                std::env::temp_dir()
            }
        }
    }
}

/// A receiver, and the source it receives from.
pub struct Receiver {
    source: Source,
    client: Client,
    scratch: TempDir,
}

impl Receiver {
    pub fn start() -> Receiver {
        let source = Source::start();
        let client = Client::new(&source.base);
        let parent = scratch_parent();
        std::fs::create_dir_all(&parent).expect("create the receiver scratch parent");
        let scratch = tempfile::Builder::new()
            .prefix("levcs-spec-receive-")
            .tempdir_in(parent)
            .expect("create a private receiver scratch directory");
        Receiver {
            source,
            client,
            scratch,
        }
    }

    /// A receiver whose source is not there: its port is closed.
    #[allow(dead_code)]
    pub fn nowhere() -> Receiver {
        let mut receiver = Receiver::start();
        let closed = TcpListener::bind("127.0.0.1:0").expect("a port to close");
        receiver.client = Client::new(format!("http://{}", closed.local_addr().unwrap()));
        receiver
    }

    /// Answer one request, with every transfer in it made by `receive`.
    pub fn answer(&mut self, request: &Value) -> Res<Value> {
        spec_support::answer_with(request, &mut |t| self.transfer(t))
    }

    /// An object store of this receiver's own, holding the objects named.
    fn store(&self, t: &Transfer, holding: &BTreeSet<ObjectId>) -> Res<(TempDir, ObjectStore)> {
        let root = tempfile::tempdir_in(self.scratch.path()).map_err(|e| e.to_string())?;
        let store = ObjectStore::new(root.path());
        for id in holding {
            let bytes = t
                .objects
                .get(id)
                .ok_or_else(|| format!("the scenario has no object {id}"))?;
            store.write_raw(bytes).map_err(|e| e.to_string())?;
        }
        Ok((root, store))
    }

    /// Have the source send every object of the scenario but these, in a
    /// fixed order, whatever it is asked for.
    fn send(&self, t: &Transfer, withheld: &BTreeSet<ObjectId>) {
        let mut ids: Vec<&ObjectId> = t
            .objects
            .keys()
            .filter(|id| !withheld.contains(id))
            .collect();
        ids.sort();
        let mut pack = Pack::new();
        for id in ids {
            let bytes = &t.objects[id];
            pack.push(bytes[4], bytes.clone());
        }
        self.source.said.lock().unwrap().pack = pack.encode();
    }

    /// One call of `receive`, and a check of what it asked the source: the
    /// repository, and exactly the objects it holds and the objects it
    /// wants, no more and no fewer.
    fn receive(&self, t: &Transfer, asking: &Asking) -> Res<Result<receive::Received, String>> {
        self.source.said.lock().unwrap().asked = None;
        let repo_id = asking.repo_id.to_hex();
        let outcome = receive::receive(
            &self.client,
            &repo_id,
            t.expected,
            t.current,
            asking.roots,
            asking.have,
            asking.local,
        );
        // A transfer that did not get its pack was not refused: it was
        // not made. Counting it as a refusal would agree with the
        // specification wherever that refuses, with nothing received.
        if let Err(e) = &outcome {
            if let Some(fault) = e.downcast_ref::<ClientError>() {
                return Err(format!("the transfer was not made: {fault}"));
            }
        }
        let asked = self
            .source
            .said
            .lock()
            .unwrap()
            .asked
            .take()
            .ok_or("receive answered without asking the source for anything")?;
        let query = asked
            .strip_prefix(&format!("GET /repos/{repo_id}/pack?"))
            .and_then(|rest| rest.split(' ').next())
            .ok_or_else(|| format!("receive asked {asked:?}, not for a pack of {repo_id}"))?;
        let listed = |name: &str| -> Res<BTreeSet<String>> {
            let mut found = query
                .split('&')
                .filter_map(|p| p.strip_prefix(name).and_then(|p| p.strip_prefix('=')));
            match (found.next(), found.next()) {
                (Some(list), None) => Ok(list
                    .split(',')
                    .filter(|id| !id.is_empty())
                    .map(str::to_string)
                    .collect()),
                _ => Err(format!(
                    "receive asked {asked:?}, which does not say `{name}` once"
                )),
            }
        };
        let hex = |ids: &mut dyn Iterator<Item = ObjectId>| -> BTreeSet<String> {
            ids.map(|id| id.to_hex()).collect()
        };
        let want = hex(&mut asking
            .roots
            .iter()
            .map(|(_, id)| *id)
            .chain([t.expected, t.current]));
        if listed("want")? != want {
            return Err(format!(
                "receive wanted {:?} of the source, and was to want {want:?}",
                listed("want")?
            ));
        }
        let have = hex(&mut asking.have.iter().copied());
        if listed("have")? != have {
            return Err(format!(
                "receive told the source it has {:?}, and was to say {have:?}",
                listed("have")?
            ));
        }
        Ok(outcome.map_err(|e| format!("{e:#}")))
    }

    /// Every ordinary fixture is intact, including those that Rule R refuses.
    fn receive_intact(
        &self,
        t: &Transfer,
        asking: &Asking,
    ) -> Res<Result<receive::Received, String>> {
        let outcome = self.receive(t, asking)?;
        if let Err(refusal) = &outcome {
            if damage_reports(refusal).next().is_some() {
                return Err(format!(
                    "receive reported damage on an intact transfer: {refusal}"
                ));
            }
        }
        Ok(outcome)
    }

    fn transfer(&mut self, t: &Transfer) -> Res<Value> {
        let nothing = BTreeSet::new();
        let root_ids: Vec<ObjectId> = t.roots.iter().map(|(_, id)| *id).collect();
        let owed = t.reached(root_ids.iter().copied());
        self.send(t, &nothing);

        // As it is asked for in the scenario: branches and releases, by a
        // receiver holding nothing. `fork` asks so, of one branch.
        let fresh = Asking {
            repo_id: t.repo_id,
            roots: &t.roots,
            have: &[],
            local: None,
        };
        let plain = self.receive_intact(t, &fresh)?;

        // As `clone` asks: for the genesis and the current authority too,
        // as roots of their own.
        let mut with_authorities = vec![
            ("refs/authority/genesis".to_string(), t.expected),
            ("refs/authority/current".to_string(), t.current),
        ];
        with_authorities.extend(t.roots.iter().cloned());
        let cloned = self.receive_intact(
            t,
            &Asking {
                roots: &with_authorities,
                ..fresh
            },
        )?;
        same_outcome("as clone asks for it", &plain, &cloned)?;
        if let Ok(received) = &cloned {
            let owed = t.reached(root_ids.iter().copied().chain([t.expected, t.current]));
            let (_dir, store) = self.store(t, &nothing)?;
            check_write(t, "as clone asks for it", received, &store, &nothing, &owed)?;
        }

        // As `pull` asks, where it could ask for this: branches only, under
        // the names of its copies of the remote's, by a receiver that holds
        // the genesis it expects.
        if t.only_commits() {
            let remote: Vec<(String, ObjectId)> = t
                .roots
                .iter()
                .enumerate()
                .map(|(n, (_, id))| (format!("refs/remote/origin/branches/b{n}"), *id))
                .collect();
            let held = t.reached([t.expected]);
            let (_dir, store) = self.store(t, &held)?;
            let pulled = self.receive_intact(
                t,
                &Asking {
                    roots: &remote,
                    local: Some(&store),
                    ..fresh
                },
            )?;
            same_outcome("as pull asks for it", &plain, &pulled)?;
            if let Ok(received) = &pulled {
                check_write(t, "as pull asks for it", received, &store, &held, &owed)?;
            }
        }

        let received = match plain {
            Ok(received) => received,
            Err(refusal) => {
                return Ok(json!({ "refused": true, "reasons": [refusal], "damage": [] }));
            }
        };
        // Everything the roots reach, trees and authorities with the
        // commits and releases, and nothing they do not.
        let (_dir, store) = self.store(t, &nothing)?;
        check_write(t, "as asked", &received, &store, &nothing, &owed)?;

        // A receiver that kept all of it, and a source that sends none of
        // what the receiver says it has. The transfer is checked from the
        // receiver's own copies alone, is accepted, and adds nothing.
        let holding_all = Asking {
            have: &root_ids,
            local: Some(&store),
            ..fresh
        };
        self.send(t, &owed);
        match self.receive_intact(t, &holding_all)? {
            Ok(again) => check_write(
                t,
                "by a receiver that holds it all",
                &again,
                &store,
                &owed,
                &owed,
            )?,
            Err(refusal) => {
                return Err(format!(
                    "recorded once, the transfer was refused of a receiver that holds it all: \
                     {refusal}"
                ))
            }
        }
        // A receiver that kept what the first root reaches, and a source
        // that sends the rest. What is kept is the rest.
        if let [first, _, ..] = root_ids.as_slice() {
            let held = t.reached([*first]);
            let (_dir, partial) = self.store(t, &held)?;
            self.send(t, &held);
            match self.receive_intact(
                t,
                &Asking {
                    have: &[*first],
                    local: Some(&partial),
                    ..fresh
                },
            )? {
                Ok(rest) => check_write(
                    t,
                    "by a receiver that holds one root",
                    &rest,
                    &partial,
                    &held,
                    &owed,
                )?,
                Err(refusal) => {
                    return Err(format!(
                        "recorded once, the transfer was refused of a receiver that holds one \
                         root: {refusal}"
                    ))
                }
            }
        }
        self.send(t, &nothing);
        // The same genesis, offered as the genesis of some other repository.
        let mut other = t.repo_id;
        other.0[0] ^= 1;
        let elsewhere = Asking {
            repo_id: other,
            ..fresh
        };
        if self.receive_intact(t, &elsewhere)?.is_ok() {
            return Err(format!(
                "asked for repository {other}, receive kept the history of {}",
                t.repo_id
            ));
        }
        // The receiver's own copy of a root, damaged: its last byte, which
        // is the end of a signature. A sound copy is sent, and would not
        // replace it. A transfer of no roots has none to damage.
        if let Some(root_id) = root_ids.first() {
            let path = store.path_for(*root_id);
            let mut bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            *bytes.last_mut().ok_or("an empty object")? ^= 1;
            std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
            let damaged_root = format!("{root_id} (this repository's own copy):");
            match self.receive(t, &holding_all)? {
                Err(refusal)
                    if damage_reports(&refusal).any(|report| report.starts_with(&damaged_root)) => {
                }
                Err(refusal) => {
                    return Err(format!(
                        "refused over a damaged copy held here, without saying so: {refusal}"
                    ))
                }
                Ok(_) => {
                    return Err(format!(
                        "accepted over this receiver's own damaged copy of {}",
                        t.about(root_id)
                    ))
                }
            }
        }
        Ok(t.recorded(owed))
    }
}

fn damage_reports(refusal: &str) -> impl Iterator<Item = &str> {
    refusal
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("damaged "))
}

/// What a caller of `receive` passes it, beside the genesis and the current
/// authority.
#[derive(Clone, Copy)]
struct Asking<'a> {
    repo_id: ObjectId,
    roots: &'a [(String, ObjectId)],
    have: &'a [ObjectId],
    local: Option<&'a ObjectStore>,
}

/// The same transfer asked for another way is kept or refused as it was.
fn same_outcome<T>(how: &str, asked: &Result<T, String>, other: &Result<T, String>) -> Res<()> {
    match (asked, other) {
        (Ok(_), Ok(_)) | (Err(_), Err(_)) => Ok(()),
        (Ok(_), Err(refusal)) => Err(format!(
            "kept as asked, the transfer was refused {how}: {refusal}"
        )),
        (Err(refusal), Ok(_)) => Err(format!(
            "kept {how}, the transfer was refused as asked: {refusal}"
        )),
    }
}

/// Apply the transfer to its destination and check both the number added and
/// the whole resulting store, including bytes the receiver already held.
fn check_write(
    t: &Transfer,
    how: &str,
    received: &receive::Received,
    destination: &ObjectStore,
    held: &BTreeSet<ObjectId>,
    reached: &BTreeSet<ObjectId>,
) -> Res<()> {
    let additions = reached.difference(held).count();
    if received.len() != additions {
        return Err(format!(
            "{how}, receive returned {} objects to add, expected {additions}",
            received.len()
        ));
    }
    received
        .write(destination)
        .map_err(|e| format!("{how}: {e}"))?;
    let actual: BTreeSet<_> = destination
        .iter_ids()
        .map_err(|e| e.to_string())?
        .into_iter()
        .collect();
    let expected: BTreeSet<_> = held.union(reached).copied().collect();
    if actual != expected {
        let names = |ids: Vec<&ObjectId>| {
            ids.into_iter()
                .map(|id| t.about(id))
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(format!(
            "{how}, destination is missing [{}] and has unexpected [{}]",
            names(expected.difference(&actual).collect()),
            names(actual.difference(&expected).collect())
        ));
    }
    for id in actual {
        // read_raw also verifies the content hash against the stored id.
        let bytes = destination
            .read_raw(id)
            .map_err(|e| format!("{how}: {e}"))?;
        if t.objects.get(&id) != Some(&bytes) {
            return Err(format!(
                "{how}, destination has different bytes for {}",
                t.about(&id)
            ));
        }
    }
    Ok(())
}
