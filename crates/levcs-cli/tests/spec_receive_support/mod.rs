// SPDX-FileCopyrightText: 2026 Levi Neuwirth
// SPDX-License-Identifier: Apache-2.0

//! Rule R, run for real, over the scenarios of the executable specification
//! in `authority-spec/`: the receiver's side by `receive`, and the source's
//! by an instance of `levcs-instance`.
//!
//! # Transfers
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
//! # Reads
//!
//! Whether to send anything is the source's decision (R.2), and a scripted
//! source decides nothing. So a read is asked of a real instance, started
//! here over a repository that was put in its root by hand: every object of
//! the scenario, and the refs the read is asked of. No push made it, and
//! nothing admitted what it holds, so it can hold history the rules refuse
//! and a current authority they would never install. The reader asks as
//! `clone` does, for what the instance publishes and then for the history,
//! and what it is sent it checks with `receive`. What the instance is held
//! to beyond its answer is said at `Receiver::make_read`.
//!
//! An instance is honest in one way the scripted source is not: asked for a
//! repository, it answers from the one stored under that id. So a read is
//! always of the repository the reader expects, and what is varied is the
//! current authority the instance has for it.
//!
//! Shared by `examples/spec_receive_oracle.rs`, which the Haskell
//! differential run drives, and `tests/spec_receive.rs`, which replays the
//! committed corpus.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read as _, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use levcs_client::{Client, ClientError};
use levcs_core::{ObjectId, ObjectStore, Refs};
use levcs_identity::keys::SecretKey;
use levcs_instance::{router, AppState, InstanceConfig, Limits};
use levcs_protocol::auth::{sign_request, AuthRequest};
use levcs_protocol::Pack;
use serde_json::{json, Value};
use tempfile::TempDir;

#[path = "../../src/receive.rs"]
mod receive;
#[path = "../../../levcs-identity/tests/spec_support/mod.rs"]
pub mod spec_support;

use spec_support::{Read, Transfer};

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
    /// What the instances that answer reads run on.
    runtime: tokio::runtime::Runtime,
    /// The instance holding the scenario of the request being answered,
    /// once a read has needed one.
    instance: Option<Instance>,
}

impl spec_support::Replication for Receiver {
    fn transfer(&mut self, t: &Transfer) -> Res<Value> {
        self.make_transfer(t)
    }

    fn read(&mut self, r: &Read) -> Res<Option<Value>> {
        self.make_read(r).map(Some)
    }
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
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime for instances");
        Receiver {
            source,
            client,
            scratch,
            runtime,
            instance: None,
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

    /// Answer one request, with every transfer in it made by `receive`, and
    /// every read in it asked of an instance.
    pub fn answer(&mut self, request: &Value) -> Res<Value> {
        // Another request is another scenario, and another instance.
        self.instance = None;
        let answer = spec_support::answer_with(request, self);
        self.instance = None;
        answer
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

    fn make_transfer(&mut self, t: &Transfer) -> Res<Value> {
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

/// An instance of `levcs-instance`, serving one repository that was put in
/// its root by hand: no push made it, and nothing admitted what it holds.
struct Instance {
    addr: SocketAddr,
    base: String,
    /// The `.levcs` directory of the one repository it holds.
    levcs: PathBuf,
    _root: TempDir,
    serving: tokio::task::JoinHandle<()>,
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// What an instance answered a read: what was asked for, or that there is
/// no such repository, which is how it refuses a reader.
fn answered<T>(what: &str, answer: Result<T, ClientError>) -> Res<Option<T>> {
    match answer {
        Ok(found) => Ok(Some(found)),
        Err(ClientError::Server { status: 404, .. }) => Ok(None),
        Err(fault) => Err(format!("{what} was not answered: {fault}")),
    }
}

impl Receiver {
    /// The instance holding the scenario, as the repository the read asks
    /// for: every object, its genesis, the current authority it is to have
    /// if any, and a ref at each root.
    ///
    /// The objects are put there once for a request, and the instance
    /// started once. Each read then gives the repository the refs it asks
    /// of: an instance reads them again for every request it answers.
    fn instance(&mut self, r: &Read) -> Res<(SocketAddr, String)> {
        let t = &r.asked;
        if self.instance.is_none() {
            let root = tempfile::tempdir_in(self.scratch.path()).map_err(|e| e.to_string())?;
            let levcs = root.path().join(t.repo_id.to_hex()).join(".levcs");
            let store = ObjectStore::new(levcs.join("objects"));
            for bytes in t.objects.values() {
                store.write_raw(bytes).map_err(|e| e.to_string())?;
            }
            let app = router(AppState::new(InstanceConfig {
                root: root.path().to_path_buf(),
                storage_mode: "full".into(),
                federation_peers: Vec::new(),
                allowed_handlers: Vec::new(),
                mirrors: Vec::new(),
                creators: Vec::new(),
                limits: Limits::default(),
            }));
            let (addr, serving) = self.runtime.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .map_err(|e| e.to_string())?;
                let addr = listener.local_addr().map_err(|e| e.to_string())?;
                let serving = tokio::spawn(async move {
                    axum::serve(listener, app).await.ok();
                });
                Ok::<_, String>((addr, serving))
            })?;
            self.instance = Some(Instance {
                addr,
                base: format!("http://{addr}/levcs/v1"),
                levcs,
                _root: root,
                serving,
            });
        }
        let instance = self
            .instance
            .as_ref()
            .expect("an instance was just started");
        let held = instance.levcs.join("refs");
        if held.exists() {
            std::fs::remove_dir_all(&held).map_err(|e| e.to_string())?;
        }
        let refs = Refs::new(&instance.levcs);
        let mut hold = vec![("refs/authority/genesis".to_string(), t.expected)];
        hold.extend(r.current.map(|c| ("refs/authority/current".to_string(), c)));
        hold.extend(t.roots.iter().cloned());
        for (name, id) in &hold {
            refs.write(name, *id).map_err(|e| e.to_string())?;
        }
        Ok((instance.addr, instance.base.clone()))
    }

    /// A read, asked of a real instance as `clone` asks: what it publishes
    /// first, and then the history, which `receive` checks.
    ///
    /// Beyond the answer, the instance is held to what R.2 must mean, and a
    /// failure of these is an error and not an answer:
    /// - its four reads are one decision: what it publishes, its refs, an
    ///   object and a pack are all answered, or none is;
    /// - what it publishes is the genesis, the current authority and the
    ///   refs it was given;
    /// - a repository with no current authority is read by no one;
    /// - where a member reads what the public may not, holding the key is
    ///   proving it: a request that names the member's key and is signed
    ///   with another, and one the member signed for a different read, are
    ///   refused.
    ///
    /// And of a transfer kept, with the instance choosing what to send:
    /// - it is kept as exactly what the roots reach;
    /// - a receiver that holds all of it, and says so, is sent what it
    ///   lacks, accepts, and adds nothing;
    /// - one that holds what the first root reaches adds the rest, where
    ///   there is more than one root.
    fn make_read(&mut self, r: &Read) -> Res<Value> {
        let t = &r.asked;
        let (addr, base) = self.instance(r)?;
        let repo = t.repo_id.to_hex();
        let anonymous = Client::new(&base);
        let client = match r.requester {
            Some(k) => Client::new(&base).with_reader(Arc::new(spec_support::key(k))),
            None => Client::new(&base),
        };

        let info = answered("what the instance publishes", client.repo_info(&repo))?;
        let others = [
            (
                "its refs",
                answered("the instance's refs", client.refs(&repo))?.is_some(),
            ),
            (
                "an object",
                answered("an object", client.get_object(&repo, t.expected))?.is_some(),
            ),
            (
                "a pack",
                answered("a pack", client.get_pack(&repo, &[], &[t.expected]))?.is_some(),
            ),
        ];
        for (what, served) in others {
            if served != info.is_some() {
                return Err(format!(
                    "the instance {} this reader what it publishes and {} it {what}",
                    if info.is_some() { "sends" } else { "refuses" },
                    if served { "sends" } else { "refuses" },
                ));
            }
        }
        let Some(info) = info else {
            return Ok(json!({ "denied": true, "damage": [] }));
        };
        let Some(current) = r.current else {
            return Err("an instance with no current authority for it served a repository".into());
        };
        let published: BTreeSet<(String, String)> = [
            ("refs/authority/genesis".to_string(), info.genesis_authority),
            ("refs/authority/current".to_string(), info.current_authority),
        ]
        .into_iter()
        .chain(
            info.branches
                .into_iter()
                .map(|(n, id)| (format!("refs/branches/{n}"), id)),
        )
        .chain(
            info.releases
                .into_iter()
                .map(|(n, id)| (format!("refs/releases/{n}"), id)),
        )
        .collect();
        let given: BTreeSet<(String, String)> = [
            ("refs/authority/genesis".to_string(), t.expected.to_hex()),
            ("refs/authority/current".to_string(), current.to_hex()),
        ]
        .into_iter()
        .chain(t.roots.iter().map(|(n, id)| (n.clone(), id.to_hex())))
        .collect();
        if info.repo_id != repo || published != given {
            return Err(format!(
                "the instance publishes {published:?} as {}, and was given {given:?} as {repo}",
                info.repo_id
            ));
        }

        // Holding a key is proving it, where the key is what lets the
        // reader in.
        if let Some(k) = r.requester {
            if answered("an unsigned read", anonymous.repo_info(&repo))?.is_none() {
                let member = spec_support::key(k);
                let path = format!("/repos/{repo}/info");
                let sign = |by: &SecretKey, path: &str| {
                    sign_request(
                        by,
                        &AuthRequest {
                            method: "GET",
                            path_with_query: path,
                            body: b"",
                        },
                    )
                    .map_err(|e| e.to_string())
                };
                // Signed by a key that is no member's, naming the member's.
                let (_, ts, nonce, sig) = sign(&spec_support::key(u64::from(u32::MAX) + 1), &path)?;
                let forged = (member.public().to_levcs(), ts, nonce, sig);
                // Signed by the member, for another read.
                let elsewhere = sign(&member, &format!("/repos/{repo}/refs"))?;
                for (what, headers) in [
                    ("signed with another key in this member's name", forged),
                    ("this member signed for another read", elsewhere),
                ] {
                    let status = raw_get(addr, &format!("/levcs/v1{path}"), &headers)?;
                    if status != 404 {
                        return Err(format!(
                            "a read {what} was answered {status} by a repository the public may \
                             not read"
                        ));
                    }
                }
                // And the same request signed as it should be is answered.
                let status = raw_get(addr, &format!("/levcs/v1{path}"), &sign(&member, &path)?)?;
                if status != 200 {
                    return Err(format!("a member's signed read was answered {status}"));
                }
            }
        }

        let nothing = BTreeSet::new();
        let root_ids: Vec<ObjectId> = t.roots.iter().map(|(_, id)| *id).collect();
        let owed = t.reached(root_ids.iter().copied());
        let fresh = Asking {
            repo_id: t.repo_id,
            roots: &t.roots,
            have: &[],
            local: None,
        };
        let received = match receive_from(&client, t, &fresh)? {
            Ok(received) => received,
            Err(refusal) => {
                return Ok(json!({ "refused": true, "reasons": [refusal], "damage": [] }));
            }
        };
        let (_dir, store) = self.store(t, &nothing)?;
        check_write(t, "from an instance", &received, &store, &nothing, &owed)?;
        let again = receive_from(
            &client,
            t,
            &Asking {
                have: &root_ids,
                local: Some(&store),
                ..fresh
            },
        )?
        .map_err(|refusal| {
            format!(
                "recorded once, the transfer was refused of a receiver that holds it all: \
                 {refusal}"
            )
        })?;
        check_write(
            t,
            "from an instance, by a receiver that holds it all",
            &again,
            &store,
            &owed,
            &owed,
        )?;
        if let [first, _, ..] = root_ids.as_slice() {
            let held = t.reached([*first]);
            let (_dir, partial) = self.store(t, &held)?;
            let rest = receive_from(
                &client,
                t,
                &Asking {
                    have: &[*first],
                    local: Some(&partial),
                    ..fresh
                },
            )?
            .map_err(|refusal| {
                format!(
                    "recorded once, the transfer was refused of a receiver that holds one \
                     root: {refusal}"
                )
            })?;
            check_write(
                t,
                "from an instance, by a receiver that holds one root",
                &rest,
                &partial,
                &held,
                &owed,
            )?;
        }
        Ok(t.recorded(owed))
    }
}

/// One call of `receive`, of an instance that is trusted to answer: a
/// transfer that was not made, and a refusal that names damage where
/// nothing is damaged, are errors.
///
/// One kind of damage is not an error, because an instance does cause it.
/// It sends an authority that a commit installs without what is behind that
/// authority (`Transfer::behind_installed`). A receiver refusing such a
/// commit, as it must where anything is missing, reports the predecessors
/// it was not sent as objects that cannot be read. Those reports are let
/// through where the object is one of those, is said to be missing, and
/// was in fact not sent. The refusal stands either way, and whether it was
/// called for is the specification's to say.
fn receive_from(
    client: &Client,
    t: &Transfer,
    asking: &Asking,
) -> Res<Result<receive::Received, String>> {
    let outcome = receive::receive(
        client,
        &asking.repo_id.to_hex(),
        t.expected,
        t.current,
        asking.roots,
        asking.have,
        asking.local,
    );
    match outcome {
        Ok(received) => Ok(Ok(received)),
        Err(e) => {
            if let Some(fault) = e.downcast_ref::<ClientError>() {
                return Err(format!("the transfer was not made: {fault}"));
            }
            let refusal = format!("{e:#}");
            if damage_reports(&refusal).next().is_some() {
                let roots = asking.roots.iter().map(|(_, id)| *id);
                let unsent_behind = t.behind_installed(roots.clone());
                let mut want: Vec<ObjectId> = roots.chain([t.expected, t.current]).collect();
                want.sort();
                want.dedup();
                let sent: BTreeSet<ObjectId> = client
                    .get_pack(&asking.repo_id.to_hex(), asking.have, &want)
                    .map_err(|fault| format!("the pack was not sent a second time: {fault}"))?
                    .entries
                    .iter()
                    .map(|e| levcs_core::blake3_hash(&e.bytes))
                    .collect();
                for report in damage_reports(&refusal) {
                    let explained = report.split_once(": ").is_some_and(|(id, what)| {
                        what.contains("missing object")
                            && unsent_behind
                                .iter()
                                .any(|a| a.to_hex() == id && !sent.contains(a))
                    });
                    if !explained {
                        return Err(format!(
                            "receive reported damage on an intact transfer: {refusal}"
                        ));
                    }
                }
            }
            Ok(Err(refusal))
        }
    }
}

/// A GET with these four signature headers and nothing else, and the status
/// it was answered with.
fn raw_get(addr: SocketAddr, path: &str, signed: &(String, String, String, String)) -> Res<u16> {
    let (key, timestamp, nonce, signature) = signed;
    let mut stream = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nLeVCS-Key: {key}\r\n\
         LeVCS-Timestamp: {timestamp}\r\nLeVCS-Nonce: {nonce}\r\nLeVCS-Signature: {signature}\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let mut answer = String::new();
    stream
        .read_to_string(&mut answer)
        .map_err(|e| e.to_string())?;
    answer
        .split(' ')
        .nth(1)
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| format!("not an HTTP answer: {answer:?}"))
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
