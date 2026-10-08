//! Several ref changes applied as one, and undone if they do not all land:
//! when a write fails, and when the process dies part way.
//!
//! A publication can move several refs: branches and releases, and `current`
//! with an authority change. They have to land together. An authority
//! removal killed after its branch write, before `current` moved, left the
//! revoking commit on the branch and the old authority current, and the
//! removed member could still publish.
//!
//! **The record.** Before any ref moves, the transaction's changes are
//! written durably to `.levcs/ref-transaction/record`. When every ref has
//! landed, the record is removed, durably. A record still present means a
//! transaction was begun and not finished. Its directory is made by the
//! first transaction and kept, so the record can be written wherever a
//! ref can.
//!
//! **Recovery.** [`recover`] rolls such a transaction back. It runs under
//! the lock every writer of these refs holds, before anything reads them to
//! decide what to publish. A transaction never starts over a pending
//! record.
//!
//! **Putting refs back.** A write can take effect and still fail: the
//! rename lands, and then the sync of its directory reports an error. So
//! undoing never trusts what a write returned. Each ref is read back:
//! - a ref that holds the transaction's new value is written back to its
//!   expected value;
//! - a ref that holds its expected value is left alone;
//! - a ref that holds anything else was moved by someone else. It is left
//!   alone and reported.
//!
//! A ref is reported as restored only if it then reads back so. While any
//! ref is not restored, the record stays, so that recovery tries again
//! rather than letting the half-applied state stand.

use std::fmt;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::hash::ObjectId;
use crate::refs::Refs;

/// One change: `name` from `expected` to `new`. `None` is absent: as
/// `expected`, the ref must not exist; as `new`, it is deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefChange {
    pub name: String,
    pub expected: Option<ObjectId>,
    pub new: Option<ObjectId>,
}

/// What a transaction needs of ref storage. [`Refs`] implements it; tests
/// substitute storage that fails, and dies, in the ways real storage does.
pub trait RefStore {
    fn read(&self, name: &str) -> Result<Option<ObjectId>>;
    fn write(&self, name: &str, id: ObjectId) -> Result<()>;
    fn delete(&self, name: &str) -> Result<()>;
    /// Record `changes` durably, before any of them is made.
    fn begin(&self, changes: &[RefChange]) -> Result<()>;
    /// The changes of a transaction begun and not ended, if any.
    fn pending(&self) -> Result<Option<Vec<RefChange>>>;
    /// Remove the record, durably.
    fn end(&self) -> Result<()>;
}

const RECORD: &str = "ref-transaction";
const MAGIC: &str = "levcs ref transaction 1";

fn record_dir(refs: &Refs) -> PathBuf {
    refs.levcs_dir.join(RECORD)
}

fn record_path(refs: &Refs) -> PathBuf {
    record_dir(refs).join("record")
}

fn encode(changes: &[RefChange]) -> String {
    let show = |v: Option<ObjectId>| v.map_or("-".to_string(), |i| i.to_hex());
    let mut out = format!("{MAGIC}\n");
    for c in changes {
        out.push_str(&format!(
            "{}\t{}\t{}\n",
            c.name,
            show(c.expected),
            show(c.new)
        ));
    }
    out
}

fn decode(text: &str) -> Result<Vec<RefChange>> {
    let bad = |why: &str| Error::Other(format!("unreadable {RECORD} ({why})"));
    let mut lines = text.lines();
    if lines.next() != Some(MAGIC) {
        return Err(bad("no header"));
    }
    let id = |s: &str| -> Result<Option<ObjectId>> {
        if s == "-" {
            Ok(None)
        } else {
            ObjectId::from_hex(s).map(Some).map_err(|_| bad("bad id"))
        }
    };
    let mut out = Vec::new();
    for line in lines {
        let parts: Vec<&str> = line.split('\t').collect();
        let [name, expected, new] = parts.as_slice() else {
            return Err(bad("bad line"));
        };
        crate::refs::validate_ref_name(name).map_err(|_| bad("bad ref name"))?;
        out.push(RefChange {
            name: name.to_string(),
            expected: id(expected)?,
            new: id(new)?,
        });
    }
    Ok(out)
}

impl RefStore for Refs {
    fn read(&self, name: &str) -> Result<Option<ObjectId>> {
        Refs::read(self, name)
    }
    fn write(&self, name: &str, id: ObjectId) -> Result<()> {
        Refs::write(self, name, id)
    }
    fn delete(&self, name: &str) -> Result<()> {
        Refs::delete(self, name)
    }
    fn begin(&self, changes: &[RefChange]) -> Result<()> {
        crate::fsutil::replace_file_staged(
            &record_path(self),
            encode(changes).as_bytes(),
            &self.levcs_dir.join("tmp"),
        )
    }
    fn pending(&self) -> Result<Option<Vec<RefChange>>> {
        let path = record_path(self);
        match std::fs::read_to_string(&path) {
            Ok(text) => decode(&text).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io {
                path: Some(path),
                source: e,
            }),
        }
    }
    fn end(&self) -> Result<()> {
        let path = record_path(self);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::Io {
                    path: Some(path),
                    source: e,
                })
            }
        }
        crate::fsutil::fsync_dir(&record_dir(self))
    }
}

/// A transaction that did not apply, and what it left behind.
#[derive(Debug)]
pub struct TxFailed {
    /// The failure that stopped it.
    pub error: Error,
    /// Refs that read back restored, but whose restoring write reported an
    /// error, so its durability is unknown.
    pub uncertain: Vec<String>,
    /// Refs that could not be put back. Their record is kept, and recovery
    /// tries again before anything else is published.
    pub unrestored: Vec<String>,
}

impl TxFailed {
    /// Whether every ref reads back as it was.
    pub fn restored(&self) -> bool {
        self.unrestored.is_empty()
    }

    fn only(error: Error) -> Self {
        TxFailed {
            error,
            uncertain: Vec::new(),
            unrestored: Vec::new(),
        }
    }
}

impl fmt::Display for TxFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}; ", self.error)?;
        if !self.unrestored.is_empty() {
            write!(
                f,
                "these refs were left changed and could not be put back: {} (the \
                 transaction's record is kept, and the next command that changes this \
                 repository tries again)",
                self.unrestored.join(", ")
            )?;
            if !self.uncertain.is_empty() {
                f.write_str("; ")?;
            }
        } else if self.uncertain.is_empty() {
            f.write_str("every ref reads back as it was")?;
        }
        if !self.uncertain.is_empty() {
            write!(
                f,
                "these refs read back as they were, but writing them back reported an \
                 error, so that may not be durable: {}",
                self.uncertain.join(", ")
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for TxFailed {}

/// Put back, newest first, every ref of `changes` that holds its new value.
/// With `rewrite`, a ref that already holds its expected value is written
/// again too, so that recovery never rests on a restore that may not have
/// been durable. Returns the refs restored, and those whose restoring write
/// reported an error or that could not be put back.
fn put_back<R: RefStore>(
    store: &R,
    changes: &[RefChange],
    rewrite: bool,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (mut restored, mut uncertain, mut unrestored) = (Vec::new(), Vec::new(), Vec::new());
    for c in changes.iter().rev() {
        match store.read(&c.name) {
            Ok(actual) if actual == c.expected && !rewrite => continue,
            Ok(actual) if actual == c.expected || actual == c.new => {}
            _ => {
                unrestored.push(c.name.clone());
                continue;
            }
        }
        let wrote = match c.expected {
            Some(old) => store.write(&c.name, old),
            None => store.delete(&c.name),
        };
        match store.read(&c.name) {
            Ok(actual) if actual == c.expected => {
                restored.push(c.name.clone());
                if wrote.is_err() {
                    uncertain.push(c.name.clone());
                }
            }
            _ => unrestored.push(c.name.clone()),
        }
    }
    (restored, uncertain, unrestored)
}

/// Apply `changes` in order, each only if its ref still holds `expected`,
/// as one transaction: recorded first, and undone if any of it fails. Call
/// under the lock every writer of these refs holds, after [`recover`].
pub fn apply<R: RefStore>(store: &R, changes: &[RefChange]) -> std::result::Result<(), TxFailed> {
    if changes.is_empty() {
        return Ok(());
    }
    match store.pending() {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(TxFailed::only(Error::Other(format!(
                "an interrupted ref transaction is pending ({RECORD}); it must be rolled \
                 back before anything else is published"
            ))))
        }
        Err(e) => return Err(TxFailed::only(e)),
    }
    if let Err(e) = store.begin(changes) {
        // Nothing has moved. A record that landed anyway is harmless: its
        // recovery finds every ref as expected.
        let _ = store.end();
        return Err(TxFailed::only(e));
    }
    // How many changes had their write attempted.
    let mut reached = 0;
    let mut failure = None;
    for (i, c) in changes.iter().enumerate() {
        match store.read(&c.name) {
            Ok(actual) if actual == c.expected => {}
            Ok(actual) => {
                let show = |v: Option<ObjectId>| v.map_or("nothing".into(), |i| i.to_hex());
                failure = Some(Error::RefChanged {
                    name: c.name.clone(),
                    expected: show(c.expected),
                    actual: show(actual),
                });
                break;
            }
            Err(e) => {
                failure = Some(e);
                break;
            }
        }
        reached = i + 1;
        let step = match c.new {
            Some(n) => store.write(&c.name, n),
            None => store.delete(&c.name),
        };
        if let Err(e) = step {
            failure = Some(e);
            break;
        }
    }
    if failure.is_none() {
        match store.end() {
            Ok(()) => return Ok(()),
            // Every ref landed, but the record could not be removed, so
            // recovery would roll the transaction back. Roll it back now,
            // and report it as not applied.
            Err(e) => failure = Some(e),
        }
    }
    let error = failure.expect("a failure");
    // Only refs whose write was attempted are put back. One that failed its
    // comparison was moved by someone else, and is theirs.
    let (_, uncertain, unrestored) = put_back(store, &changes[..reached], false);
    if unrestored.is_empty() {
        // Best effort: a record left behind finds every ref as expected.
        let _ = store.end();
    }
    Err(TxFailed {
        error,
        uncertain,
        unrestored,
    })
}

/// Roll back a transaction that was begun and not finished, and remove its
/// record. Every ref it names is written back to its expected value, moved
/// or not, and the record is removed only when all of those writes have
/// succeeded. Returns the refs, or `None` if nothing was pending.
/// Call under the lock every writer of these refs holds, before reading any
/// of them to decide what to publish. If a ref cannot be put back, the
/// record stays and this fails, so nothing is published over the
/// half-applied state.
pub fn recover<R: RefStore>(store: &R) -> std::result::Result<Option<Vec<String>>, TxFailed> {
    let changes = match store.pending() {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(None),
        Err(e) => return Err(TxFailed::only(e)),
    };
    let (restored, uncertain, unrestored) = put_back(store, &changes, true);
    if !unrestored.is_empty() || !uncertain.is_empty() {
        return Err(TxFailed {
            error: Error::Other(format!(
                "an interrupted ref transaction ({RECORD}) could not be rolled back"
            )),
            uncertain,
            unrestored,
        });
    }
    store.end().map_err(TxFailed::only)?;
    Ok(Some(restored))
}
