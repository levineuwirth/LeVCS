//! A ref transaction that fails is put back, whatever its failing write
//! reported, and says only what is true of the refs it leaves.
//!
//! The review's reproductions (2026-10-05) injected a directory-sync
//! failure after the rename: a commit advanced its branch while reporting
//! that every ref was restored, and an authority change restored its branch
//! but left `current` advanced. The store here fails in the same ways.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use levcs_core::error::{Error, Result};
use levcs_core::ref_tx::{apply, recover, RefChange, RefStore};
use levcs_core::ObjectId;

/// How one write call fails.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    /// Takes effect, then reports an error: the rename landed and the
    /// directory sync failed.
    AfterEffect,
    /// Reports an error and changes nothing.
    Before,
    /// Takes effect, and the process dies: nothing after it runs.
    Crash,
}

#[derive(Default)]
struct Store {
    refs: RefCell<BTreeMap<String, ObjectId>>,
    record: RefCell<Option<Vec<RefChange>>>,
    writes: RefCell<usize>,
    /// The fault for the nth write call (0-based), deletes included.
    faults: BTreeMap<usize, Fault>,
    /// Removing the record fails without effect.
    end_fails: bool,
    /// Every ref written or deleted, in order.
    log: RefCell<Vec<String>>,
}

impl Store {
    fn with(refs: &[(&str, ObjectId)]) -> Self {
        Store {
            refs: RefCell::new(refs.iter().map(|(n, i)| (n.to_string(), *i)).collect()),
            ..Default::default()
        }
    }
    fn fail(mut self, nth: usize, f: Fault) -> Self {
        self.faults.insert(nth, f);
        self
    }
    fn snapshot(&self) -> BTreeMap<String, ObjectId> {
        self.refs.borrow().clone()
    }
    fn step(&self, apply: impl FnOnce(&mut BTreeMap<String, ObjectId>)) -> Result<()> {
        let n = {
            let mut w = self.writes.borrow_mut();
            *w += 1;
            *w - 1
        };
        let fault = self.faults.get(&n).copied();
        if fault != Some(Fault::Before) {
            apply(&mut self.refs.borrow_mut());
        }
        match fault {
            None => Ok(()),
            Some(Fault::Crash) => panic!("process killed after write {n}"),
            Some(_) => Err(Error::Other(format!("injected failure on write {n}"))),
        }
    }
}

impl RefStore for Store {
    fn read(&self, name: &str) -> Result<Option<ObjectId>> {
        Ok(self.refs.borrow().get(name).copied())
    }
    fn write(&self, name: &str, id: ObjectId) -> Result<()> {
        self.log.borrow_mut().push(name.to_string());
        self.step(|m| {
            m.insert(name.to_string(), id);
        })
    }
    fn delete(&self, name: &str) -> Result<()> {
        self.log.borrow_mut().push(name.to_string());
        self.step(|m| {
            m.remove(name);
        })
    }
    fn begin(&self, changes: &[RefChange]) -> Result<()> {
        *self.record.borrow_mut() = Some(changes.to_vec());
        Ok(())
    }
    fn pending(&self) -> Result<Option<Vec<RefChange>>> {
        Ok(self.record.borrow().clone())
    }
    fn end(&self) -> Result<()> {
        if self.end_fails {
            return Err(Error::Other("record could not be removed".into()));
        }
        *self.record.borrow_mut() = None;
        Ok(())
    }
}

/// Run `apply` until the store's `Crash` fault kills it.
fn crash(s: &Store, changes: &[RefChange]) {
    let died = catch_unwind(AssertUnwindSafe(|| {
        let _ = apply(s, changes);
    }));
    assert!(died.is_err(), "the injected crash did not happen");
}

fn id(b: u8) -> ObjectId {
    ObjectId([b; 32])
}

fn change(name: &str, expected: Option<u8>, new: Option<u8>) -> RefChange {
    RefChange {
        name: name.into(),
        expected: expected.map(id),
        new: new.map(id),
    }
}

const MAIN: &str = "refs/branches/main";
const CURRENT: &str = "refs/authority/current";

#[test]
fn a_transaction_applies_whole() {
    let s = Store::with(&[(MAIN, id(1)), (CURRENT, id(10))]);
    apply(
        &s,
        &[
            change(MAIN, Some(1), Some(2)),
            change("refs/branches/new", None, Some(3)),
            change(CURRENT, Some(10), Some(11)),
        ],
    )
    .unwrap();
    assert_eq!(s.snapshot()[MAIN], id(2));
    assert_eq!(s.snapshot()["refs/branches/new"], id(3));
    assert_eq!(s.snapshot()[CURRENT], id(11));
}

/// The review's first reproduction: the branch write lands, then fails.
#[test]
fn a_write_that_lands_and_then_fails_is_put_back() {
    let s = Store::with(&[(MAIN, id(1))]).fail(0, Fault::AfterEffect);
    let before = s.snapshot();
    let e = apply(&s, &[change(MAIN, Some(1), Some(2))]).unwrap_err();
    assert_eq!(s.snapshot(), before);
    assert!(e.restored() && e.uncertain.is_empty(), "{e}");
    assert!(e.to_string().contains("injected failure"), "{e}");
}

/// The review's second reproduction: the branch moves, then `current`'s
/// write lands and fails. Both are put back.
#[test]
fn current_is_put_back_with_the_branch() {
    let s = Store::with(&[(MAIN, id(1)), (CURRENT, id(10))]).fail(1, Fault::AfterEffect);
    let before = s.snapshot();
    let e = apply(
        &s,
        &[
            change(MAIN, Some(1), Some(2)),
            change(CURRENT, Some(10), Some(11)),
        ],
    )
    .unwrap_err();
    assert_eq!(s.snapshot(), before, "{e}");
    assert!(e.restored(), "{e}");
}

#[test]
fn a_write_that_fails_without_effect_leaves_earlier_writes_undone() {
    let s = Store::with(&[(MAIN, id(1))]).fail(1, Fault::Before);
    let before = s.snapshot();
    let e = apply(
        &s,
        &[
            change(MAIN, Some(1), Some(2)),
            change("refs/branches/new", None, Some(3)),
        ],
    )
    .unwrap_err();
    assert_eq!(s.snapshot(), before, "{e}");
    assert!(e.restored(), "{e}");
}

/// A deletion is put back like a write.
#[test]
fn a_deletion_is_put_back() {
    let s = Store::with(&[(MAIN, id(1)), ("refs/branches/old", id(5))]).fail(1, Fault::AfterEffect);
    let before = s.snapshot();
    let e = apply(
        &s,
        &[
            change("refs/branches/old", Some(5), None),
            change(MAIN, Some(1), Some(2)),
        ],
    )
    .unwrap_err();
    assert_eq!(s.snapshot(), before, "{e}");
}

/// A restoring write that lands but reports an error is restored as far as
/// can be read, and says its durability is unknown.
#[test]
fn a_restore_whose_write_errors_is_reported_as_uncertain() {
    let s = Store::with(&[(MAIN, id(1))])
        .fail(0, Fault::AfterEffect)
        .fail(1, Fault::AfterEffect);
    let before = s.snapshot();
    let e = apply(&s, &[change(MAIN, Some(1), Some(2))]).unwrap_err();
    assert_eq!(s.snapshot(), before);
    assert_eq!(e.uncertain, vec![MAIN.to_string()]);
    assert!(e.to_string().contains("may not be durable"), "{e}");
    assert!(!e.to_string().contains("every ref reads back"), "{e}");
}

/// A ref that cannot be put back is named, never reported restored.
#[test]
fn a_ref_that_cannot_be_put_back_is_named() {
    let s = Store::with(&[(MAIN, id(1)), (CURRENT, id(10))])
        .fail(1, Fault::AfterEffect)
        .fail(2, Fault::Before)
        .fail(3, Fault::Before);
    let e = apply(
        &s,
        &[
            change(MAIN, Some(1), Some(2)),
            change(CURRENT, Some(10), Some(11)),
        ],
    )
    .unwrap_err();
    assert!(!e.restored());
    assert_eq!(e.unrestored, vec![CURRENT.to_string(), MAIN.to_string()]);
    let msg = e.to_string();
    assert!(msg.contains("could not be put back"), "{msg}");
    assert!(!msg.contains("every ref reads back"), "{msg}");
}

/// A ref that fails its comparison was moved by someone else. Earlier
/// changes are put back; that one is left as it is.
#[test]
fn a_stale_ref_is_not_overwritten_by_the_undo() {
    let s = Store::with(&[(MAIN, id(1)), ("refs/branches/b", id(7))]);
    let e = apply(
        &s,
        &[
            change(MAIN, Some(1), Some(2)),
            change("refs/branches/b", Some(6), Some(8)),
        ],
    )
    .unwrap_err();
    assert_eq!(s.snapshot()[MAIN], id(1));
    assert_eq!(s.snapshot()["refs/branches/b"], id(7));
    assert!(e.restored(), "{e}");
}

// Process termination (the review's second round, 2026-10-05). The record
// written before any ref moves is what lets the next process undo it.

/// The review's reproduction: an authority removal killed after its branch
/// write landed, before `current` moved.
#[test]
fn a_transaction_killed_part_way_is_rolled_back_by_recovery() {
    let s = Store::with(&[(MAIN, id(1)), (CURRENT, id(10))]).fail(0, Fault::Crash);
    let before = s.snapshot();
    let changes = [
        change(MAIN, Some(1), Some(2)),
        change(CURRENT, Some(10), Some(11)),
    ];
    crash(&s, &changes);
    assert_eq!(s.snapshot()[MAIN], id(2), "the branch write landed");
    assert_eq!(s.snapshot()[CURRENT], id(10), "current had not moved");
    assert!(
        s.pending().unwrap().is_some(),
        "the record survives the crash"
    );

    let rolled = recover(&s).unwrap().unwrap();
    assert!(rolled.contains(&MAIN.to_string()), "{rolled:?}");
    assert_eq!(s.snapshot(), before);
    assert!(s.pending().unwrap().is_none());
    // Nothing left to recover, and the next transaction proceeds.
    assert!(recover(&s).unwrap().is_none());
    apply(&s, &changes).unwrap();
    assert_eq!(s.snapshot()[CURRENT], id(11));
}

/// Killed after every ref landed but before the record was removed: the
/// command never reported success, and recovery undoes it.
#[test]
fn a_transaction_killed_before_its_record_is_removed_is_rolled_back() {
    let s = Store::with(&[(MAIN, id(1)), (CURRENT, id(10))]).fail(1, Fault::Crash);
    let before = s.snapshot();
    crash(
        &s,
        &[
            change(MAIN, Some(1), Some(2)),
            change(CURRENT, Some(10), Some(11)),
        ],
    );
    assert_eq!(s.snapshot()[CURRENT], id(11));
    recover(&s).unwrap();
    assert_eq!(s.snapshot(), before);
}

/// Nothing publishes over an interrupted transaction.
#[test]
fn a_transaction_does_not_start_over_a_pending_record() {
    let s = Store::with(&[(MAIN, id(1))]).fail(0, Fault::Crash);
    crash(&s, &[change(MAIN, Some(1), Some(2))]);
    let e = apply(&s, &[change(MAIN, Some(2), Some(3))]).unwrap_err();
    assert!(e.to_string().contains("pending"), "{e}");
    assert_eq!(s.snapshot()[MAIN], id(2), "nothing moved");
}

/// A ref the record names that someone else has since moved is not
/// clobbered: recovery leaves it, keeps the record, and fails.
#[test]
fn recovery_leaves_a_ref_moved_by_someone_else_and_keeps_the_record() {
    let s = Store::with(&[(MAIN, id(1))]).fail(0, Fault::Crash);
    crash(&s, &[change(MAIN, Some(1), Some(2))]);
    s.refs.borrow_mut().insert(MAIN.into(), id(9));
    let e = recover(&s).unwrap_err();
    assert_eq!(e.unrestored, vec![MAIN.to_string()]);
    assert_eq!(s.snapshot()[MAIN], id(9));
    assert!(s.pending().unwrap().is_some());
}

/// Every ref landed but the record could not be removed: recovery would
/// undo the transaction later, so it is undone now and reported failed.
#[test]
fn a_record_that_cannot_be_removed_fails_the_transaction() {
    let mut s = Store::with(&[(MAIN, id(1))]);
    s.end_fails = true;
    let e = apply(&s, &[change(MAIN, Some(1), Some(2))]).unwrap_err();
    assert!(e.to_string().contains("record could not be removed"), "{e}");
    assert_eq!(s.snapshot()[MAIN], id(1));
}

/// Recovery writes every recorded ref back, moved or not, so that clearing
/// the record never rests on an earlier restore whose durability was
/// unknown.
#[test]
fn recovery_rewrites_every_recorded_ref() {
    let s = Store::with(&[(MAIN, id(1)), (CURRENT, id(10))]).fail(0, Fault::Crash);
    crash(
        &s,
        &[
            change(MAIN, Some(1), Some(2)),
            change(CURRENT, Some(10), Some(11)),
        ],
    );
    s.log.borrow_mut().clear();
    recover(&s).unwrap();
    let mut written = s.log.borrow().clone();
    written.sort();
    assert_eq!(written, vec![CURRENT.to_string(), MAIN.to_string()]);
}
