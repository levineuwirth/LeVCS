// SPDX-FileCopyrightText: 2026 Levi Neuwirth
// SPDX-License-Identifier: Apache-2.0

//! The Rust side of the executable specification in `authority-spec/`.
//!
//! `authority-spec/` states the rules of `doc/authority-semantics.md` over an
//! abstract model: small integers for objects and keys, and a signature that
//! is simply valid or not. This turns one such scenario into real objects,
//! with real keys and real signatures, puts it to `verify_history` and
//! `admit`, and reports the verdicts in the model's terms.
//!
//! The wire format is `authority-spec/harness/LeVCS/Harness/Wire.hs`. Only
//! verdicts are compared: which commits and releases were reached, which of
//! them are invalid, which are on a conflicting lineage, how each transaction
//! was decided, and whether each transfer would be recorded and as what. The
//! reasons given here travel beside them so that a disagreement can be read.
//!
//! A transfer is decided here as `levcs-cli`'s `receive` decides one: by
//! `verify_history` against the genesis expected and the source's current
//! authority, kept if `HistoryReport::ok` and refused whole if not. That
//! function itself is not run here; it needs an instance to fetch from, and
//! this crate cannot depend on the one it is in. `levcs-cli` runs it, over
//! the same scenarios, through [`answer_with`]
//! (`crates/levcs-cli/tests/spec_receive_support`). A read, which is asked
//! of an instance, is answered only there: an answer made here says nothing
//! of the reads a request asks.
//!
//! Shared by `examples/spec_oracle.rs`, which the Haskell differential run
//! drives, `tests/spec_corpus.rs`, which replays the committed corpus, and
//! the two of the same in `levcs-cli`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use levcs_core::object::SignatureEntry;
use levcs_core::{
    Commit, CommitFlags, EntryType, FileMode, ObjectId, Release, SignedObject, Tree, TreeEntry,
    ZERO_ID,
};
use levcs_identity::admission::{admit, PreState, RefUpdate, Refused, Transaction};
use levcs_identity::authority::{
    AuthorityBody, MemberEntry, PolicyEntry, Role, AUTHORITY_SCHEMA_VERSION,
};
use levcs_identity::history::verify_history;
use levcs_identity::keys::SecretKey;
use levcs_identity::verify::MemorySource;
use serde_json::{json, Value};

type Res<T> = Result<T, String>;

/// The model's key `n`. Fixed, so that a scenario always becomes the same
/// objects.
pub fn key(n: u64) -> SecretKey {
    SecretKey::from_seed(levcs_core::blake3_hash(format!("levcs-spec-key-{n}").as_bytes()).0)
}

/// A signature by `by` over `signed`, or, for one the model calls invalid, a
/// well-formed signature by the same key over something else.
fn signature(signed: &SignedObject, by: &SecretKey, valid: bool) -> SignatureEntry {
    let hash = signed.signing_hash();
    let mut message = hash.as_bytes().to_vec();
    if !valid {
        message.extend_from_slice(b"not what was signed");
    }
    SignatureEntry {
        public_key: by.public().0,
        signature: by.sign(&message),
    }
}

fn field<'a>(v: &'a Value, name: &str) -> Res<&'a Value> {
    v.get(name)
        .ok_or_else(|| format!("missing field `{name}` in {v}"))
}

/// Every number on the wire is a `u32`: an object's number, a key, a
/// version, a count. One that is not would have to be narrowed to be used,
/// and a narrowed version is a different version.
///
/// It is the value that has to be a `u32`, not the way it is written: `0`,
/// `0.0` and `0e0` are the same number in JSON and are all read as 0. The
/// specification's reader does the same.
fn number(n: &Value, name: &str, v: &Value) -> Res<u64> {
    n.as_u64()
        .filter(|&integer| u32::try_from(integer).is_ok())
        .ok_or_else(|| format!("field `{name}` is not a u32 in {v}"))
}

/// Read the oracle's wire format without rounding a decimal before a field
/// is checked. IgnoredAny validates JSON number syntax without converting
/// the digits. The scan can then copy all strings and punctuation verbatim.
pub fn parse_wire(text: &str) -> serde_json::Result<Value> {
    serde_json::from_str::<serde::de::IgnoredAny>(text)?;
    let mut canonical = String::new();
    let mut copied = 0;
    let mut in_string = false;
    let mut bytes = text.bytes().enumerate().peekable();
    while let Some((start, byte)) = bytes.next() {
        match byte {
            b'\\' if in_string => {
                bytes.next();
            }
            b'"' => in_string = !in_string,
            b'-' | b'0'..=b'9' if !in_string => {
                // The validated number ends at whitespace, a delimiter or EOF.
                while bytes
                    .next_if(|&(_, b)| b.is_ascii_digit() || b".eE+-".contains(&b))
                    .is_some()
                {}
                let end = bytes.peek().map_or(text.len(), |&(i, _)| i);
                let token = &text[start..end];
                if token.len() <= 10 && token.bytes().all(|b| b.is_ascii_digit()) {
                    continue; // Already an integer serde_json can read exactly.
                }
                canonical.push_str(&text[copied..start]);
                match exact_u32(token) {
                    Some(n) => canonical.push_str(&n.to_string()),
                    // All numeric fields require u32. Keep other numbers out
                    // of range even if they occur in a field the reader skips.
                    None => canonical.push_str("-1"),
                }
                copied = end;
            }
            _ => {}
        }
    }
    if copied == 0 {
        return serde_json::from_str(text);
    }
    canonical.push_str(&text[copied..]);
    serde_json::from_str(&canonical)
}

fn exact_u32(text: &str) -> Option<u32> {
    let (mantissa, exponent) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
    let fraction_len = mantissa.split_once('.').map_or(0, |(_, frac)| frac.len());
    let digits = mantissa.replace('.', "");
    let coefficient = digits.trim_end_matches('0');
    if coefficient.is_empty() || coefficient == "-" {
        return Some(0); // Signed zero is zero at any exponent.
    }

    // With trailing zeros removed, a negative power of ten is always fractional.
    let trailing_zeros = digits.len() - coefficient.len();
    let adjustment = trailing_zeros as i64 - fraction_len as i64;
    let power = exponent.parse::<i64>().ok()?.checked_add(adjustment)?;
    let factor = 10_u32.checked_pow(u32::try_from(power).ok()?)?;
    coefficient.parse::<u32>().ok()?.checked_mul(factor)
}

fn int(v: &Value, name: &str) -> Res<u64> {
    number(field(v, name)?, name, v)
}

fn opt_int(v: &Value, name: &str) -> Res<Option<u64>> {
    match v.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(n) => number(n, name, v).map(Some),
    }
}

fn boolean(v: &Value, name: &str) -> Res<bool> {
    field(v, name)?
        .as_bool()
        .ok_or_else(|| format!("field `{name}` is not a boolean in {v}"))
}

/// Two objects under one number would be two objects here and one to the
/// model.
fn once<V>(known: &HashMap<u64, V>, what: &str, n: u64) -> Res<()> {
    if known.contains_key(&n) {
        return Err(format!("more than one {what} is numbered {n}"));
    }
    Ok(())
}

/// A ref a state can hold, or a transaction name: under one of the three
/// namespaces the model has. Returns the namespace and the name within it.
fn namespaced(name: &str) -> Res<(&'static str, &str)> {
    for ns in ["refs/branches/", "refs/releases/", "refs/authority/"] {
        if let Some(rest) = name.strip_prefix(ns) {
            return Ok((ns, rest));
        }
    }
    Err(format!("unknown ref {name}"))
}

fn list<'a>(v: &'a Value, name: &str) -> Res<&'a Vec<Value>> {
    field(v, name)?
        .as_array()
        .ok_or_else(|| format!("field `{name}` is not a list in {v}"))
}

fn role(v: &Value) -> Res<Role> {
    match v.as_str() {
        Some("reader") => Ok(Role::Reader),
        Some("contributor") => Ok(Role::Contributor),
        Some("maintainer") => Ok(Role::Maintainer),
        Some("owner") => Ok(Role::Owner),
        _ => Err(format!("unknown role {v}")),
    }
}

/// A scenario's objects, made real, with the way back from each id to the
/// model's name for it.
struct World {
    src: MemorySource,
    authorities: HashMap<u64, ObjectId>,
    commits: HashMap<u64, ObjectId>,
    releases: HashMap<u64, ObjectId>,
    /// `{"commit": n}` or `{"release": n}`, by object id.
    objects: HashMap<ObjectId, (u8, u64)>,
    authority_names: HashMap<ObjectId, u64>,
    /// Each authority's body, for the `repo_id` its successors carry.
    bodies: HashMap<u64, AuthorityBody>,
    empty_tree: ObjectId,
    /// What each object refers to, written down as the object is made and
    /// never read back out of it: a second account of what reaches what,
    /// beside the one the implementation's walk gives.
    links: HashMap<ObjectId, Vec<ObjectId>>,
}

impl World {
    fn put(&mut self, o: &SignedObject) -> ObjectId {
        let id = o.object_id();
        self.src.0.insert(id, o.serialize());
        id
    }

    fn put_tree(&mut self, mut t: Tree) -> Res<ObjectId> {
        t.sort_and_validate().map_err(|e| e.to_string())?;
        let id = t.object_id();
        self.src.0.insert(id, t.serialize());
        self.links
            .insert(id, t.entries.iter().map(|e| e.hash).collect());
        Ok(id)
    }

    fn authority(&self, n: u64) -> Res<ObjectId> {
        self.authorities
            .get(&n)
            .copied()
            .ok_or_else(|| format!("no authority {n}"))
    }

    fn commit(&self, n: u64) -> Res<ObjectId> {
        self.commits
            .get(&n)
            .copied()
            .ok_or_else(|| format!("no commit {n}"))
    }

    fn release(&self, n: u64) -> Res<ObjectId> {
        self.releases
            .get(&n)
            .copied()
            .ok_or_else(|| format!("no release {n}"))
    }

    /// `{"commit": n}` or `{"release": n}`.
    fn object(&self, v: &Value) -> Res<ObjectId> {
        match (opt_int(v, "commit")?, opt_int(v, "release")?) {
            (Some(n), None) => self.commit(n),
            (None, Some(n)) => self.release(n),
            _ => Err(format!("not an object: {v}")),
        }
    }

    /// Make every object of the store.
    ///
    /// The numbers are names and say nothing of order: an object can be
    /// listed, and numbered, before one it refers to. An object's id is the
    /// hash of what it refers to, though, so each is made after those.
    fn build(store: &Value) -> Res<World> {
        let mut w = World {
            src: MemorySource(Default::default()),
            authorities: HashMap::new(),
            commits: HashMap::new(),
            releases: HashMap::new(),
            objects: HashMap::new(),
            authority_names: HashMap::new(),
            bodies: HashMap::new(),
            empty_tree: ZERO_ID,
            links: HashMap::new(),
        };
        w.empty_tree = w.put_tree(Tree::default())?;
        in_dependency_order(list(store, "authorities")?, "authority", |a| {
            w.make_authority(a)
        })?;
        in_dependency_order(list(store, "commits")?, "commit", |c| w.make_commit(c))?;
        in_dependency_order(list(store, "releases")?, "release", |r| w.make_release(r))?;
        Ok(w)
    }

    /// Make an authority, unless the one it names as previous is not made
    /// yet.
    fn make_authority(&mut self, a: &Value) -> Res<bool> {
        let n = int(a, "id")?;
        once(&self.authorities, "authority", n)?;
        let prev = opt_int(a, "prev")?;
        if prev.is_some_and(|p| !self.authorities.contains_key(&p)) {
            return Ok(false);
        }
        let prev_id = match prev {
            Some(p) => Some(self.authority(p)?),
            None => None,
        };
        let mut members = Vec::new();
        for m in list(a, "members")? {
            let k = int(m, "key")?;
            members.push(MemberEntry {
                key: key(k).public(),
                handle: format!("k{k}"),
                role: role(field(m, "role")?)?,
                added_micros: 1,
                added_by: key(k).public(),
            });
        }
        let mut policy = Vec::new();
        // The policy is one string, the patterns joined by commas. A
        // pattern with a comma in it would be read back as two, and an
        // empty one as none, so the model and this would be deciding
        // different policies.
        //
        // The model's policy is a set, so a pattern listed twice is one
        // pattern, and the set is what is joined and measured.
        let mut protected: BTreeSet<&str> = BTreeSet::new();
        for p in list(a, "protected")? {
            match p.as_str() {
                Some(glob) if !glob.is_empty() && !glob.contains(',') => {
                    protected.insert(glob);
                }
                _ => {
                    return Err(format!(
                        "authority {n}: the protected pattern {p} is not a string, is \
                         empty, or has a comma in it"
                    ))
                }
            }
        }
        if !protected.is_empty() {
            let value = protected.into_iter().collect::<Vec<_>>().join(",");
            // Keep the wire error consistent with the model's reader.
            if value.len() > usize::from(u16::MAX) {
                return Err(format!(
                    "authority {n}: its protected patterns come to more than 65535 bytes"
                ));
            }
            policy.push(PolicyEntry {
                key: "protected_branches".into(),
                value: value.into_bytes(),
            });
        }
        if boolean(a, "public_read")? {
            policy.push(PolicyEntry {
                key: "public_read".into(),
                value: vec![1],
            });
        }
        let mut body = AuthorityBody {
            schema_version: AUTHORITY_SCHEMA_VERSION,
            // A successor carries its predecessor's repo_id; a genesis
            // derives its own below.
            repo_id: match prev {
                Some(p) => self.bodies[&p].repo_id,
                None => ZERO_ID,
            },
            previous_authority: prev_id.unwrap_or(ZERO_ID),
            version: u32::try_from(int(a, "version")?).map_err(|e| e.to_string())?,
            // The model's objects are distinct even when their fields are
            // equal; the timestamp keeps their ids distinct too.
            created_micros: n as i64 + 1,
            members,
            policy,
        };
        body.normalize()
            .map_err(|e| format!("authority {n}: {e}"))?;
        if prev.is_none() {
            body.assign_genesis_repo_id().map_err(|e| e.to_string())?;
        }
        let mut signed = body.to_signed().map_err(|e| e.to_string())?;
        let signatures = list(a, "signatures")?;
        // The count is one byte of the object, and serializing more is a
        // panic, which would end the oracle and not just this request.
        if signatures.len() > 255 {
            return Err(format!("authority {n} has more than 255 signatures"));
        }
        for s in signatures {
            let valid = boolean(s, "valid")?;
            let entry = signature(&signed, &key(int(s, "key")?), valid);
            signed.signatures.push(entry);
        }
        let id = self.put(&signed);
        self.links.insert(id, prev_id.into_iter().collect());
        self.authorities.insert(n, id);
        self.authority_names.insert(id, n);
        self.bodies.insert(n, body);
        Ok(true)
    }

    /// Make a commit, unless one of its parents is not made yet.
    fn make_commit(&mut self, c: &Value) -> Res<bool> {
        let n = int(c, "id")?;
        once(&self.commits, "commit", n)?;
        let sig = field(c, "signature")?;
        let by = key(int(sig, "key")?);
        let mut parents = Vec::new();
        for p in list(c, "parents")? {
            let p = number(p, "parents", c)?;
            match self.commits.get(&p) {
                Some(id) => parents.push(*id),
                None => return Ok(false),
            }
        }
        // A commit that installs an authority carries it at
        // `.levcs/authority` and says so in its flags. Any other commit
        // has an empty tree.
        let (tree, flags) = match opt_int(c, "installs")? {
            None => (self.empty_tree, CommitFlags::NONE),
            Some(a) => {
                let installed = self.authority(a)?;
                let inner = self.put_tree(Tree {
                    entries: vec![TreeEntry {
                        name: "authority".into(),
                        entry_type: EntryType::Blob,
                        mode: FileMode::REGULAR,
                        hash: installed,
                    }],
                })?;
                let outer = self.put_tree(Tree {
                    entries: vec![TreeEntry {
                        name: ".levcs".into(),
                        entry_type: EntryType::Tree,
                        mode: FileMode::REGULAR,
                        hash: inner,
                    }],
                })?;
                (outer, CommitFlags::MODIFIES_AUTHORITY)
            }
        };
        let cites = self.authority(int(c, "cites")?)?;
        let mut linked = vec![tree, cites];
        linked.extend(&parents);
        let commit = Commit {
            tree,
            parents,
            authority: cites,
            author_key: by.public().0,
            timestamp_micros: n as i64 + 1,
            flags,
            message: format!("c{n}"),
        };
        let mut signed = commit.into_signed().map_err(|e| e.to_string())?;
        let valid = boolean(sig, "valid")?;
        let entry = signature(&signed, &by, valid);
        signed.signatures.push(entry);
        let id = self.put(&signed);
        self.links.insert(id, linked);
        self.commits.insert(n, id);
        self.objects.insert(id, (0, n));
        Ok(true)
    }

    /// Make a release, unless its parent release is not made yet.
    fn make_release(&mut self, r: &Value) -> Res<bool> {
        let n = int(r, "id")?;
        once(&self.releases, "release", n)?;
        let sig = field(r, "signature")?;
        let by = key(int(sig, "key")?);
        let parent_release = match opt_int(r, "parent")? {
            Some(p) => match self.releases.get(&p) {
                Some(id) => *id,
                None => return Ok(false),
            },
            None => ZERO_ID,
        };
        let predecessor = self.commit(int(r, "predecessor")?)?;
        let cites = self.authority(int(r, "cites")?)?;
        let mut linked = vec![self.empty_tree, predecessor, cites];
        if !parent_release.is_zero() {
            linked.push(parent_release);
        }
        let release = Release {
            tree: self.empty_tree,
            parent_release,
            predecessor,
            authority: cites,
            declarer_key: by.public().0,
            timestamp_micros: n as i64 + 1,
            label: format!("r{n}"),
            notes: String::new(),
        };
        let mut signed = release.into_signed().map_err(|e| e.to_string())?;
        let valid = boolean(sig, "valid")?;
        let entry = signature(&signed, &by, valid);
        signed.signatures.push(entry);
        let id = self.put(&signed);
        self.links.insert(id, linked);
        self.releases.insert(n, id);
        self.objects.insert(id, (1, n));
        Ok(true)
    }
}

/// Make each of `items` with `make`, which answers `false` for one that
/// refers to another of its kind not made yet. Those are tried again once
/// the rest are made, until a round makes nothing: what is left then refers
/// to something that is missing, or to itself by some route.
fn in_dependency_order(
    items: &[Value],
    what: &str,
    mut make: impl FnMut(&Value) -> Res<bool>,
) -> Res<()> {
    let mut waiting: Vec<&Value> = items.iter().collect();
    while !waiting.is_empty() {
        let mut still = Vec::new();
        for item in &waiting {
            if !make(item)? {
                still.push(*item);
            }
        }
        if still.len() == waiting.len() {
            let ids: Vec<String> = still.iter().map(|i| i["id"].to_string()).collect();
            return Err(format!(
                "{what} {} names something that is missing, or that is behind itself",
                ids.join(", ")
            ));
        }
        waiting = still;
    }
    Ok(())
}

fn named(kind: u8, n: u64) -> Value {
    if kind == 0 {
        json!({ "commit": n })
    } else {
        json!({ "release": n })
    }
}

/// The roots a request names, each under a ref of its kind.
fn roots(w: &World, v: &Value) -> Res<Vec<(String, ObjectId)>> {
    let mut roots = Vec::new();
    for r in list(v, "roots")? {
        let id = w.object(r)?;
        let name = match w.objects[&id] {
            (0, n) => format!("refs/branches/c{n}"),
            (_, n) => format!("refs/releases/r{n}"),
        };
        roots.push((name, id));
    }
    Ok(roots)
}

/// What a problem is about, in the model's terms.
fn about(w: &World, object: &ObjectId) -> String {
    match (w.objects.get(object), w.authority_names.get(object)) {
        (Some((0, n)), _) => format!("commit {n}"),
        (Some((_, n)), _) => format!("release {n}"),
        (None, Some(n)) => format!("authority {n}"),
        (None, None) => format!("object {object}"),
    }
}

/// Verdicts for the history the roots reach.
fn verify(w: &World, pin: ObjectId, v: &Value) -> Res<Value> {
    let current = match opt_int(v, "current")? {
        Some(a) => Some(w.authority(a)?),
        None => None,
    };
    let roots = roots(w, v)?;
    let report = verify_history(&w.src, pin, current, &roots);

    // In the model's order: commits before releases, each by number.
    let mut invalid: BTreeSet<(u8, u64)> = BTreeSet::new();
    let mut conflicting: BTreeSet<(u8, u64)> = BTreeSet::new();
    let mut damage = Vec::new();
    let mut problems = Vec::new();
    for p in &report.problems {
        let about = about(w, &p.object);
        if p.integrity {
            damage.push(format!("{about}: {}", p.what));
            continue;
        }
        problems.push(format!("{about}: {}", p.what));
        if let Some(o) = w.objects.get(&p.object) {
            invalid.insert(*o);
        }
    }
    for p in &report.conflicting {
        match w.objects.get(&p.object) {
            Some(o) => {
                conflicting.insert(*o);
            }
            None => damage.push(format!("conflict reported on a non-object: {}", p.what)),
        }
    }
    // Whether the replica's current authority was itself reported, read
    // from this report and no other. `HistoryReport` has no field for it, so
    // it is a rule violation recorded against that authority and said to be
    // about the current authority. The second half is by the wording, which
    // is what tells it from the same authority reported where a commit
    // installs it. If the wording changes this reads `false`, the
    // specification still says `true`, and the comparison fails: it cannot
    // pass by mistake.
    let current_rejected = current.is_some_and(|cur| {
        report
            .problems
            .iter()
            .any(|p| !p.integrity && p.object == cur && p.what.starts_with("current authority"))
    });
    // Every commit and release the walk read and typed. A history the walk
    // stopped short in would otherwise look like one it found valid.
    let reached: BTreeSet<(u8, u64)> = report
        .reachable
        .iter()
        .filter_map(|id| w.objects.get(id).copied())
        .collect();
    Ok(json!({
        "reached": reached.iter().map(|(k, n)| named(*k, *n)).collect::<Vec<_>>(),
        "invalid": invalid.iter().map(|(k, n)| named(*k, *n)).collect::<Vec<_>>(),
        "conflicting": conflicting.iter().map(|(k, n)| named(*k, *n)).collect::<Vec<_>>(),
        "current_rejected": current_rejected,
        "damage": damage,
        "problems": problems,
    }))
}

/// One transfer, as the objects it is made of: the history the roots reach,
/// sent by a source whose current authority is `current`, to a receiver
/// expecting the genesis `expected`.
///
/// The objects and the repository's id are read where the transfer is
/// really made, in `levcs-cli`, and not by the report here.
#[allow(dead_code)]
pub struct Transfer<'a> {
    /// Every object of the scenario, by id: all that a source could send.
    pub objects: &'a HashMap<ObjectId, Vec<u8>>,
    /// The repository the receiver asks for: the one the authority it
    /// expects says it is an authority of.
    pub repo_id: ObjectId,
    pub expected: ObjectId,
    pub current: ObjectId,
    /// What is asked for, each under a ref of its kind.
    pub roots: Vec<(String, ObjectId)>,
    world: &'a World,
}

#[allow(dead_code)]
impl Transfer<'_> {
    /// The answer for a transfer recorded as the objects with these ids.
    /// Only commits and releases are named in an answer; trees and
    /// authorities travel with them and are not.
    pub fn recorded(&self, ids: impl IntoIterator<Item = ObjectId>) -> Value {
        let recorded: BTreeSet<(u8, u64)> = ids
            .into_iter()
            .filter_map(|id| self.world.objects.get(&id).copied())
            .collect();
        json!({
            "recorded": recorded.iter().map(|(k, n)| named(*k, *n)).collect::<Vec<_>>(),
            "damage": [],
        })
    }

    /// What an object is, in the model's terms.
    pub fn about(&self, object: &ObjectId) -> String {
        about(self.world, object)
    }

    /// Every object these reach, themselves included: commits and releases,
    /// and the trees and authorities that travel with them. Followed
    /// through what each object was made to refer to, not through the
    /// implementation's walk.
    pub fn reached(&self, from: impl IntoIterator<Item = ObjectId>) -> BTreeSet<ObjectId> {
        let mut reached = BTreeSet::new();
        let mut next: Vec<ObjectId> = from.into_iter().collect();
        while let Some(id) = next.pop() {
            if reached.insert(id) {
                next.extend(self.world.links.get(&id).into_iter().flatten());
            }
        }
        reached
    }

    /// The authorities behind an authority that these reach through a tree:
    /// every predecessor, to its genesis, of an authority some commit among
    /// them installs.
    ///
    /// An instance sends an installed authority and does not look inside
    /// it (`closure` in `levcs-instance` takes what a tree calls a blob to
    /// link to nothing), so these it may not send. In valid history the
    /// predecessor of an installed authority is the authority its commit
    /// cites, which is sent for that. Where it is not, the commit is
    /// invalid, and the receiver refuses over it and over what is missing.
    pub fn behind_installed(&self, from: impl IntoIterator<Item = ObjectId>) -> BTreeSet<ObjectId> {
        let authorities = &self.world.authority_names;
        let installed: Vec<ObjectId> = self
            .reached(from)
            .into_iter()
            .filter(|id| !authorities.contains_key(id) && !self.world.objects.contains_key(id))
            .flat_map(|tree| self.world.links.get(&tree).into_iter().flatten().copied())
            .filter(|id| authorities.contains_key(id))
            .collect();
        let mut behind = BTreeSet::new();
        for a in installed {
            let mut reached = self.reached([a]);
            reached.remove(&a);
            behind.extend(reached);
        }
        behind
    }

    /// Whether every root asked for is a commit, as every root `pull` asks
    /// for is.
    pub fn only_commits(&self) -> bool {
        self.roots
            .iter()
            .all(|(_, id)| matches!(self.world.objects.get(id), Some((0, _))))
    }
}

/// The transfer a request asks for.
fn transfer<'a>(w: &'a World, v: &Value) -> Res<Transfer<'a>> {
    let expected = int(v, "expected")?;
    Ok(Transfer {
        objects: &w.src.0,
        repo_id: w
            .bodies
            .get(&expected)
            .ok_or_else(|| format!("no authority {expected}"))?
            .repo_id,
        expected: w.authority(expected)?,
        current: w.authority(int(v, "current")?)?,
        roots: roots(w, v)?,
        world: w,
    })
}

/// A read asked of an instance that holds the scenario as the repository
/// the pin is the genesis of.
#[allow(dead_code)]
pub struct Read<'a> {
    /// The current authority the instance has for the repository, if it has
    /// one.
    pub current: Option<ObjectId>,
    /// The model's key the reader signs its requests with, if it signs
    /// them ([`key`]).
    pub requester: Option<u64>,
    /// What the reader asks for, expecting the pin. Its `current` is the
    /// instance's where the instance has one. Where it has none it is the
    /// genesis and stands for nothing: such an instance serves no one, and
    /// the transfer is never made.
    pub asked: Transfer<'a>,
}

/// The read a request asks for.
fn read<'a>(w: &'a World, pin: u64, v: &Value) -> Res<Read<'a>> {
    let genesis = w.authority(pin)?;
    let current = match opt_int(v, "current")? {
        Some(a) => Some(w.authority(a)?),
        None => None,
    };
    Ok(Read {
        current,
        requester: opt_int(v, "requester")?,
        asked: Transfer {
            objects: &w.src.0,
            repo_id: w.bodies[&pin].repo_id,
            expected: genesis,
            current: current.unwrap_or(genesis),
            roots: roots(w, v)?,
            world: w,
        },
    })
}

/// How the parts of a request that are about replication are answered.
pub trait Replication {
    /// One transfer: `{"recorded": [...]}` or `{"refused": true}`, with the
    /// reasons and any damage beside it.
    fn transfer(&mut self, t: &Transfer) -> Res<Value>;

    /// One read: `{"recorded": [...]}`, `{"denied": true}` or
    /// `{"refused": true}`. `None` where there is no instance to ask, and
    /// the answer then says nothing of reads.
    fn read(&mut self, _: &Read) -> Res<Option<Value>> {
        Ok(None)
    }
}

/// A transfer kept or refused as `levcs-cli`'s `receive` does it
/// (`receive.rs`), from the report of the same walk, without running it.
/// Reads are not answered: they are an instance's to answer.
struct ByTheReport;

impl Replication for ByTheReport {
    fn transfer(&mut self, t: &Transfer) -> Res<Value> {
        by_the_report(t)
    }
}

fn by_the_report(t: &Transfer) -> Res<Value> {
    let w = t.world;
    let report = verify_history(&w.src, t.expected, Some(t.current), &t.roots);
    let damage: Vec<String> = report
        .problems
        .iter()
        .filter(|p| p.integrity)
        .map(|p| format!("{}: {}", about(w, &p.object), p.what))
        .collect();
    if report.ok() {
        let mut recorded = t.recorded(report.reachable.iter().copied());
        recorded["damage"] = json!(damage);
        return Ok(recorded);
    }
    let reasons: Vec<String> = report
        .problems
        .iter()
        .filter(|p| !p.integrity)
        .map(|p| format!("invalid {}: {}", about(w, &p.object), p.what))
        .chain(
            report
                .conflicting
                .iter()
                .map(|p| format!("conflict {}: {}", about(w, &p.object), p.what)),
        )
        .collect();
    Ok(json!({ "refused": true, "reasons": reasons, "damage": damage }))
}

/// One transaction, decided against the state it names.
fn decide(w: &World, pin: ObjectId, v: &Value) -> Res<Value> {
    let state = field(v, "state")?;
    let mut refs = BTreeMap::new();
    for r in list(state, "refs")? {
        let name = field(r, "ref")?
            .as_str()
            .ok_or_else(|| format!("bad ref in {r}"))?;
        let target = w.object(field(r, "target")?)?;
        // A state is given, not judged. The model has no answer for one
        // whose refs are not branches at commits and release refs at
        // releases, each with a name a ref can have.
        let (ns, rest) = namespaced(name)?;
        let kind = w.objects[&target].0;
        let holdable =
            (ns == "refs/branches/" && kind == 0) || (ns == "refs/releases/" && kind == 1);
        let well_named = rest
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != ".." && !c.contains('\0'));
        if !holdable || !well_named {
            return Err(format!(
                "a state holds {name}, which is not a ref a state can hold, or not at that \
                 kind of object"
            ));
        }
        if refs.insert(name.to_string(), target).is_some() {
            return Err(format!("a state holds {name} twice"));
        }
    }
    let s0 = PreState {
        genesis: pin,
        current: match opt_int(state, "current")? {
            Some(a) => Some(w.authority(a)?),
            None => None,
        },
        refs,
    };

    let tx = field(v, "tx")?;
    let optional = |u: &Value, name: &str| -> Res<Option<ObjectId>> {
        match u.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(o) => w.object(o).map(Some),
        }
    };
    let mut updates = Vec::new();
    for u in list(tx, "updates")? {
        let name = field(u, "ref")?
            .as_str()
            .ok_or_else(|| format!("bad ref in {u}"))?;
        // A transaction is judged, so the name within a namespace can be
        // anything. The model has only these namespaces.
        namespaced(name)?;
        updates.push(RefUpdate {
            name: name.to_string(),
            expected: optional(u, "expected")?,
            new: optional(u, "new")?,
            force: boolean(u, "force")?,
        });
    }
    let tx = Transaction {
        signer: key(int(tx, "signer")?).public(),
        updates,
        authority_update: match opt_int(tx, "authority")? {
            Some(a) => Some(w.authority(a)?),
            None => None,
        },
    };

    Ok(match admit(&w.src, &s0, &tx) {
        Ok(a) => json!({
            "admitted": {
                "commits": a.commits + a.foreign_commits,
                "releases": a.releases,
                "new_current": a.new_current.and_then(|id| w.authority_names.get(&id).copied()),
            }
        }),
        Err(r) => json!({
            "refused": match r.kind {
                Refused::Stale => "stale",
                Refused::NotFastForward => "not_fast_forward",
                Refused::Unauthorized => "unauthorized",
                Refused::Invalid => "invalid",
            },
            "reasons": r.reasons,
        }),
    })
}

/// Answer one request, with each transfer decided from the report of
/// `verify_history`.
#[allow(dead_code)]
pub fn answer(request: &Value) -> Res<Value> {
    answer_with(request, &mut ByTheReport)
}

/// Answer one request, with its transfers and its reads answered by
/// `replication`.
pub fn answer_with(request: &Value, replication: &mut dyn Replication) -> Res<Value> {
    let w = World::build(field(request, "store")?)?;
    let pin_number = int(request, "pin")?;
    let pin = w.authority(pin_number)?;
    let verified = match request.get("verify") {
        None | Some(Value::Null) => Value::Null,
        Some(v) => verify(&w, pin, v)?,
    };
    let mut decisions = Vec::new();
    for a in list(request, "admit")? {
        decisions.push(decide(&w, pin, a)?);
    }
    let mut transfers = Vec::new();
    match request.get("receive") {
        // Absent from requests saved before transfers were compared.
        None | Some(Value::Null) => {}
        Some(Value::Array(asked)) => {
            for t in asked {
                transfers.push(replication.transfer(&transfer(&w, t)?)?);
            }
        }
        // Anything else is a transfer that would go unanswered.
        Some(other) => return Err(format!("field `receive` is not a list: {other}")),
    }
    let mut answer = json!({ "verify": verified, "admit": decisions, "receive": transfers });
    match request.get("serve") {
        // Absent from requests saved before reads were compared, and from
        // every request that asks none.
        None | Some(Value::Null) => {}
        Some(Value::Array(asked)) => {
            // A repository is asked for by its id, and the id is derived
            // from a genesis: a pin that is not one names no repository.
            if !asked.is_empty() && !w.bodies[&pin_number].previous_authority.is_zero() {
                return Err(
                    "reads are asked of the repository the pin is the genesis of, and the pin \
                     is not a genesis"
                        .into(),
                );
            }
            let mut reads = Vec::new();
            for r in asked {
                reads.push(replication.read(&read(&w, pin_number, r)?)?);
            }
            // Answered all or not at all: by an instance, or by no one.
            if let Some(reads) = reads.into_iter().collect::<Option<Vec<Value>>>() {
                answer["serve"] = json!(reads);
            }
        }
        Some(other) => return Err(format!("field `serve` is not a list: {other}")),
    }
    Ok(answer)
}

/// A list of `{"commit": n}` and `{"release": n}`, as the set it is: in the
/// model's order, commits before releases and each by number, whatever
/// order it was written in.
fn objects(v: &Value, name: &str) -> Res<Value> {
    let mut set: BTreeSet<(u8, u64)> = BTreeSet::new();
    for o in list(v, name)? {
        match (opt_int(o, "commit")?, opt_int(o, "release")?) {
            (Some(n), None) => set.insert((0, n)),
            (None, Some(n)) => set.insert((1, n)),
            _ => return Err(format!("not an object in `{name}`: {o}")),
        };
    }
    Ok(Value::Array(
        set.iter().map(|(k, n)| named(*k, *n)).collect(),
    ))
}

/// A response with everything that is not compared taken out: the damage
/// list, the reasons, and the account of each problem.
///
/// What is left has to be a verdict. Something that is neither one outcome
/// nor the other is an error here, and never read as either: a response
/// compared loosely could agree with an expectation by being malformed.
#[allow(dead_code)]
pub fn compared(response: &Value) -> Res<Value> {
    let verified = match response.get("verify") {
        None | Some(Value::Null) => Value::Null,
        Some(v) => json!({
            "reached": objects(v, "reached")?,
            "invalid": objects(v, "invalid")?,
            "conflicting": objects(v, "conflicting")?,
            // Absent from responses saved before it was compared.
            "current_rejected": match v.get("current_rejected") {
                None | Some(Value::Null) => false,
                Some(_) => boolean(v, "current_rejected")?,
            },
        }),
    };
    let mut decisions = Vec::new();
    for d in list(response, "admit")? {
        decisions.push(match (d.get("admitted"), d.get("refused")) {
            (Some(a), None) => json!({
                "admitted": {
                    "commits": int(a, "commits")?,
                    "releases": int(a, "releases")?,
                    "new_current": opt_int(a, "new_current")?,
                }
            }),
            (None, Some(Value::String(kind)))
                if ["stale", "not_fast_forward", "unauthorized", "invalid"]
                    .contains(&kind.as_str()) =>
            {
                json!({ "refused": kind })
            }
            _ => return Err(format!("neither admitted nor refused: {d}")),
        });
    }
    let mut transfers = Vec::new();
    match response.get("receive") {
        // Absent from responses saved before transfers were compared.
        None | Some(Value::Null) => {}
        Some(Value::Array(ts)) => {
            for t in ts {
                transfers.push(match (t.get("recorded"), t.get("refused")) {
                    (Some(_), None) => json!({ "recorded": objects(t, "recorded")? }),
                    (None, Some(Value::Bool(true))) => json!({ "refused": true }),
                    _ => return Err(format!("neither recorded nor refused: {t}")),
                });
            }
        }
        Some(other) => return Err(format!("field `receive` is not a list: {other}")),
    }
    let mut compared = json!({ "verify": verified, "admit": decisions, "receive": transfers });
    match response.get("serve") {
        // Absent where no read was asked, and from an answer that had no
        // instance to ask.
        None | Some(Value::Null) => {}
        Some(Value::Array(rs)) => {
            let mut reads = Vec::new();
            for r in rs {
                reads.push(
                    match (r.get("recorded"), r.get("denied"), r.get("refused")) {
                        (Some(_), None, None) => json!({ "recorded": objects(r, "recorded")? }),
                        (None, Some(Value::Bool(true)), None) => json!({ "denied": true }),
                        (None, None, Some(Value::Bool(true))) => json!({ "refused": true }),
                        _ => return Err(format!("not recorded, denied or refused: {r}")),
                    },
                );
            }
            compared["serve"] = json!(reads);
        }
        Some(other) => return Err(format!("field `serve` is not a list: {other}")),
    }
    Ok(compared)
}

/// Damage the implementation reported. The harness never sends a damaged
/// store, so any at all is a fault in the scenario or in this file.
#[allow(dead_code)]
pub fn damage(response: &Value) -> Vec<String> {
    let listed = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|d| {
                d.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut damage = listed(&response["verify"]["damage"]);
    for part in ["receive", "serve"] {
        if let Some(answers) = response[part].as_array() {
            for a in answers {
                damage.extend(listed(&a["damage"]));
            }
        }
    }
    damage
}
