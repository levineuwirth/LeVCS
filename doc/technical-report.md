# LeVCS: A Technical Report

**Scope:** the v1 CLI and HTTP instance on main (package version 0.2.2).
**Audience:** engineers evaluating LeVCS for their own projects, or designing
the workflow tooling that will sit on top of it.

---

## TL;DR

- **LeVCS is a distributed version control system** in the same lineage as
  git, fossil, pijul, and sapling — content-addressed objects, signed
  history, three-way merge.
- **Five things are different by design:** identity is in the protocol,
  repositories have a stable identity across instances, merge rules can
  select format-aware handlers, hashes are BLAKE3, and signed releases
  form their own chain.
- **It is a substrate, not a workflow tool.** There is no PR review
  surface, no issue tracker, no CI integration, no web UI today. Those
  are the next layer up.
- **You can host an instance on a small VPS.** The protocol runs over
  HTTP, with signing at the application layer. For now an instance
  listens on loopback and is reached through an SSH tunnel; templates for
  a TLS reverse proxy are ready for when it gets a public route.

---

## 1. Why a new VCS?

Git is the dominant DVCS. It is also a tool that grew up in 2005 around
a hashing algorithm that had visible cracks (SHA-1) and a federation
model that was, fundamentally, "your remote is a URL string." Twenty
years on, the world git serves looks different:

- Identity is no longer optional. Many projects need to know not just
  *who claims to have authored a commit* but who is *authorized* to
  alter the repo's history.
- Replication is more complex than push/pull. Mirrors, archives,
  cold-storage replicas, and read-only forks are all common — and git
  treats them with the same primitives as the source-of-truth remote.
- Line-based merge can report a conflict when two authors add distinct
  keys to a structured file. Section 3.3 describes what LeVCS checks on
  such inputs.

LeVCS is an attempt at a clean restart that takes the DAG model and
content addressing as obvious wins, and rebuilds identity, federation,
merging, and hashing as **protocol-level concerns** rather than
conventions or sidecar tools.

---

## 2. The shape of the system

LeVCS is layered:

```
┌───────────────────────────────────────────────────────┐
│ Workflow tools (TBD: review, issues, web UI)          │
├───────────────────────────────────────────────────────┤
│ CLI: `levcs init / commit / push / merge / release`    │
├───────────────────────────────────────────────────────┤
│ Federation HTTP API (instances, refs, packs, pushes)   │
├───────────────────────────────────────────────────────┤
│ Object model: Blob / Tree / Commit / Release / Authority │
│ Merge engine: per-path handler, textual by default     │
│ Trust root: signed authority chain (Ed25519)            │
│ Content addressing: BLAKE3                              │
└───────────────────────────────────────────────────────┘
```

Five object kinds, all content-addressed by their BLAKE3 digest:

- **Blob** — raw file contents.
- **Tree** — `(name, type, mode, hash)` entries; sorted, no duplicates.
- **Commit** — tree + parents + authority + author key + message,
  signed.
- **Release** — first-class artifact: tree + predecessor commit + parent
  release + label + notes, signed by a maintainer or owner.
- **Authority** — the *membership document* for a repo: who has what
  role, signed and chained.

A repository is the set of these objects plus a `refs/` map (`branches/*`,
`releases/*`, `authority/{genesis,current}`) indexing into them. The
`repo_id` is the BLAKE3 digest of the encoded genesis authority body
with its `repo_id` field zeroed. At initialization the CLI prints both
this repository ID and the object ID of the signed genesis authority.
Use the repository ID for clone and for the HTTP repository path.

---

## 3. What's different from git

| Axis | git | LeVCS |
|---|---|---|
| Object hash | SHA-1 by default, SHA-256 in repositories initialized with that format | BLAKE3 |
| Identity | Author and committer fields, optional commit signatures | Signed commits and authority objects with explicit roles |
| Push authorization | Server-side hook or hosting platform | Protocol-level role check (Reader/Contributor/Maintainer/Owner) |
| Force-push rule | Server policy (off-protocol) | Protocol enforces maintainer-or-owner role |
| Federation | URL-bound remotes | Global `repo_id`; any instance can hold the repository |
| Mirror replication | `git clone --mirror`, then `git remote update` in the mirror | The instance refuses mirror configuration pending receive verification |
| Tags / releases | Lightweight tags or annotated tag objects with optional signatures | Signed release objects name the released commit and the preceding release |
| File merges | Built-in text merge or a custom driver selected by path | Textual by default, with opt-in format and tree-sitter handlers in the CLI |
| Merge evidence | The merge commit records parents and result tree | A CLI merge commit also covers a per-file decision record in the tree |
| Web UI / issues | Provided by hosting platform | Out of scope for v1 |

Git documents these options in its [clone](https://git-scm.com/docs/git-clone),
[tag](https://git-scm.com/docs/git-tag), and
[merge driver](https://git-scm.com/docs/gitattributes) references.

### 3.1 Identity in the protocol, not on top

Git commits carry author and committer fields and can also carry a
signature. A verifier checks that signature against a key. Hooks or
hosting rules decide who may update a ref.

LeVCS makes membership a first-class object. An **authority body** has:

```
schema_version  repo_id  previous_authority  version  created_micros
members:        [(public_key, handle, role, added_micros, added_by), ...]
policy:         [(key, value), ...]
```

Roles are a strict ordering: `Reader < Contributor < Maintainer < Owner`.
Every commit names the authority under which it was signed. A membership
change installs a successor authority signed by an Owner, with
`previous_authority` pointing to the prior one. On push, the instance
checks the request signer, the newly exposed history, and the requested
ref changes against its state before the transaction. A previously
published commit can remain valid after its author's key is revoked.

The practical consequence: "give Bob push access" is not a hosting-
platform toggle. It is a signed authority update that travels in the
repo and is auditable for the lifetime of the project.

### 3.2 Federation, not "remotes"

A git remote is a URL plus some credentials. There is no fact-of-the-
matter about whether two URLs refer to the *same* repository — git
checks by walking commits, but "same project" is by convention.

A LeVCS instance serves `/levcs/v1/repos/<repo_id>/...`. Clones of a
repository share its ID across instances. Before accepting history, a
clone verifies it against the genesis pinned by that ID. An instance
refuses to start as a mirror until its sync path performs the checks
required by [Rule R](authority-semantics.md#rule-r-replication).

On the v1 push endpoint, `full` accepts branch and release updates
subject to admission. `release` accepts only release ref updates and
stores the objects in an admitted pack. A normal release push follows
the released commit and its parents, so intermediate commits and their
file contents can be present on disk. `metadata` refuses pushes.
Exact release and metadata projections belong to the instance rewrite.

### 3.3 The merge cascade

When both sides edit a file, the first matching rule in
`.levcs/merge.toml` selects a handler. Unmatched paths use textual
three-way merge. A local override in `.levcs/merge.local.toml` can keep
that choice or select textual. If the selected handler is inapplicable
or returns `NotApplicable`, the engine tries textual directly. A
conflict reported by a handler remains a conflict. For divergent binary
edits the built-ins retain our bytes and report a conflict.

The CLI offers format-aware and tree-sitter handlers. For example, the
[TOML fixture](../crates/levcs-merge/tests/corpus/004-toml-disjoint-tables/manifest.toml)
selects the TOML handler and checks that both added table names survive.
Structural handlers are opt-in because a clean result can still drop or
reorder content. The October 2026 audit found that the textual handler
produced the expected output in all 3,226 constructed Markdown cases,
and the Markdown handler in 1,828. Inspect the result before committing.

The library API `CascadeEngine::with_config_and_plugins` lets a caller
supply WebAssembly modules by hash. The CLI loads built-ins only and
refuses a rule naming an unavailable handler. For a merge commit, the
CLI stores `.levcs/merge-record` in the signed tree. It records the
merge inputs (`base`, `ours`, and `theirs`) and per-file decisions,
including handler names. CLI-created records omit the optional
`handler_hash`, so the record does not identify the handler binary.

### 3.4 Hashing

Git chooses the object format when a repository is initialized. SHA-1
is the default. To create a SHA-256 repository on a build that supports
it, run [`git init --object-format=sha256`](https://git-scm.com/docs/git-init).

LeVCS uses BLAKE3 for 32-byte object IDs. Section 7 reports the
microbenchmark for serializing and hashing a blob.

### 3.5 Releases as objects

A lightweight Git tag names an object directly. An annotated tag names
a tag object carrying the target, tagger, date, and message. `git tag -s`
signs that object. In LeVCS the release signature covers these fields:

```
tree            commit's root tree
predecessor     commit being released
parent_release  prior release in the chain (or zero)
authority       authority hash at release time
declarer_key    public key of the signing maintainer/owner
timestamp       Unix micros
label           "v1.0.0" or similar
notes           release notes (UTF-8, up to 4 GiB)
```

Following `parent_release` gives the release history independent of
branch topology. The `predecessor` field links each release back to its
commit.

---

## 4. How you use it

### 4.1 Bootstrap

```sh
levcs key generate primary
levcs init --key primary
levcs track --all
levcs commit -m "initial import"
```

After `init`, `.levcs/` exists alongside your tree. The genesis authority
names your key as the sole Owner; the `repo_id` is fixed forever. After
`commit`, you have one commit on `refs/branches/main`. In a git checkout,
put `/.git` in `.levcsignore` before `track --all`: levcs does not skip
git's store on its own.

### 4.2 Branch and merge

Creating a branch and switching to it are separate commands, so a commit
cannot land on a branch you only meant to make:

```sh
levcs branch --create feature/x
levcs branch --switch feature/x
# ... edit files ...
levcs commit -m "wip on x"
levcs branch --switch main
levcs merge feature/x
```

If the merge produces conflicts, step through them in the resolution TUI:

```sh
levcs merge --review
```

The TUI shows each file of the merge in progress with the ours, base and
theirs versions and the handler that merged it, and writes the version
you choose for each into the working tree. A conflict is then resolved
by naming it: `levcs track <path>` once the file is edited, or `levcs
forget --delete <path>` to resolve it by deletion. `levcs commit` then
records the merge, with its `.levcs/merge-record` in the signed tree, and
`levcs merge --abort` abandons it.

### 4.3 Release

```sh
levcs release v1.0.0 -m "first release"
```

Writes a Release object with the current commit as `predecessor`, signs
it with your key (named with `--key` when the keychain holds several),
and adds `refs/releases/v1.0.0`. The declarer must be a maintainer or
owner. If you've cut prior releases, `parent_release` chains to the most
recent one automatically.

### 4.4 Federation

```sh
levcs instance --set http://127.0.0.1:7117/levcs/v1   # through an SSH tunnel
levcs push --dry-run
levcs push
```

The dry run reads the remote refs and limits, then reports the size
without submitting the push. Read the report even on exit status zero.
For the first actual push, the instance creates the repository from
genesis if your key is both a genesis owner and listed in the instance's
`creators`. Every push is checked against the repository's current
authority (Rule P). Reads are open to anyone by
default: the `public_read` policy of the *current* authority, which
`init` sets. When it is false, only members can read, in requests signed
with `--key`, though no command sets it false yet.

Another machine gets the repository with `levcs clone <repo_id> --from
<url>`, and later work with `levcs pull`, which records the instance's
branches under `refs/remote/origin/`. Both check everything they receive
against the genesis the `repo_id` pins before writing any of it.

To copy a repository to a fresh instance, use a genesis owner key
listed in the destination's `creators`. A repository still under its
genesis authority is the simplest case.

```sh
levcs migrate https://new-host.example.com/levcs/v1 --set-active
```

`migrate` initializes the destination with the original signed genesis,
then sends all local branch and release tips and their reachable objects
in one push. Each destination ref must be absent. The push is subject to
the destination's limits and publication policy. A transaction may
install a direct successor to the current authority, but work signed
under that successor needs a later publication. A history containing
both cannot be replayed this way onto a fresh instance.

Initialization can succeed even when the push is refused. After a
failure or a lost response, compare the destination refs with the local
tips before retrying. For a public destination, `levcs inspect <repo_id>
--from <url>` lists its branches and releases. Supply the 64 lowercase hex
digits as the ID. On retry the CLI treats
an init conflict as “already exists” and proceeds to push. Any existing
target ref makes that push stale, even at the intended tip. The source
keeps its history. `--set-active` changes the local instance URL only
after the destination acknowledges the push.

### 4.5 Several writers, scripts, and uncommitted work

The README covers each of these in full; in brief:

- **Revisions.** Commands that take a commit accept `HEAD~2`, `main^2`
  and unique hex prefixes as well as full ids. `levcs show <rev>:<path>`
  prints a file as it was, and writes nothing.
- **Scoped commits.** `levcs commit -m ... <paths>` commits only the
  named paths. Writers sharing one file commit their own version of it
  with `--content PATH=FILE`, and `--expect-head <id>` refuses the commit,
  with exit status 5, if another landed since the version was built.
  Every command that changes the repository holds a lock on it, so
  concurrent commands queue rather than race.
- **Uncommitted work.** Switching branches, merging, `construct`, `cache
  --restore` and `forget --delete` refuse to overwrite or delete work that
  is not committed, and name each file. The last three take `--force`.
- **For tools.** `status`, `diff` and `merge` take `--format json`.
- **Checking.** `levcs verify` checks every object any ref reaches and
  the authority rules over all history. It exits 1 if anything is
  invalid, and 4 if history is valid but on an authority lineage that
  conflicts with this repository's.

---

## 5. Operating an instance

A single binary, `levcs-instance`, reads a TOML config and listens on
HTTP. The first deployment binds it to localhost and reaches it through
an SSH tunnel; the Caddy and nginx templates put TLS in front of it for
when it gets a public route. It creates a repository only for a genesis
owner listed in `creators`. For the gate, systemd unit, backups, restores,
updates, and laptop setup, see the [deployment guide](../deploy/README.md).

The protocol surface is small:

```
GET  /health
GET  /levcs/v1/instance/info
GET  /levcs/v1/instance/peers
GET  /levcs/v1/repos/<repo_id>/info
GET  /levcs/v1/repos/<repo_id>/refs
GET  /levcs/v1/repos/<repo_id>/objects/<hash>
GET  /levcs/v1/repos/<repo_id>/pack?have=...&want=...
POST /levcs/v1/repos/<repo_id>/init
POST /levcs/v1/repos/<repo_id>/push
```

The health and instance information routes are public. Repository GETs
require a member's signature when `public_read` is false. Both POSTs
require a signed request. The signer sends its public key as
`LeVCS-Key: ed25519:<64 hex digits>`, the timestamp in Unix microseconds,
a base64 nonce, and the Ed25519 signature in base64 with the `ed25519:`
prefix. The [v1 authentication module](../crates/levcs-protocol/src/auth.rs)
specifies the canonical request bytes.

Storage is a directory tree. Per-object atomic writes via temp-then-
rename, per-repo serializing mutex on push, and a journal that rolls
back a push interrupted between its ref writes. A copy taken while the
instance runs can hold a ref without the objects it names, so back up
with the service stopped, using `levcs-backup`, and restore with
`levcs-restore`, which checks every repository in the archive before
replacing anything (`deploy/README.md`, "Backups").

---

## 6. What LeVCS isn't (yet)

The honest list of things you'd want for a full project home that LeVCS
does not provide:

- **Code review.** The instance has no PR object, review threads, or comments.
- **Issue tracking.** Same — protocol substrate doesn't cover it.
- **CI integration.** No webhooks. CI systems would need to poll `/refs`
  on a cadence, which is fine but not turnkey.
- **Web UI.** No branch browser, no diff view, no blame. These can be
  built atop the existing GET endpoints; nothing in the protocol is
  hostile to a UI, but none ship.
- **Search.** No `git grep` equivalent on the server side. Local-only.
- **Submodules / monorepo tooling.** No analog yet.

If your use case requires any of the above today, run LeVCS *parallel*
to your existing platform. Forgejo, GitHub, Gitea continue to host the
workflow; the LeVCS instance holds a copy you commit and push to
alongside it, as `deploy/README.md` ("Publishing later work") does for
LeVCS's own source. That procedure copies source snapshots and keeps the
two histories by hand.

---

## 7. What is true today (and how we know)

The repository includes tests for the following paths:

- Object encoding, signatures, and protocol messages.
- The [authority model](../authority-spec/README.md) compares generated
  scenarios with the Rust history verifier, admission function, CLI
  receiver, and instance read path. Publication through the HTTP and CLI
  callers has separate integration tests.
- The [14-scenario merge corpus](../crates/levcs-merge/tests/corpus/README.md)
  checks the selected handler against each fixture's expectations. Stock
  Git 2.56.1 reported conflicts on the seven fixtures labeled
  `git_false_conflict`. It merged case 014 cleanly, preserving both edits.
- Property tests on the pack codec and object parsers (fuzz + structured
  proptest round-trip).
- The three-instance federation test pushes commits and a release under
  one authority. It drives mirror sync directly, initializes the peer
  with the client library, and pushes the commit history and release in
  separate requests. It checks the peer's refs and compares the bytes of
  the head commit across all three instances. The CLI's single-push
  `migrate` procedure is described in §4.4.
- The deployment gate, `levcs-gate`, which CI runs on the binaries it
  builds: it drives a real instance through pushes, clones, refusals,
  a crash, and a backup and restore.

A baseline microbenchmark suite is checked in (`scripts/bench.sh`). On
a Ryzen 7 laptop:

- Pack decode of a 10 × 1 MiB pack: ~2.3 ms (4.3 GiB/s).
- BLAKE3+serialize on 1 MiB blobs: ~190 µs (5.1 GiB/s).
- Textual three-way merge of a 100 KiB document: ~4.6 ms (~80 MiB/s).
- Encode is the bottleneck — zstd level 3 at ~380 MiB/s on
  incompressible data.

Run the same microbenchmarks on your machine with `scripts/bench.sh --quick`.

---

## 8. Where the project goes next

The [approved rewrite plan](instance-throughput-rewrite-plan.md#12-implementation-phases-and-subagent-execution)
places the instance rewrite ahead of review tools, CI hooks, and a web
UI. The running v1 server still uses the loose-object store. The Phase 1
`levcs-store` library sequences already validated transactions, recovers
its journal, and exposes snapshots, operation status, and checkpoints.
Its [exit criteria](phase1-storage-spine-scope.md#7-phase-1-exit-criteria-and-evidence)
require recovery evidence and a storage benchmark on reference hardware.

Phase 2 covers protocol validation, admission, migration fixtures, and
the instance harness. Phase 3 connects the store to the server, client,
and CLI after those prerequisites pass. Phase 4 covers federation,
backup, and cutover. Phase 5 calls for end-to-end release measurements.
Workflow tools are intended to consume logical snapshots and signed
events from the integrated service. The endpoints available today are
listed in §5.

---

## 9. Trying it

Build:

```sh
git clone <this repo>
cargo build --release
sudo install -m 0755 target/release/levcs target/release/levcs-instance /usr/local/bin/
```

Local single-machine tour:

```sh
levcs key generate me
levcs init --key me /tmp/demo
cd /tmp/demo
echo "hello" > a.txt
levcs track --all
levcs commit -m "first"
levcs log
```

Self-host: see `deploy/README.md`.

Read the spec: `spec/levcs-spec.pdf` (kept private until the workflow
spec lands; ask the maintainer for a copy).

Read the code: every crate is small and documented. `crates/levcs-core`
is the object model, `crates/levcs-merge` is the cascade,
`crates/levcs-instance` is the server, `crates/levcs-cli` is the user-
facing tool.

---

*Comments and corrections welcome to the maintainer.*
