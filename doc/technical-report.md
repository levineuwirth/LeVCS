# LeVCS: A Technical Report

**Status:** v0.1.0 — protocol substrate complete, workflow surface deferred.
**Audience:** engineers evaluating LeVCS for their own projects, or designing
the workflow tooling that will sit on top of it.

---

## TL;DR

- **LeVCS is a distributed version control system** in the same lineage as
  git, fossil, pijul, and sapling — content-addressed objects, signed
  history, three-way merge.
- **Five things are different by design:** identity is in the protocol,
  federation is a first-class concept, the merge engine is a cascading
  pipeline of format-aware handlers, hashes are BLAKE3, and releases are
  signed objects rather than ad-hoc tags.
- **It is a substrate, not a workflow tool.** There is no PR review
  surface, no issue tracker, no CI integration, no web UI today. Those
  are the next layer up.
- **You can host an instance on a small VPS** behind nginx or Caddy. The
  protocol terminates over HTTP; signing is at the application layer.
- **The codebase is small** (~10 crates) and runs `cargo test` in under a
  minute on a laptop. 194 tests pass at v0.1.0; baseline benchmarks are
  in the repo.

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
- Merge conflicts are still mostly resolved at the line level. JSON,
  YAML, TOML, source code with semantic structure — the line-diff
  treatment is wrong for all of these and produces false conflicts on
  reformats every team has hit.
- SHA-1 is broken; git's SHA-256 transition has been "in progress" for
  most of a decade.

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
│ Federation HTTP API (instances, mirrors, releases)     │
├───────────────────────────────────────────────────────┤
│ Object model: Blob / Tree / Commit / Release / Authority │
│ Merge engine: textual → format-aware → tree-sitter     │
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
`repo_id` is the BLAKE3 of the genesis authority — globally unique by
construction, no central registrar needed.

---

## 3. What's different from git

| Axis | git | LeVCS |
|---|---|---|
| Hash | SHA-1 (deprecated, transitioning) | BLAKE3 |
| Identity | Author string in commit | Signed authority object with explicit roles |
| Push authorization | Server-side hook or hosting platform | Protocol-level role check (Reader/Contributor/Maintainer/Owner) |
| Force-push rule | Server policy (off-protocol) | Protocol enforces maintainer-or-owner role |
| Federation | URL-bound remotes | Global `repo_id` + replicating instances |
| Mirror replication | `git fetch --mirror` (best-effort) | First-class with three storage modes |
| Tags / releases | Mutable string refs (often) | Signed objects with predecessor + parent_release chain |
| Merge granularity | Line-level (myers / patience) | Cascade: textual → format → tree-sitter → plugin |
| Merge audit | No artifact | `.levcs/merge-record` TOML, signed with the commit |
| Web UI / issues | Provided by hosting platform | Out of scope for v1 |

The rest of this section unpacks each axis.

### 3.1 Identity in the protocol, not on top

Git stores `Author: Name <email>` and `Committer: Name <email>` strings
in commits. There is nothing cryptographic about either. Signed commits
are an opt-in (`gpg-sign`, since 2014, and `ssh-sign`, since 2021), but
even when signed they answer "did *some* key sign this?" — not "is the
signer authorized to write to this repo right now?"

LeVCS makes membership a first-class object. An **authority body** has:

```
schema_version  repo_id  previous_authority  version  created_micros
members:        [(public_key, handle, role, added_micros, added_by), ...]
policy:         [(key, value), ...]
```

Roles are a strict ordering: `Reader < Contributor < Maintainer < Owner`.
Every commit references the authority hash that was current when it was
signed. Updating membership is a versioned operation: you write a new
authority object, signed by an Owner, with `previous_authority` pointing
at the prior one. The instance walks the chain on push and rejects any
push whose author key isn't a current member.

The practical consequence: "give Bob push access" is not a hosting-
platform toggle. It is a signed authority update that travels in the
repo and is auditable for the lifetime of the project.

### 3.2 Federation, not "remotes"

A git remote is a URL plus some credentials. There is no fact-of-the-
matter about whether two URLs refer to the *same* repository — git
checks by walking commits, but "same project" is by convention.

LeVCS has a **global repo_id**. It is the BLAKE3 of the genesis
authority object, so two clones of the same project have the same
`repo_id` even if they live on instances on opposite continents. An
instance is a federation peer: it serves `/levcs/v1/repos/<repo_id>/...`
endpoints and replicates state from other instances when configured to.
Mirroring is the protocol's normal mode, not a `git fetch --mirror` cron
job.

This composes with three **storage modes** (§4.3 of the spec):

- **Full** — every reachable object. The source-of-truth instance.
- **Release** — only release objects, their reachable trees and blobs,
  and the authority chain. Skips inter-release commits. For
  long-lived archive replicas.
- **Metadata** — authority objects, release headers, signed refs only.
  No content. For "is this project still alive?" pings.

The instance enforces these on push: a release-mode replica refuses
pushes that update branches; a metadata-mode replica refuses all
pushes (it's populated by mirroring).

### 3.3 The merge cascade

This is the technical centerpiece.

A traditional three-way merge — git, mercurial, fossil — works at the
line level. It is correct for prose and acceptable for code, but it
generates false conflicts on:

- Reformats (linters, prettifiers, whitespace-policy bumps).
- Key reorderings in JSON / YAML / TOML.
- Imports lists in source files that two branches both edited.
- Markdown files where two contributors modified disjoint sections of
  the same paragraph.

LeVCS dispatches per-file to a **handler cascade** ranked by aggressiveness:

```
rank 0  textual           universal line-level fallback
rank 1  format-aware      json | yaml | toml | xml | markdown | prose
rank 2  tree-sitter       rust | python | js | ts | go | c | cpp |
                          java | ruby | bash
rank 3  plugin            wasm-sandboxed, user-supplied
```

A repo's `.levcs/merge.toml` maps glob patterns to handlers. Per-user
`.levcs/merge.local.toml` can **demote** but never promote, so a
distrusted plugin can be locally turned off without a repo edit. Each
merged file produces a `FileRecord` in `.levcs/merge-record` listing the
handler used and its hash; the merge-record blob is committed alongside
the resolved tree, so every merge in history is auditable.

Format-aware example: `package.json` where Alice adds a dependency at
the top of `dependencies` and Bob adds one at the bottom. Git produces a
conflict because the lines are adjacent. The JSON handler parses both
sides, computes the structural diff, and merges them — both new entries
appear in the output, no conflict.

Tree-sitter example: two contributors add unrelated `use` statements to
a Rust file. Line diff conflicts. Tree-sitter handler treats the
`use_declaration` list as an ordered set, merges both additions, no
conflict.

The cascade is fail-safe: a tree-sitter handler that bails on a syntax
error falls through to the format-aware handler if applicable, then to
textual. The textual handler always merges — it might produce
conflicts, but it never fails to produce *some* output.

### 3.4 Hashing

Git uses SHA-1. SHAttered (2017) was a practical collision. The
SHA-256 transition is still incomplete in 2026 and is unlikely to ever
finish for the long tail of git infrastructure.

LeVCS uses BLAKE3 from day one. Faster than SHA-256 in practice (the
benchmarks in `bench-results/` show ~5 GiB/s on a laptop for blob
serialize+hash), tree-hashed, no commitment to a specific length-tag
convention. Object IDs are 32 bytes everywhere.

### 3.5 Releases as objects

Git tags are refs that point to commits — or to tag objects, if you
remember to use `-a`. Either way, they are *names*, not artifacts. A
release in LeVCS is a signed object:

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

The chain `parent_release → parent_release → ...` gives you a clean
release history independent of branch topology. The replica modes
above can replicate just releases (and their trees and authority) for
archive instances that don't need the inter-release commit history.

---

## 4. How you use it

### 4.1 Bootstrap

```sh
levcs key generate --label primary
levcs init --key primary
levcs track --all
levcs commit -m "initial import"
```

After `init`, `.levcs/` exists alongside your tree. The genesis authority
names your key as the sole Owner; the `repo_id` is fixed forever. After
`commit`, you have one commit on `refs/branches/main`.

### 4.2 Branch and merge

```sh
levcs branch feature/x
# ... edit files ...
levcs commit -m "wip on x"
levcs branch main          # switch back
levcs merge feature/x
```

If the merge produces conflicts, drop into the resolution TUI:

```sh
levcs merge --resolve
```

The TUI shows each conflicted file with the ours/base/theirs panes the
handler emitted, plus the cascade decision (which handler ran, why it
fell through if it did). On accept, it writes the resolved file and a
signed `.levcs/merge-record` entry.

### 4.3 Release

```sh
levcs release v1.0.0 --notes "first release"
```

Writes a Release object with the current commit as `predecessor`, signs
it with your active key, and adds `refs/releases/v1.0.0`. If you've cut
prior releases, `parent_release` chains to the most recent one
automatically.

### 4.4 Federation

```sh
levcs instance --set https://levcs.example.com/levcs/v1
levcs push refs/branches/main
```

The first push to a fresh instance auto-inits the repo using your
genesis authority. Subsequent pushes are role-checked. Pulls are
public-read by default (the `public_read` policy bit on the genesis
authority).

To migrate to a new home:

```sh
levcs migrate https://new-host.example.com/levcs/v1 --set-active
```

`migrate` re-inits and replays the full history at the destination, then
points your local repo at it. The `repo_id` is unchanged — it's the
same project at a new location.

---

## 5. Operating an instance

A single binary, `levcs-instance`, reads a TOML config and listens on
HTTP. Production deployments terminate TLS at a reverse proxy; the
instance binds to localhost. See `deploy/README.md` for a full
walkthrough — systemd unit, Caddy and nginx examples, firewall, and the
laptop-side bootstrap.

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

That's it. No admin endpoints, no users-and-passwords table, no web UI
to firewall. POSTs require a signed `LeVCS-Signature` header
(Ed25519-over-canonical-request, with timestamp and nonce for replay
protection). GETs are public unless the genesis authority's policy
turned that off.

Storage is a directory tree. Per-object atomic writes via temp-then-
rename, per-repo serializing mutex on push. A consistent backup is just
a snapshot of `/var/lib/levcs`.

---

## 6. What LeVCS isn't (yet)

The honest list of things you'd want for a full project home that LeVCS
does not provide:

- **Code review.** No PR object, no review threads, no comments. The
  workflow spec coming next defines these.
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
workflow; the LeVCS instance acts as a dogfood replica that gets the
same commits via a `push-both` wrapper. When the workflow surface
lands, the migration story flips.

---

## 7. What is true today (and how we know)

The repo at v0.1.0 has 194 passing tests covering:

- The full §2-§7 object model and protocol surface.
- A 14-scenario merge conformance corpus, eight of which are git-
  false-conflict cases the cascade resolves cleanly.
- Property tests on the pack codec and object parsers (fuzz + structured
  proptest round-trip).
- An end-to-end "dogfood" integration test that stands up three
  instances (source-of-truth, peer, mirror), pushes a chain of commits
  plus a release, replicates via mirror sync, migrates to the peer,
  and asserts byte-for-byte object equality across all three.

A baseline microbenchmark suite is checked in (`scripts/bench.sh`). On
a Ryzen 7 laptop:

- Pack decode of a 10 × 1 MiB pack: ~2.3 ms (4.3 GiB/s).
- BLAKE3+serialize on 1 MiB blobs: ~190 µs (5.1 GiB/s).
- Textual three-way merge of a 100 KiB document: ~4.6 ms (~80 MiB/s).
- Encode is the bottleneck — zstd level 3 at ~380 MiB/s on
  incompressible data.

Numbers are reproducible via `scripts/bench.sh --quick`.

---

## 8. Where the project goes next

The immediate roadmap, in order:

1. **Workflow spec** — the missing layer above. PR/review object,
   discussion threads, CI hook conventions, web UI design. This is the
   document the rest of v1 builds toward.
2. **Reference workflow tools** — a minimal web UI that reads the
   federation API and lets you browse, review, and merge. Probably a
   separate repo and process, not bundled into the instance.
3. **CI conventions** — a published webhook protocol so existing CI
   systems can integrate without polling.
4. **Plugin handler examples** — a few real wasm handlers (e.g.
   protobuf, SQL migrations) to validate the plugin protocol.
5. **Git import** — a one-way import path so existing projects can
   adopt LeVCS without hand-replaying history.

If you're reading this because you might write that workflow spec: the
substrate guarantees you have are
(a) signed objects with a verifiable authority chain,
(b) per-file merge records that travel with each commit,
(c) a content-addressed object store that doesn't care what kind of
content it stores, and
(d) federation as a normal operating mode rather than a special case.
Workflow surface is free to use these as building blocks — a "PR" is
just an object kind we don't have yet, an "issue" is another, and the
storage modes already define how a CI system would replicate the
metadata it needs without pulling source.

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
levcs key generate --label me
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

*Comments and corrections welcome to the maintainer. The next document
in this series is the workflow spec.*
