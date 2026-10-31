# LeVCS

A distributed version control system with first-class federation, signed
authority chains, and a cascading merge engine. Content-addressed by
BLAKE3, signed with Ed25519, and built to fix what git can't.

> **Status: v0.1.0 — protocol substrate complete, workflow surface deferred.**
> The object model, federation API, merge cascade, and instance server
> all work end-to-end. There is no PR review surface, issue tracker, or
> web UI yet — those are the next layer up. See
> [`doc/technical-report.md`](doc/technical-report.md) for a full
> framing of where this project is and why.

---

## What's different from git

- **Identity is in the protocol.** A repo's membership is a versioned,
  signed authority object with explicit roles
  (Reader/Contributor/Maintainer/Owner). Force-push enforcement and
  push authorization are protocol-level, not server policy.
- **Federation is first-class.** Every repo has a global `repo_id`
  (BLAKE3 of its genesis authority); instances mirror each other in
  three storage modes (full / release-only / metadata-only).
- **Merge is configurable per file.** By default every file merges with a
  line-level three-way diff. A repository's `.levcs/merge.toml` can opt
  paths into format-aware handlers (JSON / YAML / TOML / XML / Markdown /
  prose), tree-sitter handlers for source code (Rust, Python, JS/TS, Go,
  C/C++, Java, Ruby, Bash), or wasm-sandboxed plugins. The structural
  handlers are opt-in because they can lose, invent or reorder content
  while reporting a clean merge; they stay that way until a validator can
  confirm their output.
- **BLAKE3, not SHA-1.** Tree-hashed, ~5 GiB/s on a laptop, 32-byte
  IDs everywhere.
- **Releases are signed objects**, not mutable name pointers.

For a deeper comparison and context, see the
[technical report](doc/technical-report.md).

---

## Building

LeVCS is a Rust workspace. You'll need a recent stable toolchain
(workspace MSRV is 1.90: 1.89 for `std::fs::File::lock`, and 1.90 for the
tree-sitter grammars' runtime) and a C compiler for the grammars.

```sh
cargo build --release
```

Two binaries land in `target/release/`:

- `levcs` — the user-facing CLI.
- `levcs-instance` — the federation HTTP server.

Install them somewhere on `PATH`:

```sh
sudo install -m 0755 \
    target/release/levcs target/release/levcs-instance \
    /usr/local/bin/
```

---

## Quick start (single user, local only)

```sh
# Generate an identity key (stored in $XDG_CONFIG_HOME/levcs/keys.toml).
# Pass --encrypt if the key should not sit in plaintext.
levcs key generate me

# Create a repository wherever you have files to track.
mkdir /tmp/demo && cd /tmp/demo
echo "hello" > a.txt

levcs init --key me
levcs track --all
levcs commit -m "first commit"
levcs log
```

That's a fully working LeVCS repo.

With one key in the keychain, commands sign with it, whatever its role, and
`init` with an empty keychain creates a key called `personal`. With several
keys, as when an owner and an agent share a machine, levcs never picks one: a
signing command, `init` included, must name its key with `--key`. A
membership change (`levcs authority add`, `remove` or `promote`) must name an
owner's key with `--signing-key` even when only one key exists. A signature
records whose hand made a change; that record is worthless if a tool can pick
the hand.

Naming the key prevents accidents, not misuse. A process that can read the
keychain can still name the owner's key, so keeping an owner's key from agents
means keeping it where they cannot reach it.

A commit can be scoped to paths, which is how you commit one piece of work out
of a tree that holds several:

```sh
levcs commit -m "just the notes" notes/ README.md
```

Everything outside the named paths keeps the content it has in HEAD and stays
uncommitted — including deletions, which are not read as "drop it from the
tree" when the commit was never about that file. A path naming a directory
takes everything tracked beneath it; a path matching nothing tracked is
refused rather than silently committing nothing. `levcs diff <paths>` uses the
same rule, so it is an exact preview of what `levcs commit <paths>` will take.

Path arguments are relative to **the current directory**, and every command
that takes them refuses one that matches nothing. Those two go together: a
name can then only ever miss, and a miss is reported. Output stays
repository-relative, so `commit`'s `scoped to` line doubles as confirmation of
what your argument resolved to.

This matters more than convenience when a repository is written by more than
one hand. Attribution is the entire point of signing a commit, and a commit
that had to sweep up someone else's unfinished edits in order to exist
attributes their work to whoever signed it.

Several processes can work in one repository at once. Every command that
changes the index, a ref, or the working tree holds an exclusive lock on
`.levcs/repo.lock` for its whole run, and waits, saying so, if another holds it. A
commit only moves its branch from the parent it was built on. Before this,
two commits started together could both print an id while only one landed.
The lock orders repository changes; it cannot say who wrote which lines of a
file that several sessions edit at once, so scope each commit to the files its
author wrote.

When writers do share a file, such as an append-only log, a writer commits its
own version of it instead of the working tree's:

```sh
head=$(levcs status --format json | jq -r .head)
{ levcs show "${head}:log.md"; cat my-lines; } > /tmp/mine
levcs commit --expect-head "$head" --content log.md=/tmp/mine -m "my entries"
```

`--content PATH=FILE` commits FILE's bytes as PATH, a tracked file, and leaves
the working tree's PATH as it is. Other writers' lines stay uncommitted there,
for them to commit under their own keys. `--expect-head` refuses the commit,
under the repository lock, unless HEAD is still the commit the version was
built from. Without it, a commit that landed in between would be undone. A
refusal commits nothing and exits with status 5, so a caller can rebuild its
version from the new HEAD and try again. An id that is not a commit here, such
as a release or a mistyped hash, exits with status 1, since trying again
would not change it.

`levcs verify` checks everything the repository keeps, not just HEAD.
Every object reachable from any ref is hash-checked, and every commit and
release is checked against the authority rules in
[`doc/authority-semantics.md`](doc/authority-semantics.md), with the
repository's genesis pinned. It says what it covered. It exits 1 if
anything is invalid, and 4 if history is valid but cites an authority
lineage that conflicts with this repository's, which means two copies
disagree rather than that something is damaged. `levcs gc` keeps exactly
what that walk reaches, from the same roots, including a merge in progress.
It refuses to delete anything while any reachable object or ref is
damaged: unreadable, malformed, or not the type its link requires.

Commands that write the working tree (`branch --switch`, `merge`, `merge
--abort`, `merge --review`, `construct`, `forget --delete`, `cache --restore`,
`fork` and `dial`) write only inside it. Each walks a path one directory at a
time without following symlinks, and replaces a file by renaming a new one
over it, so neither a symlinked directory nor a symlinked or hard-linked file
can carry a write outside the repository. A tree is checked whole before
anything is written: every name, every blob against its hash, and no `.levcs`
below the top level. A tree's own top-level `.levcs` entry is history and is
never written over the repository's metadata. A refused switch or
fast-forward leaves HEAD, the branch and the index where they were. This
rests on Unix's directory-relative system calls; on other platforms levcs
refuses to write a working tree at all, rather than write one less safely.

Work that is not committed is never overwritten. A branch switch, a
fast-forward and a merge plan the whole move before writing anything. Each
refuses if the move would overwrite or remove:
- a staged change;
- an edit to a file the target changes or lacks;
- an untracked file or a link where the target has a file.
A switch carries over edits to files both branches have alike, and removes
the committed files the target lacks. The refusal names each path and why
it is not committed.

`construct` refuses in the same way. A file is safe to write if it is
missing, holds what HEAD has, or already holds the revision's version.
Anything else is work only the working tree holds: an edit, a staged
version, a change to the executable bit, an untracked file, or a link. The
refusal names each such path, whether it was named or is part of a
whole-tree construct, and nothing is written. `--force` overwrites them
and lists what it overwrote. This includes going back to HEAD after
constructing an older version: that version is in history, but it is not
HEAD's, and `status` reports the file as modified too.

`cache --restore <id>` refuses in the same way, and `--force` overwrites. A
file already as the cache has it loses nothing. `forget --delete` deletes
only a file that is missing or holds what HEAD has, which `construct` brings
back. It refuses any other, a tracked file never committed included, and
untracks nothing. `--force` deletes them. A conflicted file is exempt, since
deleting it is how a conflict is resolved by deletion.

`status` lists the same work. First comes what the index holds that HEAD
does not: new files, staged changes, and files no longer tracked. Then come
edits and deletions since a file was last tracked or committed. A staged
path stays refused until it is committed, or put back with
`levcs construct --force HEAD <path>` and staged as committed with
`levcs track <path>`.

Symlinks are never followed and never recorded. A link committed as its
target's bytes put another file, possibly from outside the repository, into
history; Fossil turned its symlink support off by default for the same
reason.
- `track` refuses a named link, and a path reached through one.
- `track` passes over links in a directory or with `--all`, and says so.
- `commit` refuses a tracked file that has become a link.
- `status` lists links on their own.
- `cache --save` skips them.

Publishing follows Rule P of
[`doc/authority-semantics.md`](doc/authority-semantics.md). Without an
instance, every command that moves a branch, release or authority ref
publishes: `commit` on a branch, `merge`, `branch --create` and `--delete`,
`release`, `authority add`, `remove` and `promote`, and `fork`. With an
instance, the instance checks each push.
- **Against what.** Each publication is checked against the state before
  it: the current authority, and the history the branches and releases
  already reach. Being present in the store, or under `refs/remote/`, does
  not count as published.
- **Exact authority.** Everything the change would newly publish must cite
  the current authority exactly and be signed by a member of it.
- **Authority changes.** An authority change publishes one commit that
  installs a direct successor, and `current` moves with it. Work under the
  new authority follows in a later publication.
- **Roles.** A protected branch needs a Maintainer. So does a rewrite of
  published history, which must also be forced. Deleting a branch whose
  commits nothing else reaches counts as one (`branch --delete --force`).
- **Not yet publishable:**
  - Work made under an older authority, until adoption (D1) has a defined
    record format.
  - A repository received by `dial`, until an owner's bootstrap statement
    exists (D6). Until then it keeps the received history under
    `refs/remote/` and has no current authority.
- **Interrupted publications.** A publication's ref changes land together
  or not at all. They are recorded in `.levcs/ref-transaction/` before any
  ref moves. One stopped part way, by an error or by the process being
  killed, is rolled back before anything else reads the refs to publish,
  or before `verify` vouches for them.
- **Keys.** Commands that publish take `--key` when the keychain holds
  several keys.
- **Workspaces.** A repository whose own `.levcs/config` names an instance
  is that instance's workspace. Its refs move freely, and the instance
  applies the rules when the work is pushed. Becoming a workspace is
  recorded in `.levcs/workspace`. A workspace's refs moved without
  admission, so they never become published history: if its config stops
  naming the instance, or cannot be read, nothing publishes.

A commit is published once its branch moves. If a step after that fails, such
as rewriting the index or clearing merge state, `commit` still prints the id,
says what did not finish, and exits with status 3. The commit stands, and
committing again will not repeat it. A missing `.levcs/index` is read as HEAD
with nothing staged, never as an empty tree.

`forget` stops tracking a file and leaves it on disk:

```sh
levcs forget build/output.bin          # untrack, keep the file
levcs forget --delete build/output.bin # untrack and remove it
```

This is a deliberate divergence from `git rm`. The verb only ever acts on
paths that are already tracked — an untracked path is refused, and a directory
expands to the tracked files beneath it. Nothing is deleted by default.
`--delete` deletes a file only if it holds what HEAD has, so whatever it
deletes comes back with `levcs construct`. A file holding an edit, or tracked
but never committed, is refused unless `--force`. Being tracked was once taken
to be enough, but a tracked file's edit has no blob until it is committed.

Commands that take a commit (`diff`, `construct`, `show`, `merge`,
`branch --create`) accept a revision, not just a full hash:

```sh
levcs diff HEAD~1            # against the previous commit
levcs construct HEAD~3 a.txt # a.txt as it was three commits ago, written back
levcs show HEAD~3:a.txt      # a.txt as it was three commits ago, printed
levcs diff 3fa9c1            # a unique hex prefix (4+ characters)
levcs merge main^2           # the second parent of main's tip
```

The base is `HEAD`, a branch, a full hash, or a hex prefix of a commit or
release. `~N` follows the first parent N times (`~` alone is `~1`); `^N` takes
the Nth parent, counting from 1, which is how you reach the other side of a
merge (`^0` is the commit itself). Suffixes chain: `HEAD~2^2`. A branch beats
a prefix of the same spelling, and a prefix matching more than one commit is
refused with the candidates listed rather than guessed at.

`diff` and `construct` also take paths, so a word that could be either is
resolved conservatively: a bare branch name or an unmatched hex word is a
path, and so is a name like `notes~` whose base is not a ref. If a bare prefix
matches a commit *and* a file in the current directory, the command refuses
and asks you to write `./name` for the file.

`construct` writes the working tree, and without `--force` refuses to write
over work that is not committed; to read history, use `show`, which writes
nothing. `show <rev>:<path>` prints the file's bytes as they are at that
revision, or a directory's entries. `show <rev>` prints the commit and the
paths it changed against its first parent, marked `A`, `M` or `D`;
`log --name-status` does the same for each commit in the log. A change to
the executable bit alone is an `M`.

`status --format json` and `diff --format json` print one JSON object for
tools, as `merge --format json` does. `status` gives HEAD's id and each group
of paths it lists, and the newest release. `diff` gives each changed file, the
blob id of each side, and each line added or removed, with its line number and
its line ending, if it has one. `show <blob-id>` prints the old side's blob,
which history holds. The new side's id is only a hash of the working tree's
file: `show` prints it only if that content was tracked or committed. The
text `diff` ends every line, and marks a last line without an ending with
`\ No newline at end of file`.

Branch and merge — note that creating a branch and switching to it are
separate operations, so a commit cannot land on a branch you only meant to
make:

```sh
levcs branch --create feature/x
levcs branch --switch feature/x
echo "more" >> a.txt
levcs commit -m "wip"

levcs branch --switch main
levcs merge feature/x
```

`merge` reports each file and the handler that resolved it:

```
AUTO     note.md  (textual)

merge summary:
  auto-resolved: 1
  conflicts:     0
```

A merge with conflicts cannot be committed until each conflicted file is
resolved explicitly. Some conflicts have no markers: a binary file keeps
your version, byte for byte, and a file one side deleted and the other
edited keeps the edited version. So resolution is a decision you name:

```sh
levcs status                      # lists the unresolved conflicts
levcs track path/to/file          # after editing it: mark it resolved
levcs forget --delete path/to/file  # or resolve it by deleting it
levcs commit -m "merge feature/x"
```

`track --all` and a directory argument never resolve a conflict; only
naming the file does. While a merge is in progress, `branch --switch` is
refused: finish the merge with `commit`, or abandon it with `merge --abort`.
Files containing NUL bytes, or that are not UTF-8, are never line-merged:
divergent edits to them are always a conflict.

To step through a merge rather than take it wholesale, and to abandon one
that went badly:

```sh
levcs merge feature/x --review
levcs merge --abort
```

`--explain` prints why each file went to the handler it did, and
`--format json` emits one structured object per §6.7 for scripting.

Cut a release:

```sh
levcs release v0.1.0 -m "first release"
```

---

## Hosting an instance

To dogfood the federation surface, run `levcs-instance` on a VPS behind
nginx or Caddy. The full walkthrough is in
[`deploy/README.md`](deploy/README.md): build, systemd unit, reverse
proxy templates, firewall, and the laptop-side bootstrap.

The compressed version:

```sh
sudo cp deploy/levcs-instance.service /etc/systemd/system/
sudo cp deploy/instance.toml.example /etc/levcs/instance.toml
sudo $EDITOR /etc/levcs/instance.toml
sudo systemctl enable --now levcs-instance
# ... then drop deploy/Caddyfile.example into /etc/caddy/Caddyfile
```

From your laptop, point the local repo at the instance and push:

```sh
levcs instance --set https://levcs.example.com/levcs/v1
levcs push refs/branches/main
```

The first push to a fresh instance auto-inits the repo with your
genesis authority. Subsequent pushes are role-checked against the
authority chain.

---

## Repository layout

```
crates/
  levcs-core/        Object model (Blob/Tree/Commit/Release/Authority),
                     hash, store, refs, repository abstractions.
  levcs-identity/    Authority objects, Ed25519 keys, signing/verify.
  levcs-merge/       Cascade engine, format and tree-sitter handlers,
                     plugin runtime, merge records.
  levcs-protocol/    Pack codec, wire types, request signing, P2P.
  levcs-client/      Thin HTTP client over the federation API.
  levcs-instance/    Axum HTTP server (the federation peer).
  levcs-cli/         The `levcs` user-facing CLI.
  levcs-tui/         Conflict-resolution terminal UI.

deploy/              Production deployment artifacts (systemd, Caddy, nginx).
scripts/             Reproducible benchmark and ops scripts.
doc/                 Technical report and architecture docs.
.github/workflows/   CI configuration.
```

---

## Testing

```sh
cargo test --workspace
```

Runs the full suite — unit tests, integration tests, federation
end-to-end tests including the three-instance "dogfood" scenario, the
merge conformance corpus, and property-based fuzz tests. ~194 tests at
v0.1.0; full run is well under a minute on a modern laptop.

Useful subsets:

```sh
# A single crate's tests
cargo test -p levcs-merge

# A specific integration test
cargo test -p levcs-instance --test dogfood

# Property tests only
cargo test -p levcs-merge --test proptest_textual
```

---

## Benchmarks

Microbenchmarks live in each crate's `benches/` directory and use
`criterion`. A reproducible runner with metadata capture and optional
flamegraph generation is at `scripts/bench.sh`:

```sh
scripts/bench.sh --quick               # smoke test (~ a minute total)
scripts/bench.sh                       # full criterion run (~ a few minutes)
scripts/bench.sh --flamegraph          # generate per-bench SVG flamegraphs
scripts/bench.sh --bench pack_codec    # one bench only
```

Output goes to `bench-results/<host>-<UTC-timestamp>/` with a parsed
`summary.txt`, criterion's HTML reports, and a `metadata.txt` capturing
rustc version, kernel, CPU, and git rev for run-to-run comparison.

Headline numbers on a Ryzen 7 laptop:

- **Pack decode** at 10 × 1 MiB entries: ~2.3 ms (4.3 GiB/s).
- **Blob serialize + BLAKE3** at 1 MiB: ~190 µs (5.1 GiB/s).
- **Textual three-way merge** of a 100 KiB document: ~4.6 ms.

Pack encoding is the throughput floor at ~380 MiB/s — bottlenecked by
zstd level 3 on incompressible data.

---

## Documentation

- **[`doc/technical-report.md`](doc/technical-report.md)** — Distribution
  document. What LeVCS is, how to use it, and how it differs from /
  improves upon git. Targets technical evaluators and the workflow-spec
  reader.
- **[`deploy/README.md`](deploy/README.md)** — Comprehensive VPS
  deployment walkthrough.
- **`spec/`** — The protocol specification and trust-root revision.
  Currently kept private; ask the maintainer for a copy.

---

## Contributing

This is a young project. The most useful contributions right now are:

1. **Trying it.** Run `levcs init` on a real project, push to a local
   instance, and report friction.
2. **Workflow design.** The next major piece of work is the workflow
   spec — PR/review surface, issues, CI conventions. Discussion welcome.
3. **Plugin handlers.** The wasm plugin protocol exists; concrete
   handlers (e.g. protobuf, SQL migrations) are needed to validate it.
4. **Tightening CI.** The `fmt` and `clippy` GitHub jobs are
   informational; flipping them to gating would close a small but real
   quality gap.

Please open an issue or reach out before starting non-trivial work so
we can coordinate.

---

## License

Released under the Apache License 2.0 — see [`LICENSE`](LICENSE) for the
full text.

---

## Citation

If LeVCS supports academic work, please cite the v0.1.0 release. A
formal citation entry will land with the workflow spec; in the meantime
a repository-URL reference is fine.
