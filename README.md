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
- **Merge is a cascade**, not a line-level diff. Per-file dispatch to
  a handler ranked by aggressiveness: textual fallback, format-aware
  (JSON / YAML / TOML / XML / Markdown / prose), tree-sitter for
  source code (Rust, Python, JS/TS, Go, C/C++, Java, Ruby, Bash), and
  wasm-sandboxed plugins for the long tail.
- **BLAKE3, not SHA-1.** Tree-hashed, ~5 GiB/s on a laptop, 32-byte
  IDs everywhere.
- **Releases are signed objects**, not mutable name pointers.

For a deeper comparison and context, see the
[technical report](doc/technical-report.md).

---

## Building

LeVCS is a Rust workspace. You'll need a recent stable toolchain
(workspace MSRV is 1.89, for `std::fs::File::lock`) and a C compiler for the
tree-sitter grammars.

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
expands to the tracked files beneath it — so everything `--delete` can reach
has a blob in the object store and comes back with `levcs construct`. Bounding
the verb is what makes deletion safe by construction rather than by analysis;
the alternative, deleting by default and refusing when the content is not yet
in a commit, would make the tool answer "is this recoverable?" on every call,
with deletion as the price of being wrong.

Commands that take a commit (`diff`, `construct`, `merge`, `branch --create`)
accept a revision, not just a full hash:

```sh
levcs diff HEAD~1            # against the previous commit
levcs construct HEAD~3 a.txt # a.txt as it was three commits ago
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
AUTO     note.md  (markdown)

merge summary:
  auto-resolved: 1
  conflicts:     0
```

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
