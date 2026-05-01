# LeVCS conformance corpus (§8.2)

This directory is the canonical conformance fixture for the LeVCS merge
engine. Any independent implementation of LeVCS that produces the same
outcome on every scenario here is conformant per the spec's testing
strategy: the scenarios tagged `git_false_conflict = true` are
specifically the cases where naive Git produces a spurious conflict and
LeVCS MUST resolve correctly.

## Layout

Each scenario lives in its own numbered directory:

```
<NNN-scenario-name>/
  manifest.toml      # what to assert about the merge result
  base.<ext>         # base / common ancestor input
  ours.<ext>         # left side input
  theirs.<ext>       # right side input
  expected.<ext>     # (optional) exact expected merged output
```

The runner is `crates/levcs-merge/tests/conformance.rs`. It walks this
directory, reads each manifest, runs the engine on the inputs, and
asserts the outcome matches.

## Manifest schema

```toml
description = "..."            # required, human-readable
path = "src/lib.rs"            # required, used for handler routing
input_ext = "rs"               # optional, defaults to extension of `path`
git_false_conflict = true      # optional, marks Git-false-conflict cases

[expected]
status   = "merged"            # "merged" | "conflict"
handler  = "tree-sitter:rust"  # required handler name
contains = ["fn a", "fn b"]    # all must appear in merged output
not_contains = []              # none may appear
content_file = "expected.rs"   # optional, exact-match against file
conflict_count = 1             # conflict-only, optional
region_descriptions_contain = ["concurrent edits"]   # conflict-only
notes_contain = ["recursive descent"]                # merged-only
```

A merged outcome that emits conflict markers (`<<<<<<<`, `=======`,
`>>>>>>>`) is treated as a runner failure regardless of substring
assertions — handlers are not allowed to silently smuggle conflicts
through.

## Adding a scenario

1. Pick the next free `NNN-` prefix.
2. Create the directory, drop in `base/ours/theirs.<ext>` files.
3. Write `manifest.toml` with what should hold.
4. Run `cargo test -p levcs-merge --test conformance`.

Scenarios should be minimal: the smallest input that exercises the
behaviour. Comments inline in input files are fine — the engine treats
them as ordinary content.
