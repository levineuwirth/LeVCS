#!/usr/bin/env bash
#
# Phase 1 gate. Supersedes check-phase0.sh by running it, so the Phase 0
# freeze stays enforced for as long as Phase 1 is in progress.
#
# A green gate is necessary and not sufficient: the Wave A freeze also
# requires the adversarial review of doc/phase1-storage-spine-scope.md
# section 5, and the review precedes the freeze.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "== Phase 0 freeze =="
bash scripts/check-phase0.sh

echo "== levcs-store, feature matrix =="
# Default features: the shipping configuration. Failpoints and the drive seam
# must be absent from it.
cargo test -p levcs-store
# Everything the crash matrix and harness need.
cargo test -p levcs-store --features failpoints,store-internals,store-privileged
# The privileged constructor in isolation, so a leak into the default build is
# not masked by the combined run.
cargo test -p levcs-store --features store-privileged
# The benchmark harness. Without this configuration the gate never compiles
# store-bench at all, so its refuse-to-start prechecks, its bundle emitter, and
# its unit tests are invisible to CI -- a check that silently does not run.
cargo test -p levcs-store --features bench-harness,store-internals,store-privileged
# ...and prove the gated binaries actually build, since a `cargo test` run does
# not necessarily compile a `required-features` bin.
cargo build -p levcs-store --features bench-harness,store-internals,store-privileged --bins
cargo build -p levcs-store --features failpoints,store-internals,store-privileged --bins

echo "== store-privileged is not a default feature =="
# The seal on ValidatedTransaction is only worth anything if the feature that
# opens it stays opt-in. A default-on gate would be decorative.
if cargo metadata --no-deps --format-version 1 \
  | python3 -c '
import json,sys
meta = json.load(sys.stdin)
for pkg in meta["packages"]:
    if pkg["name"] != "levcs-store":
        continue
    default = pkg["features"].get("default", [])
    leaked = [f for f in default if f in ("store-privileged", "store-internals", "failpoints")]
    if leaked:
        print("default features must not include: " + ", ".join(leaked))
        sys.exit(1)
sys.exit(0)
'; then
  :
else
  echo "levcs-store default feature set leaks a test/privileged feature" >&2
  exit 1
fi

echo "== golden frame corpus is not drifting =="
# A1 lands the generator; until then the corpus does not exist and this is a
# no-op rather than a false pass.
if [ -f crates/levcs-store/examples/phase1_frame_golden.rs ]; then
  before="$(sha256sum crates/levcs-store/tests/fixtures/phase1-frames.json | cut -d' ' -f1)"
  cargo run -q -p levcs-store --example phase1_frame_golden > /tmp/phase1-frames.regen.json
  after="$(sha256sum /tmp/phase1-frames.regen.json | cut -d' ' -f1)"
  if [ "$before" != "$after" ]; then
    echo "golden frame corpus differs from a fresh regeneration" >&2
    echo "  committed:   $before" >&2
    echo "  regenerated: $after" >&2
    echo "changing a frozen frame byte requires a recorded contract review" >&2
    exit 1
  fi
  rm -f /tmp/phase1-frames.regen.json
else
  echo "  (skipped: A1 has not landed examples/phase1_frame_golden.rs yet)"
fi

echo "== crash matrix has no pending rows at Phase 1 exit =="
# During Waves A and B the fixture legitimately carries pending-wave-b rows.
# This check only fires once B1 has landed engine.rs, at which point a pending
# row means a forgotten failpoint rather than a sequenced one.
matrix=crates/levcs-store/tests/fixtures/phase1-failpoints.json
if [ -f "$matrix" ] && grep -q 'fn submit' crates/levcs-store/src/engine.rs \
   && ! grep -q 'NotImplemented' crates/levcs-store/src/engine.rs; then
  if grep -q 'pending-wave-b' "$matrix"; then
    echo "engine.rs is implemented but the crash matrix still has pending rows:" >&2
    grep -n 'pending-wave-b' "$matrix" >&2
    exit 1
  fi
fi

echo "GATE_EXIT=0"
