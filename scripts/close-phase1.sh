#!/usr/bin/env bash
# Run every piece of Phase 1 exit evidence and report it as a checklist.
#
# Scope §7 lists seven exit criteria and two stop-condition clauses. Most are
# already asserted by tests that run in the ordinary gate; what this script adds
# is the part that cannot run anywhere except on reference hardware -- the P2
# campaign -- and a single place that says, in one screen, which criteria are
# met and which are not.
#
# It is deliberately a *reporter*, not a promoter. It exits non-zero unless
# every criterion passes, and it never edits a bundle to make one pass. A run on
# a machine that does not match a frozen hardware profile will correctly report
# the P2 rows as failed, which is what makes it safe to run here as a rehearsal.
#
# Usage:
#   scripts/close-phase1.sh [--work DIR] [--seconds N] [--reps N] [--cycles N]
#                           [--skip-recovery] [--skip-gate]
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

work="$repo_root/target/phase1-closure"
seconds=120
reps=3
cycles=100
run_recovery=1
run_gate=1

usage() {
  sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --work) work="$2"; shift 2 ;;
    --seconds) seconds="$2"; shift 2 ;;
    --reps) reps="$2"; shift 2 ;;
    --cycles) cycles="$2"; shift 2 ;;
    --skip-recovery) run_recovery=0; shift ;;
    --skip-gate) run_gate=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$repo_root/evidence/phase1-closure-$stamp"

# Every row this script can report on. `record` appends one; nothing else
# writes to the checklist, so a criterion with no row is a criterion nobody
# measured rather than one that silently passed.
checklist=()
record() { checklist+=("$1|$2|$3"); }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
echo "== preflight ==" >&2

target_dir="$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
if [ -z "$target_dir" ]; then
  echo "could not resolve cargo's target directory from cargo metadata" >&2
  exit 70
fi

if ! python3 -c 'import jsonschema' 2>/dev/null; then
  echo "jsonschema is not installed; bundles could not be validated" >&2
  exit 70
fi

mkdir -p "$work" "$evidence"
work="$(cd -- "$work" && pwd)"

# The frozen profile requires nodatacow on the journal and segment directories,
# and store-bench refuses on mismatch rather than recording it. Setting the
# attribute on an empty parent and creating each store root inside it is the
# only way an unprivileged run can satisfy that.
bench_parent="$work/bench"
rm -rf "$bench_parent"
mkdir -p "$bench_parent"
chattr +C "$bench_parent" 2>/dev/null || true

fs_type="$(stat -f -c %T "$work" 2>/dev/null || echo unknown)"
if [ "$fs_type" = "tmpfs" ]; then
  echo "the work directory is on tmpfs; no durability claim survives that." >&2
  echo "Pass --work with a persistent filesystem." >&2
  exit 70
fi
echo "work=$work fs=$fs_type evidence=$evidence" >&2

# ---------------------------------------------------------------------------
# 1. The ordinary gate
# ---------------------------------------------------------------------------
if [ "$run_gate" -eq 1 ]; then
  echo "== phase 1 gate ==" >&2
  if bash "$repo_root/scripts/check-phase1.sh" >"$evidence/check-phase1.log" 2>&1; then
    record "Gate (fmt, workspace tests, crash matrix, whitespace)" PASS "check-phase1.log"
  else
    record "Gate (fmt, workspace tests, crash matrix, whitespace)" FAIL "check-phase1.log"
  fi
else
  record "Gate (fmt, workspace tests, crash matrix, whitespace)" SKIP "--skip-gate"
fi

# ---------------------------------------------------------------------------
# 2. Acknowledged crash recovery
# ---------------------------------------------------------------------------
if [ "$run_recovery" -eq 1 ]; then
  echo "== crash recovery campaign ($cycles cycles) ==" >&2
  if bash "$repo_root/scripts/verify-store-recovery.sh" \
      --cycles "$cycles" --work "$work/recovery" \
      >"$evidence/verify-store-recovery.log" 2>&1; then
    record "Acknowledged crash recovery ($cycles SIGKILL cycles)" PASS "verify-store-recovery.log"
  else
    record "Acknowledged crash recovery ($cycles SIGKILL cycles)" FAIL "verify-store-recovery.log"
  fi
else
  record "Acknowledged crash recovery" SKIP "--skip-recovery"
fi

# ---------------------------------------------------------------------------
# 3. The P2 campaign
# ---------------------------------------------------------------------------
#
# Release build, because `environment_fidelity` refuses `reference_profile`
# without one -- a debug bundle is a diagnostic bundle whatever the hardware.
echo "== building store-bench (release) ==" >&2
cargo build -q --release -p levcs-store \
  --features bench-harness,store-internals,store-privileged --bin store-bench >&2

p2_pass=1
for rep in $(seq 1 "$reps"); do
  echo "== P2 repetition $rep of $reps (${seconds}s) ==" >&2
  root="$bench_parent/p2-$rep"
  out="$evidence/storage-primitive-$rep.json"
  rm -rf "$root"
  if ! "$target_dir/release/store-bench" run \
      --root "$root" --out "$out" --path submit \
      --seconds "$seconds" >"$evidence/p2-$rep.log" 2>&1; then
    record "P2 repetition $rep" FAIL "p2-$rep.log"
    p2_pass=0
    continue
  fi

  verdict="$(python3 - "$repo_root/bench/result-schema.json" "$out" <<'PY'
import json, sys
import jsonschema

schema = json.load(open(sys.argv[1]))
bundle = json.load(open(sys.argv[2]))

errors = sorted(
    jsonschema.Draft202012Validator(schema).iter_errors(bundle),
    key=lambda e: list(e.path),
)
if errors:
    print("INVALID " + "; ".join(f"{list(e.path)}: {e.message}" for e in errors[:3]))
    raise SystemExit(0)

rc = bundle.get("run_conditions", {})
# The four conditions a passing storage_primitive bundle must declare, checked
# by name so the reason a repetition did not close is the field rather than a
# schema error twenty levels down.
missing = [
    f"{k}={rc.get(k)!r}"
    for k, want in (
        ("initialization_path", "store_engine_open"),
        ("mutation_path", "store_engine_submit"),
        ("checkpointing", "exercised"),
        ("index_maintenance", "runs_sealed"),
    )
    if rc.get(k) != want
]
fidelity = rc.get("environment_fidelity")
if fidelity != "reference_profile":
    missing.append(f"environment_fidelity={fidelity!r}")
outcome = bundle.get("outcome")
if outcome != "pass":
    missing.append(f"outcome={outcome!r}")

print("PASS" if not missing else "SHORT " + ", ".join(missing))
PY
)"
  case "$verdict" in
    PASS) record "P2 repetition $rep (schema-valid, conditions met)" PASS "$(basename "$out")" ;;
    *)    record "P2 repetition $rep" FAIL "$(basename "$out"): $verdict"; p2_pass=0 ;;
  esac
done

if [ "$p2_pass" -eq 1 ]; then
  record "P2 >=75k commits/s, p99 <=50ms, $reps repetitions" PASS "storage-primitive-*.json"
else
  record "P2 >=75k commits/s, p99 <=50ms, $reps repetitions" FAIL "see repetitions above"
fi

# ---------------------------------------------------------------------------
# Checklist
# ---------------------------------------------------------------------------
echo >&2
echo "===========================================================" >&2
echo " Phase 1 exit checklist  ($stamp)" >&2
echo "===========================================================" >&2
failed=0
for row in "${checklist[@]}"; do
  IFS='|' read -r what verdict artifact <<<"$row"
  printf ' %-6s %-56s %s\n' "$verdict" "$what" "$artifact" >&2
  [ "$verdict" = "FAIL" ] && failed=1
done
echo "-----------------------------------------------------------" >&2
echo " evidence archived in: $evidence" >&2

{
  echo "# Phase 1 closure run $stamp"
  echo
  printf '| verdict | criterion | artifact |\n|---|---|---|\n'
  for row in "${checklist[@]}"; do
    IFS='|' read -r what verdict artifact <<<"$row"
    printf '| %s | %s | `%s` |\n' "$verdict" "$what" "$artifact"
  done
} >"$evidence/CHECKLIST.md"

if [ "$failed" -eq 1 ]; then
  echo "CLOSURE_EXIT=1 (at least one criterion did not pass)" >&2
  exit 1
fi
echo "CLOSURE_EXIT=0" >&2
