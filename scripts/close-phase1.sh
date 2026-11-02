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
#   scripts/close-phase1.sh [--work DIR] [--facts FILE] [--seconds N] [--warmup N]
#                           [--settle N] [--reps N] [--cycles N]
#                           [--skip-recovery] [--skip-gate]
#
# --facts FILE is the deployed-node harness's fact file (`table.key = value`
# lines): the privileged half of the hardware-profile comparison — NVMe,
# network, and the rest this process cannot read. The real campaign requires
# it; without those facts no frozen profile can be named and every P2 row
# fails on environment_fidelity.
#
# --seconds, --warmup and --settle are rehearsal controls. Omit them for the
# real campaign: store-bench then runs the frozen warmup and measured window
# from the workload file, and this script settles 120 s between repetitions
# after deleting the previous root (scope 8.2). Passing --seconds makes the
# run a rehearsal, and warmup and settle default to zero with it.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

work="$repo_root/target/phase1-closure"
facts=""
seconds=""
warmup=""
settle=""
reps=3
cycles=100
run_recovery=1
run_gate=1

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --work) work="$2"; shift 2 ;;
    --facts) facts="$2"; shift 2 ;;
    --seconds) seconds="$2"; shift 2 ;;
    --warmup) warmup="$2"; shift 2 ;;
    --settle) settle="$2"; shift 2 ;;
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

# The frozen repetition count, read from the workload file rather than assumed:
# the P2 criterion is "three repetitions", and a campaign that ran fewer — or
# none, via --reps 0 — must not be able to report the criterion as met.
frozen_reps="$(sed -n 's/^repetitions *= *\([0-9]\+\).*/\1/p' \
  "$repo_root/bench/workloads/small-commit.toml" | head -1)"
if [ -z "$frozen_reps" ]; then
  echo "could not read the frozen repetition count from bench/workloads/small-commit.toml" >&2
  exit 70
fi

# The real campaign cannot name a frozen hardware profile without the deployed
# half of the facts, and a campaign that cannot name one cannot pass. Refusing
# in preflight costs seconds; discovering it after three 20-minute repetitions
# costs the machine visit. bench/deployed-facts.template lists every fact and
# how to measure it.
if [ -z "$seconds" ] && [ -z "$facts" ]; then
  echo "the real campaign needs --facts FILE: the deployed-node harness's fact file" >&2
  echo "supplies the privileged half of the hardware-profile comparison (NVMe," >&2
  echo "network, ...). Start from bench/deployed-facts.template; measure, never" >&2
  echo "copy. Rehearsals (--seconds N) may omit it." >&2
  exit 70
fi
if [ -n "$facts" ] && [ ! -r "$facts" ]; then
  echo "--facts $facts is not readable" >&2
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

# Built in preflight because the fact validation below needs the binary, and
# because `environment_fidelity` refuses `reference_profile` without a release
# build -- a debug bundle is a diagnostic bundle whatever the hardware.
echo "== building store-bench (release) ==" >&2
cargo build -q --release -p levcs-store \
  --features bench-harness,store-internals,store-privileged --bin store-bench >&2

# Semantic validation, not a readability check: `precheck-facts` runs the same
# parse, fill-only merge, frozen-profile completeness comparison, and
# emitted-field consistency check the bundle will make at assembly. An empty
# template, a missing fact, or a syntactically valid contradiction refuses
# here, in seconds, instead of after three repetitions. Rehearsals carry their
# facts through unvalidated -- on a non-reference host the comparison would
# correctly refuse, and a rehearsal is how that host runs this script.
if [ -z "$seconds" ]; then
  echo "== validating the deployed-fact file ==" >&2
  if ! "$target_dir/release/store-bench" precheck-facts \
      --facts "$facts" --root "$bench_parent" \
      >"$evidence/precheck-facts.log" 2>&1; then
    cat "$evidence/precheck-facts.log" >&2
    echo "--facts $facts does not survive the evaluation the bundle will make" >&2
    exit 70
  fi
  cat "$evidence/precheck-facts.log" >&2
fi

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
# A rehearsal shortens every phase together: --seconds without --warmup and
# --settle implies zero for both. The real campaign leaves --seconds unset,
# takes the frozen warmup from the workload file, and settles 120 s between
# repetitions — scope 8.2 requires the interval to exist and be recorded; the
# workload file does not freeze its length.
run_flags=()
if [ -n "$seconds" ]; then
  run_flags+=(--seconds "$seconds" --warmup-seconds "${warmup:-0}")
  settle="${settle:-0}"
else
  if [ -n "$warmup" ]; then
    run_flags+=(--warmup-seconds "$warmup")
  fi
  settle="${settle:-120}"
fi
if [ -n "$facts" ]; then
  run_flags+=(--deployed-facts "$facts")
fi

p2_pass=1
for rep in $(seq 1 "$reps"); do
  rep_settle=0
  if [ "$rep" -gt 1 ]; then
    # Scope 8.2: delete the previous repetition's root first, then let
    # discard=async settle for a recorded interval, so repetition 3 is not
    # measured against a differently garbage-collected device than
    # repetition 1.
    rm -rf "$bench_parent/p2-$((rep - 1))"
    rep_settle="$settle"
    if [ "$rep_settle" -gt 0 ]; then
      echo "== settling ${rep_settle}s after deleting the previous root ==" >&2
      sleep "$rep_settle"
    fi
  fi
  echo "== P2 repetition $rep of $reps (${seconds:-frozen}s) ==" >&2
  root="$bench_parent/p2-$rep"
  out="$evidence/storage-primitive-$rep.json"
  rm -rf "$root"
  # --allow-unsigned: real attestation signing is an open interface request to
  # the lead (levcs-store carries no Ed25519 and scope section 1 forbids a
  # levcs_identity:: path in that crate). Without the flag every run refuses
  # with exit 78, on reference hardware as much as here. The checklist below
  # judges workload conditions and verification, which the placeholder
  # attestation does not weaken; bundle signing tightens later without
  # invalidating these rows.
  if ! "$target_dir/release/store-bench" run \
      --root "$root" --out "$out" --path submit \
      --repetition "$rep" --trim-settle-seconds "$rep_settle" \
      "${run_flags[@]}" --allow-unsigned >"$evidence/p2-$rep.log" 2>&1; then
    record "P2 repetition $rep" FAIL "p2-$rep.log"
    p2_pass=0
    continue
  fi

  verdict="$(python3 - "$repo_root/bench/result-schema.json" "$out" \
      "$repo_root/bench/workloads/small-commit.toml" "$rep" <<'PY'
import json, re, sys
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

# The frozen campaign's shape, from the workload file the run measured
# against. A bundle whose warmup, window, repetition number, or settle
# interval fall short of the frozen procedure is a rehearsal whatever its
# rate says, and must not close the phase.
frozen = open(sys.argv[3]).read()
def frozen_int(key):
    found = re.search(rf"^{key}\s*=\s*(\d+)", frozen, re.M)
    return int(found.group(1)) if found else None
measurement = bundle.get("measurement", {})
repetition = int(sys.argv[4])
if measurement.get("warmup_seconds") != frozen_int("p2_p3_warmup_seconds"):
    missing.append(f"warmup_seconds={measurement.get('warmup_seconds')!r}")
if (measurement.get("measured_seconds") or 0) < (frozen_int("p2_p3_measured_seconds") or 0):
    missing.append(f"measured_seconds={measurement.get('measured_seconds')!r}")
if measurement.get("repetition") != repetition:
    missing.append(f"repetition={measurement.get('repetition')!r} (expected {repetition})")
if measurement.get("coordinated_omission_corrected") is not True:
    missing.append(
        f"coordinated_omission_corrected="
        f"{measurement.get('coordinated_omission_corrected')!r}"
    )
if repetition > 1 and (bundle.get("storage", {}).get("trim_settle_seconds") or 0) <= 0:
    missing.append("trim_settle_seconds=0 on a repetition after the first")

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

if [ "$p2_pass" -eq 1 ] && [ "$reps" -eq "$frozen_reps" ]; then
  record "P2 >=75k commits/s, p99 <=50ms, $frozen_reps repetitions" PASS "storage-primitive-*.json"
elif [ "$reps" -ne "$frozen_reps" ]; then
  record "P2 >=75k commits/s, p99 <=50ms, $frozen_reps repetitions" FAIL \
    "only $reps of the frozen $frozen_reps repetitions were run"
else
  record "P2 >=75k commits/s, p99 <=50ms, $frozen_reps repetitions" FAIL "see repetitions above"
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
  # Every non-PASS row blocks closure, SKIP included: a criterion nobody ran
  # is a criterion nobody met, and --skip-* exists for rehearsals, which are
  # expected to exit non-zero.
  [ "$verdict" != "PASS" ] && failed=1
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
  echo "CLOSURE_EXIT=1 (at least one criterion did not pass or was skipped)" >&2
  exit 1
fi
echo "CLOSURE_EXIT=0" >&2
