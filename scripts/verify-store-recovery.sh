#!/usr/bin/env bash
#
# Phase 1 store recovery verification (scope 4-A3 deliverable 7).
#
# Three things, in this order, because each is only meaningful if the previous
# one passed:
#
#   1. The deterministic crash matrix — every failpoint driven to its physical
#      outcome and classified against two independent derivations.
#   2. N randomized SIGKILL cycles — the same store under a fault that is not
#      deterministic and not placed by the harness.
#   3. External acknowledgment reconciliation after every cycle.
#
# Step 3 is not a summary of steps 1 and 2. It is the only detector for a
# device that lost a *fenced* write (scope 3.8): recovery cannot distinguish
# that from an unfenced tail by inspection, because nothing on the device says
# so. A non-zero `acknowledged_loss` is a hardware finding that invalidates the
# run — it is never a store bug to tolerate, and this script exits non-zero on
# it rather than reporting it as a statistic.
#
# SIGKILL is not a substitute for power loss (plan §10). dm-flakey, block-device
# cache and barrier manipulation, and abrupt power cuts live in the reviewed
# root-only scripts of §10 and are Phase 4/5 work. This script is deliberately
# unprivileged so the matrix runs in CI.
#
# Machine-readable summary on stdout as `key=value` lines, the same shape the
# crash driver itself emits. Diagnostics go to stderr.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cycles=100
work=""
run_matrix=1
run_bundle=1
group_len=8
shard=0
# Low enough that kills land during the first journal, high enough that the
# child has reliably acknowledged something by the time it dies. A window whose
# floor is below the cost of creating a root would spend most cycles killing a
# process that had not yet promised anything, and 100 such cycles prove nothing.
min_run_ms=120
max_run_ms=900

usage() {
  cat >&2 <<'USAGE'
verify-store-recovery.sh [options]

  --cycles N        randomized SIGKILL cycles (default 100)
  --work DIR        working directory; must be on a persistent filesystem
  --group-len N     transactions per durability fence in the soak (default 8)
  --skip-matrix     do not run the deterministic crash matrix
  --skip-bundle     do not emit and validate a skeleton result bundle
  -h, --help        this text
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --cycles) cycles="$2"; shift 2 ;;
    --work) work="$2"; shift 2 ;;
    --group-len) group_len="$2"; shift 2 ;;
    --skip-matrix) run_matrix=0; shift ;;
    --skip-bundle) run_bundle=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 64 ;;
  esac
done

# ---------------------------------------------------------------------------
# Working directory
# ---------------------------------------------------------------------------

# A tmpfs working directory would make every fence free and every recovery
# trivially clean, so the whole run would prove nothing. Plan §10 has the
# evaluator reject tmpfs, overlay, and remote mounts before calculating
# anything; the same rule applies to a correctness campaign, for the same
# reason.
if [ -z "$work" ]; then
  work="$repo_root/target/store-recovery"
fi
mkdir -p "$work"
work="$(cd -- "$work" && pwd)"

fstype="$(stat -f -c %T "$work" 2>/dev/null || echo unknown)"
case "$fstype" in
  tmpfs|ramfs|overlayfs)
    echo "refusing to run on $fstype at $work: a fence that costs nothing and" >&2
    echo "a page cache that never loses a write cannot falsify any durability" >&2
    echo "claim. Pass --work with a persistent filesystem." >&2
    exit 78
    ;;
esac

cleanup() {
  # Roots are large and numerous; leave the last failing one for forensics and
  # remove the rest.
  if [ "${keep_last:-0}" = "1" ]; then
    echo "left the failing root at $work/last for inspection" >&2
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

features="failpoints,store-internals,store-privileged"

echo "== building the crash driver ==" >&2
cargo build -q -p levcs-store --features "$features" --bin store-crash-driver
driver="$repo_root/target/debug/store-crash-driver"
if [ ! -x "$driver" ]; then
  echo "store-crash-driver was not built at $driver" >&2
  exit 70
fi

# ---------------------------------------------------------------------------
# 1. The deterministic crash matrix
# ---------------------------------------------------------------------------

matrix_status="skipped"
if [ "$run_matrix" = "1" ]; then
  echo "== deterministic crash matrix ==" >&2
  if cargo test -q -p levcs-store --features "$features" --test crash_matrix >&2; then
    matrix_status="pass"
  else
    matrix_status="fail"
  fi
fi

# ---------------------------------------------------------------------------
# 2 and 3. Randomized SIGKILL cycles and acknowledgment reconciliation
# ---------------------------------------------------------------------------

echo "== $cycles randomized SIGKILL cycles ==" >&2

completed=0
total_acknowledged_loss=0
total_torn=0
total_repeated=0
total_adopted=0
total_acked=0
recovery_failures=0
cycles_with_no_acks=0

cycle=0
while [ "$cycle" -lt "$cycles" ]; do
  cycle=$((cycle + 1))
  root="$work/cycle-$cycle"
  ack="$work/cycle-$cycle.ack"
  rm -rf "$root" "$ack"
  mkdir -p "$(dirname -- "$root")"

  seed=$(( (cycle * 2654435761 + 1013904223) % 4294967296 ))

  "$driver" soak \
    --root "$root" \
    --shard "$shard" \
    --shard-count 1 \
    --seed "$seed" \
    --group-len "$group_len" \
    --ack-journal "$ack" \
    --path drive >/dev/null 2>&1 &
  soak_pid=$!

  # A uniformly random delay, so kills land across append, fence, ACK journal
  # write, seal, and manifest install rather than always at the same point in
  # the loop. A fixed delay would sample one instant of a periodic workload and
  # call it randomized.
  delay_ms=$(( min_run_ms + (RANDOM * 32768 + RANDOM) % (max_run_ms - min_run_ms + 1) ))
  sleep "$(awk "BEGIN{printf \"%.3f\", $delay_ms/1000}")"

  kill -9 "$soak_pid" 2>/dev/null || true
  wait "$soak_pid" 2>/dev/null || true

  if [ ! -f "$ack" ]; then
    # The child was killed before it durably journaled anything. Nothing was
    # acknowledged, so nothing can have been lost; counted separately so a run
    # whose kills all land too early is visible rather than looking like 100
    # clean cycles.
    cycles_with_no_acks=$((cycles_with_no_acks + 1))
    completed=$((completed + 1))
    rm -rf "$root" "$ack"
    continue
  fi

  set +e
  summary="$("$driver" reconcile --root "$root" --shard "$shard" --ack-journal "$ack" 2>/dev/null)"
  reconcile_status=$?
  set -e

  value_of() { printf '%s\n' "$summary" | sed -n "s/^$1=//p" | head -1; }

  if [ "$(value_of recovery_ok)" != "true" ]; then
    recovery_failures=$((recovery_failures + 1))
    echo "cycle $cycle: production recovery refused to open the crash image" >&2
    printf '%s\n' "$summary" >&2
    rm -rf "$work/last"; mv "$root" "$work/last" 2>/dev/null || true
    keep_last=1
    break
  fi

  loss="$(value_of acknowledged_loss)"
  torn="$(value_of torn_transactions)"
  adopted="$(value_of adopted_count)"
  acked="$(value_of ack_records)"
  # Duplicates and regressions are counted apart from holes: a repeat means the
  # same frames were adopted twice, which is a different finding from a frame
  # adopted after a hole, and summing them would hide both.
  duplicates="$(value_of adopted_duplicates)"
  regressions="$(value_of adopted_regressions)"
  repeated=$(( ${duplicates:-0} + ${regressions:-0} ))

  total_acknowledged_loss=$((total_acknowledged_loss + ${loss:-0}))
  total_torn=$((total_torn + ${torn:-0}))
  total_repeated=$((total_repeated + repeated))
  total_adopted=$((total_adopted + ${adopted:-0}))
  total_acked=$((total_acked + ${acked:-0}))
  completed=$((completed + 1))

  if [ "${loss:-0}" != "0" ] || [ "${torn:-0}" != "0" ] || [ "$repeated" != "0" ] \
     || [ "$reconcile_status" != "0" ]; then
    echo "cycle $cycle: reconciliation failed" >&2
    printf '%s\n' "$summary" >&2
    rm -rf "$work/last"; mv "$root" "$work/last" 2>/dev/null || true
    keep_last=1
    break
  fi

  rm -rf "$root" "$ack"
done

# ---------------------------------------------------------------------------
# 4. A schema-valid result bundle
# ---------------------------------------------------------------------------

bundle_status="skipped"
zero_work_status="skipped"
unaccounted_status="skipped"
if [ "$run_bundle" = "1" ]; then
  echo "== skeleton result bundle ==" >&2
  if cargo build -q -p levcs-store \
      --features bench-harness,store-internals,store-privileged \
      --bin store-bench 2>/dev/null; then
    bundle_parent="$work/bundle"
    rm -rf "$bundle_parent"

    # The frozen profile requires nodatacow on the journal and segment
    # directories, and store-bench refuses on mismatch rather than recording
    # it. An unprivileged run can only satisfy that by inheritance, so the
    # attribute is set on an empty parent and the store root is created inside
    # it. Where the filesystem has no such attribute, `chattr` fails, the
    # precheck refuses, and this reports `refused` — which is correct: the
    # bundle would otherwise claim a configuration the host does not have.
    mkdir -p "$bundle_parent"
    chattr +C "$bundle_parent" 2>/dev/null || true

    # Both paths, because the schema's verification rules branch on
    # `run_conditions.mutation_path`: the production submit path is *required*
    # to assert the two claims contract review 2026-07-28-C granted, and the
    # journal seam is forbidden from asserting any of the three. A run that
    # validated one path would leave the other's rules unexercised, and the
    # unexercised one is where a seam bundle claiming what the seam cannot
    # observe would appear.
    bundle_status="schema-valid"
    for bundle_variant in submit drive; do
    bundle_root="$bundle_parent/$bundle_variant-root"
    bundle_out="$work/storage-primitive-skeleton-$bundle_variant.json"
    rm -rf "$bundle_root" "$bundle_out"

    if "$repo_root/target/debug/store-bench" emit-skeleton \
        --root "$bundle_root" --out "$bundle_out" --path "$bundle_variant" \
        --allow-unsigned --seconds 2 --group-len 16 >&2; then
      if python3 - "$repo_root/bench/result-schema.json" "$bundle_out" >&2 <<'PY'
import json, sys
try:
    import jsonschema
except ImportError:
    sys.stderr.write("jsonschema is not installed; bundle not validated\n")
    sys.exit(3)
schema = json.load(open(sys.argv[1]))
instance = json.load(open(sys.argv[2]))
validator = jsonschema.Draft202012Validator(
    schema, format_checker=jsonschema.FormatChecker()
)
errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
for error in errors:
    sys.stderr.write(f"schema: {list(error.path)}: {error.message}\n")
sys.exit(1 if errors else 0)
PY
      then
        # A later variant may only keep the status the earlier one earned; it
        # can never upgrade a failure back to valid.
        :
      else
        case $? in
          3) bundle_status="unvalidated-no-jsonschema" ;;
          *) bundle_status="schema-invalid" ;;
        esac
      fi
    else
      bundle_status="refused"
    fi
    done

    # The zero-work negative control.
    #
    # A run with no submitter measures nothing, yet the repositories are still
    # created — so before this was fixed the bundle reported their fences and
    # their signatures as measured work and asserted setup_traffic_excluded,
    # unique_blob_tree_commit_ids, and objects_new_equals_three_per_commit over
    # an empty set. Every one of those is vacuously true over zero commits, and
    # bench/result-schema.json validates such a bundle without complaint: counts
    # are nonnegative and the claims are const true. The schema therefore cannot
    # be the thing that refuses it, and a gate that only ever ran the happy path
    # would not notice the emitter's refusal being removed.
    zero_work_root="$bundle_parent/zero-work-root"
    zero_work_out="$work/storage-primitive-zero-work.json"
    rm -rf "$zero_work_root" "$zero_work_out"
    if "$repo_root/target/debug/store-bench" emit-skeleton \
        --root "$zero_work_root" --out "$zero_work_out" --path submit \
        --allow-unsigned --seconds 2 --group-len 16 \
        --submitters-per-shard 0 >&2; then
      zero_work_status="emitted"
    else
      zero_work_status="refused"
    fi
    # A refusal that still wrote a bundle is not a refusal.
    if [ -f "$zero_work_out" ]; then
      zero_work_status="emitted"
    fi

    # The incomplete-accounting negative control.
    #
    # A commit whose acknowledgment cannot be journaled is a transaction the
    # store performed, fenced, and signed, and that the harness can never
    # count. Until this was fixed the run merely stopped: the failure set no
    # counter and recorded no error, so the emitter's refused-submit guard
    # never saw it, and — because it happens after the first commit — neither
    # did the zero-work guard. The bundle that came out omitted a committed
    # transaction while still reporting its fence and its signature, and was
    # schema-valid, exactly like the zero-work bundle above. The failure is
    # induced with a write to /dev/full so the kernel supplies a real ENOSPC
    # rather than the harness inventing one; a full tmpfs reaches the same
    # code path with EDQUOT.
    unaccounted_root="$bundle_parent/unaccounted-root"
    unaccounted_out="$work/storage-primitive-unaccounted.json"
    rm -rf "$unaccounted_root" "$unaccounted_out"
    if "$repo_root/target/debug/store-bench" emit-skeleton \
        --root "$unaccounted_root" --out "$unaccounted_out" --path submit \
        --allow-unsigned --seconds 2 --group-len 4 \
        --shards 1 --submitters-per-shard 1 \
        --fail-ack-append-after 1 >&2; then
      unaccounted_status="emitted"
    else
      unaccounted_status="refused"
    fi
    if [ -f "$unaccounted_out" ]; then
      unaccounted_status="emitted"
    fi
  else
    bundle_status="build-failed"
  fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo "verify_store_recovery_schema=1"
echo "work_directory=$work"
echo "filesystem=$fstype"
echo "matrix=$matrix_status"
echo "cycles_requested=$cycles"
echo "cycles_completed=$completed"
echo "cycles_without_acknowledgments=$cycles_with_no_acks"
echo "recovery_failures=$recovery_failures"
echo "adopted_frames=$total_adopted"
echo "acknowledged_operations=$total_acked"
echo "acknowledged_loss=$total_acknowledged_loss"
echo "torn_transactions=$total_torn"
echo "repeated_adoptions=$total_repeated"
echo "bundle=$bundle_status"
echo "zero_work_run=$zero_work_status"
echo "unaccounted_ack_run=$unaccounted_status"

exit_code=0
[ "$matrix_status" = "fail" ] && exit_code=1
[ "$completed" -ne "$cycles" ] && exit_code=1
[ "$recovery_failures" -ne 0 ] && exit_code=1
[ "$total_acknowledged_loss" -ne 0 ] && exit_code=1
[ "$total_torn" -ne 0 ] && exit_code=1
[ "$total_repeated" -ne 0 ] && exit_code=1
[ "$bundle_status" = "schema-invalid" ] && exit_code=1
# A validation that silently does not run is the defect this section exists to
# prevent, so an absent validator fails the run rather than passing it quietly.
[ "$bundle_status" = "unvalidated-no-jsonschema" ] && exit_code=1
[ "$bundle_status" = "refused" ] && exit_code=1
[ "$bundle_status" = "build-failed" ] && exit_code=1
# A zero-work run that produced a bundle is a bundle whose claims are vacuous,
# and it is schema-valid, so this is the only place it can be caught.
[ "$zero_work_status" = "emitted" ] && exit_code=1
# A run that could not account for a committed transaction and emitted a bundle
# anyway published totals for a workload that did not happen, and that bundle is
# schema-valid too.
[ "$unaccounted_status" = "emitted" ] && exit_code=1

echo "VERIFY_EXIT=$exit_code"
exit "$exit_code"
