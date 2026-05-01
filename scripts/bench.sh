#!/usr/bin/env bash
# Run LeVCS Tier 1 benchmarks reproducibly.
#
# Usage:
#   scripts/bench.sh                    Full criterion run (~few minutes per bench)
#   scripts/bench.sh --quick            Short measurement window for smoke testing
#   scripts/bench.sh --flamegraph       Generate a flamegraph SVG per bench
#   scripts/bench.sh --output-dir DIR   Override the output directory
#   scripts/bench.sh --bench NAME       Run only one bench (pack_codec|object_hash|textual_merge)
#   scripts/bench.sh -h | --help        Show this message
#
# Output layout: bench-results/<host>-<UTC-timestamp>/
#   metadata.txt              rustc / cpu / mem / git context for the run
#   <crate>-<bench>.txt       captured criterion stdout per bench
#   <crate>-<bench>.svg       flamegraph SVGs (when --flamegraph is used)
#   summary.txt               headline time/throughput pulled out of each run
#   criterion-html/           copy of criterion's HTML reports (target/criterion)
#
# Notes for cluster runs:
#   * --flamegraph requires `cargo install flamegraph` and the `perf` tool.
#   * Many cluster nodes set kernel.perf_event_paranoid >= 2, which blocks
#     unprivileged perf. The script warns but does not attempt to fix it.
#   * Criterion writes its own results to target/criterion/ regardless of
#     --output-dir; that directory is what's used for run-to-run diffing.

set -euo pipefail

MODE="criterion"
TIMING="default"
OUTPUT_DIR=""
WARM_UP=3
MEASURE=5
SAMPLES=100
ONLY_BENCH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)
            TIMING="quick"
            WARM_UP=1
            MEASURE=2
            SAMPLES=30
            shift
            ;;
        --flamegraph)
            MODE="flamegraph"
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --bench)
            ONLY_BENCH="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed -E 's/^# ?//'
            exit 0
            ;;
        *)
            echo "error: unknown argument '$1'" >&2
            echo "run with --help for usage" >&2
            exit 1
            ;;
    esac
done

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

HOST=$(hostname -s 2>/dev/null || echo unknown)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUTPUT_DIR=${OUTPUT_DIR:-bench-results/${HOST}-${STAMP}}
mkdir -p "$OUTPUT_DIR"
echo "==> output:    $OUTPUT_DIR"
echo "==> mode:      $MODE  ($TIMING — warm_up=${WARM_UP}s, measure=${MEASURE}s, samples=$SAMPLES)"
echo

# Capture machine + toolchain context. Anything that could explain a
# perf delta between two runs lives here so cluster results stay
# attributable.
{
    echo "=== rustc ==="
    rustc --version 2>&1 || true
    echo
    echo "=== cargo ==="
    cargo --version 2>&1 || true
    echo
    echo "=== uname ==="
    uname -a 2>&1 || true
    echo
    if [[ -r /proc/cpuinfo ]]; then
        echo "=== cpu ==="
        grep -m1 'model name' /proc/cpuinfo || true
        printf "cores: %d\n" "$(grep -c '^processor' /proc/cpuinfo)" || true
        echo
    fi
    if command -v free >/dev/null 2>&1; then
        echo "=== mem ==="
        free -h 2>&1 || true
        echo
    fi
    if [[ -r /proc/sys/kernel/perf_event_paranoid ]]; then
        echo "=== perf_event_paranoid ==="
        cat /proc/sys/kernel/perf_event_paranoid
        echo
    fi
    echo "=== git ==="
    git rev-parse HEAD 2>/dev/null || echo "(not a git checkout)"
    git status --porcelain 2>/dev/null | head -20 || true
    echo
    echo "=== bench config ==="
    echo "mode=$MODE"
    echo "timing=$TIMING"
    echo "warm_up=${WARM_UP}s"
    echo "measure=${MEASURE}s"
    echo "samples=$SAMPLES"
    echo "only=${ONLY_BENCH:-<all>}"
} > "$OUTPUT_DIR/metadata.txt"

BENCHES=(
    "levcs-protocol pack_codec"
    "levcs-core object_hash"
    "levcs-merge textual_merge"
)

if [[ -n "$ONLY_BENCH" ]]; then
    FILTERED=()
    for entry in "${BENCHES[@]}"; do
        bench=$(awk '{print $2}' <<<"$entry")
        if [[ "$bench" == "$ONLY_BENCH" ]]; then
            FILTERED+=("$entry")
        fi
    done
    if [[ ${#FILTERED[@]} -eq 0 ]]; then
        echo "error: --bench '$ONLY_BENCH' not in registered list" >&2
        echo "available: pack_codec, object_hash, textual_merge" >&2
        exit 1
    fi
    BENCHES=("${FILTERED[@]}")
fi

if [[ "$MODE" == "flamegraph" ]]; then
    if ! command -v cargo-flamegraph >/dev/null 2>&1; then
        echo "error: cargo-flamegraph not found on PATH" >&2
        echo "install with: cargo install flamegraph" >&2
        exit 1
    fi
    if [[ -r /proc/sys/kernel/perf_event_paranoid ]]; then
        PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid)
        if [[ "$PARANOID" -gt 1 ]]; then
            echo "warning: kernel.perf_event_paranoid=$PARANOID — perf may be blocked" >&2
            echo "         try: sudo sysctl kernel.perf_event_paranoid=1" >&2
            echo
        fi
    fi
fi

for entry in "${BENCHES[@]}"; do
    crate=$(awk '{print $1}' <<<"$entry")
    bench=$(awk '{print $2}' <<<"$entry")
    out="$OUTPUT_DIR/${crate}-${bench}.txt"
    echo "==> running $crate :: $bench"

    if [[ "$MODE" == "flamegraph" ]]; then
        svg="$OUTPUT_DIR/${crate}-${bench}.svg"
        # cargo-flamegraph runs the bench under perf. The bench binary
        # needs `--bench` to enter benchmark mode (criterion default).
        cargo flamegraph -p "$crate" --bench "$bench" \
            --output "$svg" -- --bench \
            --warm-up-time "$WARM_UP" \
            --measurement-time "$MEASURE" \
            --sample-size "$SAMPLES" 2>&1 | tee "$out"
    else
        cargo bench -p "$crate" --bench "$bench" -- \
            --warm-up-time "$WARM_UP" \
            --measurement-time "$MEASURE" \
            --sample-size "$SAMPLES" 2>&1 | tee "$out"
    fi
    echo
done

# Pull headline numbers out of the captured criterion output. The
# format is stable: a label line (no leading whitespace, contains '/'),
# then indented `time:` and optional `thrpt:` lines.
{
    echo "# LeVCS bench summary"
    echo "# host: $HOST  stamp: $STAMP"
    echo "# mode: $MODE  timing: $TIMING  (warm_up=${WARM_UP}s measure=${MEASURE}s samples=$SAMPLES)"
    echo
    for entry in "${BENCHES[@]}"; do
        crate=$(awk '{print $1}' <<<"$entry")
        bench=$(awk '{print $2}' <<<"$entry")
        out="$OUTPUT_DIR/${crate}-${bench}.txt"
        [[ -f "$out" ]] || continue
        echo "## $crate :: $bench"
        # Criterion stanzas have no blank separators; flush on each new
        # label. Exclude "Benchmarking …" status lines (also contain '/'),
        # outlier-count lines, and the "change:" stanza below the absolute
        # numbers. Keep only the first time:/thrpt: per label so the
        # change-vs-baseline lines do not overwrite the absolute ones.
        awk '
            function flush() {
                if (label != "" && time != "") {
                    if (thrpt != "") printf "  %-44s %s   %s\n", label, time, thrpt
                    else             printf "  %-44s %s\n", label, time
                }
                label=""; time=""; thrpt=""
            }
            /^Benchmarking / { next }
            /^Found / { next }
            /^[^[:space:]].*\// { flush(); label=$0; next }
            /time:/ {
                if (label != "" && time == "") {
                    sub(/^[[:space:]]+/, "")
                    time=$0
                }
                next
            }
            /thrpt:/ {
                if (label != "" && thrpt == "") {
                    sub(/^[[:space:]]+/, "")
                    thrpt=$0
                }
                next
            }
            END { flush() }
        ' "$out"
        echo
    done
} > "$OUTPUT_DIR/summary.txt"

# Snapshot criterion's HTML reports. These contain the full distribution
# plots and are what you'd open to compare two runs visually.
if [[ -d target/criterion ]]; then
    cp -r target/criterion "$OUTPUT_DIR/criterion-html"
fi

echo "==> done"
echo "    summary: $OUTPUT_DIR/summary.txt"
echo "    HTML:    $OUTPUT_DIR/criterion-html/report/index.html"
[[ "$MODE" == "flamegraph" ]] && echo "    SVGs:    $OUTPUT_DIR/*.svg"
