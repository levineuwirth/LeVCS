#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo fmt --all -- --check
cargo test --workspace

# Repository whitespace check. `git diff --check` alone only inspects
# unstaged modifications to already-tracked files, so it silently passes on
# untracked new files (every Phase 0 artifact starts out untracked) and is a
# no-op on a clean checkout. Check every tracked-or-untracked, non-ignored,
# non-binary file directly for trailing whitespace instead. Markdown is
# excluded: a trailing double-space is CommonMark's hard-line-break syntax,
# not sloppy whitespace, and the plan document uses it intentionally.
whitespace_found=0
while IFS= read -r -d '' file; do
  [ -f "$file" ] || continue
  case "$file" in
    *.md) continue ;;
  esac
  grep -Iq '' -- "$file" 2>/dev/null || continue
  if grep -nP '[ \t]+$' -- "$file" >/dev/null 2>&1; then
    echo "trailing whitespace in $file:" >&2
    grep -nP '[ \t]+$' -- "$file" >&2
    whitespace_found=1
  fi
done < <(git ls-files --cached --others --exclude-standard -z)
if [ "$whitespace_found" -ne 0 ]; then
  exit 1
fi
