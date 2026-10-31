#!/usr/bin/env bash
# Pre-push gate: the SAME three checks CI runs (black --check, ruff
# check, pytest) — catches the failures BEFORE the push instead of in
# the MR pipeline. Exit 1 blocks the push.
#
# Runs from the repo root (git hooks execute at the tree's root).
# Uses the project venv's tools when present (pipenv), else falls back
# to PATH — CI parity either way (same versions from Pipfile.lock).

set -uo pipefail
cd "$(git rev-parse --show-toplevel)/crusoe-cs-ansible"

run() {
    echo "==> $*"
    "$@"
}

if command -v pipenv >/dev/null 2>&1 && [ -d .venv ]; then
    BLACK="pipenv run black"
    RUFF="pipenv run ruff"
    PYTEST="pipenv run python -m pytest"
else
    BLACK="black"
    RUFF="ruff"
    PYTEST="python -m pytest"
fi

fail=0

run $BLACK --check images/ roles/cve_2026_98432/files/ scripts/ tests/ || fail=1
run $RUFF check --no-fix images/ roles/cve_2026_98432/files/ scripts/ tests/ || fail=1
run $PYTEST tests/ -q || fail=1

if [ "$fail" -ne 0 ]; then
    echo
    echo "PRE-PUSH FAILED — fix the above before pushing (CI runs the same gates)."
    echo "Quick fix: pipenv run black images/ roles/cve_2026_98432/files/ scripts/ tests/"
    exit 1
fi

echo "==> all gates green"
exit 0
