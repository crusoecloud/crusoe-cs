#!/usr/bin/env bash
# Pre-push gate: the SAME four checks CI runs (ruff format --check,
# ruff check, mypy, pytest) — catches the failures BEFORE the push
# instead of in the MR pipeline. Exit 1 blocks the push.
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
    RUFF="pipenv run ruff"
    MYPY="pipenv run mypy"
    PYTEST="pipenv run python -m pytest"
else
    RUFF="ruff"
    MYPY="mypy"
    PYTEST="python -m pytest"
fi

fail=0

run $RUFF format --check images/ roles/cve_2026_98432/files/ scripts/ tests/ || fail=1
run $RUFF check --no-fix images/ roles/cve_2026_98432/files/ scripts/ tests/ || fail=1
run $MYPY images/ roles/cve_2026_98432/files/ scripts/ tests/ || fail=1
run $PYTEST tests/ -q || fail=1

if [ "$fail" -ne 0 ]; then
    echo
    echo "PRE-PUSH FAILED — fix the above before pushing (CI runs the same gates)."
    echo "Quick fix: pipenv run ruff format images/ roles/cve_2026_98432/files/ scripts/ tests/"
    exit 1
fi

echo "==> all gates green"
exit 0
