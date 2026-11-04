"""The test suite's shared plumbing — THE reflective anchor.

One place derives the component root from its own location; every
test file takes it as the `repo_root` fixture (a pathlib.Path) and
writes explicit relative paths. No per-file HERE/../.. math, no
sys.path surgery for imports (pytest's pythonpath owns that).

The root conftest (crusoe-cs-ansible/conftest.py) keeps the
inventory plugin's path — that one is an import-path concern.
"""

from __future__ import annotations

from pathlib import Path

import pytest

COMPONENT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """The component root (crusoe-cs-ansible/) — derived from this
    conftest's location, the ONE reflective anchor."""
    return COMPONENT_ROOT
