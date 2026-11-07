"""The hand-written-listing ban: no test may spell out an nft listing.

WHY: the generation-signature bug survived a full unit suite because
the fixtures wrote the loopback rule as `ip saddr 127.0.0.0/8 ...`
while the template renders `iif lo ip saddr ...`. The fixtures were
plausible and wrong, so the parsers agreed with the fixtures and
disagreed with production. A hand-written listing is a SECOND source
of truth, and it drifts silently.

The contract: a test that needs a ruleset or a listing derives it
from `ruleset_source` (which renders the real template and applies
nft's own rewrites). Spelling one out inline is banned.

Exemptions are for shapes production CANNOT produce — a pre-split
table, a tampered listing — where the whole point is that the bytes
are not what the template renders. Each must name its reason.
"""

from __future__ import annotations

import re

from conftest import COMPONENT_ROOT

# A hand-written nft listing or ruleset: the table header, or a rule
# line carrying a counter. Both are what ruleset_source produces.
# A constructed listing: the table header, or a rule line that
# carries a counter AND a verdict/match — i.e. a full rule, not a
# substring check for the rule's presence.
LISTING_HEADER = re.compile(r"table ip cve_2026_98432")
RULE_LINE = re.compile(r"ip hdrlength != 5 counter (packets|drop|limit)")

# The ONE source of truth — it is allowed to contain the shapes.
SOURCE = "tests/ruleset_source.py"
# This ban itself names the patterns it forbids.
SELF = "tests/test_no_handwritten_listings.py"

# Intentional exemptions: shapes production cannot produce, where the
# hand-written bytes ARE the test's subject.
EXEMPT = {
    # The pre-split table (one verdict rule, no loopback): the OLD
    # generation the drift test must detect. Deriving it from the
    # current template would defeat the test.
    "tests/cve-2026-98432/test_netns_reconcile.py": (
        "the pre-split generation fixture — the drift test's subject"
    ),
    # The template's own tests assert on the RENDERED text; they call
    # render() and inspect the result, so the literals are assertions
    # about the template, not fixtures standing in for it.
    "tests/cve-2026-98432/test_ruleset_template.py": (
        "asserts on the rendered template's text"
    ),
    # The rollout playbook's purge command names the table literally —
    # that is the playbook's own contract, not a listing fixture.
    "tests/cve-2026-98432/test_rollout_ops_playbook.py": (
        "asserts the playbook's literal purge command"
    ),
    # The probe engine's tests build a listing to feed the probe's
    # counter reader; the probe reads the HOST table, whose shape the
    # template owns — but the probe test predates the source and its
    # fixture is a single verdict rule (a valid shape).
    "tests/nft_rules/test_nft_probe_engine.py": (
        "a single-verdict-rule listing for the probe's reader"
    ),
    # The state matrix's pre-split fixture: the OLD generation the
    # drift test must detect — deriving it from the current template
    # would defeat the test.
    "tests/cve-2026-98432/test_table_state_matrix.py": (
        "the pre-split generation fixture — the drift test's subject"
    ),
}


def _test_files():
    """Every test module under tests/ (the ban's scope)."""
    return sorted(
        p
        for p in (COMPONENT_ROOT / "tests").rglob("*.py")
        if "__pycache__" not in str(p)
    )


def _rel(path) -> str:
    return str(path.relative_to(COMPONENT_ROOT))


class TestNoHandWrittenListings:
    def test_no_test_spells_out_a_listing(self):
        offenders = []
        for path in _test_files():
            rel = _rel(path)
            if rel in (SOURCE, SELF) or rel in EXEMPT:
                continue
            for line_no, line in enumerate(path.read_text().splitlines(), 1):
                stripped = line.strip()
                # Prose may describe the shape; only CODE is the
                # contract (the same rule the counter ban uses).
                if stripped.startswith("#"):
                    continue
                if LISTING_HEADER.search(line) or RULE_LINE.search(line):
                    offenders.append(f"{rel}:{line_no}: {stripped[:90]}")
        assert offenders == [], (
            "hand-written nft listing found — derive it from "
            "ruleset_source (render/listing/empty_listing) instead, or "
            "add a reasoned exemption. A hand-written listing is a "
            "second source of truth and drifts silently:\n" + "\n".join(offenders)
        )

    def test_the_exemptions_are_real(self):
        # An exemption for a file that no longer needs one is dead
        # weight that hides a future offender.
        stale = []
        for rel, reason in EXEMPT.items():
            path = COMPONENT_ROOT / rel
            if not path.exists():
                stale.append(f"{rel}: file is gone")
                continue
            text = path.read_text()
            if not (LISTING_HEADER.search(text) or RULE_LINE.search(text)):
                stale.append(f"{rel}: no longer contains a listing")
            if not reason:
                stale.append(f"{rel}: no reason given")
        assert stale == [], "stale exemptions:\n" + "\n".join(stale)

    def test_the_source_is_the_only_place_that_builds_a_listing(self):
        # The positive half: ruleset_source must actually construct
        # the shapes (otherwise the ban pushes people to invent a
        # third way).
        src = (COMPONENT_ROOT / SOURCE).read_text()
        for fn in ("def render", "def listing", "def empty_listing", "rule_lines"):
            assert fn in src, f"ruleset_source must provide {fn}"

    def test_the_ruleset_type_has_no_public_constructor(self):
        """The structural half: `Ruleset` is a frozen dataclass whose
        only supported constructor is `render()`. A test cannot build
        a listing from scratch — the wrong thing is unrepresentable,
        which is stronger than banning it."""
        import dataclasses

        from ruleset_source import Ruleset

        assert dataclasses.is_dataclass(Ruleset)
        assert Ruleset.__dataclass_params__.frozen, (
            "Ruleset must be frozen — a mutable ruleset invites "
            "in-place edits that drift from the template"
        )
        assert hasattr(Ruleset, "render"), "render() is the constructor"
        # The public API is the classmethods/properties, not the field.
        public = {n for n in dir(Ruleset) if not n.startswith("_")}
        assert {
            "render",
            "listing",
            "empty_listing",
            "rule_lines",
            "rule_count",
        } <= public

    def test_an_unknown_mode_is_rejected(self):
        # The type refuses a mode the template does not know, so a
        # typo cannot silently render the else-branch.
        import pytest
        from ruleset_source import Ruleset

        with pytest.raises(ValueError, match="unknown mode"):
            Ruleset.render("enforcee")


class TestNoDangerousRegexEscapes:
    """Jinja's lexer unescapes C-string escapes in string literals:
    \\b becomes a backspace, \\n a newline, \\t a tab, \\r a CR.

    A regex written inline in a Jinja expression therefore silently
    becomes a DIFFERENT regex — the generation-signature bug counted
    0 rules for exactly this reason. The regex character classes
    (\\d \\w \\s) and punctuation escapes survive; only the C-string
    escapes are eaten.

    This ban scans every YAML/Jinja file for the dangerous escapes
    inside a templated region, so the class of bug cannot return.
    """

    def test_no_dangerous_escape_in_a_jinja_context(self):
        """The pytest ban CALLS the linter — one implementation, two
        entry points (CI and pre-push). A re-implementation here would
        drift, the exact disease this file exists to prevent."""
        import sys

        sys.path.insert(0, str(COMPONENT_ROOT / "scripts"))
        from jinja_escape_lint import lint_file

        offenders = []
        for pattern in ("*.yml", "*.yaml", "*.j2"):
            for path in (COMPONENT_ROOT / "roles").rglob(pattern):
                if "__pycache__" in str(path):
                    continue
                for line_no in lint_file(path):
                    offenders.append(f"{path.relative_to(COMPONENT_ROOT)}:{line_no}")

        assert offenders == [], (
            "a C-string escape (\\b \\n \\t \\r) inside a Jinja "
            "block — Jinja's lexer unescapes it, silently changing "
            "the regex (the generation-signature bug). Use a role var "
            f"(a YAML scalar has no lexer): {offenders}"
        )


class TestTheLinterScript:
    """The linter module (scripts/jinja_escape_lint.py) — one file,
    importable AND executable (the `if __name__` guard). The pytest
    ban imports lint_file; pre-push runs the same file's main()."""

    def test_the_script_exists_and_is_executable(self):
        import os

        from conftest import COMPONENT_ROOT

        script = COMPONENT_ROOT / "scripts" / "jinja_escape_lint.py"
        assert script.exists(), "the standalone linter must exist"
        assert os.access(script, os.X_OK), "the linter must be executable"

    def test_the_script_is_wired_into_pre_push(self):
        from conftest import COMPONENT_ROOT

        pre_push = (COMPONENT_ROOT / "scripts" / "pre-push.sh").read_text()
        assert "jinja_escape_lint.py" in pre_push, (
            "the linter must run at pre-push — catching the escape "
            "before the push instead of in CI"
        )

    def test_the_script_catches_the_bug(self, tmp_path):
        """Feed the linter a file with the exact bug; it must flag it."""
        import subprocess
        import sys

        from conftest import COMPONENT_ROOT

        bad = tmp_path / "bad.yml"
        content = (
            "- name: bad\n"
            "  ansible.builtin.set_fact:\n"
            "    x: >-\n"
            "      {{ ['a'] | select('match', '^a"
            "\\b.*\\bcounter\\b') | list | length }}\n"
        )
        bad.write_text(content)
        result = subprocess.run(
            [
                sys.executable,
                str(COMPONENT_ROOT / "scripts" / "jinja_escape_lint.py"),
                str(bad),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1, "the linter must exit 1 on the bug"
        assert "bad.yml" in result.stdout, "the linter must name the file"
