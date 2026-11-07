"""The verdict-anchoring ban: EVERY counter extraction in the repo
must anchor on the VERDICT rule (drop / log prefix) — never
'first counter'.

The loopback split renders a count-only rule FIRST in every table;
a first-counter anchor reads the LOOPBACK counter instead of the
verdict counter. This ban makes that mistake structurally
impossible.

The contract: any regex or extraction reading 'counter packets N'
from an nft listing must require the verdict token (drop|log
prefix) on the matched line — or document its exemption here.
"""

import re

from conftest import COMPONENT_ROOT

# The extraction sites (files that READ counters from nft listings).
READER_GLOBS = [
    "roles/nft_rules/files/nft-probe.py",
    "roles/nft_rules/files/nft-metrics.sh",
    "roles/cve_2026_98432/files/cve-2026-98432-netns-reconcile.py",
    "tests/e2e/lib/parsers.py",
]

# A first-counter anchor is any line that reads a counter WITHOUT
# requiring a verdict token on the same line. Expressed as two plain
# substring checks rather than one clever regex: the regex form was
# itself buggy (it could not match a Python `(\d+)` extractor, so the
# ban was vacuous for three of the four reader files).
COUNTER_READ = "counter packets"
VERDICT_TOKENS = ("drop", "log prefix")


def is_first_counter_anchor(line: str) -> bool:
    """True when the line reads a counter but does not require a
    verdict token — i.e. it would read the loopback rule's counter."""
    return COUNTER_READ in line and not any(t in line for t in VERDICT_TOKENS)


# Intentional exemptions — extractions that read the LOOPBACK rule's
# counter BY DESIGN (the split's other half). Each must name its
# reason.
EXEMPT_PATTERNS = [
    # nft_loopback_counter: extracts the loopback rule's counter —
    # anchored on 'ip saddr 127.0.0.0/8', the loopback rule's own
    # signature (a verdict anchor would be wrong here).
    re.compile(r"ip saddr 127\\.0\\.0\\.0"),
]


class TestVerdictAnchoringBan:
    def test_every_counter_reader_is_verdict_anchored(self):
        offenders = []
        for rel in READER_GLOBS:
            path = COMPONENT_ROOT / rel
            if not path.exists():
                continue
            src = path.read_text()
            for line_no, line in enumerate(src.splitlines(), 1):
                stripped = line.strip()
                # Skip comments/docstrings — prose may describe the
                # shape; only CODE is the contract.
                if stripped.startswith("#") or stripped.startswith('"'):
                    continue
                if is_first_counter_anchor(line):
                    if any(p.search(line) for p in EXEMPT_PATTERNS):
                        continue
                    offenders.append(f"{rel}:{line_no}: {stripped[:80]}")
        assert offenders == [], (
            "first-counter anchor found — the loopback split renders a "
            "count-only rule FIRST; every counter reader must anchor on "
            "the VERDICT rule (drop|log prefix). Offenders:\n" + "\n".join(offenders)
        )

    def test_the_reader_list_is_complete(self):
        # The ban's own completeness: every file in the repo that
        # mentions 'counter packets' in code must be in READER_GLOBS
        # (or exempted with a reason here). This is what let the
        # harness's parser slip through — the list was written from
        # memory, not from the tree.
        import subprocess

        out = subprocess.run(
            [
                "grep",
                "-rln",
                "counter packets",
                str(COMPONENT_ROOT / "roles"),
                str(COMPONENT_ROOT / "images"),
                str(COMPONENT_ROOT / "tests"),
                str(COMPONENT_ROOT / "scripts"),
            ],
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        found = {
            p.split("crusoe-cs-ansible/")[-1] for p in out if "__pycache__" not in p
        }
        known = set(READER_GLOBS)
        # Exemptions: prose-only mentions (docs/comments), no extraction.
        exempt = {
            "tests/nft_rules/test_nft_metrics_lib.py",  # fixtures, not a reader
            "tests/cve-2026-98432/test_netns_reconcile.py",  # fixtures
            "tests/nft_rules/test_nft_probe_engine.py",  # fixtures
            "tests/nft_rules/test_metrics_parity.py",  # fixtures
            "tests/cve-2026-98432/test_table_state_matrix.py",  # fixtures
            "tests/ruleset_source.py",  # the ONE ruleset source (fixtures)
            "roles/cve_2026_98432/tasks/metrics.yml",  # prose: explains the legacy bug
            "tests/cve-2026-98432/test_role_task_order.py",  # prose: the legacy test
            "tests/test_e2elib.py",  # the parser's own tests (fixtures)
            "tests/nft_rules/test_counter_anchor_ban.py",  # this ban itself
            "roles/cve_2026_98432/tasks/main.yml",  # already verdict-anchored (requires drop)
            "tests/e2e/cve-2026-98432/scenarios_cve.py",  # chain_counter — now verdict-anchored
        }
        unlisted = found - known - exempt
        assert not unlisted, (
            f"files mentioning 'counter packets' not in the ban's reader "
            f"list — add them or exempt with a reason: {sorted(unlisted)}"
        )


class TestTheBanItselfWorks:
    """A ban that cannot match the thing it bans is worse than no ban:
    it reads as protection. These tests feed the ban the exact shapes
    it exists to catch.

    The previous regex form could not match a Python `(\\d+)`
    extractor, so the ban was vacuous for three of the four reader
    files — the very regression it exists to prevent would have
    passed silently.
    """

    def test_it_flags_a_python_extractor(self):
        line = 'NFT_COUNTER_RE = re.compile(r"counter packets (\\d+)")'
        assert is_first_counter_anchor(line), (
            "the ban must flag a Python (\\d+) extractor"
        )

    def test_it_flags_a_sed_extractor(self):
        assert is_first_counter_anchor('grep -o "counter packets \\([0-9]*\\)"')

    def test_it_flags_a_literal_listing(self):
        assert is_first_counter_anchor("counter packets 5 bytes 220 drop") is False, (
            "a line carrying the verdict token is anchored — not flagged"
        )
        assert is_first_counter_anchor("counter packets 5 bytes 220")

    def test_it_clears_a_verdict_anchored_reader(self):
        line = (
            're.compile(r"counter packets (\\d+) bytes \\d+[^\\n]*(?:drop|log prefix)")'
        )
        assert not is_first_counter_anchor(line), (
            "a reader requiring the verdict token is correct"
        )
