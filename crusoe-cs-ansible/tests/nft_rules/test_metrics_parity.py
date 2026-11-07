"""Metrics parity: the two generators (the sh engine and the
reconciler's inline host republish) declare the SAME families with
BYTE-IDENTICAL HELP text.

serve-metrics dedupes identical re-declarations silently but WARNs
on a conflict (different HELP for one family) — and the kubelet
probes /metrics every 10s, so a conflict is ~505 stderr lines/hour/
pod of scrape noise. Both generators write into
the same hostPath; the parity must hold for every shared family.

The test renders BOTH generators with the same inputs and diffs the
full exposition — not just the families one side happens to test.
"""

import re
import subprocess

from ruleset_source import Ruleset

from conftest import COMPONENT_ROOT

SH_ENGINE = COMPONENT_ROOT / "roles" / "nft_rules" / "files" / "nft-metrics.sh"
RECONCILER = (
    COMPONENT_ROOT
    / "roles"
    / "cve_2026_98432"
    / "files"
    / "cve-2026-98432-netns-reconcile.py"
)

# DERIVED from the real template (ruleset_source) — the parity test
# compares the two generators' output for the SAME input, so the input
# must be the shape production produces.
CHAIN = Ruleset.render("enforce").listing(counters={0: 3, 1: 42})


def _sh_exposition() -> dict[str, str]:
    """Render the sh engine's emit with the split inputs."""
    out = subprocess.run(
        [
            "sh",
            "-c",
            f'. "{SH_ENGINE}" && nft_metrics_emit cve_2026_98432 42 enforce 3',
        ],
        capture_output=True,
        text=True,
    ).stdout
    return dict(re.findall(r"# HELP (\S+) (.+)", out))


def _reconciler_exposition() -> dict[str, str]:
    """Render the reconciler's inline republish with the same inputs
    (the FakeHost seam: the host chain listing is the input)."""
    import importlib.util
    from types import SimpleNamespace

    spec = importlib.util.spec_from_file_location("r", RECONCILER)
    assert spec and spec.loader, f"reconciler not found at {RECONCILER}"
    mod = importlib.util.module_from_spec(spec)
    assert mod is not None
    spec.loader.exec_module(mod)

    def fake_host(*argv: str) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout=CHAIN, stderr="")

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        # The reconciler's module-level seams (the test suite's
        # established pattern — see test_netns_reconcile.py).
        mod.host = fake_host  # type: ignore[attr-defined]
        mod.METRICS_DIR = tmp  # type: ignore[attr-defined]
        mod.republish_host_metrics()  # type: ignore[attr-defined]
        prom = open(f"{tmp}/cve_2026_98432.prom").read()
    return dict(re.findall(r"# HELP (\S+) (.+)", prom))


def test_generators_declare_identical_help_texts():
    sh = _sh_exposition()
    py = _reconciler_exposition()
    shared = sorted(set(sh) & set(py))
    assert shared, "the generators must share families (they write one hostPath)"
    for fam in shared:
        assert sh[fam] == py[fam], (
            f"HELP text drift for {fam} — serve-metrics warns on every "
            f"scrape when two files declare one family with different "
            f"HELP text (~505 stderr lines/hour/pod):\n"
            f"  sh engine:     {sh[fam]!r}\n"
            f"  reconciler:    {py[fam]!r}"
        )


def test_generators_cover_the_same_families():
    # The shared families must be exactly the host series — a family
    # one generator adds and the other doesn't is a parity gap (the
    # scrape would carry it only while that generator's file is
    # freshest, flapping).
    sh = _sh_exposition()
    py = _reconciler_exposition()
    sh_only = set(sh) - set(py)
    py_only = set(py) - set(sh)
    assert not sh_only, f"sh-engine-only families (parity gap): {sorted(sh_only)}"
    assert not py_only, f"reconciler-only families (parity gap): {sorted(py_only)}"


class TestSeriesNamesAreThePublicContract:
    """The series names are a PUBLIC contract: dashboards, alerts and
    the rollout runbook reference them by name. A rename is a breaking
    change, and the runbook is the place it is documented.

    This pins the two generators' families against the runbook's
    table, so a rename that forgets the docs (or a doc edit that
    forgets the code) fails here instead of in someone's dashboard.
    """

    def _runbook_series(self) -> set[str]:
        import re

        from conftest import COMPONENT_ROOT

        runbook = COMPONENT_ROOT / "docs" / "runbooks" / "cve-2026-98432-rollout.md"
        text = runbook.read_text()
        return set(re.findall(r"cve_2026_98432_[a-z_]+_total", text))

    def _generated_series(self) -> set[str]:
        # Both generators, from the same derived input.
        sh = _sh_exposition()
        rec = _reconciler_exposition()
        return {
            name
            for name in set(sh) | set(rec)
            if name.startswith("cve_2026_98432_") and name.endswith("_total")
        }

    def test_every_generated_series_is_documented(self):
        documented = self._runbook_series()
        generated = self._generated_series()
        undocumented = generated - documented
        assert not undocumented, (
            "series generated but absent from the runbook's table — a "
            f"dashboard author cannot find them: {sorted(undocumented)}"
        )

    def test_every_documented_series_is_generated(self):
        documented = self._runbook_series()
        generated = self._generated_series()
        stale = documented - generated
        assert not stale, (
            "the runbook documents series nothing generates — a stale "
            f"contract: {sorted(stale)}"
        )
