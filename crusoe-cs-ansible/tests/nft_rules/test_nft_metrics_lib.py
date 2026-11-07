"""Unit tests for the nft-metrics engine
(roles/nft_rules/files/nft-metrics.sh).

ONE file, two sections: §1 a sourceable function library (pure, no
side effects at source time — a future mitigation's host-side
script sources it and calls nft_metrics_publish with its own
identity), §2 a guarded CLI (runs only when EXECUTED; identity from
the environment — the systemd timer's shape).

The functions are exercised via `sh` (POSIX) — the same shell the
timer uses on hosts; bash-isms would break the contract. The CLI is
exercised end-to-end with a fake nft on PATH.
"""

import os
import re
import stat
import subprocess

from ruleset_source import Ruleset

from conftest import COMPONENT_ROOT

SCRIPT = COMPONENT_ROOT / "roles" / "nft_rules" / "files" / "nft-metrics.sh"

CHAIN_OBSERVE = Ruleset.render("observe").listing(counters={1: 7})
CHAIN_ENFORCE = Ruleset.render("enforce").listing(counters={1: 42})
CHAIN_TWO_COUNTERS = Ruleset.render("observe").listing(counters={1: 60000})

# The probe/local split: the loopback count-only rule renders FIRST
# (before the verdict rule). 'First counter' extraction would read
# the LOOPBACK counter — the extractors must anchor on the VERDICT
# rule (drop / log prefix).
#
# DERIVED from the real template (ruleset_source), not hand-written:
# the loopback rule renders as `iif lo ip saddr ...`, and a fixture
# that omits the `iif lo` prefix tests a shape production never
# produces.
CHAIN_WITH_LOOPBACK_ENFORCE = Ruleset.render("enforce").listing(counters={0: 3, 1: 42})
CHAIN_WITH_LOOPBACK_OBSERVE = Ruleset.render("observe").listing(counters={0: 3, 1: 7})


def call_lib(expr, env=None):
    """Source the library and evaluate an expression under POSIX sh."""
    cmd = f'. "{SCRIPT}" && {expr}'
    return subprocess.run(
        ["sh", "-c", cmd],
        capture_output=True,
        text=True,
        env=env,
    )


def chain_arg(chain):
    """A shell-safe $(cat file) argument carrying REAL newlines.

    printf %s with a Python repr keeps \\n literal — the chain becomes
    ONE line and sed's greedy match takes the LAST counter (a fixture
    artifact that masked the loopback-anchor bug). Real nft output is
    multi-line; the file carries it faithfully."""
    import tempfile

    fh = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    fh.write(chain)
    fh.close()
    return f'"$(cat {fh.name})"', fh.name


class TestMatchCounter:
    def test_extracts_the_match_counter(self):
        arg, path = chain_arg(CHAIN_OBSERVE)
        try:
            r = call_lib(f'nft_match_counter {arg} "hdrlength != 5"')
            assert r.returncode == 0, r.stderr
            assert r.stdout.strip() == "7"
        finally:
            os.unlink(path)

    def test_enforce_listing(self):
        arg, path = chain_arg(CHAIN_ENFORCE)
        try:
            r = call_lib(f'nft_match_counter {arg} "hdrlength != 5"')
            assert r.stdout.strip() == "42"
        finally:
            os.unlink(path)

    def test_match_counter_not_log_counter(self):
        # The observe rule renders TWO counters on one line: the match
        # counter, then the rate-limited log counter (≤6/min clamp).
        # The function must return the MATCH counter.
        arg, path = chain_arg(CHAIN_TWO_COUNTERS)
        try:
            r = call_lib(f'nft_match_counter {arg} "hdrlength != 5"')
            assert r.stdout.strip() == "60000"
        finally:
            os.unlink(path)

    def test_missing_rule_is_empty(self):
        r = call_lib('nft_match_counter "chain input { }" "hdrlength != 5"')
        assert r.stdout.strip() == ""

    def test_custom_match_expression(self):
        # A different mitigation's rule shape: the match fragment is
        # a parameter, not a hardcode.
        chain = (
            "table ip cve_2099_12345 {\n\tchain input {\n\t\t"
            "tcp dport 31337 counter packets 11 bytes 528 drop\n\t}\n}"
        )
        arg, path = chain_arg(chain)
        try:
            r = call_lib(f'nft_match_counter {arg} "tcp dport 31337"')
            assert r.stdout.strip() == "11"
        finally:
            os.unlink(path)

    def test_anchors_on_the_verdict_rule_not_the_loopback_rule(self):
        # The probe/local split renders a count-only loopback rule
        # FIRST — 'first counter after the match fragment' would read
        # the LOOPBACK counter (3), under-reporting non-loopback traffic by
        # orders of magnitude. The extractor must anchor on the
        # VERDICT rule: the counter whose line carries the verdict
        # (drop / log prefix). REAL newlines (the one-line fixture
        # artifact masked this bug — sed's greedy match took the last
        # counter on a single line).
        arg, path = chain_arg(CHAIN_WITH_LOOPBACK_ENFORCE)
        try:
            r = call_lib(f'nft_match_counter {arg} "hdrlength != 5"')
            assert r.stdout.strip() == "42", (
                "the extractor must read the VERDICT rule's counter (42), "
                "not the loopback rule's (3) — the loopback rule renders "
                "first and also matches the fragment"
            )
        finally:
            import os

            os.unlink(path)

    def test_anchors_on_verdict_in_observe_too(self):
        arg, path = chain_arg(CHAIN_WITH_LOOPBACK_OBSERVE)
        try:
            r = call_lib(f'nft_match_counter {arg} "hdrlength != 5"')
            assert r.stdout.strip() == "7"
        finally:
            import os

            os.unlink(path)

    def test_loopback_counter_extraction(self):
        # The SPLIT's other half: the loopback counter (probe/local
        # traffic) is extractable too — the metrics publish it as the
        # probe series.
        arg, path = chain_arg(CHAIN_WITH_LOOPBACK_ENFORCE)
        try:
            r = call_lib(f"nft_loopback_counter {arg}")
            assert r.stdout.strip() == "3"
        finally:
            import os

            os.unlink(path)


class TestVerdict:
    def test_log_prefix_is_observe(self):
        r = call_lib(f'nft_verdict "$(printf %s {CHAIN_OBSERVE!r})"')
        assert r.stdout.strip() == "observe"

    def test_drop_is_enforce(self):
        r = call_lib(f'nft_verdict "$(printf %s {CHAIN_ENFORCE!r})"')
        assert r.stdout.strip() == "enforce"


class TestExposition:
    def test_emit_observe_series(self):
        r = call_lib('nft_metrics_emit "cve_2026_98432" 7 observe')
        out = r.stdout
        assert "cve_2026_98432_rule_loaded 1" in out
        assert 'cve_2026_98432_mode{mode="observe"} 1' in out
        assert 'cve_2026_98432_mode{mode="enforce"} 0' in out
        assert 'cve_2026_98432_matched_packets_total{scope="host"} 7' in out
        assert "cve_2026_98432_dropped_packets_total 0" in out

    def test_emit_with_probe_split(self):
        # The probe/local split: the emit takes the loopback counter
        # and publishes loopback_packets_total (kernel-truth
        # node-local count) + non_loopback_packets_total (total −
        # loopback) alongside the unchanged matched/dropped series.
        r = call_lib('nft_metrics_emit "cve_2026_98432" 42 enforce 3')
        out = r.stdout
        assert "cve_2026_98432_loopback_packets_total 3" in out
        assert "cve_2026_98432_non_loopback_packets_total 39" in out
        assert 'cve_2026_98432_matched_packets_total{scope="host"} 42' in out, (
            "the total series is UNCHANGED — the gate check and the "
            "four-vantage validation key off it"
        )

    def test_split_math_zero_loopback(self):
        # No probe has run yet (fresh rule): non_loopback must equal
        # the FULL total — the split must not eat real traffic.
        r = call_lib('nft_metrics_emit "cve_2026_98432" 42 enforce 0')
        out = r.stdout
        assert "cve_2026_98432_loopback_packets_total 0" in out
        assert "cve_2026_98432_non_loopback_packets_total 42" in out

    def test_split_math_all_loopback(self):
        # Only the probe has ever matched: non_loopback must be 0 —
        # the split must not invent traffic that isn't there.
        r = call_lib('nft_metrics_emit "cve_2026_98432" 7 enforce 7')
        out = r.stdout
        assert "cve_2026_98432_loopback_packets_total 7" in out
        assert "cve_2026_98432_non_loopback_packets_total 0" in out

    def test_split_math_invariant(self):
        # THE identity that makes the split trustworthy:
        # loopback + non_loopback == matched, in every combination.
        for matched, loopback in ((42, 3), (100, 0), (5, 5), (99, 98), (1, 1)):
            r = call_lib(
                f'nft_metrics_emit "cve_2026_98432" {matched} enforce {loopback}'
            )
            out = r.stdout
            lb = int(re.search(r"loopback_packets_total (\d+)", out).group(1))
            nlb = int(re.search(r"non_loopback_packets_total (\d+)", out).group(1))
            tot = int(
                re.search(r'matched_packets_total\{scope="host"\} (\d+)', out).group(1)
            )
            assert lb + nlb == tot, (
                f"split invariant violated: {lb} + {nlb} != {tot} "
                f"(matched={matched} loopback={loopback})"
            )

    def test_split_math_never_negative(self):
        # The impossible-but-defensive case: the ruleset guarantees
        # loopback <= matched (every loopback packet also hits the
        # verdict rule), but a stale listing or a ruleset regression
        # could violate it — the metric must CLAMP to 0, never
        # publish a negative (Prometheus counters are monotonic >= 0).
        r = call_lib('nft_metrics_emit "cve_2026_98432" 5 enforce 9')
        out = r.stdout
        assert "cve_2026_98432_non_loopback_packets_total 0" in out, (
            "non_loopback must clamp to 0 when loopback > matched — "
            "a negative counter would break Prometheus monotonicity"
        )

    def test_emit_enforce_series(self):
        r = call_lib('nft_metrics_emit "cve_2026_98432" 42 enforce')
        out = r.stdout
        assert 'cve_2026_98432_mode{mode="enforce"} 1' in out
        assert "cve_2026_98432_dropped_packets_total 42" in out

    def test_emit_unloaded(self):
        r = call_lib('nft_metrics_emit_unloaded "cve_2026_98432"')
        assert "cve_2026_98432_rule_loaded 0" in r.stdout
        assert "matched_packets_total" not in r.stdout

    def test_emit_carries_help_and_type(self):
        # The exposition is complete Prometheus textfile format —
        # HELP/TYPE per family (serve-metrics warns on malformed
        # families).
        r = call_lib('nft_metrics_emit "cve_2026_98432" 7 observe')
        assert "# HELP cve_2026_98432_rule_loaded" in r.stdout
        assert "# TYPE cve_2026_98432_matched_packets_total counter" in r.stdout


class TestAtomicWrite:
    def test_atomic_write_leaves_no_tmp(self, tmp_path):
        out = tmp_path / "out.prom"
        r = subprocess.run(
            [
                "sh",
                "-c",
                f'. "{SCRIPT}" && printf "line\\n" | nft_atomic_write "{out}"',
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        assert out.read_text() == "line\n"
        assert not (tmp_path / "out.prom.tmp").exists()

    def test_atomic_write_is_world_readable(self, tmp_path):
        # mktemp creates 0600 whatever the umask, and mv keeps the
        # mode — without an explicit chmod every published .prom is
        # root:root 0600 and a non-root node_exporter gets EACCES
        # (found by review: the old `> file` path honoured the umask
        # and gave 0644; the mktemp switch silently broke that).
        out = tmp_path / "out.prom"
        r = subprocess.run(
            [
                "sh",
                "-c",
                f'. "{SCRIPT}" && printf "line\\n" | nft_atomic_write "{out}"',
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        mode = stat.S_IMODE(out.stat().st_mode)
        assert mode == 0o644, f"the published file must be 0644, got {mode:o}"


class TestOneFileIdiom:
    """§1/§2 split: sourcing loads ONLY the functions (no side
    effects — a consumer's script must not publish on source);
    executing runs the CLI pipeline."""

    def test_sourcing_has_no_side_effects(self, tmp_path):
        # Source the file as a LIBRARY: no destination dirs exist,
        # and none may be created — the CLI section must not run.
        r = subprocess.run(
            ["sh", "-c", f'. "{SCRIPT}" && echo sourced-ok'],
            capture_output=True,
            text=True,
            env={"NFT_METRICS_CHART_DIR": str(tmp_path / "chart")},
        )
        assert r.returncode == 0, r.stderr
        assert "sourced-ok" in r.stdout
        assert not (tmp_path / "chart").exists(), (
            "sourcing must not run the CLI — a consumer's script "
            "sources the library and calls the pipeline explicitly"
        )

    def test_cli_runs_when_executed(self, tmp_path):
        chart = tmp_path / "chart"
        chart.mkdir()
        r = subprocess.run(
            ["sh", str(SCRIPT)],
            capture_output=True,
            text=True,
            env={
                "NFT_METRICS_CHART_DIR": str(chart),
                "NFT_CHAIN_FIXTURE": CHAIN_OBSERVE,
            },
        )
        assert r.returncode == 0, r.stderr
        prom = (chart / "cve_2026_98432.prom").read_text()
        assert "cve_2026_98432_rule_loaded 1" in prom

    def test_functions_available_after_source(self):
        r = subprocess.run(
            [
                "sh",
                "-c",
                f'. "{SCRIPT}" && type nft_metrics_publish >/dev/null && echo fn-ok',
            ],
            capture_output=True,
            text=True,
        )
        assert "fn-ok" in r.stdout

    def test_legacy_env_aliases(self, tmp_path):
        # Deployed hosts run systemd units that pass the OLD
        # CVE_METRICS_* env names — the CLI must honor them (upgrade
        # safety) until the units are replaced.
        chart = tmp_path / "chart"
        chart.mkdir()
        r = subprocess.run(
            ["sh", str(SCRIPT)],
            capture_output=True,
            text=True,
            env={
                "CVE_METRICS_CHART_DIR": str(chart),
                "NFT_CHAIN_FIXTURE": CHAIN_OBSERVE,
            },
        )
        assert r.returncode == 0, r.stderr
        prom = (chart / "cve_2026_98432.prom").read_text()
        assert "cve_2026_98432_rule_loaded 1" in prom

    def test_publish_writes_the_destination(self, tmp_path):
        dest = tmp_path / "chart"
        dest.mkdir()
        r = subprocess.run(
            [
                "sh",
                "-c",
                (
                    f'. "{SCRIPT}" && '
                    f"NFT_CHAIN_FIXTURE={CHAIN_OBSERVE!r} "
                    f"nft_metrics_publish cve_2026_98432 cve_2026_98432 "
                    f'"hdrlength != 5" "{tmp_path / "node_exporter"}" "{dest}"'
                ),
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        prom = (dest / "cve_2026_98432.prom").read_text()
        assert 'cve_2026_98432_matched_packets_total{scope="host"} 7' in prom

    def test_publish_noop_when_neither_dir(self, tmp_path):
        r = subprocess.run(
            [
                "sh",
                "-c",
                (
                    f'. "{SCRIPT}" && '
                    f"NFT_CHAIN_FIXTURE={CHAIN_OBSERVE!r} "
                    f"nft_metrics_publish cve_2026_98432 cve_2026_98432 "
                    f'"hdrlength != 5" "{tmp_path / "a"}" "{tmp_path / "b"}"'
                ),
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert not (tmp_path / "b" / "cve_2026_98432.prom").exists()
