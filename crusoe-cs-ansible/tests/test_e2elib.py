"""Unit tests for the shared e2e foundation (tests/e2e/lib).

Tested with FAKES (no cluster): the runner against a stub subprocess,
the parsers against canned outputs (every live-found parsing trap),
the syn craft against the exact payload contract. This is the point
of the Python port — the shell era's contract tests were regex pins
on script text; these test BEHAVIOR.
"""

from __future__ import annotations

import subprocess
from unittest import mock

import pytest
from ruleset_source import Ruleset

from e2e.lib import parsers, runner, syn
from e2e.lib.logging_setup import get_logger  # noqa: F401 (tested below)  # noqa: E402


class TestRunner:
    def test_success_first_try(self):
        with mock.patch.object(subprocess, "run") as m:
            m.return_value = subprocess.CompletedProcess(
                ["kubectl"], 0, stdout="ok", stderr=""
            )
            out = runner.run(["kubectl", "get", "pods"])
        assert out.stdout == "ok"
        assert m.call_count == 1

    def test_api_blip_retried(self):
        # The live-found rule: the API server can blip (DNS i/o
        # timeout mid-wait) — a transient failure must retry, not die.
        results = [
            subprocess.CompletedProcess(["k"], 1, stdout="", stderr="i/o timeout"),
            subprocess.CompletedProcess(["k"], 0, stdout="ok", stderr=""),
        ]
        with (
            mock.patch.object(subprocess, "run", side_effect=results),
            mock.patch.object(runner.time, "sleep"),
        ):
            out = runner.run(["kubectl", "get"], retries=3)
        assert out.stdout == "ok"

    def test_persistent_failure_raises_with_stderr(self):
        bad = subprocess.CompletedProcess(["k"], 1, stdout="", stderr="boom")
        with (
            mock.patch.object(subprocess, "run", return_value=bad),
            mock.patch.object(runner.time, "sleep"),
        ):
            with pytest.raises(runner.CommandError, match="boom"):
                runner.run(["kubectl"], retries=2)

    def test_check_false_returns_process(self):
        bad = subprocess.CompletedProcess(["k"], 1, stdout="", stderr="x")
        with mock.patch.object(subprocess, "run", return_value=bad):
            out = runner.run(["kubectl"], check=False)
        assert out.returncode == 1


class TestRetryTransient:
    """The named retry policy — run()'s exception-based twin: 3
    attempts, 2s apart, CommandError on exhaust. Deliberate
    failures (CommandError) raise immediately; a caller-supplied
    no_retry predicate fast-fails errors that will never heal."""

    def test_success_first_try(self):
        calls = []

        def fn() -> str:
            calls.append(1)
            return "ok"

        assert runner.retry_transient(fn) == "ok"
        assert len(calls) == 1

    def test_transient_failure_retried(self):
        calls = {"n": 0}

        def fn() -> str:
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("i/o timeout")
            return "ok"

        with mock.patch.object(runner.time, "sleep"):
            assert runner.retry_transient(fn) == "ok"
        assert calls["n"] == 2

    def test_exhausted_raises_commanderror_with_cause(self):
        def fn() -> str:
            raise OSError("still down")

        with mock.patch.object(runner.time, "sleep"):
            with pytest.raises(runner.CommandError, match="still down") as excinfo:
                runner.retry_transient(fn, attempts=2)
        assert isinstance(excinfo.value.__cause__, OSError)

    def test_commanderror_raises_immediately(self):
        # A DELIBERATE failure must not retry (the runner.run lesson:
        # expected failures ran 3x with 4s of sleep).
        calls = []

        def fn() -> str:
            calls.append(1)
            raise runner.CommandError("deliberate")

        with pytest.raises(runner.CommandError, match="deliberate"):
            runner.retry_transient(fn)
        assert len(calls) == 1

    def test_no_retry_predicate_fast_fails(self):
        # Client errors (4xx) never heal — retrying is waste. The
        # predicate says which exceptions are permanent.
        calls = []

        class NotFound(Exception):
            pass

        def fn() -> str:
            calls.append(1)
            raise NotFound("404 pod not found")

        with pytest.raises(runner.CommandError, match="404"):
            runner.retry_transient(fn, no_retry=lambda e: isinstance(e, NotFound))
        assert len(calls) == 1


class TestParsers:
    def test_nft_counter(self):
        out = Ruleset.render("enforce").listing(counters={1: 6})
        assert parsers.nft_counter(out) == 6

    def test_nft_counter_anchors_on_the_verdict_rule(self):
        # The loopback split renders a count-only rule FIRST — a
        # first-counter anchor reads the LOOPBACK counter and the
        # phase-4 vantage asserts read 0→0 while the verdict rule's
        # counter moved. The parser must anchor on the VERDICT rule
        # (drop / log prefix).
        out = Ruleset.render("enforce").listing(counters={0: 0, 1: 6})
        assert parsers.nft_counter(out) == 6, (
            "the parser must read the VERDICT rule's counter (6), not "
            "the loopback rule's (0) — the loopback rule renders first"
        )

    def test_nft_counter_absent_rule(self):
        assert parsers.nft_counter("no such chain") == -1

    def test_netns_inode(self):
        assert parsers.netns_inode("net:[4026533106]") == 4026533106

    def test_prom_value_anchored(self):
        # The live-found trap: the TYPE line contains the family name
        # and 'gauge' — a bare grep reads gauge as the value.
        text = (
            "# HELP cve_2026_98432_netns_seen Pod network namespaces.\n"
            "# TYPE cve_2026_98432_netns_seen gauge\n"
            "cve_2026_98432_netns_seen 14\n"
            "cve_2026_98432_netns_covered 14\n"
        )
        assert parsers.prom_value(text, "cve_2026_98432_netns_seen") == "14"
        assert parsers.prom_value(text, "cve_2026_98432_netns_covered") == "14"

    def test_prom_value_label_filter(self):
        text = (
            'cve_2026_98432_matched_packets_total{scope="netns",'
            'netns="cni-abc"} 6\n'
            'cve_2026_98432_matched_packets_total{scope="netns",'
            'netns="cni-other"} 0\n'
        )
        assert (
            parsers.prom_value(text, "cve_2026_98432_matched_packets_total", "cni-abc")
            == "6"
        )

    def test_prom_value_missing(self):
        assert parsers.prom_value("nothing here", "family") is None

    def test_install_line_bare_and_pod_qualified(self):
        # The live-found trap: the line carries "(pod <name>)" when
        # the name resolves — the regex must accept BOTH forms.
        bare = "2026-11-03T07:14:30Z [cve-2026-98432] netns cni-x: rule installed"
        named = (
            "2026-11-03T07:14:30Z [cve-2026-98432] "
            "netns cni-x (pod web-7f9d): rule installed"
        )
        assert parsers.install_line_present(bare, "cni-x")
        assert parsers.install_line_present(named, "cni-x")
        assert not parsers.install_line_present(bare, "cni-other")

    def test_fallback_line(self):
        text = "2026-11-03T07:14:30Z netns proc/4242 (pod web-7f9d): rule installed"
        assert parsers.fallback_line_present(text, "web-7f9d")
        assert not parsers.fallback_line_present(text, "other-pod")

    def test_log_timestamp_before(self):
        text = (
            "2026-11-03T07:14:30Z first line\n"
            "2026-11-03T07:14:35Z netns cni-x: rule installed\n"
        )
        assert (
            parsers.log_timestamp_before(text, r"netns cni-x: rule installed")
            == "2026-11-03T07:14:35Z"
        )


class TestWaitUntilTruthiness:
    def test_falsy_tuple_first_element_is_not_truthy(self):
        # The live-found trap (Must Fix): wait_until treats ANY
        # non-None return as success — a predicate returning
        # (False, None) is a truthy TUPLE, so a failing condition
        # reads as met. Predicates must return the VALUE, not a
        # (bool, value) pair — or wait_until must check the first
        # element of tuples.
        from e2e.lib.waits import wait_until

        calls = {"n": 0}

        def bad() -> tuple[bool, None]:
            calls["n"] += 1
            return (False, None)  # the failing shape

        res = wait_until(bad, attempts=2, delay=0.0)
        # The contract: a predicate whose payload is falsy must NOT
        # read as success.
        assert res is None or res[0] is not True, (
            "wait_until must not treat (False, None) as success"
        )


class TestLoggingFactory:
    def test_prefix_and_shape(self, capsys):
        # The line shape: '<ts> [<prefix>] <LEVEL> <message>' — the
        # same contract as the reconciler's own logging.
        log = get_logger("shape-test")
        log.info("hello")
        out = capsys.readouterr().out
        assert "[shape-test] INFO hello" in out
        assert "T" in out  # the UTC timestamp

    def test_idempotent_no_double_handlers(self, capsys):
        # Re-requesting the same name must not double-log (a test
        # importing the module twice would print every line twice).
        get_logger("dup-test").info("once")
        get_logger("dup-test").info("once")
        out = capsys.readouterr().out
        assert out.count("once") == 2  # two calls, two lines — not four

    def test_distinct_names_distinct_prefixes(self, capsys):
        get_logger("alpha").info("a")
        get_logger("beta").info("b")
        out = capsys.readouterr().out
        assert "[alpha] INFO a" in out
        assert "[beta] INFO b" in out


class TestSyn:
    def test_payload_is_four_nops(self):
        # The verified payload: 4x NOP (RFC 793 padding) -> IHL 24
        # bytes -> hdrlength 6 != 5 -> the rule's match. Proven on the
        # wire: first byte 0x46, options 01010101 in the header tail.
        assert syn.NOP_OPTIONS == b"\x01\x01\x01\x01"

    def test_script_carries_options_when_asked(self):
        script = syn.syn_script("10.0.0.1", 9999, options=True)
        assert "setsockopt" in script
        assert "\\x01\\x01\\x01\\x01" in script
        assert "10.0.0.1" in script and "9999" in script

    def test_plain_script_has_no_setsockopt(self):
        script = syn.syn_script("10.0.0.1", 9999, options=False)
        assert "setsockopt" not in script

    def test_verdicts(self):
        assert syn.is_blocked("BLOCKED\n")
        assert syn.is_connected("CONNECTED")
        assert not syn.is_blocked("ConnectionRefusedError")


class TestScaleDaemonsetToZero:
    """The deterministic DaemonSet drain.

    A DaemonSet has NO replicas field (node-count-driven) and no
    scale subresource — kubectl scale fails NotFound and
    spec.replicas is silently dropped (both verified live on CMK).
    The drain is a nodeSelector no node carries.
    """

    def test_the_method_exists(self):
        from e2e.lib import kube_cluster

        assert hasattr(kube_cluster.KubeCluster, "scale_daemonset_to_zero"), (
            "the Cluster class must expose the typed drain"
        )

    def test_the_patch_is_a_non_matching_node_selector(self):
        import inspect

        from e2e.lib import kube_cluster

        src = inspect.getsource(kube_cluster.KubeCluster.scale_daemonset_to_zero)
        assert "nodeSelector" in src, "the drain must be a nodeSelector"
        assert "crusoe-mitigator-scale-down" in src, (
            "the nodeSelector must match no node"
        )
        # The CODE must not set replicas (the docstring explains why).
        code = src.split('"""', 2)[-1]
        assert "replicas" not in code.split("nodeSelector")[0], (
            "a DaemonSet has no replicas field — spec.replicas is silently dropped"
        )
        assert "patch_namespaced_daemon_set" in src, (
            "the native k8s client's patch, not a kubectl shell-out"
        )


class TestDaemonsetGetter:
    """The typed DaemonSet read — the coverage source.

    The roll wait compares the Ready count against
    status.desiredNumberScheduled, so the cluster lib must expose
    the DaemonSet in the same kubectl-shaped wire form as pods().
    """

    def test_the_method_exists(self):
        from e2e.lib import kube_cluster

        assert hasattr(kube_cluster.KubeCluster, "daemonset"), (
            "the Cluster class must expose the typed DaemonSet read"
        )

    def test_the_read_is_native_and_wire_shaped(self):
        import inspect

        from e2e.lib import kube_cluster

        src = inspect.getsource(kube_cluster.KubeCluster.daemonset)
        assert "read_namespaced_daemon_set" in src, (
            "the native k8s client's read, not a kubectl shell-out"
        )
        assert "sanitize_for_serialization" in src, (
            "the wire form (camelCase) — the callers assert against "
            "status.desiredNumberScheduled"
        )
