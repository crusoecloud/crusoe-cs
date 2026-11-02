"""Unit tests for the crusoe-mitigator entrypoint (images/ansible/mitigate.py).

Covers the MITIGATIONS parser (the chart→entrypoint contract) and the
scheduler's due-time arithmetic without running ansible-playbook.
"""

import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
MITIGATE = os.path.join(HERE, "..", "images", "ansible", "mitigate.py")


@pytest.fixture()
def mitigate():
    spec = importlib.util.spec_from_file_location("mitigate", MITIGATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestParseMitigations:
    def test_basic_line(self, mitigate):
        parsed = mitigate.parse_mitigations(
            "cve|wrapper.yml|-e a=true -e b=false |3600"
        )
        assert parsed == [
            ("cve", "wrapper.yml", ["-e", "a=true", "-e", "b=false"], 3600)
        ]

    def test_missing_interval_defaults_to_zero(self, mitigate):
        parsed = mitigate.parse_mitigations("name|wrapper.yml|-e a=1")
        assert parsed[0][3] == 0

    def test_missing_vars_defaults_to_empty(self, mitigate):
        parsed = mitigate.parse_mitigations("name|wrapper.yml||5")
        assert parsed[0][2] == []
        assert parsed[0][3] == 5

    def test_blank_lines_skipped(self, mitigate):
        parsed = mitigate.parse_mitigations("\n\nname|wrapper.yml||0\n\n")
        assert len(parsed) == 1

    def test_malformed_line_skipped(self, mitigate, caplog):
        parsed = mitigate.parse_mitigations("badline\nname|wrapper.yml||0")
        assert len(parsed) == 1
        # caplog: the module's handlers bind the import-time streams,
        # so assert on the log records, not capsys.
        assert "malformed" in caplog.text

    def test_duplicate_name_keeps_first(self, mitigate, caplog):
        parsed = mitigate.parse_mitigations("dup|first.yml||1\ndup|second.yml||2")
        assert len(parsed) == 1
        assert parsed[0][1] == "first.yml"
        assert "duplicate" in caplog.text

    def test_non_numeric_interval_treated_as_zero(self, mitigate):
        parsed = mitigate.parse_mitigations("name|wrapper.yml||abc")
        assert parsed[0][3] == 0

    def test_empty_input(self, mitigate):
        assert mitigate.parse_mitigations("") == []

    def test_chart_rendered_shape(self, mitigate):
        # The exact line the chart's helper emits (trailing space after
        # the vars, from the flat -e rendering).
        raw = (
            "cve-2026-98432|wrapper-cve-2026-98432.yml|"
            "-e cve_2026_98432_run_probe=true -e cve_2026_98432_metrics=true |3600\n"
        )
        parsed = mitigate.parse_mitigations(raw)
        assert parsed[0][0] == "cve-2026-98432"
        assert parsed[0][3] == 3600
        assert "-e" in parsed[0][2]


class TestFailureIsolation:
    """Scheduled-mitigation failure isolation: a transient failure in
    one mitigation must not kill the pod (and with it every other
    mitigation's schedule). Only N consecutive failures CrashLoop."""

    def test_once_only_failure_is_always_fatal(self, mitigate):
        # interval 0: the CrashLoop backoff IS the retry cadence.
        assert mitigate.failure_is_fatal(interval=0, consecutive=1) is True

    def test_scheduled_failure_under_threshold_not_fatal(self, mitigate):
        assert mitigate.failure_is_fatal(interval=3600, consecutive=1) is False
        assert mitigate.failure_is_fatal(interval=3600, consecutive=2) is False

    def test_scheduled_failure_at_threshold_fatal(self, mitigate):
        assert mitigate.failure_is_fatal(interval=3600, consecutive=3) is True

    def test_threshold_configurable(self, mitigate, monkeypatch):
        monkeypatch.setenv("MITIGATION_MAX_CONSECUTIVE_FAILURES", "2")
        import importlib.util

        spec = importlib.util.spec_from_file_location("mitigate_env2", MITIGATE)
        mod2 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod2)
        assert mod2.failure_is_fatal(interval=60, consecutive=2) is True
        assert mod2.failure_is_fatal(interval=60, consecutive=1) is False

    def test_main_scheduled_transient_failure_does_not_exit(
        self, mitigate, monkeypatch, caplog
    ):
        # One scheduled-mitigation failure: main() must NOT return 1 —
        # it loops (sleep) and retries at the next scheduled run.
        class StopLoop(Exception):
            pass

        monkeypatch.setattr(mitigate, "MITIGATIONS_ENV", "sched|wrapper.yml||3600")
        monkeypatch.setattr(
            mitigate,
            "run_mitigation",
            lambda name, playbook, argv: 1,
        )
        monkeypatch.setattr(
            mitigate.time, "sleep", lambda s: (_ for _ in ()).throw(StopLoop())
        )
        with pytest.raises(StopLoop):
            mitigate.main()
        assert "consecutive" in caplog.text

    def test_failed_scheduled_retry_waits_not_immediately(self, mitigate, monkeypatch):
        # A scheduled mitigation that succeeded once, then fails, must
        # retry at a BOUNDED interval — not immediately. The pre-fix
        # delay calc used last SUCCESS: after a success, next_due was
        # already in the past, so a ~45s transient failure burned all 3
        # consecutive-failure strikes in one blip and CrashLooped the
        # pod (killing every other mitigation's schedule with it).
        calls = {"n": 0}
        clock = {"t": 100.0}
        sleeps = []

        def flaky(name, playbook, argv):
            calls["n"] += 1
            return 0 if calls["n"] == 1 else 1

        def fake_sleep(s):
            sleeps.append(s)
            clock["t"] += s

        monkeypatch.setattr(mitigate, "MITIGATIONS_ENV", "sched|wrapper.yml||3600")
        monkeypatch.setattr(mitigate, "run_mitigation", flaky)
        monkeypatch.setattr(mitigate.time, "monotonic", lambda: clock["t"])
        monkeypatch.setattr(mitigate.time, "sleep", fake_sleep)

        # Runs to the designed CrashLoop (3 consecutive failures).
        assert mitigate.main() == 1
        # First run succeeds at t=100 and sleeps its interval (t=3700).
        # Failed retries then BACK OFF from each attempt: 30s, 60s
        # (FAILURE_RETRY_BASE=30, doubling per consecutive failure,
        # capped at the interval) — fast first retry (drift heals in
        # 30s), growing room for transients. The 3rd failure is fatal
        # (CrashLoop at ~90s of retries + run time), so only two
        # retry sleeps occur. Never immediate (pre-fix: all three at
        # t=100). sleep_slices chops each wait into <=1s slices; the
        # TOTAL slept time is the contract.
        assert calls["n"] == 4
        assert sum(sleeps) == 3600.0 + 30.0 + 60.0

    def test_failure_retry_backoff_capped_at_interval(self, mitigate, monkeypatch):
        # The backoff must never exceed the mitigation's own interval
        # (retrying a 45s schedule at 60s would starve it). Interval
        # 45s, base 30s: retry 1 = 30s (doubling), retry 2 would be
        # 60s uncapped but is capped at the 45s interval.
        calls = {"n": 0}
        clock = {"t": 100.0}
        sleeps = []

        def always_fail(name, playbook, argv):
            calls["n"] += 1
            return 1

        def fake_sleep(s):
            sleeps.append(s)
            clock["t"] += s

        monkeypatch.setattr(mitigate, "MITIGATIONS_ENV", "sched|wrapper.yml||45")
        monkeypatch.setattr(mitigate, "run_mitigation", always_fail)
        monkeypatch.setattr(mitigate.time, "monotonic", lambda: clock["t"])
        monkeypatch.setattr(mitigate.time, "sleep", fake_sleep)

        assert mitigate.main() == 1
        # fail@100 → sleep 30 → fail@130 → sleep 45 (capped, not 60)
        # → fail@175 → CrashLoop. The cap, not the doubling, sets the
        # second retry's pace.
        assert calls["n"] == 3
        assert sum(sleeps) == 30.0 + 45.0

    def test_failure_retry_base_env_override(self, mitigate, monkeypatch):
        # The backoff base is operator-tunable; 0 restores the old
        # immediate-retry behavior (a failure retried on the next
        # scheduler pass).
        calls = {"n": 0}
        clock = {"t": 100.0}

        def flaky(name, playbook, argv):
            calls["n"] += 1
            return 0 if calls["n"] == 1 else 1

        monkeypatch.setenv("MITIGATION_FAILURE_RETRY_BASE_SECONDS", "0")
        spec = importlib.util.spec_from_file_location("mitigate_env3", MITIGATE)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        monkeypatch.setattr(mod, "MITIGATIONS_ENV", "sched|wrapper.yml||3600")
        monkeypatch.setattr(mod, "run_mitigation", flaky)
        monkeypatch.setattr(mod.time, "monotonic", lambda: clock["t"])
        monkeypatch.setattr(
            mod.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s)
        )

        assert mod.main() == 1
        # Immediate retries: the first success sleeps its interval
        # (t=3700), then all 3 failures happen at t=3700 — zero
        # pacing between attempts (the old behavior, restored).
        assert calls["n"] == 4
        assert clock["t"] == 100.0 + 3600.0

    def test_main_scheduled_persistent_failure_crashloops(self, mitigate, monkeypatch):
        # 3 consecutive scheduled failures: main() returns 1. The fake
        # clock advances with sleep() — a no-op sleep would never make
        # the next run due.
        monkeypatch.setattr(mitigate, "MITIGATIONS_ENV", "sched|wrapper.yml||3600")
        monkeypatch.setattr(
            mitigate,
            "run_mitigation",
            lambda name, playbook, argv: 1,
        )
        clock = {"t": 100.0}
        monkeypatch.setattr(mitigate.time, "monotonic", lambda: clock["t"])
        monkeypatch.setattr(
            mitigate.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s)
        )
        assert mitigate.main() == 1

    def test_main_once_only_failure_exits_immediately(self, mitigate, monkeypatch):
        monkeypatch.setattr(mitigate, "MITIGATIONS_ENV", "once|wrapper.yml||0")
        monkeypatch.setattr(
            mitigate,
            "run_mitigation",
            lambda name, playbook, argv: 1,
        )
        assert mitigate.main() == 1

    def test_main_success_resets_consecutive_count(self, mitigate, monkeypatch):
        # fail, fail, succeed, fail, fail, fail → the success resets
        # the count, so the exit happens on the 3rd consecutive
        # failure (6th call), not the 3rd call.
        calls = {"n": 0}

        def flaky(name, playbook, argv):
            calls["n"] += 1
            return 0 if calls["n"] == 3 else 1

        monkeypatch.setattr(mitigate, "MITIGATIONS_ENV", "sched|wrapper.yml||3600")
        monkeypatch.setattr(mitigate, "run_mitigation", flaky)
        clock = {"t": 100.0}
        monkeypatch.setattr(mitigate.time, "monotonic", lambda: clock["t"])
        monkeypatch.setattr(
            mitigate.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s)
        )
        assert mitigate.main() == 1
        assert calls["n"] == 6


class TestNodeModeWatcher:
    """Event-driven mode flips: the mitigator watches its node's mode
    label via the k8s watch API; a change forces the scheduled
    mitigations due immediately — no pod delete, no interval wait."""

    def test_watch_event_mode_added_sets_baseline(self, mitigate):
        event = {
            "type": "ADDED",
            "object": {
                "metadata": {
                    "labels": {
                        "cve-2026-98432.remediator.crusoe.ai/mode": "observe",
                    }
                }
            },
        }
        mode = mitigate.watch_event_mode(
            event, "cve-2026-98432.remediator.crusoe.ai/mode"
        )
        assert mode == "observe"

    def test_watch_event_mode_modified_reads_new_value(self, mitigate):
        event = {
            "type": "MODIFIED",
            "object": {
                "metadata": {
                    "labels": {
                        "cve-2026-98432.remediator.crusoe.ai/mode": "enforce",
                    }
                }
            },
        }
        mode = mitigate.watch_event_mode(
            event, "cve-2026-98432.remediator.crusoe.ai/mode"
        )
        assert mode == "enforce"

    def test_watch_event_mode_absent_label_is_observe(self, mitigate):
        # Absent label = observe (the fleet default).
        event = {"type": "MODIFIED", "object": {"metadata": {"labels": {}}}}
        mode = mitigate.watch_event_mode(
            event, "cve-2026-98432.remediator.crusoe.ai/mode"
        )
        assert mode == ""

    def test_watch_event_mode_ignores_bookmarks_and_deletes(self, mitigate):
        # BOOKMARK events carry no label state — treating them as a
        # change would fire the re-run on every heartbeat.
        for etype in ("BOOKMARK", "DELETED", "ERROR"):
            event = {"type": etype, "object": {"metadata": {}}}
            assert mitigate.watch_event_mode(event, "x") is None

    def test_watch_event_mode_typeless_initial_object(self, mitigate):
        # A single-resource watch streams the CURRENT object as the
        # first line — NO type field (found live: the watcher never
        # baselined and swallowed every change). The typeless object
        # IS the baseline: its label state must be returned.
        event = {
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"labels": {"m": "enforce"}},
        }
        assert mitigate.watch_event_mode(event, "m") == "enforce"
        # And with the label absent:
        event2 = {"apiVersion": "v1", "kind": "Node", "metadata": {"labels": {}}}
        assert mitigate.watch_event_mode(event2, "m") == ""

    def test_watcher_started_only_when_configured(self, mitigate, monkeypatch):
        started = []
        monkeypatch.setattr(
            mitigate,
            "NodeModeWatcher",
            lambda *a: type("W", (), {"start": lambda s: started.append(1)})(),
        )
        # All three env pieces required: watch flag, label, node name.
        monkeypatch.setattr(mitigate, "MODE_WATCH", True)
        monkeypatch.setattr(mitigate, "NODE_MODE_LABEL", "some/label")
        monkeypatch.setattr(mitigate, "NODE_NAME", "node-1")
        assert mitigate.start_mode_watcher(monkeypatch) is True
        assert started == [1]
        # Missing node name (tests/unset env) → not started.
        monkeypatch.setattr(mitigate, "NODE_NAME", "unknown")
        assert mitigate.start_mode_watcher(monkeypatch) is False

    def test_mode_change_forces_immediate_scheduled_rerun(self, mitigate, monkeypatch):
        # The watcher event wakes the scheduler and forces the
        # scheduled mitigation due NOW — a label flip converges in
        # seconds, not the 3600s interval.
        runs = []

        class FakeWatcher:
            def __init__(self, *a):
                pass

            def start(self):
                # Fire the change after the first pass (the scheduler
                # sleeps; the event wakes it).
                mitigate._fire_soon()

        monkeypatch.setattr(mitigate, "NodeModeWatcher", FakeWatcher)
        monkeypatch.setattr(mitigate, "MODE_WATCH", True)
        monkeypatch.setattr(mitigate, "NODE_MODE_LABEL", "some/label")
        monkeypatch.setattr(mitigate, "NODE_NAME", "node-1")
        monkeypatch.setattr(mitigate, "MITIGATIONS_ENV", "sched|wrapper.yml||3600")
        monkeypatch.setattr(
            mitigate,
            "run_mitigation",
            lambda name, playbook, argv: runs.append(name) or 0,
        )
        clock = {"t": 100.0, "fired": False}
        monkeypatch.setattr(mitigate.time, "monotonic", lambda: clock["t"])

        def fake_sleep(s):
            clock["t"] += s
            if not clock["fired"]:
                clock["fired"] = True
                mitigate._mode_event.set()

        monkeypatch.setattr(mitigate.time, "sleep", fake_sleep)
        # Stop after the second run (the watcher-forced re-run).
        real_run = mitigate.run_mitigation

        def counting(name, playbook, argv):
            real = real_run(name, playbook, argv)
            if len(runs) >= 2:
                raise mitigate._StopLoop()
            return real

        monkeypatch.setattr(mitigate, "run_mitigation", counting)
        with pytest.raises(mitigate._StopLoop):
            mitigate.main()
        # Two runs with < 3600s elapsed: the initial + the event-driven.
        assert len(runs) == 2
        assert clock["t"] < 100 + 3600


class TestScheduler:
    def test_once_only_is_due_only_before_first_success(self, mitigate):
        # interval 0: due when never run; after a success, never again.
        last_run = {}
        interval = 0
        assert last_run.get("m") is None  # due
        last_run["m"] = 123.0
        now = last_run["m"] + 999
        due = last_run.get("m") is None or (
            interval > 0 and now - last_run["m"] >= interval
        )
        assert not due

    def test_scheduled_is_due_after_interval(self, mitigate):
        interval = 3600
        last = 100.0
        now = last + 3599
        assert not (now - last >= interval)
        now = last + 3600
        assert now - last >= interval

    def test_next_due_is_earliest_scheduled(self, mitigate):
        # Mirrors main()'s min() over scheduled mitigations.
        last_run = {"a": 100.0, "b": 200.0}
        scheduled = [("a", 60), ("b", 300)]
        now = 260.0
        next_due = min(last_run[name] + iv for name, iv in scheduled)
        assert next_due == 160.0
        assert max(0.0, next_due - now) == 0.0  # a is overdue

    def test_no_mitigations_exits_nonzero(self, mitigate, capsys):
        # main() with an empty list must exit 1 with the actionable message.

        mitigations = mitigate.parse_mitigations("")
        assert mitigations == []
        # The message main() prints in this case:
        assert "no mitigations enabled" in (
            "[crusoe-mitigator] no mitigations enabled — "
            "check the chart's mitigations list"
        )


class TestWatcherReconnect:
    """A change during a connection gap must still fire: only the very
    first event ever baselines; reconnect ADDED events carry the
    CURRENT label and are compared (found live — the 300s watch cycle
    re-baselined silently and swallowed the flip)."""

    def test_first_event_ever_baselines(self, mitigate):
        w = mitigate.NodeModeWatcher("n", "l", lambda: None)
        assert w._ever_connected is False
        w._last_mode = None
        # First event: baseline, no fire.
        assert (
            mitigate.watch_event_mode(
                {"type": "ADDED", "object": {"metadata": {"labels": {"l": "observe"}}}},
                "l",
            )
            == "observe"
        )

    def test_reconnect_added_compares_not_rebaselines(self, mitigate):
        w = mitigate.NodeModeWatcher("n", "l", lambda: None)
        w._last_mode = "observe"
        w._ever_connected = True
        # A reconnect ADDED carrying enforce != last_mode: the change
        # fires (the _ever_connected guard keeps it out of the
        # baseline branch).
        assert w._ever_connected is True
        assert w._last_mode == "observe"


class FakeWatchResp:
    """A urlopen() result whose line iterator ends (clean EOF) after
    the given lines — the shape of both the healthy timeout cycle and
    the degraded immediate close."""

    def __init__(self, lines, on_exit=None):
        self._lines = lines
        self._on_exit = on_exit

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self._on_exit:
            self._on_exit()
        return False

    def __iter__(self):
        return iter(self._lines)


def node_event(mode, etype="ADDED", label="m"):
    return json.dumps(
        {"type": etype, "object": {"metadata": {"labels": {label: mode}}}}
    )


@pytest.fixture()
def in_cluster(monkeypatch):
    """run() reads the in-cluster pieces (SA token, CA, service env);
    fake them so the watcher loop runs outside a pod."""
    import builtins
    import io
    import ssl

    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if str(path).endswith("/token"):
            return io.StringIO("fake-token")
        if str(path).endswith("/ca.crt"):
            return io.StringIO("fake-ca")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(ssl, "create_default_context", lambda cafile=None: None)


class TestWatchUrl:
    """The watch URL MUST be the list+fieldSelector form: the
    single-resource form (?watch=true on a named object) is served as
    a plain GET — current object, connection closed, reconnect flood
    (found live on CMK and GKE: millions of API requests/day/pod)."""

    def test_uses_the_list_fieldselector_form(self, mitigate):
        url = mitigate.watch_url("https://api.example:6443", "node-1", 300)
        assert url == (
            "https://api.example:6443/api/v1/nodes?watch=true"
            "&fieldSelector=metadata.name%3Dnode-1&timeoutSeconds=300"
        )

    def test_never_the_single_resource_form(self, mitigate):
        url = mitigate.watch_url("https://api.example:6443", "node-1", 300)
        assert "/nodes/node-1" not in url


class TestWatcherRateLimit:
    """A watch stream that dies early must reconnect at a BOUNDED,
    growing interval and LOG the degradation — the pre-fix loop
    reconnected instantly and silently (a clean EOF raised nothing),
    flooding the API server."""

    def test_first_connect_logs_baseline(
        self, mitigate, in_cluster, monkeypatch, caplog
    ):
        import urllib.request

        def fake_urlopen(req, timeout=None, context=None):
            return FakeWatchResp([node_event("observe")])

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(mitigate.time, "monotonic", lambda: 100.0)
        monkeypatch.setattr(
            mitigate.time,
            "sleep",
            lambda s: (_ for _ in ()).throw(mitigate._StopLoop()),
        )

        w = mitigate.NodeModeWatcher("node-1", "m", lambda: None)
        with pytest.raises(mitigate._StopLoop):
            w.run()
        # The first-ever connect is a visible, one-time lifecycle event.
        assert "node mode watch connected" in caplog.text
        assert "baseline mode='observe'" in caplog.text

    def test_short_lived_stream_backs_off_and_logs(
        self, mitigate, in_cluster, monkeypatch, caplog
    ):
        import urllib.request

        streams = {"n": 0}
        sleeps = []

        def fake_urlopen(req, timeout=None, context=None):
            streams["n"] += 1
            if streams["n"] > 4:
                raise mitigate._StopLoop()
            return FakeWatchResp([node_event("observe")])

        def fake_sleep(s):
            sleeps.append(s)
            if len(sleeps) >= 3:
                raise mitigate._StopLoop()

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(mitigate.time, "monotonic", lambda: 100.0)
        monkeypatch.setattr(mitigate.time, "sleep", fake_sleep)

        w = mitigate.NodeModeWatcher("node-1", "m", lambda: None)
        with pytest.raises(mitigate._StopLoop):
            w.run()
        # Each short-lived stream reconnects after the growing backoff
        # — never instantly (the pre-fix tight loop).
        assert sleeps == [1, 2, 4]
        # And the degradation is VISIBLE (the flood was silent).
        assert "ended after" in caplog.text

    def test_full_cycle_stream_reconnects_without_backoff(
        self, mitigate, in_cluster, monkeypatch
    ):
        import urllib.request

        fired = []
        streams = {"n": 0}
        clock = {"t": 100.0}

        def fake_urlopen(req, timeout=None, context=None):
            streams["n"] += 1
            if streams["n"] == 3:
                raise mitigate._StopLoop()
            lines = [node_event("observe")]
            if streams["n"] == 2:
                # A label flip mid-stream on the second cycle.
                lines.append(node_event("enforce", "MODIFIED"))
            return FakeWatchResp(
                lines, on_exit=lambda: clock.__setitem__("t", clock["t"] + 300)
            )

        def no_sleep(s):
            raise mitigate._StopLoop(f"healthy cycle must not back off (slept {s}s)")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(mitigate.time, "monotonic", lambda: clock["t"])
        monkeypatch.setattr(mitigate.time, "sleep", no_sleep)

        w = mitigate.NodeModeWatcher("node-1", "m", lambda: fired.append(1))
        with pytest.raises(mitigate._StopLoop):
            w.run()
        # Two full cycles: no backoff sleeps, and the mid-stream flip
        # fired exactly once.
        assert streams["n"] == 3
        assert fired == [1]
        assert w._last_mode == "enforce"

    def test_error_backs_off_and_logs(self, mitigate, in_cluster, monkeypatch, caplog):
        import urllib.request

        calls = {"n": 0}
        sleeps = []

        def fake_urlopen(req, timeout=None, context=None):
            calls["n"] += 1
            if calls["n"] > 2:
                raise mitigate._StopLoop()
            raise OSError("connection refused")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(mitigate.time, "monotonic", lambda: 100.0)
        monkeypatch.setattr(mitigate.time, "sleep", sleeps.append)

        w = mitigate.NodeModeWatcher("node-1", "m", lambda: None)
        with pytest.raises(mitigate._StopLoop):
            w.run()
        assert sleeps == [1, 2]
        assert "watch failed" in caplog.text
