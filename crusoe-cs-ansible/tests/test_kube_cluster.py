"""Unit tests for the native-client Cluster (KubeCluster).

Tested with FAKES: a stub kubernetes client module injected via
sys.modules — no cluster needed. The public interface is IDENTICAL
to the subprocess Cluster (the callers don't change); these tests
pin the native transport's behavior: exec rc/stdout/stderr as
first-class values, watch-based waits, the explicit context.
"""

from __future__ import annotations

import types

import pytest


class _FakeApiClient:
    @staticmethod
    def sanitize_for_serialization(obj: object) -> object:
        # The fake pods are already dicts — pass through
        return obj._d if isinstance(obj, _FakeV1Pod) else obj


class _FakeV1PodList:
    def __init__(self, items: list[dict]) -> None:
        self.items = items


class _FakeV1Pod:
    def __init__(self, d: dict) -> None:
        self._d = d

    def to_dict(self) -> dict:
        return self._d


class _FakeWSClient:
    """Mimics kubernetes.stream.ws_client.WSClient — the REAL shape
    the transport must consume: stream() with _preload_content=False
    returns this object; the rc lives HERE (returncode), parsed from
    the error channel, NOT in the preloaded str (which is stdout+
    stderr joined and carries no rc — found by reading the client's
    source: the str path hardcodes rc 0 and exec_rc/exec_ok lie)."""

    def __init__(self, stdout: str = "", stderr: str = "", rc: int = 0) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._rc = rc
        self.run_forever_calls: list[dict] = []

    def run_forever(self, timeout: float | None = None) -> None:
        self.run_forever_calls.append({"timeout": timeout})

    def read_channel(self, channel: int) -> str:
        if channel == 1:
            return self._stdout
        if channel == 2:
            return self._stderr
        return ""

    @property
    def returncode(self) -> int:
        return self._rc


class _FakeCoreV1:
    """The surface KubeCluster uses, stubbed."""

    def __init__(self) -> None:
        self.exec_calls: list[tuple] = []
        self.pods: list[dict] = []
        self.exec_result: _FakeWSClient = _FakeWSClient(stdout="fake-output", rc=0)
        self.exec_kwargs: list[dict] = []
        self.last_ws: _FakeWSClient | None = None

    def list_namespaced_pod(self, namespace: str, **kwargs: object) -> _FakeV1PodList:
        return _FakeV1PodList([_FakeV1Pod(p) for p in self.pods])  # type: ignore[misc]

    def connect_get_namespaced_pod_exec(
        self, name: str, namespace: str, container: str, command: list, **kwargs
    ):
        self.exec_calls.append((name, namespace, container, tuple(command)))
        self.exec_kwargs.append(dict(kwargs))
        ws = _FakeWSClient(
            stdout=self.exec_result._stdout,
            stderr=self.exec_result._stderr,
            rc=self.exec_result._rc,
        )
        self.last_ws = ws
        return ws


class _FakeClientModule(types.ModuleType):
    def __init__(self) -> None:
        super().__init__("kubernetes")
        self.config = types.SimpleNamespace(
            load_kube_config=self._load_kube_config,
            context=None,
        )
        self.client = types.SimpleNamespace(
            CoreV1Api=_FakeCoreV1, ApiClient=_FakeApiClient
        )
        # stream: a MODULE with a .stream function — the real
        # kubernetes.stream is a module; `from kubernetes import
        # stream` binds the module, and the call is stream.stream()
        self.stream = types.ModuleType("kubernetes.stream")
        self.stream.stream = _fake_stream  # type: ignore[attr-defined]
        self.watch = types.SimpleNamespace(Watch=self._FakeWatch)
        self.config_loaded_with: str | None = None

    def _load_kube_config(self, context: str | None = None, **kwargs) -> None:
        self.config_loaded_with = context

    class _FakeWatch:
        @staticmethod
        def stream(*args, **kwargs):
            return iter([])


def _fake_stream(call, *args, **kwargs):
    return call(*args, **kwargs)


class _FakeApiException(Exception):
    """Mimics kubernetes.client.rest.ApiException — the client's
    stream() wraps websocket handshake failures in ApiException
    (status=0): 'container not found', exec-able-not-yet, API blips."""

    def __init__(self, reason: str = "", status: int = 0) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@pytest.fixture()
def fake_k8s(monkeypatch):
    """Patch the REAL module's attributes — kube_cluster binds
    `from kubernetes import client/config` at import time, so
    swapping sys.modules entries does nothing once the real module
    is cached (the cve contract tests importlib-load cmk_live first,
    caching it). Attribute patching works regardless of order."""
    import kubernetes

    mod = _FakeClientModule()
    monkeypatch.setattr(kubernetes, "client", mod.client)
    monkeypatch.setattr(kubernetes, "config", mod.config)
    monkeypatch.setattr(kubernetes, "stream", mod.stream)
    monkeypatch.setattr(kubernetes, "watch", mod.watch)
    # kube_cluster binds `from kubernetes import client/config` at
    # ITS module level — rebind those names too, or the real ones
    # stay live (order-dependent: the cve contract tests load
    # cmk_live -> kube_cluster before this file runs).
    import e2e.lib.kube_cluster as kc

    monkeypatch.setattr(kc, "k8s_client", mod.client)
    monkeypatch.setattr(kc, "k8s_config", mod.config)
    monkeypatch.setattr(kc, "watch", mod.watch)
    return mod


class TestKubeClusterContext:
    def test_context_pinned_at_construction(self, fake_k8s):
        # The live-found trap: kubeconfig context resolution differs
        # from kubectl's — the context must be EXPLICIT, pinned at
        # construction, and fail loudly on mismatch.
        from e2e.lib.kube_cluster import KubeCluster

        KubeCluster(context="cmk-saguilarg")
        assert fake_k8s.config_loaded_with == "cmk-saguilarg"

    def test_default_context_loads_current(self, fake_k8s):
        from e2e.lib.kube_cluster import KubeCluster

        KubeCluster()
        assert fake_k8s.config_loaded_with is None


class TestKubeClusterExec:
    def test_exec_returns_stdout(self, fake_k8s):
        from e2e.lib.kube_cluster import KubeCluster

        c = KubeCluster()
        out = c.exec("pod1", "container1", "ns1", "echo", "hi")
        assert out == "fake-output"

    def test_exec_command_assembled(self, fake_k8s):
        from e2e.lib.kube_cluster import KubeCluster

        c = KubeCluster()
        c.exec("pod1", "c1", "ns1", "nsenter", "--net=/host/run/netns/x", "nft")
        # The fake CoreV1Api is a class; instances record calls — the
        # KubeCluster holds ONE instance; reach it via the cluster.
        assert c._api.exec_calls[-1] == (
            "pod1",
            "ns1",
            "c1",
            ("nsenter", "--net=/host/run/netns/x", "nft"),
        )

    def test_exec_rc_first_class(self, fake_k8s):
        # The review-bug killer: the rc is a first-class value, not
        # argv plumbing. rc 0 = success; non-zero raises (check=True)
        # or returns (check=False).
        from e2e.lib.kube_cluster import KubeCluster

        c = KubeCluster()
        c._api.exec_result = _FakeWSClient(stdout="out", rc=3)
        out = c.exec("p", "c", "ns", "cmd", check=False)
        assert out == "out"
        rc = c.exec_rc("p", "c", "ns", "cmd")
        assert rc == 3

    def test_exec_rc_nonzero_raises_on_check(self, fake_k8s):
        # exec(check=True) must RAISE on a non-zero rc — the str
        # path's hardcoded rc 0 meant it never raised (found by
        # reading the client's source: _preload_content=True returns
        # a str with no rc; the rc lives on the WSClient).
        from e2e.lib.kube_cluster import KubeCluster
        from e2e.lib.runner import CommandError

        c = KubeCluster()
        c._api.exec_result = _FakeWSClient(stdout="out", rc=7)
        with pytest.raises(CommandError):
            c.exec("p", "c", "ns", "cmd")

    def test_exec_ok_false_on_nonzero_rc(self, fake_k8s):
        # exec_ok must reflect the rc — the hardcoded rc 0 made it
        # vacuously True (the two-surface checks boot_unit_enabled/
        # host_rule_loaded would pass on a broken node).
        from e2e.lib.kube_cluster import KubeCluster

        c = KubeCluster()
        c._api.exec_result = _FakeWSClient(stdout="", rc=1)
        assert c.exec_ok("p", "c", "ns", "false") is False

    def test_exec_stream_uses_raw_wsclient(self, fake_k8s):
        # The REAL client's contract: the rc is only available with
        # _preload_content=False, which returns the WSClient — the
        # preloaded str path carries NO rc. The transport must use
        # the raw form.
        from e2e.lib.kube_cluster import KubeCluster

        c = KubeCluster()
        c.exec("p", "c", "ns", "cmd")
        kwargs = c._api.exec_kwargs[-1]
        assert kwargs.get("_preload_content") is False
        # run_forever must be called on the per-call WSClient — the
        # exec must run to completion before the rc is read.
        assert c._api.last_ws.run_forever_calls == [{"timeout": None}]

    def test_exec_retries_transport_errors(self, fake_k8s):
        # The API-blip contract the subprocess Cluster had via
        # runner.run: stream() wraps websocket handshake failures in
        # ApiException(status=0) — 'container not found' right after
        # phase=Running, API blips mid-reboot. exec must RETRY them
        # (found by review: the exception escaped and crashed the
        # exec-settle loop instead of retrying).
        from e2e.lib.kube_cluster import KubeCluster

        c = KubeCluster()
        calls = {"n": 0}

        def _flaky_stream(call, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise _FakeApiException("container not found")
            return call(*args, **kwargs)

        fake_k8s.stream.stream = _flaky_stream  # type: ignore[attr-defined]
        out = c.exec("p", "c", "ns", "cmd")
        assert out == "fake-output"
        assert calls["n"] == 2

    def test_exec_transport_error_exhausts_to_commanderror(self, fake_k8s):
        # After the retries are exhausted the caller gets the
        # foundation's contract: CommandError — never a raw
        # ApiException escaping through exec/exec_ok/exec_rc.
        from e2e.lib.kube_cluster import KubeCluster
        from e2e.lib.runner import CommandError

        c = KubeCluster()

        def _always_fails(call, *args, **kwargs):
            raise _FakeApiException("container not found")

        fake_k8s.stream.stream = _always_fails  # type: ignore[attr-defined]
        with pytest.raises(CommandError):
            c.exec("p", "c", "ns", "cmd")
        with pytest.raises(CommandError):
            c.exec_rc("p", "c", "ns", "cmd")
        with pytest.raises(CommandError):
            c.exec_ok("p", "c", "ns", "cmd")

    def test_exec_4xx_fast_fails_no_retry(self, fake_k8s):
        # Client errors never heal: a 404 pod retried 3x with 2s
        # sleeps is pure waste. The transport fast-fails on 4xx —
        # ONE attempt, CommandError. The client wraps the real
        # status in ApiException(status=0) with the handshake in
        # the reason string (found live: the status attr is 0, the
        # fast-fail never fired until the reason was parsed).
        from e2e.lib.kube_cluster import KubeCluster
        from e2e.lib.runner import CommandError

        c = KubeCluster()
        calls = {"n": 0}

        def _not_found(call, *args, **kwargs):
            calls["n"] += 1
            raise _FakeApiException(
                "Handshake status 404 Not Found -+-+- pods not found", status=0
            )

        fake_k8s.stream.stream = _not_found  # type: ignore[attr-defined]
        with pytest.raises(CommandError, match="permanent"):
            c.exec("p", "c", "ns", "cmd")
        assert calls["n"] == 1


class TestKubeClusterWaits:
    def test_wait_phase_timeout_raises_commanderror(self, fake_k8s):
        # The live-found trap: the watch generator propagates a raw
        # urllib3 ReadTimeoutError when _request_timeout fires with
        # no events — callers catch CommandError (the foundation's
        # contract), so a raw urllib3 error would crash them. The
        # timeout must surface as CommandError.
        from e2e.lib.kube_cluster import KubeCluster
        from e2e.lib.runner import CommandError

        class _Boom(Exception):
            pass

        def _raise_timeout(*args, **kwargs):
            raise _Boom("simulated urllib3 timeout")

        fake_k8s.watch.Watch = lambda: types.SimpleNamespace(
            stream=_raise_timeout, stop=lambda: None
        )
        c = KubeCluster()
        with pytest.raises(CommandError):
            c.wait_phase("p", "ns", timeout=5)


class TestKubeClusterGets:
    def test_pods_returns_dicts(self, fake_k8s):
        from e2e.lib.kube_cluster import KubeCluster

        c = KubeCluster()
        c._api.pods = [{"metadata": {"name": "p1"}}]
        pods = c.pods("ns")
        assert pods == [{"metadata": {"name": "p1"}}]
