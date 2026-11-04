"""The native-client Cluster: same interface as cluster.Cluster,
backed by the kubernetes python client.

The migration destination (work item #2): exec is the hottest
operation (every vantage, counter read, probe) — the client's exec
stream gives rc/stdout/stderr as first-class values, killing the
argv plumbing where the two worst review bugs lived (the rc-0/2/3
hole, the env-flag bug). Waits go watch-based: event-driven blocks
instead of poll loops — the no-sleep rule becomes the platform's
behavior.

Stays CLI (delegated to the subprocess Cluster): kubectl apply
(server-side apply semantics are load-bearing), helm, the crusoe
CLI, and the kubectl-only deployment ops (create/patch/rollout).

The context is EXPLICIT: pinned at construction (kubeconfig context
resolution differs from kubectl's — found live: context switches
bit us twice in one session).
"""

from __future__ import annotations

import datetime as dt
import time
from collections.abc import Iterable
from typing import Any

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes import watch

from .cluster import Cluster
from .runner import CommandError, retry_transient


def _cpu_m(v: object) -> int:
    """Millicores: '250m' -> 250, 2 -> 2000."""
    s = str(v)
    return int(s[:-1]) if s.endswith("m") else int(float(s) * 1000)


class KubeCluster(Cluster):
    """The native transport. The public interface is IDENTICAL to
    the subprocess Cluster — callers (cmk-live.py, verify_new_node.py)
    don't change; only the construction site picks the transport."""

    def __init__(self, context: str | None = None) -> None:
        # The context is pinned HERE, once — every call after uses
        # the loaded api_client, immune to kubeconfig switches.
        k8s_config.load_kube_config(context=context)
        self._api = k8s_client.CoreV1Api()
        # The wire-shape serializer: the callers' contract is
        # KUBECTL-SHAPED dicts (camelCase keys — nodeName,
        # creationTimestamp). The client's to_dict() returns
        # snake_case; sanitize_for_serialization produces the exact
        # kubectl JSON shape (found live: nodeName read as None).
        self._wire = k8s_client.ApiClient()
        # The CLI escape hatch (apply, deployment ops) delegates to
        # the subprocess Cluster with the same context.
        self._cli = Cluster(context=context)

    # --- exec (the hottest operation) ---------------------------------
    def _exec_stream(
        self, pod: str, container: str, namespace: str, cmd: tuple[str, ...]
    ) -> dict[str, Any]:
        """One exec via the client's stream, rc/stdout/stderr as
        first-class values.

        The rc lives on the WSClient — only returned with
        _preload_content=False (found by reading the client's
        source: the preloaded form returns a str with stdout+stderr
        joined and NO rc; hardcoding rc 0 there made exec_rc/exec_ok
        lie). run_forever blocks until the exec completes, then
        read_channel gives stdout/stderr separately and returncode
        parses the status channel.

        Transport errors retry via retry_transient (the API-blip
        contract the subprocess Cluster had through runner.run —
        the client can't do it itself: exec bypasses the urllib3
        pool, and websocket_call wraps every failure in
        ApiException(status=0) and raises immediately). 4xx client
        errors fast-fail — a 404 pod will never heal."""

        def _once() -> dict[str, Any]:
            from kubernetes import stream as k8s_stream

            ws = k8s_stream.stream(
                self._api.connect_get_namespaced_pod_exec,
                pod,
                namespace,
                container=container,
                command=list(cmd),
                stdout=True,
                stderr=True,
                stdin=False,
                _preload_content=False,
            )
            ws.run_forever()
            return {
                "stdout": ws.read_channel(1),
                "stderr": ws.read_channel(2),
                "rc": ws.returncode,
            }

        def _permanent(e: Exception) -> bool:
            # The client wraps websocket handshake failures in
            # ApiException(status=0) — the REAL status is buried in
            # the reason string ("Handshake status 404 Not Found").
            # Client errors never heal: fast-fail them.
            status = getattr(e, "status", None)
            if isinstance(status, int) and 400 <= status <= 499:
                return True
            reason = str(getattr(e, "reason", "") or e)
            return "Handshake status 4" in reason[:24]

        return retry_transient(_once, no_retry=_permanent)

    def exec(
        self, pod: str, container: str, namespace: str, *cmd: str, check: bool = True
    ) -> str:
        """Exec into a container; stdout returned. check=True raises
        CommandError on a non-zero rc (the rc is first-class — no
        argv plumbing)."""
        result = self._exec_stream(pod, container, namespace, cmd)
        if check and result["rc"] != 0:
            raise CommandError(f"exec rc {result['rc']}: {' '.join(cmd)}")
        return result["stdout"]

    def exec_ok(self, pod: str, container: str, namespace: str, *cmd: str) -> bool:
        """True iff the exec exits 0."""
        return self._exec_stream(pod, container, namespace, cmd)["rc"] == 0

    def exec_rc(self, pod: str, container: str, namespace: str, *cmd: str) -> int:
        """The exit code (the probe contract: rc 1 = PASS, 0/2/3 =
        failure modes — only rc 1 passes)."""
        return self._exec_stream(pod, container, namespace, cmd)["rc"]

    # --- gets (typed, no parse) -----------------------------------------
    def pods(self, namespace: str) -> list[dict]:
        """All pods in a namespace — KUBECTL-SHAPED dicts (camelCase,
        the callers' contract; to_dict's snake_case broke nodeName)."""
        listing = self._api.list_namespaced_pod(namespace)
        return [self._wire.sanitize_for_serialization(p) for p in listing.items]

    def pod(self, name: str, namespace: str) -> dict:
        return self._wire.sanitize_for_serialization(
            self._api.read_namespaced_pod(name, namespace)
        )

    def pod_start_time(self, name: str, namespace: str) -> dt.datetime:
        """The pod's startTime as a tz-aware datetime — the client's
        NATIVE type (status.start_time carries tzinfo=UTC already;
        serializing to the wire dict and re-parsing the string
        throws it away and recreates the format duality)."""
        pod_obj = self._api.read_namespaced_pod(name, namespace)
        start = pod_obj.status.start_time if pod_obj.status else None
        if start is None:
            raise CommandError(f"pod {name} has no startTime")
        return start

    def nodes(self) -> list[dict]:
        listing = self._api.list_node()
        return [self._wire.sanitize_for_serialization(n) for n in listing.items]

    # --- waits (watch-based — event-driven, the no-sleep rule native) ---
    def wait_phase(self, pod: str, namespace: str, timeout: int = 60) -> None:
        """Wait for a pod to be Running — WATCH-based: block on the
        event stream, bounded by the timeout (the no-sleep rule as
        the platform's behavior, not a poll loop).

        The watch generator propagates RAW urllib3 errors when
        _request_timeout fires with no events (found live) — the
        foundation's contract is CommandError, so any exception
        from the stream surfaces as CommandError."""
        deadline = time.monotonic() + timeout
        w = watch.Watch()
        try:
            stream = w.stream(
                self._api.list_namespaced_pod,
                namespace,
                field_selector=f"metadata.name={pod}",
                _request_timeout=max(int(deadline - time.monotonic()), 1),
            )
            for event in stream:
                obj = event.get("object")
                if obj is None:
                    continue
                phase = obj.status.phase if hasattr(obj, "status") else None
                if phase == "Running":
                    w.stop()
                    return
                if time.monotonic() >= deadline:
                    break
        except CommandError:
            raise
        except Exception as e:
            raise CommandError(
                f"pod {pod} not Running within {timeout}s: {type(e).__name__}: {e}"
            ) from e
        raise CommandError(f"pod {pod} not Running within {timeout}s")

    # --- the CLI escape hatches (delegated) ------------------------------
    def json(self, *args: str) -> object:
        """The kubectl escape hatch (apply-adjacent reads)."""
        return self._cli.json(*args)

    def raw(self, *args: str, check: bool = True) -> str:
        """The kubectl escape hatch (deployment create/patch/rollout,
        node labels — kubectl-only operations)."""
        return self._cli.raw(*args, check=check)

    def apply_manifest(self, manifest: str) -> None:
        """kubectl apply — server-side apply semantics are
        load-bearing; the client's create/replace is worse."""
        self._cli.apply_manifest(manifest)

    def delete(self, resource: str, name: str, namespace: str) -> None:
        self._cli.delete(resource, name, namespace)

    # --- the scheduling math (unchanged — pure dict work) ----------------
    def free_cpu_millicores(
        self, node: str, pods: Iterable[dict], nodes: list[dict] | None = None
    ) -> int:
        """Allocatable minus requested (init containers COUNT — the
        scheduler counts their requests too; found live: a node at
        765m regular + 1230m init rejected BestEffort pods)."""
        node_list = nodes if nodes is not None else self.nodes()
        by_name = {n["metadata"]["name"]: n for n in node_list}
        if node not in by_name:
            return -1
        alloc = _cpu_m(by_name[node]["status"]["allocatable"].get("cpu", 0))
        used = 0
        for p in pods:
            if p.get("spec", {}).get("nodeName") != node:
                continue
            if p.get("status", {}).get("phase") != "Running":
                continue
            for c in p["spec"].get("containers", []) + p["spec"].get(
                "initContainers", []
            ):
                used += _cpu_m(c.get("resources", {}).get("requests", {}).get("cpu", 0))
        return alloc - used
