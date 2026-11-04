"""Cluster queries: kubectl-backed, typed, API-blip tolerant.

Every query goes through runner.run (retries). JSON is parsed once,
here — no jsonpath string surgery at the call sites.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from .runner import run


def _cpu_m(v: object) -> int:
    """Millicores: '250m' -> 250, 2 -> 2000."""
    s = str(v)
    return int(s[:-1]) if s.endswith("m") else int(float(s) * 1000)


class Cluster:
    """The kubectl-facing surface of a live cluster."""

    def __init__(self, context: str | None = None) -> None:
        self._base = ["kubectl"] + (["--context", context] if context else [])

    def json(self, *args: str) -> object:
        """Run a kubectl -o json query, parsed."""
        out = run([*self._base, *args, "-o", "json"])
        return json.loads(out.stdout)

    def raw(self, *args: str, check: bool = True) -> str:
        """Run any kubectl command, return stdout."""
        return run([*self._base, *args], check=check).stdout

    def exec(
        self, pod: str, container: str, namespace: str, *cmd: str, check: bool = True
    ) -> str:
        """kubectl exec into a container; stdout returned."""
        return run(
            [*self._base, "exec", pod, "-c", container, "-n", namespace, "--", *cmd],
            check=check,
        ).stdout

    def exec_ok(self, pod: str, container: str, namespace: str, *cmd: str) -> bool:
        """True iff the exec exits 0 (retries applied)."""
        from .runner import run_ok

        return run_ok(
            [*self._base, "exec", pod, "-c", container, "-n", namespace, "--", *cmd]
        )

    def pods(self, namespace: str) -> list[dict]:
        """All pods in a namespace."""
        return self.json("get", "pods", "-n", namespace)["items"]  # type: ignore[index]

    def pod(self, name: str, namespace: str) -> dict:
        return self.json("get", "pod", name, "-n", namespace)  # type: ignore[return-value]

    def nodes(self) -> list[dict]:
        return self.json("get", "nodes")["items"]  # type: ignore[index]

    def apply_manifest(self, manifest: str) -> None:
        """Apply a manifest from stdin."""
        import subprocess

        proc = subprocess.run(
            [*self._base, "apply", "-f", "-"],
            input=manifest,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"kubectl apply failed: {proc.stderr.strip()}")

    def delete(self, resource: str, name: str, namespace: str) -> None:
        run(
            [*self._base, "delete", resource, name, "-n", namespace, "--wait=false"],
            check=False,
        )

    def wait_phase(self, pod: str, namespace: str, timeout: int = 60) -> None:
        """Wait for a pod to be Running (bounded)."""
        run(
            [
                *self._base,
                "wait",
                "--for=jsonpath={.status.phase}=Running",
                f"pod/{pod}",
                "-n",
                namespace,
                f"--timeout={timeout}s",
            ],
            check=True,
        )

    def free_cpu_millicores(
        self, node: str, pods: Iterable[dict], nodes: list[dict] | None = None
    ) -> int:
        """Allocatable minus requested (init containers COUNT — the
        scheduler counts their requests too; found live: a node at
        765m regular + 1230m init rejected BestEffort pods). The
        node list can be passed in — discover() calls this per
        mitigator node and must not re-fetch N times (found by
        review)."""
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
