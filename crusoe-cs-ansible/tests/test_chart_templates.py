"""Chart template tests for crusoe-mitigator (helm template golden
checks — no cluster needed).

Covers: metrics sidecar + scrape annotations present by default;
absent when all mitigations disable metrics; PodMonitoring CR only
with metricsBackend=gmp; MITIGATIONS env renders the mode var.
"""

import os
import shutil
import subprocess

import pytest

from conftest import COMPONENT_ROOT

CHART = COMPONENT_ROOT / "charts" / "crusoe-mitigator"

# The chart tests render via `helm template`; when helm is absent
# (minimal environments) they SKIP with a clear reason rather than
# erroring — CI installs helm so they run for real there.
pytestmark = pytest.mark.skipif(
    shutil.which("helm") is None,
    reason="helm not on PATH — chart-template tests need `helm template`",
)


def helm_template(*extra):
    result = subprocess.run(
        ["helm", "template", "test-release", CHART, *extra],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def helm_template_values(values, *extra):
    """helm template with a values file — the SAFE override shape
    (`--set mitigations[0]...` REPLACES the list element wholesale)."""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        for line in values.splitlines():
            fh.write(line + "\n")
        path = fh.name
    try:
        return helm_template("-f", path, *extra)
    finally:
        os.unlink(path)


def test_default_render_has_sidecar_and_annotations():
    out = helm_template()
    assert "name: metrics-server" in out
    assert "containerPort: 19698" in out
    assert 'prometheus.io/scrape: "true"' in out
    assert 'prometheus.io/port: "19698"' in out
    assert "serve-metrics.py" in out


def test_host_root_mounts_propagate_host_mounts():
    # The reconciler enters pod netns via the /host/run/netns/<id>
    # bind mounts the CNI creates AFTER this pod started. A hostPath
    # mount without mountPropagation is a snapshot: mounts created
    # later on the host are INVISIBLE inside the container, so
    # nsenter opens a plain file and fails with "Invalid argument"
    # — every pod scheduled after the mitigator stays uncovered
    # until the /proc scan catches it (found live:
    # ~10s exposure window per fresh pod). HostToContainer (rslave
    # under the hood) makes the host's mounts visible here. Required
    # on BOTH containers that mount host-root: the sidecar (sweep,
    # --verify, --undo) and the mitigator (the purge op's fallback
    # exec target).
    import yaml

    out = helm_template()
    docs = [d for d in yaml.safe_load_all(out) if d]
    doc = next(d for d in docs if d["kind"] == "DaemonSet")
    containers = doc["spec"]["template"]["spec"]["containers"]
    for cname in ("mitigator", "cve-2026-98432-sidecar"):
        c = next(x for x in containers if x["name"] == cname)
        mounts = [m for m in c["volumeMounts"] if m["name"] == "host-root"]
        assert len(mounts) == 1, f"{cname}: expected exactly one host-root mount"
        assert mounts[0].get("mountPropagation") == "HostToContainer", (
            f"{cname}: host-root mount must propagate host mounts"
        )


def test_pod_spec_requires_hostnetwork():
    # Pod-native delivery (design spec §8) loads the table with nft -f
    # in the pod's OWN netns, and the reconciler reads the "host" table
    # the same way (no nsenter) — both are only the HOST's netns when
    # the pod is hostNetwork. Without it the rule loads in the pod's
    # isolated netns: the probe, metrics, and reconciler all read it
    # there and report protected while the host netns (kubelet, sshd,
    # hostNetwork pods) stays bare (found live on a
    # real fleet — the hostNetwork regression this test guards).
    out = helm_template()
    assert "hostNetwork: true" in out
    # The standard companion (the sibling chart's reviewed pattern):
    # cluster DNS stays resolvable for hostNetwork pods.
    assert "dnsPolicy: ClusterFirstWithHostNet" in out


def test_mitigations_env_renders_mode():
    # AUTO mode renders NO mode var — the role's defaults own it.
    out = helm_template()
    assert "cve_2026_98432_mode=" not in out


def test_mode_pin_via_entry_vars():
    # The ONLY mode surface: the entry's generic vars map. A pinned
    # cluster sets the role's mode var there (air-gapped, SSH path,
    # freeze hold); the role's label resolution no-ops (mode != auto).
    out = helm_template_values("""
mitigations:
  - name: cve-2026-98432
    enabled: true
    playbook: wrapper-cve-2026-98432-pod.yml
    interval: 3600
    vars:
      cve_2026_98432_mode: enforce
""")
    assert "-e cve_2026_98432_mode=enforce" in out
    assert "wrapper-cve-2026-98432-pod.yml" in out
    assert "name: metrics-server" in out  # sidecar still rendered


def test_mode_and_modevar_fields_gone():
    # The mode/modeVar sugar is REMOVED: it duplicated the generic
    # vars mechanism. The label IS the rollout state; pins go in vars.
    out = helm_template_values("""
mitigations:
  - name: cve-2026-98432
    enabled: true
    playbook: wrapper-cve-2026-98432-pod.yml
    interval: 3600
    mode: enforce
    modeVar: cve_2026_98432_mode
""")
    assert "cve_2026_98432_mode=" not in out


def test_top_level_downgrade_override_renders_string_true():
    # cveAllowModeDowngrade is GONE from the chart: in auto mode the
    # label IS the sanction; on a pinned cluster the ROLE var is
    # passed via the entry's vars (a values file). The chart renders
    # no downgrade var in either mode.
    out = helm_template()
    assert "cve_2026_98432_allow_mode_downgrade=" not in out


def test_no_sidecar_when_metrics_disabled():
    out = helm_template(
        "--set",
        "mitigations[0].metrics=false",
        "--set",
        "mitigations[1].enabled=false",
    )
    assert "metrics-server" not in out
    assert "prometheus.io/scrape" not in out


def test_reconciler_metrics_dir_is_host_side():
    # The reconciler mounts the host root at /host; its METRICS_DIR env
    # must be the HOST-side path (/host/<metricsDir>) so netns.prom lands
    # in the hostPath volume the metrics-server serves — not inside the
    # reconciler's own container where no scraper can reach it.
    out = helm_template()
    assert 'value: "/host/var/lib/crusoe-mitigator"' in out


def test_podmonitoring_only_with_gmp_backend():
    out_default = helm_template()
    assert "PodMonitoring" not in out_default
    out_gmp = helm_template("--set", "metricsBackend=gmp")
    assert "PodMonitoring" in out_gmp
    assert "19698" in out_gmp


def test_liveness_probes_render_by_default():
    out = helm_template()
    assert "livenessProbe:" in out
    # reconciler: the alive-file contract
    assert "cve-2026-98432-alive" in out
    # metrics-server: GET /metrics (the scrape path itself)
    assert "readinessProbe:" in out


def test_probes_disabled():
    out = helm_template("--set", "probes.enabled=false")
    assert "livenessProbe" not in out
    assert "readinessProbe" not in out


def test_termination_grace_period_default():
    # A small grace period lets a running playbook finish cleanly on
    # pod deletion instead of an instant SIGKILL mid-template-write.
    out = helm_template()
    assert "terminationGracePeriodSeconds: 10" in out


def test_termination_grace_period_configurable():
    out = helm_template("--set", "terminationGracePeriodSeconds=30")
    assert "terminationGracePeriodSeconds: 30" in out


def test_failure_threshold_zero_renders():
    # 0 = crash on the first scheduled failure (the operator's
    # explicit choice) — it MUST render, not silently fall back to
    # the default 3 (a bare `if` treats 0 as falsy).
    out = helm_template("--set", "mitigationMaxConsecutiveFailures=0")
    assert "MITIGATION_MAX_CONSECUTIVE_FAILURES" in out
    assert 'value: "0"' in out


def test_failure_threshold_env_rendered():
    out = helm_template()
    assert "MITIGATION_MAX_CONSECUTIVE_FAILURES" in out
    assert 'value: "3"' in out
    out = helm_template("--set", "mitigationMaxConsecutiveFailures=5")
    assert 'value: "5"' in out


def test_failure_retry_backoff_env_rendered():
    # The failed-run retry backoff base is chart-tunable.
    out = helm_template()
    assert "MITIGATION_FAILURE_RETRY_BASE_SECONDS" in out
    assert 'value: "30"' in out
    out = helm_template("--set", "mitigationFailureRetryBaseSeconds=60")
    assert 'value: "60"' in out


def test_failure_retry_base_zero_renders():
    # 0 is the documented escape hatch (immediate retries) — it MUST
    # render, not silently fall back to the default 30 (a bare `if`
    # treats 0 as falsy and skips the env var entirely).
    out = helm_template("--set", "mitigationFailureRetryBaseSeconds=0")
    assert "MITIGATION_FAILURE_RETRY_BASE_SECONDS" in out
    assert 'value: "0"' in out


def test_auto_mode_default_and_rbac():
    # AUTO mode: the node's label IS the rollout state — one release,
    # one pod per node. The chart renders NO mode vars (the role's
    # defaults own them; an extra var would beat the label
    # resolution's set_fact). The pod needs read-only node access to
    # resolve the mode each run, and WATCH access for the
    # event-driven flip.
    out = helm_template()
    assert "kind: ClusterRole" in out
    assert "nodes" in out
    assert (
        'verbs: ["get", "list", "watch"]' in out
        or "verbs: ['get', 'list', 'watch']" in out
    )
    assert "kind: ClusterRoleBinding" in out
    assert "serviceAccountName:" in out
    # The watcher env plumbing (auto mode only).
    assert "NODE_MODE_WATCH" in out
    assert 'value: "1"' in out
    assert "NODE_MODE_LABEL" in out
    assert "cve-2026-98432.remediator.crusoe.ai/mode" in out
    # NO mode vars rendered in auto mode — the role's defaults own
    # them (an extra var would beat the label resolution's set_fact).
    assert "cve_2026_98432_mode=" not in out
    assert "cve_2026_98432_allow_mode_downgrade=" not in out


def test_explicit_mode_still_supported():
    # Air-gapped clusters pin the mode via the entry's vars (the
    # generic mechanism); the RBAC/watcher still render (the role
    # no-ops the label resolution on a pinned mode).
    out = helm_template_values("""
mitigations:
  - name: cve-2026-98432
    enabled: true
    playbook: wrapper-cve-2026-98432-pod.yml
    interval: 3600
    vars:
      cve_2026_98432_mode: enforce
""")
    assert "-e cve_2026_98432_mode=enforce" in out
    out = helm_template_values("""
mitigations:
  - name: cve-2026-98432
    enabled: true
    playbook: wrapper-cve-2026-98432-pod.yml
    interval: 3600
    vars:
      cve_2026_98432_mode: observe
""")
    assert "-e cve_2026_98432_mode=observe" in out


def test_metrics_port_override_for_two_release_coexistence():
    # The enforce canary coexists with the observe release on the same
    # hostNetwork node — it must serve metrics on a different port.
    out = helm_template("--set", "metricsPort=19699")
    assert "containerPort: 19699" in out
    assert 'prometheus.io/port: "19699"' in out
    # The default release keeps the standard port.
    out = helm_template()
    assert "containerPort: 19698" in out


def test_node_selector_bool_values_coerced_to_strings():
    # K8s label values are strings by API contract; users will write
    # unquoted true (values file) or plain --set (bool) — the chart
    # must coerce, not pass the boolean through to the API server.
    out = helm_template(
        "--set", "nodeSelector.cve-2026-98432\\.remediator\\.crusoe\\.ai/enforce=true"
    )
    assert 'cve-2026-98432.remediator.crusoe.ai/enforce: "true"' in out
    # Numeric values coerce too (label values are always strings).
    out = helm_template("--set", "nodeSelector.topology\\.kubernetes\\.io/zone=42")
    assert 'topology.kubernetes.io/zone: "42"' in out


def test_mitigations_line_parses_through_the_entrypoint():
    # The rendered MITIGATIONS env must be parseable by the image's
    # parse_mitigations — a separator regression (concatenated -e
    # pairs) reached the cluster live (ansible-playbook rc=2).
    import importlib.util

    out = helm_template()
    import re

    match = re.search(r"cve-2026-98432\|.*\|3600", out)
    assert match, "no MITIGATIONS line in the rendered chart"
    line = match.group(0)
    spec = importlib.util.spec_from_file_location(
        "mitigate",
        str(COMPONENT_ROOT / "images" / "ansible" / "mitigate.py"),
    )
    assert spec and spec.loader, "mitigate.py not found"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    parsed = mod.parse_mitigations(line)
    assert parsed[0][0] == "cve-2026-98432"
    assert parsed[0][3] == 3600
    # Every var is a proper -e key=value pair (the separator contract).
    argv = parsed[0][2]
    assert argv[0] == "-e"
    for i in range(0, len(argv), 2):
        assert argv[i] == "-e"
        assert "=" in argv[i + 1]


def test_emudhra_run_wires_capture_output():
    # chart-smoke.py's run() gained a capture_output kwarg (mypy
    # round) but the body still passed capture_output=True to
    # subprocess.run unconditionally — a caller asking to stream
    # output got it captured silently (found by review). The kwarg
    # must be wired through.
    import importlib.util
    import inspect

    spec = importlib.util.spec_from_file_location(
        "chart_smoke",
        str(COMPONENT_ROOT / "tests" / "e2e" / "emudhra-ca" / "chart-smoke.py"),
    )
    assert spec and spec.loader, "chart-smoke.py not found"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    src = inspect.getsource(mod.run)
    assert "capture_output=capture_output" in src, (
        "run() must pass its capture_output kwarg to subprocess.run"
    )


def test_daemonset_has_exactly_one_pod_template():
    # A structural regression spliced updateStrategy INTO the pod
    # template (two template: blocks) — helm v4's server-side apply
    # rejected the schema. The DaemonSet must have exactly one
    # template, with updateStrategy at the SPEC level.
    out = helm_template()
    # Count template: at the spec level (2-space indent under spec:)
    import re

    body_match = re.search(r"kind: DaemonSet.*", out, re.S)
    assert body_match, "no DaemonSet in the rendered chart"
    body = body_match.group(0)
    spec_level_templates = re.findall(r"^  template:", body, re.M)
    assert len(spec_level_templates) == 1, (
        f"expected exactly one spec-level template:, found {len(spec_level_templates)}"
    )
    # updateStrategy at spec level, BEFORE template:
    assert re.search(r"\n  updateStrategy:.*?\n  template:", body, re.S)
