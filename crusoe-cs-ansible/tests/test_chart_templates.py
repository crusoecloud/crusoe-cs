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
    # until the /proc scan catches it. HostToContainer (rslave
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
    # hostNetwork pods) stays bare.
    out = helm_template()
    assert "hostNetwork: true" in out
    # The standard companion (the sibling chart's reviewed pattern):
    # cluster DNS stays resolvable for hostNetwork pods.
    assert "dnsPolicy: ClusterFirstWithHostNet" in out


def test_mitigations_env_renders_mode():
    # AUTO mode renders NO mode var — the role's defaults own it.
    out = helm_template()
    assert "cve_2026_98432_mode=" not in out


def test_metrics_interval_flows_from_helm():
    # The timer cadence is Helm-settable: the entry's vars flow
    # through MITIGATIONS as -e pairs, overriding the role default
    # (60). The safe override shape is a values FILE (--set
    # mitigations[0]... REPLACES the list element wholesale).
    out = helm_template_values(
        """
mitigations:
  - name: cve-2026-98432
    enabled: true
    playbook: wrapper-cve-2026-98432-pod.yml
    interval: 3600
    vars:
      cve_2026_98432_run_probe: "true"
      cve_2026_98432_metrics: "true"
      cve_2026_98432_fail_on_unsupported_family: "true"
      cve_2026_98432_metrics_interval_seconds: "10"
"""
    )
    assert "cve_2026_98432_metrics_interval_seconds=10" in out, (
        "the cadence var must flow from the chart's values through "
        "MITIGATIONS to the role — the knob is discoverable where "
        "operators look (the chart), not only in role defaults"
    )


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


class TestPriorityAndResources:
    """The reported eviction gap (concern 1): the DaemonSet ran
    BestEffort at default priority — under memory pressure (common
    on GPU nodes during big jobs) the kubelet evicts BestEffort pods
    FIRST, and while the mitigator is gone its netns reconciler
    isn't running: pods created in that window get no netns rule
    until it's back. Two optional values, both default-empty (the
    chart stays minimal; the operator opts in per fleet):
      priorityClassName — e.g. system-node-critical (the Cilium
        pattern: the node's security infrastructure must not be the
        first thing evicted)
      resources — per container (mitigator, the sidecar, the
        metrics-server): requests keep the pod OUT of BestEffort
        (the eviction class), limits cap it."""

    def test_priority_class_name_renders(self):
        out = helm_template("--set", "priorityClassName=system-node-critical")
        assert "priorityClassName: system-node-critical" in out, (
            "the pod-level priorityClassName must render when set — "
            "without it the mitigator is BestEffort-at-default-priority "
            "and the kubelet evicts it first under memory pressure"
        )

    def test_priority_class_name_absent_by_default(self):
        out = helm_template()
        assert "priorityClassName" not in out, (
            "the default stays minimal — the operator opts in per fleet"
        )

    def test_mitigator_container_resources_render(self):
        out = helm_template_values(
            """
resources:
  mitigator:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      memory: 512Mi
"""
        )
        assert "cpu: 100m" in out
        assert "memory: 128Mi" in out
        assert "memory: 512Mi" in out

    def test_sidecar_resources_render(self):
        # The reconciler sidecar carries its own block — the
        # all three containers are configurable.
        out = helm_template_values(
            """
resources:
  reconciler:
    requests:
      cpu: 50m
      memory: 64Mi
"""
        )
        assert "cpu: 50m" in out
        assert "memory: 64Mi" in out

    def test_metrics_server_resources_render(self):
        out = helm_template_values(
            """
resources:
  metricsServer:
    requests:
      cpu: 10m
      memory: 32Mi
"""
        )
        assert "cpu: 10m" in out
        assert "memory: 32Mi" in out

    def test_resources_absent_by_default(self):
        out = helm_template()
        assert "requests:" not in out, (
            "no resources block by default — the chart stays minimal; "
            "the operator opts in (a default request would change "
            "scheduling on every existing fleet)"
        )


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
    # output got it captured silently. The kwarg
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


class TestCallbackPluginPath:
    """ANSIBLE_CALLBACK_PLUGINS must point at the CALLBACK directory,
    not its parent.

    `/opt/ansible/plugins` holds both `callback/` and `module_utils/`.
    Ansible scans every .py under the configured path as a callback
    plugin, finds `module_utils/journald.py`, and warns on every run:

        [WARNING]: Skipping plugin (.../module_utils/journald.py) as it
        seems to be invalid: module 'ansible.plugins.callback.journald'
        has no attribute 'CallbackModule'

    The callback still loads (the warning is about the helper), so the
    symptom is noise on every playbook run plus a misleading message
    that suggests the journald plugin is broken.
    """

    def test_mitigator_points_at_the_callback_dir(self):
        out = helm_template()
        assert "value: /opt/ansible/plugins/callback" in out, (
            "ANSIBLE_CALLBACK_PLUGINS must be the callback directory — "
            "the parent makes Ansible scan module_utils/ as callbacks "
            "and warn on every run"
        )

    def test_no_chart_points_at_the_plugin_parent(self):
        # The sibling chart already had this right; a regression in
        # either would reintroduce the warning.
        from conftest import COMPONENT_ROOT

        offenders = []
        for chart in (COMPONENT_ROOT / "charts").iterdir():
            ds = chart / "templates" / "daemonset.yaml"
            if not ds.exists():
                continue
            for line_no, line in enumerate(ds.read_text().splitlines(), 1):
                if line.strip() == "value: /opt/ansible/plugins":
                    offenders.append(f"{chart.name}:{line_no}")
        assert not offenders, (
            "a chart points ANSIBLE_CALLBACK_PLUGINS at the plugin "
            f"parent (Ansible then scans module_utils/): {offenders}"
        )


class TestTolerationsAreOptIn:
    """Tolerations default to EMPTY: the chart stays minimal and an
    upgrade changes nothing about where the pod schedules.

    The gap that leaves is documented, loudly: a DaemonSet with no
    tolerations stays off every tainted node, GPU nodes are usually
    tainted, and the DaemonSet just schedules fewer pods — nothing
    reports the gap. The README and the values comment both say so,
    with the kubectl command to check a fleet.
    """

    def test_the_default_is_empty(self):
        import yaml

        from conftest import COMPONENT_ROOT

        values = yaml.safe_load(
            (COMPONENT_ROOT / "charts" / "crusoe-mitigator" / "values.yaml").read_text()
        )
        assert values.get("tolerations") == [], (
            "tolerations must default to empty — a default that "
            "tolerates everything would schedule a privileged "
            "hostNetwork pod on control-plane nodes without anyone "
            "asking for it"
        )

    def test_the_default_renders_no_tolerations(self):
        out = helm_template()
        assert "tolerations:" not in out, (
            "an empty default must render no tolerations block"
        )

    def test_opting_in_renders_the_toleration(self):
        out = helm_template("--set-json", 'tolerations=[{"operator":"Exists"}]')
        assert "operator: Exists" in out

    def test_the_values_comment_warns_about_the_gap(self):
        from conftest import COMPONENT_ROOT

        raw = (
            COMPONENT_ROOT / "charts" / "crusoe-mitigator" / "values.yaml"
        ).read_text()
        assert "GPU nodes are usually tainted" in raw, (
            "the values comment must warn that the empty default "
            "silently skips tainted nodes"
        )
        assert "kubectl get nodes" in raw, (
            "the comment must give the operator a way to check their fleet for taints"
        )

    def test_the_readme_warns_about_the_gap(self):
        from conftest import COMPONENT_ROOT

        readme = (
            COMPONENT_ROOT / "charts" / "crusoe-mitigator" / "README.md"
        ).read_text()
        assert "GPU nodes are usually tainted" in readme


class TestTheMetricsBindIsNotPublic:
    """With hostNetwork: true the pod shares the node's network
    namespace, so binding 0.0.0.0 also listens on the node's PUBLIC
    interface — an unauthenticated endpoint exposing per-namespace
    series.

    Binding to 127.0.0.1 would break the scrape: vmagent targets the
    pod IP, which under hostNetwork IS the node's internal address.
    The correct default is that internal address.
    """

    def test_the_default_bind_is_the_node_internal_ip(self):
        out = helm_template()
        assert '"$(STATUS_HOST_IP)"' in out, (
            "the metrics server must bind the node's internal address "
            "by default — 0.0.0.0 also listens on the public interface"
        )

    def test_status_host_ip_is_injected(self):
        out = helm_template()
        assert "fieldPath: status.hostIP" in out, (
            "STATUS_HOST_IP must come from the downward API"
        )

    def test_the_bind_is_overridable(self):
        out = helm_template("--set", "metricsBind=0.0.0.0")
        assert '"0.0.0.0"' in out, (
            "an operator must be able to override the bind (a "
            "node-local scraper may need 0.0.0.0)"
        )


class TestTheValuesTableIsComplete:
    """Every user-facing value must appear in the README's table.

    A value that exists only in values.yaml is a value an operator
    cannot discover — and the metrics bind is a security-relevant
    choice, not a tuning knob.
    """

    def test_the_metrics_values_are_documented(self):
        from conftest import COMPONENT_ROOT

        readme = (
            COMPONENT_ROOT / "charts" / "crusoe-mitigator" / "README.md"
        ).read_text()
        for value in ("metricsPort", "metricsBind"):
            assert f"`{value}`" in readme, (
                f"{value} must appear in the README's values table"
            )

    def test_the_bind_choices_are_spelled_out(self):
        from conftest import COMPONENT_ROOT

        readme = (
            COMPONENT_ROOT / "charts" / "crusoe-mitigator" / "README.md"
        ).read_text()
        # The three meaningful choices, and the one that breaks.
        assert "status.hostIP" in readme
        assert "0.0.0.0" in readme
        assert "127.0.0.1" in readme, (
            "the README must warn that loopback breaks scraping"
        )


class TestTheBindResolvesPerNode:
    """`metricsBind` is a DaemonSet-wide setting, so it must resolve
    PER NODE.

    A literal IP does not work: every node would try to bind the same
    address, and all but one would fail with "address not available" —
    the metrics server would die on every other node. The default must
    therefore be the downward API's status.hostIP, not a literal.
    """

    def test_the_default_is_the_downward_api_not_a_literal(self):
        out = helm_template()
        assert '"$(STATUS_HOST_IP)"' in out, (
            "the default bind must be the downward API's status.hostIP "
            "— a literal IP is a per-node address in a fleet-wide "
            "setting"
        )

    def test_the_docs_state_the_two_choices(self):
        from conftest import COMPONENT_ROOT

        readme = (
            COMPONENT_ROOT / "charts" / "crusoe-mitigator" / "README.md"
        ).read_text()
        assert "Two choices only" in readme, (
            "the README must state that only two values are valid"
        )
        assert "fails the render" in readme, (
            "the README must say an invalid value is rejected, not silently accepted"
        )

    def test_the_values_comment_warns_too(self):
        import yaml

        from conftest import COMPONENT_ROOT

        # The comment lives above the key; read the raw text.
        raw = (
            COMPONENT_ROOT / "charts" / "crusoe-mitigator" / "values.yaml"
        ).read_text()
        assert "resolve PER NODE" in raw, (
            "the values comment must explain why a literal IP fails"
        )
        # And the key itself still parses as the empty sentinel.
        values = yaml.safe_load(raw)
        assert values["metricsBind"] == ""


class TestTheBindAcceptsOnlyTwoChoices:
    """`metricsBind` is a DaemonSet-wide setting, so only two values
    are meaningful:

      ""          the node's own internal IP (resolved per node)
      "0.0.0.0"   all interfaces

    Anything else is a per-node address in a fleet-wide setting: every
    node would bind the same address and all but one would fail with
    "address not available" — the metrics server dies on every other
    node. A chart that silently accepts that is a chart that lets an
    operator break their fleet with a plausible-looking value.

    The template fails the render instead.
    """

    def test_the_two_valid_choices_render(self):
        assert '"$(STATUS_HOST_IP)"' in helm_template()
        assert '"0.0.0.0"' in helm_template("--set", "metricsBind=0.0.0.0")

    def test_a_literal_ip_fails_the_render(self):
        import pytest

        with pytest.raises(Exception, match="metricsBind"):
            helm_template("--set", "metricsBind=10.0.0.5")

    def test_loopback_fails_the_render(self):
        # 127.0.0.1 is a valid bind but breaks the scrape — vmagent
        # targets the pod IP. Reject it rather than let it silently
        # produce an unscrapable pod.
        import pytest

        with pytest.raises(Exception, match="metricsBind"):
            helm_template("--set", "metricsBind=127.0.0.1")


class TestTheBindEnvIsInTheRightContainer:
    """$(VAR) expansion in command/args sees only the SAME container's
    env. The reconciler's STATUS_HOST_IP does not reach the
    metrics-server — each container needs its own, or the bind gets
    the literal string "$(STATUS_HOST_IP)" and dies with
    "Name does not resolve" (found live on CMK: CrashLoop).

    This test parses the RENDERED manifest and checks the container
    that runs serve-metrics carries the env it references.
    """

    def _containers(self, out: str):
        import yaml

        doc = yaml.safe_load(out)
        for d in doc["items"] if isinstance(doc, dict) and "items" in doc else [doc]:
            if not isinstance(d, dict):
                continue
            pod = d.get("spec", {}).get("template", {}).get("spec", {})
            if pod.get("containers"):
                return pod["containers"]
        return []

    def test_the_metrics_server_container_has_the_env(self):
        out = helm_template()
        # Find the container whose command runs serve-metrics.
        import yaml

        docs = []
        for chunk in out.split("---"):
            if chunk.strip():
                docs.append(yaml.safe_load(chunk))
        server = None
        for d in docs:
            if not isinstance(d, dict):
                continue
            pod = d.get("spec", {}).get("template", {}).get("spec", {})
            for c in pod.get("containers", []):
                cmd = " ".join(c.get("command", []) or [])
                if "serve-metrics" in cmd:
                    server = c
        assert server, "the metrics-server container was not found"
        names = [e["name"] for e in server.get("env", [])]
        assert "STATUS_HOST_IP" in names, (
            "the metrics-server container must define STATUS_HOST_IP "
            "itself — $(VAR) expansion does not see other containers' "
            "env, so the bind gets the literal string and dies"
        )


def test_metrics_interval_docs_match_the_pod_native_truth():
    # The knob's documentation must not promise a host timer in
    # chart deployments: the pod-native image (alpine) ships no
    # systemctl, so cve_2026_98432_systemd_usable.rc != 0 and the
    # timer install tasks skip — the reconciler's 10s republish owns
    # host-series freshness there. A comment claiming the timer runs
    # on "CMK-style Ubuntu nodes" sends an operator to tune a knob
    # that does nothing (the review's finding).
    values = (CHART / "values.yaml").read_text()
    assert "inert" in values, (
        "values.yaml must say the cadence knob is INERT in chart "
        "deployments (pod-native: no systemctl, no timer)"
    )
    assert "CMK-style" not in values, (
        "the knob does NOT run a timer on CMK-style nodes — the "
        "comment must not claim it does"
    )
    readme = (CHART / "README.md").read_text()
    assert "bare-VM" in readme, "the README must scope the knob to SSH/bare-VM delivery"
