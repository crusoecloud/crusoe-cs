"""The chart's `mitigations[].vars` are passed to the role as extra
vars. Two things must hold, and neither is enforced by anything else.

1. EVERY chart var must be a var the role actually knows. A chart var
   the role renamed (or never had) is silently ignored — the fleet
   runs the role's default while the operator believes they set a
   value. That is the staleness this file exists to catch.

2. A chart var spelled "true"/"false" is a STRING at the role. Any
   consumer reading it without `| bool` treats "false" as truthy.

The chart MAY deliberately override a role default (a managed fleet
failing loudly on unsupported nodes is a policy, not drift), so the
values are not required to match — only the NAMES must be real.
"""

from __future__ import annotations

import re

import yaml

from conftest import COMPONENT_ROOT

DEFAULTS = COMPONENT_ROOT / "roles" / "cve_2026_98432" / "defaults" / "main.yml"
VALUES = COMPONENT_ROOT / "charts" / "crusoe-mitigator" / "values.yaml"
TASKS = COMPONENT_ROOT / "roles" / "cve_2026_98432" / "tasks"


def _role_defaults() -> dict:
    return yaml.safe_load(DEFAULTS.read_text()) or {}


def _chart_vars() -> dict:
    values = yaml.safe_load(VALUES.read_text()) or {}
    out = {}
    for mitigation in values.get("mitigations", []):
        for key, value in (mitigation.get("vars") or {}).items():
            out[key] = value
    return out


def _role_defaults_for(mitigation_name: str) -> dict:
    """The defaults of the role a mitigation names. The chart carries
    several mitigations; each var belongs to ITS role."""
    role = COMPONENT_ROOT / "roles" / mitigation_name.replace("-", "_")
    defaults = role / "defaults" / "main.yml"
    if not defaults.exists():
        return {}
    return yaml.safe_load(defaults.read_text()) or {}


def test_every_chart_var_is_a_real_role_var():
    values = yaml.safe_load(VALUES.read_text()) or {}
    mitigations = values.get("mitigations", [])
    assert mitigations, "the chart declares no mitigations — vacuous"

    unknown = []
    for mitigation in mitigations:
        name = mitigation.get("name", "")
        defaults = _role_defaults_for(name)
        for key in mitigation.get("vars") or {}:
            if key not in defaults:
                unknown.append(f"{name}: {key}")
    assert not unknown, (
        "the chart sets vars its role does not define — they are "
        "silently ignored, so the fleet runs the role's default while "
        f"the operator believes otherwise: {unknown}"
    )


def test_every_boolean_chart_var_is_coerced_by_its_consumer():
    """A chart var spelled "true"/"false" is a STRING at the role. A
    consumer reading it without `| bool` treats "false" as truthy."""
    chart = _chart_vars()
    boolean_vars = [
        key
        for key, value in chart.items()
        if isinstance(value, str) and value.lower() in ("true", "false")
    ]
    assert boolean_vars, "no boolean chart vars found — the check is vacuous"

    offenders = []
    for path in sorted(TASKS.glob("*.yml")):
        for line_no, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if not any(v in stripped for v in boolean_vars):
                continue
            if "| bool" in stripped:
                continue
            # Only a boolean DECISION is a risk: a `when:`/`failed_when:`
            # line, or a Jinja expression that is not a plain string
            # interpolation into an env var.
            if re.search(r"(when|failed_when|changed_when)\s*:", stripped):
                offenders.append(f"{path.name}:{line_no}: {stripped[:80]}")
    assert not offenders, (
        "a boolean chart var is consumed in a condition without "
        '`| bool` — the string "false" is truthy:\n' + "\n".join(offenders)
    )


class TestSharedPathsAgree:
    """The chart and the role each name the metrics directory, and the
    two must be the SAME path.

    The chart mounts `metricsDir` as a hostPath and points the
    reconciler's METRICS_DIR at `/host<metricsDir>`; the role writes
    its host-side series to `cve_2026_98432_metrics_host_dir`. If they
    diverge, the reconciler writes where no scraper reads — silently:
    the file exists, the pod is healthy, and the series are simply
    absent from Prometheus.
    """

    def test_metrics_dir_matches_the_role_var(self):
        values = yaml.safe_load(VALUES.read_text()) or {}
        chart_dir = values.get("metricsDir")
        assert chart_dir, "the chart must declare metricsDir"

        role_vars = yaml.safe_load(
            (
                COMPONENT_ROOT / "roles" / "cve_2026_98432" / "vars" / "main.yml"
            ).read_text()
        )
        role_dir = role_vars.get("cve_2026_98432_metrics_host_dir")
        assert role_dir, "the role must declare cve_2026_98432_metrics_host_dir"

        assert chart_dir == role_dir, (
            f"the chart's metricsDir ({chart_dir}) and the role's "
            f"cve_2026_98432_metrics_host_dir ({role_dir}) disagree — "
            "the reconciler would write where no scraper reads"
        )

    def test_the_pod_side_path_is_the_host_path_under_host(self):
        # The reconciler mounts the host root at /host, so its view of
        # the same directory is /host<host path>. A mismatch here is
        # the same silent failure one level down.
        role_vars = yaml.safe_load(
            (
                COMPONENT_ROOT / "roles" / "cve_2026_98432" / "vars" / "main.yml"
            ).read_text()
        )
        host = role_vars["cve_2026_98432_metrics_host_dir"]
        pod = role_vars["cve_2026_98432_metrics_host_dir_pod"]
        assert pod == f"/host{host}", (
            f"the pod-side path ({pod}) must be the host path ({host}) "
            "under the /host mount"
        )
