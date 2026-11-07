"""The cve_2026_98432 role's wiring to the shared nft_rules
engines — the DRY contract (engines design §5).

The role is the FIRST CONSUMER of the engines: its tasks reference
roles/nft_rules/files/* by path (role_path-relative — resolves
locally AND in the image's /opt/ansible/roles/), the identity
(table, match) flows from the role's vars, and the old CVE-specific
scripts are GONE (one engine, no forks to drift).
"""

import yaml

from conftest import COMPONENT_ROOT

ROLE = COMPONENT_ROOT / "roles" / "cve_2026_98432"
ENGINE_ROLE = COMPONENT_ROOT / "roles" / "nft_rules"


def _tasks():
    with open(ROLE / "tasks" / "main.yml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _task_file(name):
    with open(ROLE / "tasks" / name, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


class TestProbeWiring:
    def test_probe_task_uses_the_engine(self):
        probe = _task_file("probe.yml")
        run = next(t for t in probe if "drop probe" in t["name"])
        cmd = str(run["ansible.builtin.script"]["cmd"])
        assert "nft_rules" in cmd, (
            "the probe task must run the shared engine "
            "(roles/nft_rules/files/nft-probe.py), not a "
            "CVE-specific copy"
        )
        assert "--table {{ cve_2026_98432_table }}" in cmd, (
            "the table identity flows from the role's var — the "
            "engine is parameterized, the role owns the identity"
        )

    def test_baseline_task_uses_the_engine(self):
        baseline = _task_file("baseline.yml")
        run = next(t for t in baseline if "script" in str(t))
        cmd = str(run["ansible.builtin.script"]["cmd"])
        assert "nft_rules" in cmd

    def test_old_probe_deleted(self):
        assert not (ROLE / "files" / "probe.py").exists(), (
            "the CVE-specific probe is deleted — one engine, no forks"
        )


class TestMetricsWiring:
    def test_metrics_task_installs_the_sh_engine(self):
        metrics = _task_file("metrics.yml")
        install = next(
            t for t in metrics if t.get("ansible.builtin.copy", {}).get("src")
        )
        assert "nft_rules" in str(install["ansible.builtin.copy"]["src"]), (
            "the host-side metrics engine is the shared POSIX sh one — "
            "the systemd timer runs it on the HOST's userspace where "
            "python3 is NOT a guaranteed dependency"
        )

    def test_metrics_env_carries_identity(self):
        # The one-shot publish task must pass the identity env vars.
        metrics = _task_file("metrics.yml")
        one_shot = next(
            t for t in metrics if "Publish the metrics once now" in t["name"]
        )
        cmd = str(one_shot["ansible.builtin.command"])
        assert "NFT_METRICS_TABLE" in cmd, (
            "the engine's identity comes from the env — the role's "
            "table var is the single source of truth"
        )

    def test_old_metrics_script_deleted(self):
        assert not (ROLE / "files" / "cve-2026-98432-metrics.sh").exists()

    def test_unit_calls_the_engine_with_env(self):
        unit = (ROLE / "files" / "cve-2026-98432-metrics.service").read_text()
        assert "nft-metrics.sh" in unit, "the systemd unit runs the shared engine"
        assert "NFT_METRICS_TABLE" in unit, (
            "the unit passes the identity env — the engine is parameterized"
        )


class TestReconcilerWiring:
    def test_probe_path_default_is_the_engine(self):
        src = (ROLE / "files" / "cve-2026-98432-netns-reconcile.py").read_text()
        assert '"/opt/ansible/roles/nft_rules/files/nft-probe.py"' in src, (
            "the reconciler's --verify probe default is the shared "
            "engine (the image bakes roles/ wholesale)"
        )


class TestEngineRoleShape:
    def test_engine_role_has_no_tasks(self):
        # A delivery vehicle, not a task role: files + defaults only.
        assert not (ENGINE_ROLE / "tasks").exists()

    def test_defaults_document_the_contract(self):
        defaults = ENGINE_ROLE / "defaults" / "main.yml"
        assert defaults.exists(), (
            "the parameter contract is documented in the engine role's defaults"
        )
