# Ansible + Crusoe Dynamic Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bootstrap a pyenv + pipenv Python environment with Ansible and a dynamic inventory script that groups Crusoe Cloud VMs by project, instance type, and region via the Crusoe CLI.

**Architecture:** A standalone Python executable (`inventory/crusoe.py`) shells out to `crusoe compute vms list --output json`, parses the output, and returns an Ansible-compatible inventory JSON with `_meta` hostvars. SSH reaches VMs through a bastion configured in `group_vars/all.yml`.

**Tech Stack:** Python 3.12, pyenv, pipenv, Ansible, pytest, Crusoe CLI (`crusoe` on `$PATH`)

---

## Task 1: Python environment bootstrap

**Files:**
- Create: `.python-version`
- Create: `Pipfile`

- [ ] **Step 1: Create `.python-version`**

```
3.12.7
```

File path: `.python-version` (repo root)

- [ ] **Step 2: Verify pyenv has 3.12.7 available**

```bash
pyenv versions | grep 3.12.7
```

If not listed, install it first:

```bash
pyenv install 3.12.7
```

Expected: `3.12.7` appears in the list.

- [ ] **Step 3: Create `Pipfile`**

```toml
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
ansible = ">=9.0"

[dev-packages]
ansible-lint = "*"
pytest = "*"

[requires]
python_version = "3.12"
```

- [ ] **Step 4: Install dependencies**

```bash
pipenv install --dev
```

Expected: virtualenv created, `Pipfile.lock` written, no errors.

- [ ] **Step 5: Verify Python version inside virtualenv**

```bash
pipenv run python --version
```

Expected: `Python 3.12.7`

- [ ] **Step 6: Verify Ansible is available**

```bash
pipenv run ansible --version
```

Expected: `ansible [core 2.17.x]` or newer, `python version = 3.12.x`

- [ ] **Step 7: Commit**

```bash
git init
git add .python-version Pipfile Pipfile.lock
git commit -m "chore: bootstrap pyenv 3.12.7 and pipenv with ansible"
```

---

## Task 2: Directory structure and Ansible config

**Files:**
- Create: `ansible.cfg`
- Create: `inventory/group_vars/all.yml`
- Create: `playbooks/.gitkeep`
- Create: `roles/.gitkeep`

- [ ] **Step 1: Create directory skeleton**

```bash
mkdir -p inventory/group_vars playbooks roles
touch playbooks/.gitkeep roles/.gitkeep
```

- [ ] **Step 2: Create `ansible.cfg`**

```ini
[defaults]
inventory           = inventory/crusoe.py
host_key_checking   = False
remote_user         = ubuntu
retry_files_enabled = False

[ssh_connection]
pipelining = True
```

- [ ] **Step 3: Create `inventory/group_vars/all.yml`**

```yaml
ansible_ssh_common_args: "-J {{ bastion_user }}@{{ bastion_host }}"
```

`bastion_user` and `bastion_host` are supplied at runtime via `--extra-vars` or Ansible Vault — never hardcoded.

- [ ] **Step 4: Verify Ansible reads the config**

```bash
pipenv run ansible --version
```

Expected output includes:
```
config file = /path/to/repo/ansible.cfg
```

- [ ] **Step 5: Commit**

```bash
git add ansible.cfg inventory/group_vars/all.yml playbooks/.gitkeep roles/.gitkeep
git commit -m "chore: add ansible config and directory structure"
```

---

## Task 3: Inventory script — `build_inventory` (TDD)

**Files:**
- Create: `conftest.py`
- Create: `tests/test_crusoe_inventory.py`
- Create: `inventory/crusoe.py`

- [ ] **Step 1: Create `conftest.py` at repo root**

This lets pytest find `inventory/crusoe.py` without installing it as a package.

```python
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "inventory"))
```

- [ ] **Step 2: Create `tests/test_crusoe_inventory.py` with all `build_inventory` tests**

```python
import pytest
from crusoe import build_inventory

SAMPLE_VMS = [
    {
        "id": "vm-001",
        "name": "gpu-worker-01",
        "type": "a40.80gb",
        "location": "us-northcentral1-a",
        "project_name": "ml-training",
        "state": "STATE_RUNNING",
        "network_interfaces": [
            {"ips": [{"address": "10.0.1.10"}]}
        ],
    },
    {
        "id": "vm-002",
        "name": "cpu-worker-01",
        "type": "c1a.16x",
        "location": "us-east1-a",
        "project_name": "data-pipeline",
        "state": "STATE_RUNNING",
        "network_interfaces": [
            {"ips": [{"address": "10.0.2.20"}]}
        ],
    },
    {
        "id": "vm-003",
        "name": "stopped-vm",
        "type": "a40.80gb",
        "location": "us-northcentral1-a",
        "project_name": "ml-training",
        "state": "STATE_STOPPED",
        "network_interfaces": [],
    },
]


def test_all_running_vms_in_all_group():
    inv = build_inventory(SAMPLE_VMS)
    assert "gpu-worker-01" in inv["all"]["hosts"]
    assert "cpu-worker-01" in inv["all"]["hosts"]


def test_non_running_vms_excluded():
    inv = build_inventory(SAMPLE_VMS)
    assert "stopped-vm" not in inv["all"]["hosts"]


def test_project_groups_created():
    inv = build_inventory(SAMPLE_VMS)
    assert "project_ml_training" in inv
    assert "gpu-worker-01" in inv["project_ml_training"]["hosts"]
    assert "project_data_pipeline" in inv
    assert "cpu-worker-01" in inv["project_data_pipeline"]["hosts"]


def test_type_groups_created():
    inv = build_inventory(SAMPLE_VMS)
    assert "type_a40" in inv
    assert "gpu-worker-01" in inv["type_a40"]["hosts"]
    assert "type_c1a" in inv
    assert "cpu-worker-01" in inv["type_c1a"]["hosts"]


def test_region_groups_created():
    inv = build_inventory(SAMPLE_VMS)
    assert "region_us_northcentral1" in inv
    assert "gpu-worker-01" in inv["region_us_northcentral1"]["hosts"]
    assert "region_us_east1" in inv
    assert "cpu-worker-01" in inv["region_us_east1"]["hosts"]


def test_hostvars_ansible_host_is_internal_ip():
    inv = build_inventory(SAMPLE_VMS)
    assert inv["_meta"]["hostvars"]["gpu-worker-01"]["ansible_host"] == "10.0.1.10"


def test_hostvars_crusoe_metadata():
    inv = build_inventory(SAMPLE_VMS)
    hv = inv["_meta"]["hostvars"]["gpu-worker-01"]
    assert hv["crusoe_project"] == "ml_training"
    assert hv["crusoe_type"] == "a40.80gb"
    assert hv["crusoe_location"] == "us-northcentral1-a"


def test_meta_key_present():
    inv = build_inventory(SAMPLE_VMS)
    assert "_meta" in inv
    assert "hostvars" in inv["_meta"]


def test_empty_vm_list():
    inv = build_inventory([])
    assert inv["all"]["hosts"] == []
    assert inv["_meta"]["hostvars"] == {}
```

- [ ] **Step 3: Run tests — verify they FAIL**

```bash
pipenv run pytest tests/test_crusoe_inventory.py -v
```

Expected: `ModuleNotFoundError: No module named 'crusoe'` — confirms tests are wired correctly.

- [ ] **Step 4: Create `inventory/crusoe.py` with `build_inventory`**

```python
#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys


def build_inventory(vms):
    inventory = {
        "_meta": {"hostvars": {}},
        "all": {"hosts": []},
    }
    groups = {}

    for vm in vms:
        if vm.get("state") != "STATE_RUNNING":
            continue

        name = vm["name"]

        ip = None
        for iface in vm.get("network_interfaces", []):
            for ip_entry in iface.get("ips", []):
                ip = ip_entry.get("address")
                break
            if ip:
                break

        if not ip:
            continue

        raw_project = vm.get("project_name", "unknown")
        project = raw_project.lower().replace("-", "_").replace(" ", "_")

        instance_type = vm.get("type", "unknown").split(".")[0].lower()

        # Strip availability zone suffix (e.g. "us-northcentral1-a" -> "us-northcentral1")
        raw_location = vm.get("location", "unknown")
        region = raw_location.rsplit("-", 1)[0].lower().replace("-", "_")

        project_group = f"project_{project}"
        type_group = f"type_{instance_type}"
        region_group = f"region_{region}"

        for group in [project_group, type_group, region_group]:
            if group not in groups:
                groups[group] = {"hosts": []}
            groups[group]["hosts"].append(name)

        inventory["all"]["hosts"].append(name)
        inventory["_meta"]["hostvars"][name] = {
            "ansible_host": ip,
            "crusoe_project": project,
            "crusoe_type": vm.get("type"),
            "crusoe_location": raw_location,
        }

    inventory.update(groups)
    return inventory


def get_vms():
    result = subprocess.run(
        ["crusoe", "compute", "vms", "list", "--output", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description="Crusoe Cloud dynamic inventory")
    parser.add_argument("--list", action="store_true", dest="list_hosts")
    parser.add_argument("--host", type=str)
    args = parser.parse_args()

    if args.list_hosts:
        vms = get_vms()
        print(json.dumps(build_inventory(vms), indent=2))
    elif args.host:
        print(json.dumps({}))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
```

> **Note:** The CLI command `crusoe compute vms list --output json` may differ depending on your installed CLI version. Run `crusoe --help` to verify the exact subcommand. Common alternatives: `crusoe vm list --output json`.

- [ ] **Step 5: Run tests — verify they PASS**

```bash
pipenv run pytest tests/test_crusoe_inventory.py -v
```

Expected:
```
tests/test_crusoe_inventory.py::test_all_running_vms_in_all_group PASSED
tests/test_crusoe_inventory.py::test_non_running_vms_excluded PASSED
tests/test_crusoe_inventory.py::test_project_groups_created PASSED
tests/test_crusoe_inventory.py::test_type_groups_created PASSED
tests/test_crusoe_inventory.py::test_region_groups_created PASSED
tests/test_crusoe_inventory.py::test_hostvars_ansible_host_is_internal_ip PASSED
tests/test_crusoe_inventory.py::test_hostvars_crusoe_metadata PASSED
tests/test_crusoe_inventory.py::test_meta_key_present PASSED
tests/test_crusoe_inventory.py::test_empty_vm_list PASSED

9 passed
```

- [ ] **Step 6: Commit**

```bash
git add conftest.py tests/test_crusoe_inventory.py inventory/crusoe.py
git commit -m "feat: add crusoe dynamic inventory script with build_inventory"
```

---

## Task 4: Inventory script — CLI wiring and `get_vms` (TDD)

**Files:**
- Modify: `tests/test_crusoe_inventory.py` (add `get_vms` test)
- Modify: `inventory/crusoe.py` (make executable)

- [ ] **Step 1: Add `get_vms` test to `tests/test_crusoe_inventory.py`**

Add this import at the top of the test file (after existing imports):

```python
import json
from unittest.mock import MagicMock, patch
from crusoe import get_vms
```

Add this test at the bottom of the file:

```python
def test_get_vms_calls_crusoe_cli():
    mock_result = MagicMock()
    mock_result.stdout = json.dumps(SAMPLE_VMS)
    with patch("crusoe.subprocess.run", return_value=mock_result) as mock_run:
        result = get_vms()
        mock_run.assert_called_once_with(
            ["crusoe", "compute", "vms", "list", "--output", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert result == SAMPLE_VMS
```

- [ ] **Step 2: Run new test — verify it FAILS**

```bash
pipenv run pytest tests/test_crusoe_inventory.py::test_get_vms_calls_crusoe_cli -v
```

Expected: `AssertionError` or import error — confirms test is live.

- [ ] **Step 3: Run test — verify it PASSES (implementation already exists)**

`get_vms` was implemented in Task 3. Run to confirm:

```bash
pipenv run pytest tests/test_crusoe_inventory.py::test_get_vms_calls_crusoe_cli -v
```

Expected: `PASSED`

- [ ] **Step 4: Make inventory script executable**

```bash
chmod +x inventory/crusoe.py
```

- [ ] **Step 5: Run the full test suite**

```bash
pipenv run pytest tests/ -v
```

Expected: `10 passed`

- [ ] **Step 6: Smoke test the script interface**

This verifies `--host` returns `{}` and `--list` parses args correctly (mocking the CLI call):

```bash
pipenv run python inventory/crusoe.py --host fake-host
```

Expected:
```json
{}
```

- [ ] **Step 7: Verify `ansible-inventory` can parse the script**

> Requires `crusoe` CLI on `$PATH` and `CRUSOE_API_KEY` set. Skip if running in CI without credentials — the unit tests cover correctness.

```bash
CRUSOE_API_KEY=your-key pipenv run ansible-inventory --list
```

Expected: JSON output with `all`, `project_*`, `type_*`, `region_*` groups and `_meta.hostvars` populated.

- [ ] **Step 8: Commit**

```bash
git add tests/test_crusoe_inventory.py inventory/crusoe.py
git commit -m "feat: wire crusoe inventory CLI, make script executable"
```

---

## Verification Checklist

After all tasks complete, confirm:

- [ ] `pipenv run python --version` → `Python 3.12.7`
- [ ] `pipenv run ansible --version` → `ansible [core 2.17+]`
- [ ] `pipenv run pytest tests/ -v` → `10 passed`
- [ ] `pipenv run python inventory/crusoe.py --host any` → `{}`
- [ ] `ansible-inventory --list` (with live credentials) → groups `project_*`, `type_*`, `region_*` present
- [ ] `ansible all -m ping -e "bastion_user=X bastion_host=Y"` (with live credentials) → all VMs reachable
