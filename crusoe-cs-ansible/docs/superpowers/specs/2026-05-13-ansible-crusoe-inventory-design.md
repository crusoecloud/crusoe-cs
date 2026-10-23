# Ansible + Crusoe Infrastructure Management — Design Spec

**Date:** 2026-05-13
**Scope:** Bootstrap pyenv + pipenv environment with Ansible and a dynamic inventory script that interfaces with the Crusoe CLI for configuration management of Crusoe Cloud VMs.

---

## Goals

- Manage existing Crusoe Cloud VMs (compute, networking, storage, K8s) via Ansible configuration management
- Dynamic inventory pulled live from the Crusoe CLI on each run
- Multi-dimensional host grouping: project, instance type, region
- SSH access routed through a bastion/jump host
- Python environment fully reproducible via pyenv + pipenv

## Out of Scope

- Provisioning or destroying Crusoe resources via Ansible
- Inventory caching (may be added later if performance becomes an issue)
- Crusoe Python SDK (CLI subprocess is the integration point)

---

## Repository Structure

```
repo/
├── .python-version          # pyenv interpreter pin (3.12.x)
├── Pipfile                  # pipenv manifest
├── Pipfile.lock             # locked dependency tree
├── ansible.cfg              # Ansible config, points inventory at inventory/crusoe.py
├── inventory/
│   ├── crusoe.py            # dynamic inventory script (executable)
│   └── group_vars/
│       └── all.yml          # shared vars: bastion config, ansible_user, etc.
├── playbooks/               # playbooks
└── roles/                   # roles
```

---

## Python Environment

### pyenv
A `.python-version` file pins the interpreter to `3.12.x`. pyenv reads this automatically on `cd` — no manual activation step required.

### pipenv
`Pipfile` declares:

```toml
[packages]
ansible = "*"
ansible-lint = "*"

[requires]
python_version = "3.12"
```

No dev-packages initially. Run playbooks via `pipenv run ansible-playbook ...` or inside `pipenv shell`.

The `crusoe` CLI is a system-level dependency — expected on `$PATH`, installed separately, not managed by pipenv.

---

## Ansible Configuration

**`ansible.cfg`:**

```ini
[defaults]
inventory           = inventory/crusoe.py
host_key_checking   = False
remote_user         = ubuntu
retry_files_enabled = False

[ssh_connection]
pipelining = True
```

- `host_key_checking = False`: standard for cloud environments with ephemeral VMs
- `pipelining = True`: reduces SSH round-trips, significantly speeds up task execution

---

## Dynamic Inventory Script

**File:** `inventory/crusoe.py`
**Interface:** Standard Ansible dynamic inventory (`--list` / `--host <hostname>`)

### `--list`

1. Shells out to `crusoe vm list --output json`
2. Parses JSON output and constructs inventory with these group dimensions:
   - `project_<name>` — one group per Crusoe project
   - `type_<instance_family>` — e.g., `type_a40`, `type_c1a`
   - `region_<location>` — e.g., `region_us-northcentral1`
   - `all` — flat group containing every VM
3. Populates `_meta.hostvars` for each host: `ansible_host` (internal IP), instance type, project, region

### `--host <hostname>`

Returns `{}`. All hostvars are embedded in `--list` via `_meta` to avoid N+1 subprocess calls.

### Authentication

The script inherits `CRUSOE_API_KEY` from the shell environment. No credentials are stored in the repository.

---

## Bastion / Jump Host

SSH jump host is configured in `inventory/group_vars/all.yml`:

```yaml
ansible_ssh_common_args: "-J {{ bastion_user }}@{{ bastion_host }}"
```

`bastion_user` and `bastion_host` are supplied as extra vars or Ansible Vault secrets — never hardcoded in the repo.

---

## Success Criteria

- `pipenv install` reproduces the environment cleanly on a fresh machine
- `ansible-inventory --list` returns grouped hosts drawn from live Crusoe VM data
- `ansible all -m ping` reaches VMs through the bastion
- Groups `project_*`, `type_*`, and `region_*` are all present and correctly populated
