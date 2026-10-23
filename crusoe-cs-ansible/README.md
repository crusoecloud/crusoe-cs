# crusoe-cs-ansible

Ansible playbooks from the Crusoe Cloud Support team for operating,
remediating, and diagnosing hosts on Crusoe Cloud — VMs and Kubernetes nodes
alike.

Every playbook targets hosts from a shared dynamic inventory built from the
Crusoe Cloud API, so there is no inventory file to maintain: set up the repo
once, pick a host group, run a playbook.

## Playbooks

| Playbook | What it does | Docs |
|---|---|---|
| [eMudhra CA distrust](#emudhra-ca-distrust) | Removes root CAs chained to the compromised eMudhra intermediates | [README](playbooks/emudhra-ca/README.md) |
| [NFS](#nfs) | Mounts, troubleshoots, and validates Crusoe shared disks | [README](playbooks/nfs/README.md) |
| [Log collection](#log-collection) | Collects node logs for troubleshooting | [Playbook](playbooks/logs_collector.yml) |
| [SSH key management](#ssh-key-management) | Adds or removes SSH authorized keys | [Playbook](playbooks/ssh_keys.yml) |

### eMudhra CA distrust

Removes the distrusted eMudhra root CAs from hosts' trust stores.

📖 [`playbooks/emudhra-ca/README.md`](playbooks/emudhra-ca/README.md)

### NFS

Mounts and unmounts VAST NFS shared disks, works around IPv6 resolution
issues, captures CSI mount diagnostics, and validates mounts from Kubernetes
with the `nfs-test` Helm chart.

📖 [`playbooks/nfs/README.md`](playbooks/nfs/README.md)

### eMudhra CA DaemonSet chart

Runs the `emudhra_ca` role against every Kubernetes node's host VM via a
privileged DaemonSet + chroot — fleet-wide remediation from a single
`helm install`, no SSH.

📖 [`charts/crusoe-distrust-emudhra-ca/README.md`](charts/crusoe-distrust-emudhra-ca/README.md)

### Log collection

Collects kernel, journal, kubelet, containerd, and container logs from nodes
and saves them to `logs/<node>/` locally.

📄 [`playbooks/logs_collector.yml`](playbooks/logs_collector.yml)

### SSH key management

Adds or removes the SSH authorized keys defined in
[`roles/ssh_keys/files/authorized_keys.yml`](roles/ssh_keys/files/authorized_keys.yml).

📄 [`playbooks/ssh_keys.yml`](playbooks/ssh_keys.yml)

## Prerequisites

### Tooling

Install the following before running bootstrap:

```bash
# pyenv — Python version management
brew install pyenv
echo 'eval "$(pyenv init -)"' >> ~/.zshrc && source ~/.zshrc

# pipenv — virtualenv + package management
pip install --user pipenv

# direnv — per-directory environment activation
brew install direnv
echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc && source ~/.zshrc

# helm >= 4.0 and kubectl — only needed for Kubernetes playbooks
brew install helm kubectl
```

### Crusoe CLI

The dynamic inventory (`inventory/crusoe.py`) requires the `crusoe` CLI to be
installed and authenticated:

```bash
brew install crusoecloud/tap/crusoe
crusoe auth login
```

## Setup

```bash
./scripts/bootstrap.sh
direnv allow
```

Bootstrap installs the pinned Python version (3.14), creates the virtualenv,
installs Ansible + dependencies, and installs the required collections. direnv
activates the virtualenv and adds `scripts/` to `PATH` whenever you enter the
repo.

## Inventory

`inventory/crusoe.py` is a dynamic inventory that queries the Crusoe Cloud API
via the `crusoe` CLI and builds these groups, which you pass to playbooks as
`-e target_hosts=<group>` (or pass a single hostname):

| Group pattern | Example | Contains |
|---|---|---|
| `all` | `all` | Every VM in your account |
| `project_<project_id>` | `project_8f21c0b4_…` | All VMs in one project (the project **ID**, not its display name) |
| `type_<instance_type>` | `type_c1a` | All VMs of one instance type |
| `region_<region>` | `region_us_east1` | All VMs in a region (AZ suffix stripped) |
| `nodepool_<nodepool>` | `nodepool_gpu_workers` | Kubernetes nodes in one nodepool |
| `k8s_<cluster>` | `k8s_prod_cluster` | All Kubernetes nodes in one cluster |

## Repository layout

| Path | What it is |
|---|---|
| [`playbooks/`](playbooks/) | Playbooks — larger ones live in their own directory with a README |
| [`roles/`](roles/) | Roles backing the playbooks |
| [`inventory/`](inventory/) | Dynamic Crusoe Cloud inventory and `group_vars` |
| [`charts/`](charts/) | Helm charts used by Kubernetes playbooks |
| [`images/`](images/) | Container image build contexts (derived images for the charts) |
| [`tests/`](tests/) | Inventory unit tests and per-playbook e2e suites |
| [`scripts/`](scripts/) | `bootstrap.sh` (one-time setup) and `anssh <host>` (SSH to a node by inventory name) |

## Adding a playbook

1. Put it under `playbooks/` — give it its own directory and `README.md` if it
   needs more than a few lines of documentation.
2. Add a row to the [Playbooks](#playbooks) table and a short section linking
   to it.
