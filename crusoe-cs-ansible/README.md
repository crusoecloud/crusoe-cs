# crusoe-cx-ansible

Ansible playbooks and Helm charts for operating and diagnosing Crusoe Cloud Kubernetes nodes.

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

# helm >= 4.0
brew install helm

# kubectl
brew install kubectl
```

### Kubeconfig

1. Log in to the [Crusoe Cloud console](https://console.crusoe.ai)
2. Navigate to **Kubernetes** → select your cluster
3. Click **Download kubeconfig** and save the file
4. Point kubectl at it:

```bash
export KUBECONFIG=~/Downloads/<your-cluster>.kubeconfig

# Verify connectivity
kubectl get nodes
```

To make it permanent, add the `export KUBECONFIG=...` line to your `~/.zshrc`.

### Crusoe CLI

The dynamic inventory (`inventory/crusoe.py`) requires the `crusoe` CLI to be installed and authenticated:

```bash
brew install crusoecloud/tap/crusoe
crusoe auth login
```

## Setup

```bash
./scripts/bootstrap.sh
direnv allow
```

Bootstrap installs the pinned Python version (3.14), creates the virtualenv, installs Ansible + dependencies, and installs the `kubernetes.core` collection. direnv activates the virtualenv and adds `scripts/` to `PATH` whenever you enter the repo.

## Playbooks

All remote playbooks require `-e target_hosts=<group>`. Omitting it will fail with a clear error.

### NFS

```bash
# Install VAST NFS driver and mount volumes
ansible-playbook playbooks/nfs/nfs_mount.yml -e target_hosts=<group>

# Unmount volumes
ansible-playbook playbooks/nfs/nfs_unmount.yml -e target_hosts=<group>

# Fix IPv6 precedence (workaround for bogus AAAA records)
ansible-playbook playbooks/nfs/fix_ipv6_precedence.yml -e target_hosts=<group>
```

`nfs_mount.yml` defaults to DNS mode (`remoteports=dns`). Switch to IPv4:

```bash
ansible-playbook playbooks/nfs/nfs_mount.yml -e "target_hosts=<group> nfs_mode=ip"
```

### Kubernetes NFS test

Deploys the `nfs-test` Helm chart, waits for all pods to reach Running, and prints probe logs. Runs locally against your kubeconfig.

```bash
# DNS mode (default)
ansible-playbook playbooks/nfs/nfs_k8s_test.yml

# IPv4 mode
ansible-playbook playbooks/nfs/nfs_k8s_test.yml -e nfs_mode=ipv4

# Tear down
ansible-playbook playbooks/nfs/nfs_k8s_test.yml -e uninstall=true
```

### Log collection

Collects kernel, journal, kubelet, containerd, and container logs from remote nodes and saves them to `logs/<node>/` locally.

```bash
ansible-playbook playbooks/log_collect.yml -e target_hosts=<group>

# Specific nodes
ansible-playbook playbooks/log_collect.yml -e target_hosts=<group> -l "node1,node2"

# Custom time window
ansible-playbook playbooks/log_collect.yml -e "target_hosts=<group> since=2026-05-13T00:00:00"
```

## Helm chart: nfs-test

Located at `charts/nfs-test/`. Deploys:

- **DaemonSet** — one pod per node; writes and reads a probe file on each NFS volume to validate per-node mount health
- **Deployment** — 2 replicas spread across distinct nodes via `topologySpreadConstraints`; validates RWX multi-attach as a real app would use it

Key values:

| Value | Default | Description |
|---|---|---|
| `nfsServer` | `nfs.crusoecloudcompute.com` | NFS server address (IP or hostname) |
| `nfsMountOptions` | `vers=3,nconnect=16,spread_reads,spread_writes,remoteports=dns` | Mount options passed to every PV |
| `volumes` | `disk-a`, `disk-b` (placeholder `nfsPath`s — set your own volume UUIDs) | NFS volumes to mount and test |
| `nodeSelector` | `{}` | Restrict to a specific node pool |
| `deployment.enabled` | `true` | Toggle the app-validation Deployment |
| `deployment.replicas` | `2` | Number of Deployment replicas |

## Inventory

`inventory/crusoe.py` is a dynamic inventory plugin that queries the Crusoe Cloud API via the `crusoe` CLI. Results are cached for 120 seconds.

## Scripts

| Script | Description |
|---|---|
| `scripts/bootstrap.sh` | One-time project setup |
| `scripts/anssh <host>` | SSH into a node by its Ansible inventory name |

`anssh` is available in your shell whenever you're inside the repo (via direnv `PATH_add`). It resolves `ansible_host` from the inventory and connects as `ubuntu`.
