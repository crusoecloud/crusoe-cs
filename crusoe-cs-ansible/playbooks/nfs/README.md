# NFS

Playbooks for mounting, troubleshooting, and validating Crusoe shared disks
(VAST NFS) on VMs and Kubernetes nodes.

| Playbook | What it does | Runs against |
|---|---|---|
| [`nfs_mount.yml`](nfs_mount.yml) | Installs the VAST NFS driver and mounts shared disks | Remote hosts |
| [`nfs_unmount.yml`](nfs_unmount.yml) | Unmounts shared disks | Remote hosts |
| [`fix_ipv6_precedence.yml`](fix_ipv6_precedence.yml) | Prefers IPv4 over IPv6 (workaround for bogus AAAA records) | Remote hosts |
| [`nfs_diag.yml`](nfs_diag.yml) | Captures a trace of the CSI-driven NFS mount path on a node | Remote hosts + your kubeconfig |
| [`nfs_k8s_test.yml`](nfs_k8s_test.yml) | Deploys the `nfs-test` Helm chart and checks mount health | Your kubeconfig (local) |

## Prerequisites

Complete the repository setup first — see the root README's
[Prerequisites](../../README.md#prerequisites), [Setup](../../README.md#setup),
and [Inventory](../../README.md#inventory).

Remote playbooks require `-e target_hosts=<group_or_host>`. The Kubernetes
playbooks (`nfs_diag.yml`, `nfs_k8s_test.yml`) also need `helm`, `kubectl`,
and a kubeconfig for the target cluster:

1. Log in to the [Crusoe Cloud console](https://console.crusoe.ai)
2. Navigate to **Kubernetes** → select your cluster
3. Click **Download kubeconfig** and save the file
4. Point kubectl at it:

```bash
export KUBECONFIG=~/Downloads/<your-cluster>.kubeconfig
kubectl get nodes   # verify connectivity
```

## Mount and unmount

```bash
# Install the VAST NFS driver and mount volumes
ansible-playbook playbooks/nfs/nfs_mount.yml -e target_hosts=<group> \
  -e 'nfs_mounts=[{src: "<nfs-server>:/volumes/<uuid>", path: "/mnt/disk-a"}]'

# Unmount volumes (defaults to /mnt/disk-a and /mnt/disk-b)
ansible-playbook playbooks/nfs/nfs_unmount.yml -e target_hosts=<group>
```

`nfs_mount.yml` defaults to IP mode (`nfs_mode=ip`), which uses
`nfs_server_ip` and `nfs_vip_range`. Switch to DNS mode (`remoteports=dns`):

```bash
ansible-playbook playbooks/nfs/nfs_mount.yml -e "target_hosts=<group> nfs_mode=dns" \
  -e 'nfs_mounts=[...]'
```

| Variable | Default | Description |
|---|---|---|
| `nfs_mounts` | *(required)* | List of `{src, path}` mounts |
| `nfs_mode` | `ip` | `ip` or `dns` |
| `nfs_server_ip` | `$NFS_SERVER_IP` | NFS server IP (IP mode) |
| `nfs_vip_range` | `$NFS_VIP_RANGE` | VIP range for `remoteports=` (IP mode) |
| `nfs_server_dns` | `$NFS_SERVER_DNS` or `nfs.crusoecloudcompute.com` | NFS hostname (DNS mode) |

## IPv6 precedence fix

Sets IPv4 precedence in `/etc/gai.conf` and pins the NFS hostname to its IPv4
VIPs, for environments where bogus AAAA records break NFS resolution.

```bash
ansible-playbook playbooks/nfs/fix_ipv6_precedence.yml -e target_hosts=<group> \
  -e 'nfs_vips=["10.0.0.1", "10.0.0.2"]'
```

| Variable | Default | Description |
|---|---|---|
| `nfs_vips` | `$NFS_VIPS` (comma-separated) | **Required.** IPv4 VIPs to pin |
| `nfs_hostname` | `$NFS_HOSTNAME` or `nfs.crusoecloudcompute.com` | NFS hostname |

## CSI mount diagnostics

Copies [`nfs_csi_mount_diag.sh`](../../roles/nfs/files/nfs_csi_mount_diag.sh)
to each target node (installs `bpftrace` on Debian-family hosts) and runs it
in the background. It then deletes the `nfs-test` pod on that node to trigger
a CSI remount, waits for the script to finish (up to ~11 minutes), and
fetches the evidence to `logs/` locally.

Requires the [`nfs-test`](#kubernetes-nfs-test) chart to be running on the
target nodes.

```bash
ansible-playbook playbooks/nfs/nfs_diag.yml -e target_hosts=<group>
```

## Kubernetes NFS test

Deploys the [`nfs-test`](../../charts/nfs-test/) Helm chart, waits for all
pods to reach Running, and prints probe logs. Runs locally against your
kubeconfig — no `target_hosts` needed.

```bash
ansible-playbook playbooks/nfs/nfs_k8s_test.yml                    # DNS mode (default)
ansible-playbook playbooks/nfs/nfs_k8s_test.yml -e nfs_mode=ipv4   # IPv4 mode
ansible-playbook playbooks/nfs/nfs_k8s_test.yml -e uninstall=true  # tear down
```

| Variable | Default | Description |
|---|---|---|
| `nfs_mode` | `dns` | `dns` or `ipv4` |
| `helm_release` | `nfs-test` | Helm release name |
| `k8s_namespace` | `default` | Namespace to deploy into |
| `uninstall` | `false` | Tear down the release instead of installing |

### Helm chart: nfs-test

Located at [`charts/nfs-test/`](../../charts/nfs-test/). Deploys:

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
