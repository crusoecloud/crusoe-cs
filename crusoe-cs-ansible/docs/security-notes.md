# Security notes — remediation DaemonSets

This document records the deliberate security posture of the
remediation charts and the rationale for the SAST findings that are
**by design**, not defects. It exists so the vulnerability-report
findings on these charts (in the project's CI security scanning) can
be dismissed with a documented risk-acceptance instead of
re-litigated on every MR.

## The pattern

Both charts — [`crusoe-mitigator`](../charts/crusoe-mitigator/) and
[`crusoe-distrust-emudhra-ca`](../charts/crusoe-distrust-emudhra-ca/) —
run a privileged DaemonSet that remediates the **host VM** from inside
a pod: the pod mounts the host's root filesystem and runs Ansible
against it (chroot connection, or image-native tooling via netlink).
This is the same trust model as a node agent (the DaemonSet is
cluster-admin-controlled, like the kubelet itself).

## Findings that are the mechanism, not bugs

| Finding | Why it is required |
|---|---|
| **Privilege Escalation Allowed** (critical) | The pod must act as root on the host: `nft` (netlink), `nsenter --net` (CAP_SYS_ADMIN), `chroot`, systemd unit management. A non-privileged remediation pod cannot remediate anything. |
| **Volume Mount With OS Directory Write Permissions** (critical) | The host root at `/host` IS the remediation target: the role writes the ruleset, the boot units, and the mode state there. Read-only would make the mitigation impossible. |
| **Shared Host Network Namespace** (medium) | The nft rule must load in the HOST netns (the CVE is in the host kernel's TCP stack). The metrics sidecar binds `:19698` hostNetwork so vmagent scrapes it without extra Services. |
| **NET_RAW Capabilities Not Being Dropped** (medium) | The reconciler's `nsenter` + netlink socket work needs the full capability set that `privileged: true` implies. |
| **Service Account Token Automount Not Disabled** (medium) | crusoe-mitigator's auto mode READS the node's mode label via the API (get/list/watch on nodes — a read-only ClusterRole, rendered by the chart). The token is required for the label resolution and the event-driven watcher. |
| **Memory/CPU Requests & Limits Not Defined** (medium/info) | The mitigator runs short Ansible bursts then parks; the reconciler sweeps every 10s. Requests would reserve capacity on every node for a mostly-idle pod; the DaemonSet is bounded by the node count. Revisit if a real resource incident appears. |
| **Readiness/Liveness Probes** (medium/info) | Probes are configurable (`probes.enabled`, default on) in crusoe-mitigator: the reconciler's alive-file heartbeat, the metrics-server's GET /metrics, and the mitigator's pgrep. The emudhra chart predates the pattern; adopting it there is a follow-up, not a defect. |
| **Root Container Not Mounted Read-only** (info) | The entrypoint writes metrics `.prom` files and the alive-file heartbeat inside the container. |

## What IS hardened

- **Least-privilege RBAC where API access is needed**: the
  crusoe-mitigator chart renders a read-only ClusterRole
  (`get`/`list`/`watch` on `nodes` only) — no writes, no secrets.
- **Digest-pinned images**: the chart refuses to render a floating
  tag; the reviewed bytes are the running bytes.
- **No secrets in the pod**: the mitigations are host-state
  operations; no credentials are mounted or logged.
- **The mode guard**: an enforce table can never be silently
  downgraded (the R1 label is the explicit, audited sanction).
- **API-outage safety**: the mode resolution fails open to the last
  known mode — no flip during an outage.

## Dependency findings

The Pipfile dependency-scanning findings (urllib3, cryptography,
certifi, oauthlib, filelock, ansible-core) are resolved by the
lockfile update (see the repo's Pipfile.lock); the certifi bundle is
verified to carry none of the distrusted eMudhra root fingerprints
(the emudhra_ca role's `emudhra_ca_bad_roots` list) — in the venv and
in the built image.

## Dismissal guidance

When dismissing a finding on these charts in the GitLab
vulnerability report, link this document and cite the table row.
Findings NOT covered here (something new in the diff) get real
treatment — this document is the standing rationale for the pattern,
not a blanket waiver.
