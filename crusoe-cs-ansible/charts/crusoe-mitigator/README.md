# crusoe-mitigator chart

Runs **configurable security mitigations** against every Kubernetes
node's host VM — one privileged DaemonSet, a list of mitigations in
values, no per-mitigation chart. Today: `cve-2026-98432` (default on)
and `emudhra-ca` (default off; the dedicated
[`crusoe-distrust-emudhra-ca`](../crusoe-distrust-emudhra-ca/) chart
remains the production path for that one — migrating it here is a
follow-up).

A privileged DaemonSet pod mounts the node's root filesystem at
`/host` (plus `/proc`, `/sys`, `/dev`) and runs each enabled
mitigation's wrapper playbook over the `community.general.chroot`
connection — every module (apt/dnf, systemd, nft) runs with the host's
own binaries.

**Why a DaemonSet (and not the SSH playbook) on Kubernetes:** the
sidecar's per-pod-netns coverage has no SSH equivalent — Cilium
delivers pod-bound traffic past the host's nft input hook, so only a
per-netns rule protects pod sockets, and only an always-scheduled
agent maintains it across pod churn and node replacement. The SSH
playbook is the right path for bare VMs (see the
[playbook README](../../playbooks/cve-2026-98432/README.md)); on k8s
the chart is the delivery. The generic entrypoint (`mitigate.py`, baked into the
image) runs **every** enabled mitigation (one failure does not block
the others) and reports each to stdout and the host journal. Failure
handling is per-mitigation: a once-only failure exits non-zero
immediately (the CrashLoop backoff is the retry cadence); a scheduled
failure rides the retry backoff — `mitigationFailureRetryBaseSeconds`
(30s) doubling per consecutive failure, capped at the mitigation's
interval — and only CrashLoops after 3 consecutive failures
(`mitigationMaxConsecutiveFailures`) — a transient failure
in one mitigation must not kill the pod and with it every other
mitigation's schedule. On SIGTERM (pod deletion) the entrypoint
drains: the in-flight playbook finishes, no new run starts, exit 0.

Nodes that join, rejoin, or get reimaged are covered automatically:
the DaemonSet schedules a pod on them and the pod runs the list once.
Deleting a pod re-runs every mitigation (self-healing).

## Progressive rollout (observe → enforce)

The cve-2026-98432 mitigation ships **observe-first** (counts +
rate-limited logs, drops nothing). With the cve-2026-98432 entry's `mode: auto` (the default),
**the node's label IS the rollout state** — one release, one pod per
node; the pod resolves its mode from the node's
`cve-2026-98432.remediator.crusoe.ai/mode` label on every run:

```bash
# One release, auto mode (values default). Unlabeled nodes resolve
# observe — Stage 1 is just the install.
helm install crusoe-mitigator charts/crusoe-mitigator -n <ns>

# Canary: label the node — the mitigator's node watcher (k8s watch
# API) fires an immediate re-run; the node converges in seconds.
# No pod delete, no second release, no port conflict.
kubectl label node <node> cve-2026-98432.remediator.crusoe.ai/mode=enforce

# Rollback (R1): the explicit observe label IS the sanctioned
# downgrade — the operator's deliberate, audited action; the watcher
# converges the node in seconds.
kubectl label node <node> cve-2026-98432.remediator.crusoe.ai/mode=observe
```

The label carries the mode **explicitly** (`enforce`|`observe`; absent
= observe): `kubectl get nodes -L cve-2026-98432.remediator.crusoe.ai/mode`
shows the fleet's rollout state at a glance, and an unknown value
(e.g. a typo) fails the pod loudly instead of silently resolving
observe. The whole lifecycle (stages, gates, R1/R2/R3) is codified in
[`playbooks/cve-2026-98432/rollout-ops.yml`](../../playbooks/cve-2026-98432/rollout-ops.yml).

The role's mode guard refuses a silent enforce→observe downgrade (an
explicit `mode=observe` label is the sanctioned path). Gates, waves,
and the
R1/R2/R3 rollback ladder: the
[rollout runbook](../../docs/runbooks/cve-2026-98432-rollout.md).

## Metrics

Any enabled mitigation with `metrics: true` (default) renders the
**metrics-server sidecar**: a tiny HTTP server (baked into the image)
serving every `*.prom` in the chart hostPath
(`/var/lib/crusoe-mitigator`) on `:19698`.

> **The metrics port is unauthenticated.** With `hostNetwork: true`
> the pod shares the node's network namespace, so the bind address
> decides who can reach it. It defaults to the node's **internal**
> address (`status.hostIP`) — vmagent scrapes the pod IP, which under
> hostNetwork IS that address, so the scrape works while the public
> interface stays closed.
>
> Setting `metricsBind: "0.0.0.0"` re-exposes it on the node's public
> interface wherever the provider firewall allows it. The exposition
> includes per-namespace series. Firewall `:19698` to the scraper if
> you override it.
>
> **Node-local consumers don't need the HTTP hop at all:** the `.prom`
> files live in the hostPath (`/var/lib/crusoe-mitigator`), so a host
> agent can read them directly — the node_exporter textfile-collector
> pattern. That covers the loopback case without a second listener.
>
> The bind address decides which **interfaces** listen — and for a
> `hostNetwork: true` pod that is the only reliable control.
> Kubernetes NetworkPolicy behaviour on hostNetwork pods is
> undefined; common CNIs treat that traffic as node traffic and
> ignore podSelector policies, so a policy here would promise a
> restriction it cannot deliver. Firewall `:19698` at the provider
> level if you need peer restrictions.

The pod carries
`prometheus.io/scrape` annotations, so the cluster's existing scrape
path picks it up with zero config changes (vmagent's `kubernetes-pods`
job on Crusoe; set `metricsBackend: gmp` to render a `PodMonitoring`
CR for GKE managed collection instead — same port, same exposition).

### Overriding a mitigation's vars (the values-file shape)

Helm's `--set mitigations[0]...` **replaces the list element
wholesale** — dropping `name`/`playbook`/`enabled` and silently
disabling the mitigation. The safe override is a values FILE that
re-declares the entry with the one var changed. Copy-paste snippet
(the metrics timer cadence as the example — role default 60s; the
timer is the host-side consumer and only affects SSH/bare-VM
delivery: the pod-native chart image (alpine) ships no `systemctl`,
so the timer never installs in chart deployments — the reconciler's
10s republish owns host-series freshness there and this var is
inert; on bare VMs it sets the timer's cadence):

```yaml
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
    sidecar:
      command: /usr/local/sbin/cve-2026-98432-netns-reconcile.py
      interval: 10
```

```bash
helm upgrade crusoe-mitigator charts/crusoe-mitigator -n crusoe-mitigator -f your-values.yaml
```

## Delivery: pod-native

The mitigator runs **pod-native** (default): the privileged
`hostNetwork: true` pod uses the IMAGE's own `nft` via netlink against
the shared host netns — no chroot into host userspace, no host package
manager, no host python. Works identically on Ubuntu VMs and minimal
hosts (COS).

> **History:** chart versions before the next release rendered the
> DaemonSet WITHOUT `hostNetwork` — the rule loaded in the pod's
> isolated netns while every check read it there and reported
> protected. Fixed after the hostNetwork regression; the chart's unit
> test now pins it.

Persistence auto-detects: a writable host `/etc` (via
`/host`) installs the boot unit for instant post-reboot coverage;
otherwise the chart's scheduled re-run interval is the persistence
(the honest model on hosts that are replaced rather than rebooted).

## Install / teardown

```bash
# Install (default: cve-2026-98432 on every node)
helm install crusoe-mitigator charts/crusoe-mitigator -n <namespace> --create-namespace

# Canary: ONE node first (recommended for the first install)
helm install crusoe-mitigator charts/crusoe-mitigator -n <namespace> --create-namespace \
  --set nodeSelector.'kubernetes\.io/hostname'=<node-name>

# Enable both mitigations (values-file form; --set list-index syntax
# cannot express partial map entries):
helm install crusoe-mitigator charts/crusoe-mitigator -n <namespace> \
  --values <(yq '.mitigations[].enabled = true' charts/crusoe-mitigator/values.yaml)

# Tear down (mitigations REMAIN on the hosts — they outlive the chart)
helm uninstall crusoe-mitigator -n <namespace>
```

### CCR tenants: override the image

The chart's default image is the **public** ghcr publish
(`ghcr.io/crusoecloud/crusoe-cs/ansible@sha256:...` — no pull secret
needed). Tenants whose clusters cannot reach ghcr.io must mirror the
image into their registry and override with their own digest-pinned
ref:

```bash
--set image.full=registry.<your-location>.ccr.crusoecloudcompute.com/<your-repo>.<your-project8>/ansible@sha256:<digest>
```

⚠️ The default digest predates the `cve_2026_98432` role and the
generic entrypoint — rebuild the image and re-pin from the
`ansible-image:merge` job output before installing with the
cve-2026-98432 mitigation enabled.

## Values

| Value | Default | Meaning |
|---|---|---|
| `mitigations` | cve-2026-98432 on, emudhra-ca off | The list of mitigations to run (see below) |
| `journaldLogging` | `true` | Structured events to the host journal (Managed Logs console: `SYSLOG_IDENTIFIER=crusoe-mitigator`) |
| `nodeSelector` | `{}` | Restrict to specific nodes |
| `tolerations` | `[]` | Taints the mitigator tolerates. **Empty by default — check your fleet:** a DaemonSet with no tolerations stays off every tainted node, GPU nodes are usually tainted, and nothing reports the gap (`kubectl get nodes -o custom-columns='NAME:.metadata.name,TAINTS:.spec.taints'`). Opt in with `tolerations: [{operator: Exists}]` to cover tainted nodes; scope it with a `key` if tolerating everything (including control-plane taints) is too broad |
| `metricsPort` | `19698` | The metrics server's port |
| `metricsBind` | `""` (the node's internal IP) | Which interface the metrics server listens on. **Two choices only:** `""` = `status.hostIP`, resolved per node (public interface closed); `"0.0.0.0"` = all interfaces. Anything else fails the render — a literal IP is a per-node address in a DaemonSet-wide setting, and `127.0.0.1` breaks scraping |

### Adding a mitigation

Each entry in `mitigations`:

```yaml
mitigations:
  - name: cve-2026-98432          # logs, journal, failure reporting
    enabled: true
    playbook: wrapper-cve-2026-98432.yml  # baked at /opt/ansible in the image
    vars:                         # flat map → -e key=value to the playbook
      cve_2026_98432_run_probe: "true"
```

To add a new mitigation: write the role + a thin wrapper playbook
(pre-flight play + chroot play, like
[`wrapper-cve-2026-98432.yml`](../../images/ansible/wrapper-cve-2026-98432.yml)),
bake both into the image (Dockerfile), and add the entry here. The
chart needs no other change. A mitigation that needs a long-running
helper declares it as a `sidecar` on its own entry (command + optional
`interval` env) — the chart renders it only while that mitigation is
enabled, and `hostPID` is set automatically when any sidecar is
present.

## Pod-netns coverage (Cilium)

On Cilium nodes (veth/tc datapath), pod-bound traffic is delivered into
the pod netns by Cilium's BPF **without traversing the host's nft
hooks** — the host rule alone leaves pod sockets exposed (verified
empirically; see the playbook README's pod-netns section). The
`cve-2026-98432` mitigation declares its own reconciler `sidecar`
(see values): event-driven — inotify on `/run/netns` fires the instant
Cilium mounts a new pod netns — with an interval fallback sweep. It
installs the same rule in each pod netns via `nsenter` + the host's
`nft`. Verified live: option-TCP to a previously-exposed pod is
DROPPED (netns rule counter increments), plain traffic unaffected,
fresh pods auto-covered.

The `/host` mounts (sidecar and mitigator containers) carry
`mountPropagation: HostToContainer`: the reconciler enters pod netns
via the `/run/netns/<id>` bind mounts the CNI creates AFTER the
mitigator pod started — without propagation those mounts are
invisible inside the container, `nsenter` fails `Invalid argument`,
and the event-driven path silently degrades to the interval fallback
(found live: fresh pods ran ~10s uncovered). The
reconciler diagnoses every EINVAL skip against the two
mount-namespace views it can read (hostPID): a mount the host has
but this container lacks WARNs naming the propagation fix, while a
stale leftover (pod gone) logs benign INFO — so a propagation
regression cannot hide (the chart's unit test pins the field) and
pod churn does not flood a WARN-level console.

## Verification

```bash
# Every pod parked (not CrashLooping) = every node mitigated:
kubectl get pods -n <namespace> -l app=crusoe-mitigator

# A mitigation's state on a node (example: the cve rule):
kubectl exec -n <namespace> <pod> -c mitigator -- chroot /host /usr/sbin/nft list chain ip cve_2026_98432 input
```
