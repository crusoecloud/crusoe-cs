# crusoe-distrust-emudhra-ca chart

Runs the [`emudhra_ca`](../../roles/emudhra_ca/) role against **every
Kubernetes node's host VM** — no SSH, no per-host action. A privileged
DaemonSet pod mounts the node's root filesystem at `/host` (plus `/proc`,
`/sys`, `/dev`) and executes the role over the
`community.general.chroot` connection, so every module (apt/dnf, openssl,
`update-ca-certificates`) runs with the host's own binaries and trust
stores. The role ships **unchanged** inside a derived container image.

Nodes that join, rejoin, or get reimaged are covered automatically: the
DaemonSet schedules a pod on them and the pod runs the role once. A
successful run **parks** (`sleep infinity`) — logs stay readable via
`kubectl logs`, and deleting the pod re-runs the role. A failed run exits
non-zero and **CrashLoops loudly** (self-retrying with backoff).

## Install / teardown

```bash
# Install (defaults: every node, extended stores on, connectivity check off)
helm install crusoe-distrust-emudhra-ca charts/crusoe-distrust-emudhra-ca -n <namespace> --create-namespace

# Canary: ONE node first (recommended for the first install — see below)
helm install crusoe-distrust-emudhra-ca charts/crusoe-distrust-emudhra-ca -n <namespace> --create-namespace \
  --set nodeSelector.'kubernetes\.io/hostname'=<node-name>

# Scope to a node pool (recommended on mixed-OS fleets — see the unsupported-OS warning)
helm install crusoe-distrust-emudhra-ca charts/crusoe-distrust-emudhra-ca \
  --set nodeSelector.'nodepool\.example\.com/name'=gpu-workers

# Tear down
helm uninstall crusoe-distrust-emudhra-ca -n <namespace>
```

### CCR tenants: override the image

The chart's default image is the **public** ghcr publish
(`ghcr.io/crusoecloud/crusoe-cs/ansible@sha256:...` — no pull secret
needed). Tenants whose clusters can pull from ghcr.io need no override.
Only tenants whose clusters **cannot reach ghcr.io** (egress-restricted
to their own CCR) must mirror the image into their registry and override
with their own digest-pinned ref:

```bash
--set image.full=registry.<your-location>.ccr.crusoecloudcompute.com/<your-repo>.<your-project8>/ansible@sha256:<digest>
```

### Canary rollout (one node first)

A fleet-wide privileged DaemonSet deserves a staged rollout:

1. Pick a node: `kubectl get nodes`.
2. Install scoped to it with the `kubernetes.io/hostname` selector above.
3. Verify: the pod parks (`kubectl get pods -n <namespace>`), the recap
   shows `failed=0`, and the journal events appear in the Managed Logs
   console (`SYSLOG_IDENTIFIER=crusoe-distrust-emudhra-ca`).
4. Widen to the whole fleet: `helm upgrade` without the `nodeSelector`
   (or with a node-pool selector).

Caveat: a `kubernetes.io/hostname` selector pins the DaemonSet to that
one node — if the node is deleted, the DS has nowhere to schedule until
you re-scope. That is exactly what you want for a canary, and exactly
what you don't want long-term.

## Values

| Value | Default | Description |
|---|---|---|
| `image` | Public ghcr image pinned by `@sha256:` digest | Derived image (role + wrapper + inventory baked at `/opt/ansible`). **Always pin by digest** — a floating tag could silently run different bytes than the ones reviewed. Re-pin after each CI publish (see the values.yaml comment). Clusters that cannot reach ghcr.io (e.g. egress-restricted CCR tenants) override with their own digest-pinned ref via `--set image.full=` (see [CCR tenants](#ccr-tenants-override-the-image)). |
| `connectivityCheck` | `false` | Opt-in live `s_client` canary on remediated hosts. A single egress pre-check gates it: with no route to the test sites the canary is skipped with an explanatory message, not a failure. Keep `false` anyway — a pod start should not open external TLS connections; enable only for interactive verification runs. Only runs on hosts the run remediated. |
| `failOnUnsupportedFamily` | `true` | CrashLoop on nodes outside the supported OS families (Debian: Ubuntu/Debian; RedHat: Rocky/AlmaLinux/RHEL) instead of parking silently. |
| `extendedStores` | `true` | Also remediate certifi bundles and Java cacerts **where already present** (never installs them). |
| `nodeSelector` | `{}` | Restrict to specific nodes. |
| `tolerations` | `[]` | Toleration passthrough (control-plane taints are the installer's call). |
| `imagePullSecrets` | `[]` | Not needed for the default public ghcr image. **Required when overriding `image.full` with a CCR ref** — CCR is private, so create a docker-registry secret for `registry.<location>.ccr.crusoecloudcompute.com` (username: your Crusoe account email, password: a token from `crusoe registry tokens create`) and reference it here. |

## Re-running

The role is idempotent (proven by the e2e suite). To re-run on a node,
delete that node's pod — the DaemonSet replaces it and the role runs
again. Node lifecycle events (join, reimage) re-trigger naturally.

## Privileged / hostPath requirement

The pod runs `privileged: true` with `runAsUser: 0` and mounts host `/`,
`/proc`, `/sys`, `/dev` — the chroot connection requires root and
`CAP_SYS_CHROOT`, and apt/dnf inside the chroot need the host's
pseudo-filesystems. **If the install namespace enforces PodSecurity
`baseline`/`restricted` (or OPA/Gatekeeper policies), the pod will be
rejected** — exempt the namespace or scope the install to one that
allows privileged pods.

## ⚠️ Unsupported-OS warning (e.g. GKE Container-Optimized OS)

`failOnUnsupportedFamily: true` + an empty `nodeSelector` means every
unsupported node **CrashLoops loudly** — that is intended (a silent gap
is worse). On fleets that include nodes running unsupported OSes (e.g.
GKE's Container-Optimized OS), you MUST scope `nodeSelector` to actual
supported-family nodes (Debian: Ubuntu/Debian; RedHat: Rocky/AlmaLinux/RHEL), or every unsupported node will CrashLoop forever.
A remediation path for unsupported OSes is out of scope.

## Image workflow

- CI builds the image **from the merge commit** (tag = commit SHA) on
  every chart/image change — the bytes that run are the bytes reviewed.
- The `ansible-image:build` job pushes the multi-arch image to the
  **public** `ghcr.io/crusoecloud/crusoe-cs/ansible` on the default
  branch and prints the pushed digest — update the chart's
  `values.yaml` pin from that output in the same MR flow.
  Requires the protected `GHCR_USERNAME`/`GHCR_TOKEN` CI/CD variables
  (PAT with `write:packages` on the crusoecloud org).
- The chart's default points at the public ghcr publish
  (digest-pinned); installs need no pull secret. Override with
  `--set image.full=` if your registry differs.
- Fleet installs pin the image **by digest** (`@sha256:`), never a
  floating tag.
- Local builds are for the [chart smoke](../../tests/e2e/emudhra-ca/) only,
  never for a fleet.
