# eMudhra CA DaemonSet — Fleet-Wide Host Remediation via Helm Chart

**Date:** 2026-10-21

## Intent

The `emudhra_ca` role and its playbook remediate the four distrusted eMudhra
roots host-by-host over SSH. That works for a one-time sweep, but it depends
on someone remembering to re-run it whenever a node joins the fleet or gets
reimaged — and a fresh image ships the package-rooted distrusted roots again.
We want the remediation to be a single `helm install` that covers every node
in the cluster, now and automatically as nodes join, without SSH. The role
ships inside a derived container image (the house pattern — see Mechanism)
published to `ghcr.io/crusoecloud/emudhra-ca`, so both target fleets pull
it natively with no imagePullSecrets.

This is **phase 2** of the emudhra-ca work (the phase-1 design is
`2026-10-21-emudhra-sca-distrust-roots-design.md`; the role, playbook, and
e2e harnesses are complete and green on that branch).

## Goals

- A Helm chart (`charts/emudhra-ca/`) whose `helm install` runs the existing
  `emudhra_ca` role against every node's host VM — no SSH, no per-host action.
- Nodes that join (or rejoin, or reimage) later are covered automatically:
  the DaemonSet schedules a pod on them and the pod runs the role once.
- The role itself is the single source of remediation logic — the image
  bakes it in verbatim at CI build time from the merge commit; nothing is
  reimplemented in the chart.
- Failure is loud and self-retrying: a node that cannot be remediated shows
  a CrashLooping pod, not a silent gap.
- Success is quiet and cheap: a remediated (or already-clean) node parks a
  small sleeping container; re-runs are safe because the role is idempotent
  (proven by the clean/mixed e2e scenarios).

## Non-Goals

- No changes to the role's remediation logic, detection fingerprints, or
  fallback behavior — the chart is a delivery mechanism only.
- No scheduled/periodic re-runs inside the pod (re-run = delete the pod or
  bump the chart; node lifecycle events re-trigger naturally).
- No Java truststore remediation beyond the role's existing extended-stores
  scope (certifi + Java cacerts, never-install semantics — folded into the
  role 2026-10-21; the chart only passes the opt-out through).
- No GitOps/CI wiring for the chart's rollout (manual `helm install` for now).

## Anti-Goals

- Never let the baked role drift from `roles/emudhra_ca/`: the image is
  built by CI **from the merge commit** (tag = commit SHA), so the bytes
  that run are the bytes reviewed in the PR. Hand-built local images are
  for the kind smoke only, never for a fleet.
- Never require SSH or the dynamic inventory on the cluster side — the pod
  reaches the host through the mounted filesystem only.
- No floating image tags in default values — the image is pinned by digest.

## Constraints

- The pod must run privileged: the chroot connection requires root
  (`community.general.chroot` refuses non-root controllers), and mounting
  the host's `/` plus `/proc`, `/sys`, `/dev` requires it.
- `alpine/ansible` (Docker Hub, community-maintained by alpine-docker org)
  ships ansible-core 2.21.0 with `community.general` 13.0.1 bundled —
  verified by inspection (`ansible-doc -t connection chroot` resolves). The
  role's floor is ansible-core 2.20, so the stock image works unmodified.
- The chroot connection does not support `become` — the wrapper playbook
  omits it (the pod is already root). The repo playbook keeps `become: true`
  for SSH use; the chart ships its own thin wrapper.
- Facts, package operations, and trust-store refreshes execute inside the
  host's filesystem via chroot — the host needs `/proc`, `/sys`, `/dev`
  mounted under `/host` for apt/dnf to function (verified empirically).
- Chart pattern: follow `charts/nfs-test/` (Chart.yaml, values.yaml,
  templates/daemonset.yaml; nodeSelector/tolerations passthrough;
  `spec.nodeName` via fieldRef for per-node identity).
- Repo lint gates must pass (yamllint; the chart's YAML is helm-templated so
  ansible-lint does not apply to it).

## Design

### Mechanism (spike-verified 2026-10-21)

Each pod:

1. Mounts the node's root filesystem at `/host` (hostPath `/`), plus
   hostPath `/proc` → `/host/proc`, `/sys` → `/host/sys`, `/dev` →
   `/host/dev` (kernel pseudo-filesystems needed by apt/dnf inside the
   chroot).
2. Runs `ansible-playbook` with `ansible_connection=community.general.chroot`
   and `ansible_host=/host` against a one-host inventory. Every module
   executes as `chroot /host <cmd>` — the host's own bash, python3, apt/dnf,
   openssl, and trust store. The role runs **unchanged**.
3. On success, parks (`sleep infinity`) — logs stay readable via
   `kubectl logs`, and deleting the pod re-runs the role.
4. On failure, exits non-zero → CrashLoopBackOff: visible in
   `kubectl get pods` and self-retrying with backoff.

Empirical proof (throwaway spike, since cleaned up): exported the e2e
Ubuntu 24.04 rootfs into `/host` inside a privileged `alpine/ansible`
container, bind-mounted `/proc` `/sys` `/dev`, injected a distrusted root
(`emSign_Root_TLS_CA_-_G3.crt`) and refreshed the store, then ran the real
role over the chroot connection:

```
PLAY RECAP
spike-host : ok=17  changed=2  unreachable=0  failed=0  skipped=13
```

Detection reported `affected=True matched=7DD78D5F...`, remediation removed
the root (bundle 121 → 120 certs, manual copy gone), final verification
scan clean. Facts, the interpreter pre-flight, and family-var dispatch all
worked through the chroot. One Colima-only artifact surfaced: `mount -t
sysfs` fails inside the nested VM ("Resource busy") — bind-mounting `/sys`
works identically; on a real kubelet, hostPath `/sys` is already the host's
sysfs, so this does not arise in production.

### Chart layout

```
charts/emudhra-ca/
  Chart.yaml
  values.yaml
  templates/
    daemonset.yaml
images/
  emudhra-ca/Dockerfile   # FROM alpine/ansible@<digest> + role + wrapper + inventory
```

### Image mechanism (settled 2026-10-21, replacing the ConfigMap payload)

The role, wrapper playbook, and inventory are **baked into a derived
image** — the house pattern: `crusoe-node-remediation` ships its code in
its image and only config via ConfigMap, and `ghcr.io/crusoecloud/*` is
already the public-image channel both target fleets pull natively (GKE
the GKE fleet: CSI driver, watch-agent, fluent-bit; the Crusoe cluster:
158 refs). A public ghcr image needs **no imagePullSecrets on either
fleet** — that was the deciding factor over CCR (Crusoe-cluster-only) and
the GitLab registry (needs a deploy-token secret).

- **Dockerfile** (`images/emudhra-ca/Dockerfile`): `FROM
  alpine/ansible@sha256:<pinned digest>` + `COPY` of `roles/emudhra_ca/`
  → `/opt/ansible/roles/emudhra_ca/`, `wrapper.yml` and `inventory` →
  `/opt/ansible/`. The wrapper/inventory are the same spike shapes
  (two plays, chroot connection, `ansible_host: /host`, no `become`).
- **Registry**: `ghcr.io/crusoecloud/emudhra-ca:<git-sha>` — tag = commit
  SHA so any image maps to the exact reviewed commit; `values.yaml` pins
  by **digest**, never a floating tag. The push workflow follows however
  `crusoecloud/*` ghcr images publish (a deployment decision, not a chart
  one).
- **Drift guard**: the image is built **from the merge commit** in CI, so
  the bytes that run are the bytes reviewed in the PR — the ConfigMap sync
  check's job is done by construction. The generator/sync-check scripts
  (`scripts/gen-emudhra-chart-payload.py`,
  `scripts/check-emudhra-chart-sync.sh`) are **retired** with the
  ConfigMap mechanism.
- **kind smoke** builds the image locally and `kind load`s it
  (`imagePullPolicy: Never`) — the smoke needs no registry at all.

### Fleet findings (2026-10-21, from the live clusters)

- **The Crusoe cluster under test** (the first
target): Ubuntu 22.04.5 nodes — squarely in the role's
supported matrix; pristine Crusoe VMs ship the distrusted roots, so
the chart does real remediation there. CCR is that cluster's dominant
registry and `crusoe-node-remediation` (CCR image +
`crusoe-registry-pull` secret, remediation-taint tolerations,
run-to-Completion) is the established privileged-DaemonSet precedent.
- **the GKE fleet** (later expansion): its nodes are all **Container-
  Optimized OS** — NOT Debian/RedHat, so the role's family dispatch
  would fail every node. Installing there requires a `nodeSelector`
  scoping to actual Debian/RedHat nodes (or a COS-specific remediation
  path, out of scope). Documented as a deployment constraint, not
  implemented.

### DaemonSet spec (key points)

- `hostNetwork: true` — chrooted apt/dnf resolve DNS via the host's
  resolv.conf; hostNetwork makes package fetches and the optional `s_client`
  canary behave exactly as they would on the host.
- `dnsPolicy: ClusterFirstWithHostNet` (standard companion to hostNetwork).
- Privileged securityContext (root, `CAP_SYS_CHROOT` needed for chroot).
- `terminationGracePeriodSeconds: 0` (nfs-test pattern; pods are
  disposable).
- `nodeSelector`/`tolerations` passthrough from values — defaults run on
  every node (empty selector, no tolerations), which is the point: no node
  missed. Control-plane tolerations are the installer's call via values.
- `NODE_NAME` via `spec.nodeName` fieldRef (nfs-test pattern) — used in the
  pod's log preamble so `kubectl logs` output is self-identifying.
- The pod's command: run `ansible-playbook -i /opt/ansible/inventory
  /opt/ansible/wrapper.yml` with `ANSIBLE_ROLES_PATH=/opt/ansible/roles`
  (the image's copy is writable by root), then park or exit.

### values.yaml (defaults)

```yaml
image: ghcr.io/crusoecloud/emudhra-ca@sha256:<digest>  # pinned; overridable
connectivityCheck: false          # opt-in s_client canary
failOnUnsupportedFamily: true     # loud on unsupported nodes
extendedStores: true               # certifi/Java passthrough (role default)
nodeSelector: {}                   # every node by default
  # the GKE fleet (COS nodes) MUST scope this — see Fleet findings
tolerations: []
imagePullSecrets: []               # empty: public ghcr image
```

## Left to the Builder

- The exact digest pin for the `alpine/ansible` base at build time
  (community-maintained; re-pin deliberately, never float).
- The ghcr push workflow (GitHub Actions on the crusoecloud org vs. a CI
  job with org credentials) — a deployment decision, not a chart one.
- Whether the wrapper playbook needs `interpreter_python` pinned to
  `/usr/bin/python3` inside the chroot (the spike used it; auto_silent may
  suffice — verify against a real node).
- Pod resources (requests/limits) — the parked container is tiny; a nominal
  request is fine.
- Chart version numbering (start `0.1.0`, nfs-test pattern).

## Open Questions (answered by the design conversation; none blocking)

None — all decisions were settled in the design conversation: DaemonSet
over Job/sweep (lifecycle coverage), ConfigMap embedding over derived CCR
image (no build step), stock `alpine/ansible` pinned by digest (verified
bundled chroot plugin), hostNetwork (host DNS for apt), connectivity check
off by default.

## Open Questions (pending the owner — from the builder check)

1. **Target cluster and admission posture**: the design requires a
   privileged pod mounting host `/`, `/proc`, `/sys`, `/dev`. If the target
   cluster enforces PodSecurity `baseline`/`restricted`, OPA/Gatekeeper,
   or similar in the install namespace, the chart needs an exemption or a
   different mechanism — this could invalidate the design as written.
2. **Fleet egress to Docker Hub**: if nodes can't pull `alpine/ansible`
   from Docker Hub (air-gapped, egress-firewalled, rate-limited), the
   default image must be a one-time CCR mirror instead — which changes
   the "no publish step" constraint.
3. **Acceptance bar**: is "done" a kind/Colima e2e harness at the phase-1
   bar, a manual dev-cluster smoke, or validation on one real cluster
   node (real kubelet, SELinux-enforcing EL9, real hostPath semantics)?
4. **Unfixable-node steady state**: nodes the role can never process
   (unsupported OS families park quietly with a warning log; no-Python
   hosts CrashLoop forever). Should the chart surface
   `emudhra_ca_fail_on_unsupported_family` as a value (and default it to
   `true` in the chart, making unsupported nodes loud), and is a
   forever-CrashLooping pod on unfixable nodes acceptable fleet behavior?
