# eMudhra CA DaemonSet Chart Implementation Plan (v2 — image mechanism)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Status: COMPLETE (2026-10-22).** Tasks 1–2 were implemented on the
> standalone repo's `emudhra-ca-daemonset` branch and imported into the
> monorepo; Tasks 3–5 (real-cluster smoke, CI wiring, docs) were
> implemented directly here. The v1 ConfigMap plan is archived at
> `2026-10-21-emudhra-ca-daemonset-chart-v1-configmap.md`.
>
> **Monorepo adaptation:** all repo-relative paths in this plan resolve
> inside `crusoe-cs-ansible/` (the component root) — `charts/`,
> `images/`, `roles/`, `tests/`, `.gitlab-ci.yml`. The Docker build
> context is `crusoe-cs-ansible/` (not the monorepo root). The smoke
> builds with `--platform linux/amd64` (fleet nodes are amd64; the
> local Docker host is arm64). The kube-context check validates the
> context's *user* (`crusoe-client-admin-*`), not the context name —
> context names follow the cluster (`cmk-<cluster>`).

**Goal:** Ship `charts/emudhra-ca/` — a Helm chart whose DaemonSet runs the existing `emudhra_ca` role against every node's host VM via the chroot connection, with the role baked into a derived image published to `ghcr.io/crusoecloud/emudhra-ca`.

**Architecture:** A Dockerfile (`images/emudhra-ca/Dockerfile`) bakes the role + wrapper playbook + one-host inventory into a digest-pinned `alpine/ansible` base. Each privileged pod mounts the host's `/` at `/host` (plus `/proc`, `/sys`, `/dev`), runs `ansible-playbook` over `community.general.chroot` from `/opt/ansible`, then parks on success or CrashLoops on failure. CI builds the image from the merge commit (tag = commit SHA); `values.yaml` pins by digest. This **replaces** the v1 ConfigMap-payload mechanism: the generator/sync-check scripts and the configmap template are retired.

**Tech Stack:** Docker (multi-arch: amd64 for fleets, arm64 for the local kind smoke), Helm 3, `alpine/ansible` (ansible-core 2.21.0, `community.general` 13.0.1 bundled — spike-verified), bash, yamllint.

**Spec:** `docs/superpowers/specs/2026-10-21-emudhra-ca-daemonset-design.md`

## Global Constraints

- Base image: `alpine/ansible` pinned by **digest** in the Dockerfile FROM (never a floating tag).
- Fleet image: `ghcr.io/crusoecloud/emudhra-ca:<git-sha>` — public, no imagePullSecrets needed on either target fleet (the GKE fleet and the Crusoe cluster both already pull `ghcr.io/crusoecloud/*`).
- The role runs **unchanged** — no edits to `roles/emudhra_ca/` logic in this plan.
- The chroot connection does not support `become` — the wrapper playbook omits it; the pod runs as root.
- `hostNetwork: true` + `dnsPolicy: ClusterFirstWithHostNet`.
- Chart pattern follows `charts/nfs-test/` (Chart.yaml, values.yaml, templates/; nodeSelector/tolerations passthrough; `spec.nodeName` fieldRef).
- `.yamllint` ignores `charts/` — chart templates are exempt from yamllint but must pass `helm lint` and `helm template`.
- No `Co-authored-by` trailers in commits. Conventional commit prefixes (`feat:`, `test:`, `chore:`, `docs:`).
- **Retirement is part of this plan**: the v1 ConfigMap artifacts (`charts/emudhra-ca/templates/configmap.yaml`, `scripts/gen-emudhra-chart-payload.py`, `scripts/check-emudhra-chart-sync.sh`, `tests/test_emudhra_chart_payload.py`) are deleted in Task 1 — they are dead weight once the image mechanism lands.

## Review Focus

- **Stale image vs. role:** the image is built from the merge commit, but a locally built smoke image can silently diverge from the role. Test: the smoke builds the image from the working tree in the same run that tests it — never reuses a stale local tag.
- **Wrapper/inventory drift:** the wrapper playbook and inventory live in the image build context; if they're duplicated anywhere else, they drift. Test: they exist exactly once (in `images/emudhra-ca/`), and the Dockerfile COPYs them.
- **COS nodes CrashLoop:** `failOnUnsupportedFamily: true` + empty nodeSelector means every unsupported node (e.g. the GKE fleet's COS nodes) CrashLoops loudly. That is intended, but the chart README must say so, and `helm template` must render the passthrough. Test: `helm template` shows all three `-e` flags.
- **Base digest float:** `FROM alpine/ansible:latest` would silently change the Ansible version under the role. Test: the Dockerfile FROM carries a `@sha256:` digest; a grep test pins it.
- **Park/exit semantics:** a successful run must park (logs readable, delete-to-rerun) and a failed run must exit non-zero. Test: the real-cluster smoke asserts both the parked state and the recap line.

---

### Task 1: Retire the ConfigMap mechanism + image scaffold

**Files:**
- Delete: `charts/emudhra-ca/templates/configmap.yaml`
- Delete: `scripts/gen-emudhra-chart-payload.py`
- Delete: `scripts/check-emudhra-chart-sync.sh`
- Delete: `tests/test_emudhra_chart_payload.py`
- Create: `images/emudhra-ca/Dockerfile`
- Create: `images/emudhra-ca/wrapper.yml`
- Create: `images/emudhra-ca/inventory`
- Modify: `charts/emudhra-ca/values.yaml` (image default → ghcr; add `extendedStores`, `imagePullSecrets`)

**Interfaces:**
- Produces: `images/emudhra-ca/` build context consumed by Task 2's build and Task 3's smoke; values keys consumed by Task 3's daemonset — `image` (string, digest-pinned ghcr default), `connectivityCheck` (bool, `false`), `failOnUnsupportedFamily` (bool, `true`), `extendedStores` (bool, `true`), `nodeSelector` (map, `{}`), `tolerations` (list, `[]`), `imagePullSecrets` (list, `[]`).

- [x] **Step 1: Write `images/emudhra-ca/wrapper.yml`**

The spike shape, verbatim: two plays — play 1 `gather_facts: false`, `import_role` `emudhra_ca` `tasks_from: preflight.yml`; play 2 `connection: community.general.chroot`, `roles: [emudhra_ca]`, NO `become`.

- [x] **Step 2: Write `images/emudhra-ca/inventory`**

One host: `ansible_connection=community.general.chroot`, `ansible_host=/host`, `ansible_python_interpreter=/usr/bin/python3`.

- [x] **Step 3: Write `images/emudhra-ca/Dockerfile`**

`FROM alpine/ansible@sha256:4eb8563ae4d14f7ed96ea05cc8f4286005c2d0558fbbc0f9ed3029b01d89fa54` (the spike-verified digest); `COPY roles/emudhra_ca/ /opt/ansible/roles/emudhra_ca/`; `COPY images/emudhra-ca/wrapper.yml images/emudhra-ca/inventory /opt/ansible/`; build context = repo root (so `roles/` resolves); `WORKDIR /opt/ansible`.

- [x] **Step 4: Update `charts/emudhra-ca/values.yaml`**

Keys per the Interfaces block; `image:` default `ghcr.io/crusoecloud/emudhra-ca:latest` with a comment that fleet installs pin `@sha256:` (the real digest exists only after the first CI publish — the smoke overrides the image anyway).

- [x] **Step 5: Delete the v1 artifacts**

`git rm` the four ConfigMap-mechanism files listed above.

- [x] **Step 6: Verify**

Run: `docker build -f images/emudhra-ca/Dockerfile -t emudhra-ca:plan-test . && docker run --rm emudhra-ca:plan-test ls /opt/ansible/roles/emudhra_ca/tasks/ && helm lint charts/emudhra-ca && helm template charts/emudhra-ca >/dev/null && echo OK`
Expected: role tasks listed (detect, main, preflight, remediate, verify), lint passes, `OK`.

- [x] **Step 7: Commit**

```bash
git add -A images/ charts/emudhra-ca/values.yaml
git rm charts/emudhra-ca/templates/configmap.yaml scripts/gen-emudhra-chart-payload.py scripts/check-emudhra-chart-sync.sh tests/test_emudhra_chart_payload.py
git commit -m "feat: bake emudhra-ca role into derived image; retire ConfigMap payload"
```

---

### Task 2: DaemonSet template (image mechanism)

**Files:**
- Modify: `charts/emudhra-ca/templates/daemonset.yaml` (replace the ConfigMap/untar flow with the image flow)

**Interfaces:**
- Consumes: Task 1's values keys and `/opt/ansible` layout.
- Produces: a DaemonSet whose pods run the wrapper playbook against `/host` from the image's baked copy.

- [x] **Step 1: Rewrite the container command**

Drop the base64/untar/payload steps. New command: log preamble with `NODE_NAME`; `cd /opt/ansible`; run `ANSIBLE_ROLES_PATH=/opt/ansible/roles ansible-playbook -i inventory wrapper.yml -e emudhra_ca_run_connectivity_check={{ .Values.connectivityCheck }} -e emudhra_ca_fail_on_unsupported_family={{ .Values.failOnUnsupportedFamily }} -e emudhra_ca_extended_stores={{ .Values.extendedStores }}` with `|| rc=$?`; on `rc=0` `exec sleep infinity`, else exit `rc`.

- [x] **Step 2: Drop the payload volumes, keep the host volumes**

Volumes: hostPath `/`→host-root, `/proc`→host-proc, `/sys`→host-sys, `/dev`→host-dev (all `type: Directory`). Mounts: `/host`, `/host/proc`, `/host/sys`, `/host/dev`. No ConfigMap volume, no emptyDir, no `/payload` mount. Add `imagePullSecrets` passthrough from values.

- [x] **Step 3: Verify**

Run: `helm lint charts/emudhra-ca && helm template charts/emudhra-ca | grep -c 'opt/ansible' && helm template charts/emudhra-ca --set extendedStores=false | grep -m1 'emudhra_ca_extended_stores'`
Expected: lint passes; multiple `/opt/ansible` refs; the `--set` override renders `emudhra_ca_extended_stores=false`.

- [x] **Step 4: Commit**

```bash
git add charts/emudhra-ca/templates/daemonset.yaml
git commit -m "feat: DaemonSet runs the role from the baked image over chroot"
```

---

### Task 3: E2E smoke against the real Crusoe cluster

**Files:**
- Create: `tests/e2e/emudhra-ca/chart-smoke.sh`

**Interfaces:**
- Consumes: the chart (Task 2) + the image build (Task 1). Requires `kubectl` (context `a crusoe-client-admin-* kube context`), `docker`, `helm`, `crusoe` CLI.

**Settled (2026-10-22, user): the smoke targets the real Crusoe cluster under test instead of local kind.** The cluster is the first deployment target anyway (8× Ubuntu 22.04.5, genuinely affected nodes), so the smoke proves the real thing: real kubelet, real hostPath, real CCR pull path, real remediation on real nodes. kind cannot side-load images onto a remote cluster, so the smoke pushes the image to CCR (the cluster's native registry, `us-southcentral1-a`) and installs from there.

**No hardcoding (user ruling 2026-10-22):** every environment-specific value flows from an environment variable with a *discovery-based* default — the script never carries literal registry URLs, repo names, project IDs, namespaces, or secret names that another environment would have to edit. The contract:

| Value | Env var | Discovery default (when unset) |
|---|---|---|
| Kube context | `EMUDHRA_SMOKE_KUBE_CONTEXT` | `crusoe registry`-adjacent default: the current `kubectl config current-context` — must be a `crusoe-client-admin-*` context; abort otherwise |
| CCR location | `EMUDHRA_SMOKE_CCR_LOCATION` | parsed from the context name (`cmk-<location>` → `us-southcentral1-a`) |
| CCR repo name | `EMUDHRA_SMOKE_CCR_REPO` | `emudhra-ca` (chart name — not environment-specific) |
| CCR project id | `EMUDHRA_SMOKE_CCR_PROJECT` | `crusoe registry repositories list --format json` → find/create repo, read its project id (same pattern as the existing node-remediation repo) |
| Namespace | `EMUDHRA_SMOKE_NAMESPACE` | `emudhra-ca-smoke` |
| Pull secret | `EMUDHRA_SMOKE_PULL_SECRET` | `crusoe-registry-pull` if it exists in the namespace, else the script creates it from the CCR token it minted |
| Image tag | `EMUDHRA_SMOKE_IMAGE_TAG` | `smoke-$(git rev-parse --short HEAD)` (never `latest`; traceable to the commit) |

The script prints the resolved values before doing anything. A different cluster/location/repo works by setting env vars — zero edits.

- [x] **Step 1: Write `tests/e2e/emudhra-ca/chart-smoke.sh`**

Bash, `run.sh` house style (`set -euo pipefail`, log functions, cleanup trap, `--keep` flag). Steps:
1. Resolve all values per the no-hardcoding table above; print them; abort if the kube context is not a `crusoe-client-admin-*` one.
2. Build the image from the working tree: `docker build -f images/emudhra-ca/Dockerfile -t registry.${CCR_LOCATION}.ccr.crusoecloudcompute.com/${CCR_REPO}.${PROJECT8}/emudhra-ca:${IMAGE_TAG} .` (repo created via `crusoe registry repositories create` if `repositories list` doesn't show it).
3. Push to CCR (`crusoe registry tokens create` → `docker login` with account email + token, `--password-stdin`; single-quoted token — it contains `$`).
4. `helm install` into `${NAMESPACE}` with `--set image=<resolved CCR image>` and `--set imagePullSecrets[0].name=${PULL_SECRET}` — reuse the existing secret if present in the namespace, else create it there from the same CCR token.
5. Wait event-driven (`kubectl wait --for=condition=Ready pod -l app=<release> -n ${NAMESPACE} --timeout=600s`, no sleep loops).
6. Assert: pods park (Running, not CrashLoop); `kubectl logs` contains `failed=0` in the recap; the pod logs' `affected=` lines show the first run detected and remediated (Ubuntu 22.04 nodes ship the distrusted roots).
7. Idempotency: delete one pod, wait for the replacement, assert its recap shows `changed=0` (the node was already remediated by the first run).
8. Teardown: `helm uninstall` + namespace delete + `--keep` flag to skip. NEVER touch the `crusoe-node-remediation` namespace or its DaemonSet.

- [x] **Step 2: Run it**

Run: `tests/e2e/emudhra-ca/chart-smoke.sh`
Expected: PASS end-to-end — 8 pods park, first run remediates (Ubuntu 22.04 nodes ship the distrusted roots), re-run idempotent. If a pod CrashLoops, debug via `kubectl logs --previous` / `describe`; fix the smoke or report the chart bug — never paper over it. If CCR push fails (auth/quota), report BLOCKED with the error — do not retry blindly. The smoke is a **real-fleet action**: it remediates 8 production nodes' trust stores (idempotent, advisory-mandated) and creates a CCR repo + token — that is the point, but say it out loud in the script's preamble.

- [x] **Step 3: Commit**

```bash
git add tests/e2e/emudhra-ca/chart-smoke.sh
git commit -m "test: real-cluster smoke for the emudhra-ca chart on the target cluster"
```

---

### Task 4: CI wiring

**Files:**
- Modify: `.gitlab-ci.yml`

**Interfaces:**
- Consumes: the Dockerfile (Task 1), the smoke's existence (Task 3, local + real-cluster — not CI-runnable).

- [x] **Step 1: Add a `chart` stage job**

Runs on merge commits: `helm lint charts/emudhra-ca`, `helm template charts/emudhra-ca >/dev/null`, and a `docker build` of the image (build-only, no push — the ghcr push workflow is a deployment decision outside this repo's CI; document that in the job's comment). Follow the existing file's job style (the repo already has yamllint/ansible-lint jobs using `pipelinecomponents/*` images).

- [x] **Step 2: Verify**

Run the job's commands locally exactly as written.

- [x] **Step 3: Commit**

```bash
git add .gitlab-ci.yml
git commit -m "chore: CI builds the emudhra-ca image and lints the chart"
```

---

### Task 5: Docs

**Files:**
- Create: `charts/emudhra-ca/README.md`
- Modify: `tests/e2e/emudhra-ca/README.md`

- [x] **Step 1: Write `charts/emudhra-ca/README.md`**

What it does (one paragraph); install/teardown; values table (including `extendedStores` and the three `-e` passthroughs); the re-run story (delete the pod; node lifecycle re-triggers); the privileged/hostPath requirement and its admission-policy implication; **the COS warning** — `failOnUnsupportedFamily: true` + empty nodeSelector CrashLoops on unsupported nodes (the GKE fleet's COS), so scope `nodeSelector` there; the image workflow (CI builds from the merge commit, tag = SHA, fleet pins digest; local builds are for the smoke only).

- [x] **Step 2: Add a chart-smoke section to the e2e README**

Three lines: what `chart-smoke.sh` proves, how to run it, its env-var contract (no hardcoded cluster/registry values), and that it needs docker + helm + kubectl + the crusoe CLI.

- [x] **Step 3: Commit**

```bash
git add charts/emudhra-ca/README.md tests/e2e/emudhra-ca/README.md
git commit -m "docs: emudhra-ca chart usage, image workflow, and smoke harness"
```
