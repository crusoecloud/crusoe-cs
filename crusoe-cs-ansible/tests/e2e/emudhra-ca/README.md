# eMudhra SCA e2e tests

Docker-based end-to-end tests for the `emudhra_ca` role and its playbook.
Ansible runs from the repo `.venv` (with the `community.docker` connection
plugin) against sibling containers — no SSH, no systemd, no controller image.

## Prerequisites

- Docker (Colima on arm64 works; all images are multi-arch)
- Repo `.venv` with `ansible`, `community.docker` collection, and the docker
  SDK (`pipenv install && pipenv install --dev`, then
  `ansible-galaxy collection install -r requirements.yml`)

## Usage

```bash
# Single scenario
tests/e2e/emudhra-ca/run.sh remediate

# Full suite (all scenarios in order, stops on first failure)
tests/e2e/emudhra-ca/run.sh all

# Custom matrix (default: ubuntu:22.04,ubuntu:24.04,rockylinux:9,debian:12,almalinux:9)
tests/e2e/emudhra-ca/run.sh all --images ubuntu:22.04,ubuntu:24.04,rockylinux:9,debian:12,almalinux:9
```

Target images are derived from stock distro images with python3 (Ansible
modules need an interpreter) and trust-store tooling baked in — see
[`images/Dockerfile.debian`](images/Dockerfile.debian) /
[`images/Dockerfile.redhat`](images/Dockerfile.redhat) /
[`images/Dockerfile.alpine`](images/Dockerfile.alpine). They build once and
are cached by Docker.

## Scenarios

| Scenario      | Proves |
|---------------|--------|
| `smoke`       | Harness plumbing: container up, inventory, ansible reaches it |
| `vars`        | Family-var dispatch: Debian and RedHat resolve their own paths/commands |
| `detect`      | Fingerprint detection: injected→affected, pristine Rocky→affected (real state), missing bundle→clean |
| `remediate`   | Bad root removed (arbitrary filename), name-similar decoy untouched, idempotent re-run; Rocky exercises the blocklist fallback |
| `fallback`    | The Debian `!`-prefix fallback actually fires: package held (repo-lag proxy) → root survives the upgrade → fallback excises it, `!`-prefix lands in `/etc/ca-certificates.conf`, re-run idempotent with no `!!` |
| `airgapped`   | No egress at all: apt update/download fail outright (dead proxy) → the failed upgrade is tolerated → fallback fires, root excised, re-run idempotent. The advisory's workaround for hosts without updated packages. |
| `airgapped-rhel` | Same air-gap on the RedHat path: Rocky 9 with a dead dnf proxy → failed upgrade tolerated → p11-kit blocklist fallback (blocklist dir + `update-ca-trust`) fires, root excised, re-run idempotent. |
| `extended`    | certifi bundles: injected root excised in place; images without certifi must NOT get it installed; re-run idempotent. (Java-keystore path is not e2e-covered — needs a JVM in the matrix.) |
| `wrapper`     | The real playbook works end-to-end; connectivity check skippable |
| `clean`       | Clean hosts (fixture-constructed) are zero-change no-ops |
| `mixed`       | One run over a mixed fleet: affected hosts remediated, clean hosts untouched |
| `unsupported` | Alpine (unsupported family) skips with a warning, zero changes |
| `all`         | Everything above in sequence |

## Environment

- `EMUDHRA_E2E_JOBS=N` — concurrent scenarios for `all` (default 3). Each
  running scenario needs roughly 1 GiB of docker-VM memory; size your VM
  accordingly (e.g. `colima start --cpu 4 --memory 4` for 3 jobs).
- `EMUDHRA_E2E_CONNECTIVITY=1` — run the wrapper scenario with the live
  `s_client` canary check enabled (needs egress to the advisory test sites).

## Matrix

The default matrix covers both Debian-family (Ubuntu 22.04, Ubuntu 24.04,
Debian 12) and RedHat-family (Rocky 9, AlmaLinux 9) images. All targets use
derived images with python3 + trust-store tooling baked in.

**Rocky 8 is deliberately not in the default matrix.** Its repos ship no dnf
bindings for any Python new enough for ansible-core 2.20 modules (verified
against Rocky 8's actual repos), so the `package` module cannot run there —
the constraint is ansible-core's, not the role's. The role's logic is
family-generic and proven on EL9; real EL8 hosts that meet the interpreter
pre-flight ([`roles/emudhra_ca/tasks/preflight.yml`](../../../roles/emudhra_ca/tasks/preflight.yml)) remediate the same way.
You can still run it explicitly with `--images rockylinux:8` if your
controller runs an older ansible-core that supports EL8's Python.

## VM harness

A second harness, [`vms.py`](vms.py), runs the same scenarios against **real Crusoe
VMs** — one per latest-tagged x86_64 VM image — instead of containers. It
discovers every `latest` image (`crusoe compute images list`), creates one
small VM per image (round-robin across regions, capacity fallback), and
drives the scenarios over SSH via the repo's dynamic inventory
([`inventory/crusoe.py`](../../../inventory/crusoe.py)). arm64 images are excluded — the catalog has no
arm64 CPU type.

Because every `latest` image predates the advisory, pristine VMs genuinely
ship the distrusted roots — the VM harness exercises the **real
package-shipped case** end-to-end (detect→affected, remediate→clean,
re-run→idempotent) with no injection fixtures.

```bash
tests/e2e/emudhra-ca/vms.py matrix          # image→VM mapping (no side effects)
tests/e2e/emudhra-ca/vms.py test            # up → run all → down
tests/e2e/emudhra-ca/vms.py forensics       # per-VM evidence: versions, logs, holds
```

Every invocation's full output is saved under `/tmp/emudhra-vm-e2e/<run>/`
as numbered logs — the empirical transcript kept even (especially) on
failure. `EMUDHRA_E2E_VM_KEEP=1` skips teardown for debugging.

## Chart smoke

`chart-smoke.py` proves the full `crusoe-distrust-emudhra-ca`
image-mechanism path on a **real Crusoe cluster**: builds the image from
the working tree, pushes it to the cluster's native CCR registry,
helm-installs the chart, and asserts real remediation — pods park with
`failed=0` (state-tolerant: `changed>=1`+`affected=True` on a fresh
fleet, `changed=0`+`affected=False` on an already-remediated one), a
deleted pod's replacement re-runs idempotently with `changed=0`, and the
journald callback's events are present in the node's journal.

```bash
tests/e2e/emudhra-ca/chart-smoke.py [--keep]
```

Every environment-specific value (kube context, CCR location/repo/
project, namespace, pull secret, image tag) flows from an
`EMUDHRA_SMOKE_*` env var with a discovery-based default — no hardcoded
cluster or registry values; the chart itself is discovered from its
Chart.yaml (`EMUDHRA_SMOKE_CHART` overrides). A different cluster works
by setting env vars. Requires docker, helm, kubectl, and the crusoe CLI.
⚠️ It is a real-fleet action: it remediates the target nodes' trust
stores (idempotent, advisory-mandated) and creates a CCR repo + token.
