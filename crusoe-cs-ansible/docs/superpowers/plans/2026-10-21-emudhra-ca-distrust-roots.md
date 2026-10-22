# eMudhra SCA Distrusted Roots — Family-Aware Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Execution ledger (2026-10-21, inline execution):**
> - Ruling: controller container dropped (user) — `.venv` ansible-playbook drives containers via community.docker connection plugin.
> - Ruling: prebuilt derived images with python3+ca-certificates+openssl baked in (user) — no runtime package installs in fixtures.
> - Ruling: all 4 roots driven programmatically (user, critical) — harness loads `emudhra_ca_bad_roots` from role vars; every scenario injects/asserts all four.
> - Ruling: matrix expanded to Debian 12 + AlmaLinux 9 (user); Rocky 8 added (user). Rocky 8 lacks python3 → RedHat derived image created.
> - Harness hardening after the AAA miss: anti-vacuous guard (empty scan = rc 2, never "absent"); unified `toupper` fingerprint normalization everywhere.
> - Final review (fresh subagent): REQUEST_CHANGES on a "Critical" Debian `!`-prefix bug — **disproven against the file** (the code has the correct `'!'*)` glob; live test confirms). Important finding (connectivity check fails on network errors) is by-design per spec. Real gap noted: no e2e scenario exercises the Debian `!`-prefix fallback (Ubuntu's fixed package always clears the root first) — accepted as a known coverage gap; the RedHat blocklist fallback IS covered end-to-end.

**Goal:** Build the `emudhra_ca` role — family-aware, fingerprint-gated distrust of the four compromised-chain roots — plus a bash e2e harness proving it on Ubuntu 22.04, Ubuntu 24.04, and Rocky 9 containers.

**Architecture:** One role with automatic family-var dispatch (`vars/Debian.yml`, `vars/RedHat.yml`): detect affected state by SHA-256 fingerprint against the active trust bundle, remediate only when affected (package upgrade → manual-copy removal → trust refresh), fall back to the advisory's official blocklist method when the package can't clear the root, and optionally canary-check affected hosts with `s_client`. A generic bash harness (`tests/e2e/run.sh`) drives the playbook against Docker containers through a derived `alpine/ansible` controller image.

**Tech Stack:** Ansible builtin modules + `community.docker` (docker connection plugin), bash, Docker (Colima/arm64), `alpine/ansible` controller image, openssl.

**Spec:** `docs/superpowers/specs/2026-10-21-emudhra-ca-distrust-roots-design.md`

## Global Constraints

- Lint gates on every commit: `.venv/bin/yamllint` + `.venv/bin/ansible-lint` (production profile) — zero failures.
- Fingerprint-only matching; never by file name. Pinned fingerprints live in `roles/emudhra_ca/vars/main.yml` (`emudhra_ca_bad_roots`); PEMs in `roles/emudhra_ca/files/certs/` (already shipped and verified — do not regenerate).
- No per-release package-version pins anywhere.
- Role variables prefixed `emudhra_ca_` (ansible-lint var-naming).
- Never fail a mixed-fleet run because one host is unaffected or unsupported; unsupported families skip with a warning (`meta: end_host`) unless `emudhra_ca_fail_on_unsupported_family: true`.
- Family dispatch via `ansible_facts.os_family`; the role must not depend on execution order (`strategy = free`) or fact-cache freshness.
- E2E inventory overrides: `ansible_connection=community.docker.docker`, `ansible_user=root`, `ansible_python_interpreter=/usr/bin/python3`; e2e disables fact caching (`ANSIBLE_CACHE_PLUGIN=memory`) because container names are reused across runs.
- Multi-arch images only (arm64 Colima): `ubuntu`, `rockylinux`, `alpine/ansible`, `alpine`.
- Connectivity check: affected hosts only; default `emudhra_ca_run_connectivity_check: true`; e2e always runs it with `false`.
- Commit messages: conventional prefixes (`feat:`, `test:`, `chore:`, `docs:`); never any `Co-authored-by` trailer.

## Review Focus

1. **Missing/empty bundle file** → detection reports not affected, no crash. Test: Task 3 detect scenario, case (c).
2. **Name-similar but not-bad cert** (e.g. a cert with CN "emSign Root CA - G1") → survives remediation untouched. Test: Task 4 remediate scenario.
3. **Unsupported family** (Alpine) → warning + skip, zero changes, run exit 0. Test: Task 7 unsupported scenario.
4. **Manually-added bad cert with arbitrary filename** → removed by fingerprint, not name. Test: Task 4 remediate scenario (injects `random-name-123.crt`).
5. **Package upgrade restores a package-owned bad root after fallback** → blocklist keeps the host clean; re-run is a no-op. Test: Task 5 fallback scenario, persistence phase.

---

### Task 1: E2E harness skeleton + controller image

> **Ruling (2026-10-21, user):** drop the controller container — the repo `.venv`
> ansible-playbook (with `community.docker` connection plugin) executes against
> sibling containers directly. `Dockerfile.controller` is deleted; `run.sh`
> runs `ansible-playbook` from `.venv` only. The `alpine/ansible` controller
> image concept is not needed for this change.

**Files:**
- Create: `tests/e2e/run.sh`, `tests/e2e/Dockerfile.controller`
- Modify: `requirements.yml`, `.gitignore`

**Interfaces:**
- Produces: `tests/e2e/run.sh <scenario> [--images <csv>]` — scenarios: `smoke` (this task); later tasks add `vars`, `detect`, `remediate`, `fallback`, `wrapper`, `clean`, `mixed`, `unsupported`, `all`. Exit 0 = pass, non-zero = fail. Default images: `ubuntu:22.04,ubuntu:24.04,rockylinux:9`.
- Produces: env vars `EMUDHRA_E2E_CONTROLLER=local|docker` (default `docker`), `EMUDHRA_E2E_CONNECTIVITY=0|1` (default `0`).
- Produces: container names `emudhra-e2e-<scenario>-<n>`; ephemeral inventory `tests/e2e/.inventory.ini` (gitignored).
- Produces (bash functions in run.sh, sourced by later scenarios): `up_container <name> <image>`, `bootstrap_python <name>` (dnf on RedHat, no-op on Debian), `write_inventory <name...>`, `run_playbook [args...]` (routes controller-vs-local; always `-i tests/e2e/.inventory.ini`; exports `ANSIBLE_CACHE_PLUGIN=memory`), `down_container <name>`, `cleanup_trap`.
- Produces: controller image `emudhra-e2e-controller:local`.

- [ ] **Step 1: Write the failing smoke scenario**

`tests/e2e/run.sh smoke` must: up `emudhra-e2e-smoke-1` (ubuntu:24.04), bootstrap, write inventory, run `ansible all -m setup -a 'filter=ansible_os_family'` through the controller, assert output contains `Debian`, down. Run it → expect FAIL (no run.sh).

- [ ] **Step 2: Write `tests/e2e/Dockerfile.controller`**

`FROM alpine/ansible:v2.19.0` (verify the tag pulls; if it doesn't, pin `latest` and record the ansible-core version in a comment), `RUN pip install --no-cache-dir docker`, `RUN ansible-galaxy collection install community.docker`.

- [ ] **Step 3: Add `community.docker` to `requirements.yml` and install**

`version: ">=3.0.0"`; then `.venv/bin/ansible-galaxy collection install -r requirements.yml` (local controller mode needs it).

- [ ] **Step 4: Implement `run.sh`**

Socket resolution: `docker context inspect --format '{{.Endpoints.docker.Host}}'` must be a unix socket — fail with a clear message otherwise (Colima default is unix). Controller invocation: `docker run --rm -v "$PWD":/apps -w /apps -v <socket>:<socket> -e DOCKER_HOST=unix://<socket> emudhra-e2e-controller:local ansible-playbook ...`. Local mode: `.venv/bin/ansible-playbook`. Inventory line format: `<name> ansible_connection=community.docker.docker ansible_user=root ansible_python_interpreter=/usr/bin/python3`. Add `tests/e2e/.inventory.ini` to `.gitignore`.

- [ ] **Step 5: Run `tests/e2e/run.sh smoke` → PASS**

- [ ] **Step 6: Lint + commit**

`bash -n tests/e2e/run.sh` (shellcheck if available); pre-commit linters; commit `test: e2e harness skeleton with alpine/ansible controller`.

---

### Task 2: Role scaffolding — family vars, defaults, stub

**Files:**
- Create: `roles/emudhra_ca/vars/Debian.yml`, `roles/emudhra_ca/vars/RedHat.yml`, `roles/emudhra_ca/defaults/main.yml`, `roles/emudhra_ca/tasks/main.yml` (stub), `tests/e2e/probe-vars.yml`

**Interfaces:**
- Consumes: `emudhra_ca_bad_roots`, `emudhra_ca_test_sites` (shipped in `vars/main.yml`), `files/certs/` PEMs (shipped).
- Produces (exact values):
  - `Debian.yml`: `emudhra_ca_bundle_paths: ["/etc/ssl/certs/ca-certificates.crt"]`, `emudhra_ca_manual_ca_dir: /usr/local/share/ca-certificates`, `emudhra_ca_refresh_cmd: update-ca-certificates --fresh`, `emudhra_ca_conf_file: /etc/ca-certificates.conf`, `emudhra_ca_package_ca_dir: /usr/share/ca-certificates`
  - `RedHat.yml`: `emudhra_ca_bundle_paths: ["/etc/pki/tls/certs/ca-bundle.crt", "/etc/pki/tls/certs/ca-bundle.trust.crt"]`, `emudhra_ca_manual_ca_dir: /etc/pki/ca-trust/source/anchors`, `emudhra_ca_refresh_cmd: update-ca-trust`, `emudhra_ca_blocklist_dir: /etc/pki/ca-trust/source/blocklist`
  - `defaults/main.yml`: `emudhra_ca_run_connectivity_check: true`, `emudhra_ca_fail_on_unsupported_family: false`
  - `tasks/main.yml` stub: one debug task, `msg: "emudhra_ca stub on {{ ansible_facts.os_family }}"`.

- [ ] **Step 1: Write the failing `vars` scenario**

Add to run.sh: up ubuntu:24.04 + rockylinux:9; run `tests/e2e/probe-vars.yml` (named play, `hosts: all`, `become: true`, `tasks: [{include_role: {name: emudhra_ca}}, {debug: {var: emudhra_ca_bundle_paths}}, {debug: {var: emudhra_ca_refresh_cmd}}]`); assert output contains `/etc/ssl/certs/ca-certificates.crt` (ubuntu host) and `update-ca-trust` (rocky host). Run → FAIL (no `tasks/main.yml`).

- [ ] **Step 2: Implement the four role files exactly per Interfaces**

- [ ] **Step 3: Run `tests/e2e/run.sh vars` → PASS (both families)**

- [ ] **Step 4: Lint + commit**

`feat: emudhra_ca role scaffolding with family vars`

---

### Task 3: Detection gate

**Files:**
- Modify: `roles/emudhra_ca/tasks/main.yml` (unsupported-family gate + detect include)
- Create: `roles/emudhra_ca/tasks/detect.yml`

**Interfaces:**
- Consumes: `emudhra_ca_bad_roots` (match keys = `sha256`, uppercase hex, no colons), `emudhra_ca_bundle_paths`.
- Produces facts: `emudhra_ca_affected` (bool), `emudhra_ca_matched` (list of matched SHA-256 hex strings).
- Produces: unsupported-family behavior — debug `emudhra_ca: unsupported OS family {{ ansible_facts.os_family }}, skipping` then `ansible.builtin.meta: end_host`; `ansible.builtin.fail` instead when `emudhra_ca_fail_on_unsupported_family | bool`.
- Produces: debug summary line `emudhra_ca: affected={{ emudhra_ca_affected }} matched={{ emudhra_ca_matched | join(',') }}` (harness greps this).

- [ ] **Step 1: Write the failing `detect` scenario**

Three cases in run.sh: (a) ubuntu:24.04 + fixture `inject_root <container> <cert-basename>` (docker cp `roles/emudhra_ca/files/certs/<cert>` to `/usr/local/share/ca-certificates/` + `update-ca-certificates`) using `emSign_ECC_Root_CA_-_G3.crt` → run playbook → assert output has `affected=True` and `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B`; (b) pristine rockylinux:9 → `affected=False`; (c) ubuntu:24.04 with bundle moved aside (`mv /etc/ssl/certs/ca-certificates.crt{,.bak}` fixture) → `affected=False`, no crash, restore. Run → FAIL.

- [ ] **Step 2: Implement the gate + `detect.yml`**

Detection algorithm (one `ansible.builtin.shell` task, bash, `changed_when: false`): bad fingerprints passed via env `BAD_FPS` (space-separated); for each existing path in `emudhra_ca_bundle_paths`: split PEMs with `awk '/BEGIN CERTIFICATE/{f=sprintf("%s/c.%d.pem",d,++i)} f{print > f} /END CERTIFICATE/{close(f); f=""}'` (d = `mktemp -d`), fingerprint each with `openssl x509 -noout -fingerprint -sha256` (strip `=`, colons, uppercase), print matches against `BAD_FPS` (dedup, one per line). Missing bundle file → skip silently. Then `set_fact`: `emudhra_ca_matched: "{{ detect_out.stdout_lines }}"`, `emudhra_ca_affected: "{{ emudhra_ca_matched | length > 0 }}"`.

- [ ] **Step 3: Run `tests/e2e/run.sh detect` → PASS (3 cases)**

- [ ] **Step 4: Lint + commit**

`feat: fingerprint detection gate for emudhra_ca`

---

### Task 4: Remediation

**Files:**
- Modify: `roles/emudhra_ca/tasks/main.yml` (remediate include, `when: emudhra_ca_affected`)
- Create: `roles/emudhra_ca/tasks/remediate.yml`

**Interfaces:**
- Consumes: `emudhra_ca_affected`, `emudhra_ca_matched`, family vars, `emudhra_ca_bad_roots`.
- Produces: `emudhra_ca_remediation_changed` (bool — true if package or manual-copy step changed) consumed by Task 5's refresh gating; debug summary `emudhra_ca: remediated <n> root(s)`.
- Task order inside remediate.yml: (1) Debian-only `ansible.builtin.apt: update_cache: true`; (2) `ansible.builtin.package: name=ca-certificates state=latest` (no pins); (3) manual-dir scan: fingerprint every `*.crt`/`*.pem` in `emudhra_ca_manual_ca_dir`, remove exact matches with `ansible.builtin.file: state=absent` loop (name-independent); (4) refresh via `emudhra_ca_refresh_cmd` when (2) or (3) changed.

- [ ] **Step 1: Write the failing `remediate` scenario**

Per image (all three): fixture injects `emSign_ECC_Root_CA_-_G3.crt` as `/usr/local/share/ca-certificates/random-name-123.crt` + refresh, and injects a decoy self-signed cert (fixture: `openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=emSign Root CA - G1" -days 2`) as `decoy-g1.crt` + refresh → run playbook → assert: bad fingerprint absent from active bundle (harness re-splits + fingerprints the bundle itself), `decoy-g1.crt` still present, run reports `changed` ≥ 1; second run → `changed=0` (idempotent). Run → FAIL.

- [ ] **Step 2: Implement `remediate.yml` per Interfaces**

- [ ] **Step 3: Run `tests/e2e/run.sh remediate` → PASS (3 images, incl. re-run)**

- [ ] **Step 4: Lint + commit**

`feat: gated remediation for emudhra_ca`

---

### Task 5: Verify + blocklist fallback

**Files:**
- Modify: `roles/emudhra_ca/tasks/main.yml` (verify include)
- Create: `roles/emudhra_ca/tasks/verify.yml`

**Interfaces:**
- Consumes: detection (re-run), family vars, `files/certs/` PEMs, `emudhra_ca_bad_roots` (fp→cert map), `emudhra_ca_remediation_changed`.
- Produces: fallback marker debug msg starting `EMUDHRA_SCA_FALLBACK:` (harness greps the prefix); terminal `ansible.builtin.fail` msg `emudhra_ca: still affected after fallback: <fps>` if re-verify still finds matches.
- Debian fallback: for each matched fp, find the `emudhra_ca_conf_file` entry whose `{{ emudhra_ca_package_ca_dir }}/<entry>` cert fingerprints to it; prefix the entry with `!` (idempotent — skip already-prefixed lines).
- RedHat fallback: `ansible.builtin.copy` the role PEM for each matched fp (map via `emudhra_ca_bad_roots`) into `emudhra_ca_blocklist_dir` (create dir first; comment notes older p11-kit uses `blacklist/`).
- Then refresh + re-detect; still affected → fail per above.

- [ ] **Step 1: Write the failing `fallback` scenario**

ubuntu:22.04 (pristine = affected via package-shipped emSign ECC root) with `apt-mark hold ca-certificates`; rockylinux:9 with `exclude=ca-certificates` appended to `/etc/dnf/dnf.conf`. Run → assert `EMUDHRA_SCA_FALLBACK` in output, bad fp absent from bundle, `changed` ≥ 1. Persistence phase (Review Focus #5): remove hold/exclude, `apt-get install --only-upgrade ca-certificates` / `dnf upgrade ca-certificates`, re-run role → `changed=0`, fp still absent.

- [ ] **Step 2: Implement `verify.yml` per Interfaces**

- [ ] **Step 3: Run `tests/e2e/run.sh fallback` → PASS (both families + persistence)**

- [ ] **Step 4: Lint + commit**

`feat: blocklist fallback when package upgrade cannot clear roots`

---

### Task 6: Connectivity check + playbook wrapper

**Files:**
- Modify: `roles/emudhra_ca/tasks/main.yml` (connectivity block)
- Rewrite: `playbooks/emudhra-ca/distrust-emudhra-roots.yml`

**Interfaces:**
- Connectivity: loop `emudhra_ca_test_sites`; `ansible.builtin.command: openssl s_client -connect {{ item }}:443 -verify_return_error`, `stdin: Q`, `changed_when: false`, `failed_when: "'certificate verify failed' not in <register>.stderr"`; `when: emudhra_ca_affected and emudhra_ca_run_connectivity_check | bool`.
- Wrapper: usage comment block in the `playbooks/ssh_keys.yml` house style; `hosts: "{{ target_hosts | mandatory('Required: -e target_hosts=<group_or_host>') }}"`, `become: true`, `roles: [emudhra_ca]`.

- [ ] **Step 1: Write the failing `wrapper` scenario**

Run `ansible-playbook playbooks/emudhra-ca/distrust-emudhra-roots.yml -e target_hosts=<e2e-inventory-group> -e emudhra_ca_run_connectivity_check=false` via `run_playbook` against injected ubuntu:24.04 → assert remediated, output contains no `s_client` task, and the wrapper file contains the usage block (grep `# Usage:`). Second run → `changed=0`. Run → FAIL (playbook still has old inline tasks).

- [ ] **Step 2: Implement connectivity block + rewrite the wrapper**

- [ ] **Step 3: Run `tests/e2e/run.sh wrapper` → PASS**

Optional live variant: `EMUDHRA_E2E_CONNECTIVITY=1` runs the wrapper without the override on a remediated container with egress and asserts the s_client task passes.

- [ ] **Step 4: Lint + commit**

`feat: affected-only connectivity check and thin playbook wrapper`

---

### Task 7: Matrix completion, mixed fleet, unsupported family

**Files:**
- Modify: `tests/e2e/run.sh` (scenario wiring + `all`)
- Create: `tests/e2e/README.md`

**Interfaces:**
- `clean` scenario: fixture `make_clean <container>` — Debian: `apt-get update && apt-get install --only-upgrade ca-certificates`; Rocky: `dnf upgrade ca-certificates`, then if the bad fp is still in the bundle (fixed package not yet in released repos) apply the blocklist fixture (docker cp role PEMs to `/etc/pki/ca-trust/source/blocklist/` + `update-ca-trust`) → run → assert `changed=0`.
- `mixed` scenario: all three images up; ubuntu:24.04 + rockylinux:9 injected, ubuntu:22.04 clean-fixture → one run → per-host asserts: injected hosts `changed` ≥ 1 + fp absent; clean host `changed=0`.
- `unsupported` scenario: `alpine:3.20` (bootstrap: `apk add python3`) → run → assert the skip warning line, exit 0, `changed=0`.
- `all`: every scenario in sequence, stop on first failure.

- [ ] **Step 1: Run `tests/e2e/run.sh all` → FAIL (scenarios missing)**

- [ ] **Step 2: Implement `clean`, `mixed`, `unsupported`, `all` + README**

README: usage, env vars, scenario table, and the one-line Rocky 8 extension note (append `rockylinux:8` to `--images`).

- [ ] **Step 3: Run `tests/e2e/run.sh all` → PASS end-to-end**

- [ ] **Step 4: Lint + commit**

`test: full e2e matrix, mixed fleet, and unsupported-family scenarios`

---

### Task 8: Build-time cert check + docs

**Files:**
- Create: `tests/e2e/check-certs.sh`
- Modify: `README.md` (repo — e2e section)

**Interfaces:**
- `tests/e2e/check-certs.sh`: parses `emudhra_ca_bad_roots` from `roles/emudhra_ca/vars/main.yml` (python3 + yaml — repo already requires python3); for each entry, `openssl x509 -in roles/emudhra_ca/files/certs/<cert> -noout -fingerprint -sha256` must equal `sha256` (case/colon-insensitive); exit 1 naming the mismatching entry otherwise.

- [ ] **Step 1: Verify the check catches corruption (failing-path test)**

Run the script against a temp copy of the role with one PEM byte-flipped → expect exit 1 naming that cert.

- [ ] **Step 2: Implement + run against the real role → PASS (4/4)**

- [ ] **Step 3: README e2e section** (how to run the harness, the cert check, and what `all` covers)

- [ ] **Step 4: Lint + commit**

`test: build-time fingerprint check for shipped root certs`
