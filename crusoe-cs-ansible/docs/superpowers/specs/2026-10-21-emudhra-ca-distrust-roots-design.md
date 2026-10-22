# eMudhra SCA Distrusted Roots — Family-Aware Remediation Design

**Date:** 2026-10-21

## Intent

The private keys of eight eMudhra intermediate CA certificates were compromised (advisory: <https://emudhra.we-have-a-problem.com/>, 2026-10-20; Mozilla bug 2083449). The intermediates chain — directly or via cross-signs — to four roots listed in the advisory's machine-readable `roots.json`. The existing playbook (`playbooks/emudhra-ca/distrust-emudhra-roots.yml`) removes two of them by file name, but it only works on Ubuntu 24.04: it uses `apt` with a 24.04-pinned package version, Debian-only paths, and `update-ca-certificates`. The fleet also runs Ubuntu 22.04 and Rocky Linux, and the playbook runs its tasks regardless of whether a host is actually affected.

We need one remediation that:

1. Works across OS families (Debian and RedHat),
2. Only acts on hosts that are actually affected (idempotent, detect-first),
3. Has e2e proof against real containers for every supported image.

## Goals

- A reusable `emudhra_ca` role that detects and removes all four distrusted roots (per the advisory's `roots.json`) on Debian and RedHat families.
- Detection by exact SHA-256 certificate fingerprint against the active trust bundle — never by file name or package version.
- Remediation runs only when detection says the host is affected; clean hosts report zero changes.
- A post-remediation verification pass; if the CA survives the package upgrade, an explicit fallback removes the offending cert file directly and reports that it did.
- Optional live connectivity check (`s_client`) proving sites chained to the distrusted roots fail verification; on by default, skippable via variable.
- E2E harness (bash) driving the playbook against Docker containers — Ubuntu 22.04, Ubuntu 24.04, Rocky 9, Debian 12, AlmaLinux 9 (Rocky 8 dropped from the default matrix — see "Left to the Builder") — with scenarios: affected→remediated, clean→no-op, re-run→idempotent, and a mixed-fleet single run.
- E2E controller: derived `alpine/ansible` image (pinned tag + Docker SDK for Python + `community.docker` collection), with a `local` escape hatch using the repo `.venv`.

## Non-Goals

- Any in-cluster rollout mechanism for patching host VMs — out of scope here and tracked separately. This change keeps that option open by using only files, packages, and trust-store commands: no reboot, no SSH assumptions, no systemd dependency.
- Java truststores (`cacerts`), NSS databases, or application-specific stores — system trust bundle only.
- Families beyond Debian/RedHat (e.g. Alpine, SUSE) — unsupported hosts are skipped with a clear warning.
- Removing or managing any CA other than the four on the bad list.

## Anti-Goals

- Never remove or modify a certificate that is not an exact fingerprint match — similarly named CAs must not be touched.
- Never fail a mixed-fleet run because one host is unaffected or unsupported.
- No per-release package-version pins — the `>=20260816ubuntu0.24.04.1` style is exactly what made the current playbook 24.04-only.

## Constraints

- Repo lint gates must pass: `yamllint` + `ansible-lint` (pre-commit hook).
- `ansible.cfg`: `remote_user = ubuntu`, fact caching enabled, `strategy = free` — the role must not depend on execution order or on facts being fresh; family dispatch uses `ansible_facts.os_family`.
- `requirements.yml` gains `community.docker` (docker connection plugin for e2e).
- Local Docker is Colima on arm64 — every image used must be multi-arch (`ubuntu`, `rockylinux`, `alpine/ansible` all are).
- E2E containers have no systemd/SSH; the docker connection plugin with `ansible_user=root` is the access path (generated inventory overrides `remote_user`).

## Design

### Role structure

```
roles/emudhra_ca/
  tasks/main.yml        # detect → gate → remediate → verify → connectivity check
  defaults/main.yml     # emudhra_run_connectivity_check: true
                        # emudhra_fail_on_unsupported_family: false
  vars/main.yml         # bad CA list: 4 roots from roots.json (names + SHA-256), test sites
  vars/Debian.yml      # bundle paths, manual CA dir, package-shipped dir, refresh command
  vars/RedHat.yml       # same for RedHat
  files/certs/          # the four distrusted CA certs (public data) — used by e2e injection
```

Family vars load automatically via `ansible_os_family`. Unsupported families skip with a warning (or fail, per `emudhra_fail_on_unsupported_family`).

### Authoritative fingerprint source

The incident advisory's machine-readable artifact — <https://emudhra.we-have-a-problem.com/roots.json> — is the source of truth (advisory published 2026-10-20; Mozilla bug 2083449). It lists four roots; the role's bad list carries their SHA-256 fingerprints verbatim:

| Root | Role in `roots.json` | SHA-256 | Presence in Linux bundles |
|------|----------------------|---------|---------------------------|
| emSign ECC Root CA - G3 | cross_signer | `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` | Mozilla-included — the root distro updates blacklist |
| AAA Certificate Services (Comodo/Sectigo) | direct_issuer | `D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4` | Older bundles; Ubuntu ≥22.04 dropped it earlier (20260223 / Mozilla 2.82) |
| emSign Root TLS CA - G3 | direct_issuer | `7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D` | Not in Mozilla-based bundles (Microsoft-only) — manual-add only |
| emSign Root CS CA - G3 | direct_issuer | `F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5` | Not in Mozilla-based bundles (Microsoft-only) — manual-add only |

Corroboration independent of the advisory: the AAA SHA-256 matches the Rocky 9 (c9s) `remove-aaa-certificate-services.patch` certdata block verbatim; the emSign ECC Root CA - G3 entry matches that patch's serial (`3CF607A968700EDA8B84`) and MD5/SHA1. Distro USNs/changelogs (Ubuntu USN-8944-1, Debian DSA-6572-1 / `20260816+nmu1`) carry names only — they corroborate the event, not fingerprints. Research corpus: [`corpus-distro-records.md`](../../research/corpus-distro-records.md), merged report: [`corpus-merged-report.md`](../../research/corpus-merged-report.md).

The role ships the four root PEMs (extracted from `roots.json`) in `files/certs/` for e2e injection and the blocklist fallback; a build-time check asserts each shipped PEM's certificate fingerprint (SHA-256 over the DER encoding — what `openssl x509 -fingerprint -sha256` reports, and what `roots.json`'s `sha256` field is) equals its pinned fingerprint. (`roots.json` also carries SPKI SHA-256s if key-based matching is ever needed.)

**Status: done (2026-10-21).** `roles/emudhra_ca/vars/main.yml` pins the four roots as `emudhra_ca_bad_roots` (name + sha256 + cert file + note) and `emudhra_ca_test_sites`; the four PEMs are in `roles/emudhra_ca/files/certs/`, each verified to hash to its pinned fingerprint. Lint-clean (yamllint + ansible-lint production profile).

### Detection (the gate)

"Affected" = any certificate in the active trust bundle whose SHA-256 fingerprint is on the bad list.

- Debian active bundle: `/etc/ssl/certs/ca-certificates.crt`
- RedHat active bundles: `/etc/pki/tls/certs/ca-bundle.crt` and `/etc/pki/tls/certs/ca-bundle.trust.crt`
- A missing bundle file means not affected (nothing is trusted from it).
- Implementation: split the bundle into individual PEM certs, fingerprint each with `openssl x509 -fingerprint -sha256`, intersect with the bad list. One shell task, registered, parsed into `emudhra_affected` (bool) plus the list of matching fingerprints found.

Everything below is gated on `emudhra_affected`.

### Remediation (only when affected)

1. **Upgrade the trust package**: `ansible.builtin.package: name=ca-certificates state=latest`, with an apt cache refresh on Debian first. No version pins — the verify pass handles a lagging distro.
2. **Remove manual copies**: fingerprint-scan `*.crt` in the manual CA dir (Debian: `/usr/local/share/ca-certificates/`; RedHat: `/etc/pki/ca-trust/source/anchors/`), remove exact fingerprint matches only. Name-independent — an admin may have named the file anything.
3. **Refresh the trust store**: Debian `update-ca-certificates --fresh`; RedHat `update-ca-trust`. Only when step 1 or 2 changed something.

### Verify + fallback

Re-run detection. If still affected (fixed package not yet in the host's repos — expected on Rocky at first):

- Apply the advisory's official distrust method rather than deleting package-owned files (deletion is undone by the next package upgrade):
  - Debian: `!`-prefix the matching entries in `/etc/ca-certificates.conf` (idempotent edit; fingerprint-verify the cert files the entries reference before prefixing).
  - RedHat: copy the matching root PEMs from the role's `files/certs/` into `/etc/pki/ca-trust/source/blocklist/` (fallback `blacklist/` on older p11-kit), then refresh.
- Refresh the trust store, re-verify.
- Report loudly that the package upgrade did not clear the root and the blocklist fallback was applied (a later fixed package converges the host to the package-managed state; re-running the role stays idempotent).
- If still affected after the fallback: fail the host with a clear message.

### Connectivity check (optional, last)

The existing `openssl s_client -verify_return_error` check against the two distrusted-chain test sites, unchanged semantics (stdin `Q`, match `certificate verify failed` in stderr so DNS/network failures don't count as a pass). **Scope (settled 2026-10-21): affected hosts only** — hosts the role remediated get canary-checked; clean hosts are never touched and never fail the run for lacking egress. Gated by `emudhra_ca_run_connectivity_check` (default `true`). E2E runs with `false` by default — the check needs real egress/DNS and is inherently environment-dependent.

### Playbook

`playbooks/emudhra-ca/distrust-emudhra-roots.yml` becomes a thin wrapper in the `ssh_keys.yml` house style: usage comment block, `hosts: "{{ target_hosts | mandatory(...) }}"`, `become: true`, `roles: [emudhra_ca]`.

### E2E harness

```
tests/e2e/
  run.sh                  # generic bash runner (container lifecycle, inventory gen, assertions)
  Dockerfile.controller   # FROM alpine/ansible:<pinned tag> + Docker SDK + community.docker
```

- Generic runner: takes a playbook and an image list; spins up named containers (`emudhra-e2e-<distro>-<scenario>`); bootstraps python3 on Rocky (`dnf install -y python3`) before Ansible connects; writes an ephemeral INI inventory (`ansible_connection=community.docker.docker`, `ansible_user=root`); runs the playbook via the controller container (repo and docker socket mounted, targets addressed as sibling containers); tears down.
- Scenarios:
  - **affected→remediated**: inject distrusted roots the way an admin would (manual dir + trust refresh), run, assert the roots are gone from the active bundle and the run reports changed. Ubuntu 22.04 pristine images are already affected (emSign ECC Root CA - G3 is package-shipped pre-fix) — a natural package-shipped case.
  - **clean→no-op**: construct the clean state in the fixture — upgrade `ca-certificates` via apt/dnf directly (never via the role); on Rocky, if the fixed package isn't in released repos yet, apply the advisory's blocklist commands in the fixture — then run and assert zero changed tasks.
  - **re-run→idempotent**: run twice on an affected container, assert the second run reports zero changes.
  - **fallback→blocklist**: hold the package (`apt-mark hold` / dnf exclude) so `state=latest` cannot clear the root, run, assert the blocklist fallback remediated the host and the run reports the fallback loudly.
  - **mixed fleet**: all matrix images up simultaneously, some injected some clean, one playbook run, per-host assertions — proves family dispatch works side-by-side in a single run.
- Injection uses the role's own `files/certs/` — proving the shipped fingerprints match the shipped certs.
- Controller: derived `alpine/ansible` image by default; `EMUDHRA_E2E_CONTROLLER=local` uses the repo `.venv` for fast iteration.

## Left to the Builder

- Exact `alpine/ansible` tag pin (current ansible-core at implementation time).
- ~~Extracting the four root PEMs from `roots.json` into `files/certs/` and adding the build-time fingerprint cross-check~~ — done 2026-10-21; the build-time check script itself lands with the e2e harness task.
- The exact bundle-splitting command (awk/openssl) — must handle multi-cert PEM bundles and RedHat's two bundle files.
- ~~Rocky 9 in the matrix is a default call (8 vs 9 vs both was never confirmed); the matrix must be a one-line extension to add Rocky 8~~ — settled 2026-10-21: Rocky 9 + AlmaLinux 9 are the RedHat-family defaults; Rocky 8 is dropped from the default matrix (its repos ship no dnf bindings for any Python new enough for ansible-core 2.20 — verified against Rocky 8's actual repos). The role itself stays family-generic; real EL8 hosts that pass the interpreter pre-flight work the same way, and `--images rockylinux:8` remains available for controllers running an older ansible-core.
- Assertion details in `run.sh` (parsing playbook output for per-host changed counts).
