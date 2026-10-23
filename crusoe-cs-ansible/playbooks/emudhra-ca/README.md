# eMudhra CA distrusted-roots remediation

Removes the distrusted eMudhra root CAs from hosts' trust stores,
following the security advisory at
<https://emudhra.we-have-a-problem.com/> (published 2026-10-20;
Mozilla bug 2083449).

## Background

The private keys of eight eMudhra intermediate CA certificates were
compromised. The intermediates chain — directly or via cross-signs —
to four root CAs listed in the advisory's machine-readable
[`roots.json`](https://emudhra.we-have-a-problem.com/roots.json).
Any system whose trust store includes those roots will validate
certificates issued by the attacker.

This playbook detects and removes all four roots on Debian-family
(Ubuntu, Debian) and RedHat-family (Rocky, AlmaLinux, RHEL) hosts.
Detection is by **exact SHA-256 fingerprint** — never by file name or
package version — so similarly named CAs are never touched.

## Which certificates are mitigated

The four distrusted roots (fingerprints pinned verbatim from
[`roots.json`](https://emudhra.we-have-a-problem.com/roots.json)):

| Root | SHA-256 (prefix) | Why it's on the list |
|---|---|---|
| emSign ECC Root CA - G3 | `86A1ECBA…` | Cross-signer of the compromised eMudhra intermediates; Mozilla-included, ships in distro bundles |
| AAA Certificate Services (Comodo/Sectigo) | `D7A7A0FB…` | Direct issuer of the Sectigo cross-signs; present in older bundles |
| emSign Root TLS CA - G3 | `7DD78D5F…` | Direct issuer; Microsoft-only root — found in manually-added copies |
| emSign Root CS CA - G3 | `F2EDAAFF…` | Direct issuer; Microsoft-only root — found in manually-added copies |

The eight compromised intermediates themselves (`EM DV/OV/EV TLS CA -
G3B/G3C`) chain to these roots; removing the roots distrusts every
certificate issued beneath them. The full intermediate list is in the
advisory's
[`impacted-intermediates.json`](https://emudhra.we-have-a-problem.com/impacted-intermediates.json).

## ⚠️ Scope — what this playbook does NOT cover

This playbook remediates the **system trust bundle** (plus certifi and
Java where already installed). The advisory documents a much wider
ecosystem of affected [root store bundles, libraries, and language
runtimes](https://emudhra.we-have-a-problem.com/#patched-bundles) —
each ships its **own copy** of the roots and needs its **own update**:

- **Language runtimes and package managers** — Node.js, Python
  `certifi`/pip/uv/pixi, Rust (rustls-webpki, webpki-roots, rustup),
  Go, Java, Electron, Bun, Deno, Composer, Elixir/Erlang, Perl
  Mozilla::CA, mise, Claude Code — see
  [patched runtimes](https://emudhra.we-have-a-problem.com/#patched-runtimes)
- **Standalone bundles and libraries** — curl CA bundle, NSS,
  Cloudflare CFSSL, Homebrew, Chainguard, Alpine, Arch, Gentoo,
  FreeBSD, and more — see
  [patched bundles and libraries](https://emudhra.we-have-a-problem.com/#patched-bundles)
- **Anything a user installed manually** — application-specific
  truststores (e.g. `pip install --cert`, custom `curl --cacert`,
  vendored bundles in containers, third-party appliances) are outside
  this playbook's reach entirely

**If your hosts run software from the lists above, update those
packages too.** The advisory's
[tables of fixed versions](https://emudhra.we-have-a-problem.com/#patched-bundles)
name the fixed release of each.

## What it does

Per host, in order:

1. **Pre-flight** — verifies the target has a Python ≥ 3.7 interpreter
   (Ansible modules need one; fails with a clear message instead of a
   cryptic module error).
2. **Detect** — scans the active trust bundles for any of the four
   distrusted fingerprints. Unaffected hosts report zero changes and
   are never modified.
3. **Remediate** (affected hosts only) — upgrades the
   `ca-certificates` package and removes manual copies of the roots
   (matched by fingerprint, whatever the file is named), then refreshes
   the trust store.
4. **Verify + fallback** — re-scans. If a root survives the package
   upgrade (fixed package not yet in the host's repos), the advisory's
   official distrust method is applied: `!`-prefixing the entry in
   `/etc/ca-certificates.conf` (Debian) or copying the root PEM into
   the p11-kit blocklist (RedHat). Still affected after the fallback →
   the host fails loudly.
5. **Extended stores** (default on) — also remediates Python `certifi`
   bundles and Java `cacerts` keystores **where already present** —
   never installing a package the host doesn't have. (These are the
   two runtime stores most commonly found on fleet hosts; the advisory
   lists many more — see the scope warning above.)
6. **Connectivity canary** (optional, default on) — proves sites chained
   to the distrusted roots now *fail* verification. A single egress
   pre-check gates it: no route to the test sites → skipped with an
   explanatory message, not a failure.

## Air-gapped environments (no internet)

The role's preferred remediation is upgrading the `ca-certificates`
package — that needs egress. On hosts **without internet access** the
upgrade cannot succeed, and the role degrades gracefully:

1. The apt cache refresh and the package upgrades (`ca-certificates`
   and, where installed, `python3-certifi`) are **tolerated failures**
   — the run continues instead of aborting. Controlled by
   `emudhra_ca_tolerate_missing_egress` (default `true`).
2. Removal of manually-installed copies (fingerprint-matched) still
   runs — it needs no egress.
3. The verify pass re-scans the bundle; if the distrusted roots
   survive (they will — no updated package arrived), the role applies
   the advisory's official **local distrust workaround**:
   - **Debian/Ubuntu:** `!`-prefixes the matching entries in
     `/etc/ca-certificates.conf` and runs `update-ca-certificates`.
   - **RedHat family:** copies the matching root PEMs into the p11-kit
     blocklist dir and runs `update-ca-trust`.
   Both are local operations — no egress required.
4. The final scan must come back clean or the run fails loudly.

### Manual workaround (if you cannot run the playbook)

The advisory documents the same steps by hand — for reference, on
Debian/Ubuntu as root:

```bash
sed -i \
  -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
  -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \
  /etc/ca-certificates.conf && update-ca-certificates
```

On Fedora/RHEL/CentOS Stream/Rocky/AlmaLinux as root:

```bash
d=/etc/pki/ca-trust/source/blocklist; [ -d $d ] || d=/etc/pki/ca-trust/source/blacklist
trust extract --overwrite --format=pem-bundle \
  --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \
  $d/Comodo_AAA_Services_root.pem &&
trust extract --overwrite --format=pem-bundle \
  --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
  $d/emSign_ECC_Root_CA_-_G3.pem &&
update-ca-trust
```

If you use the Java certificate store, sync it after the Debian
workaround (the role's extended-stores pass handles Java keystores it
finds — using `emudhra_ca_java_keystore_pass`, default `changeit`; a
keystore with a custom password is skipped silently — but a
system-store sync keeps them consistent):

```bash
touch /var/lib/ca-certificates-java/fresh
dpkg-reconfigure ca-certificates-java
```

Full advisory workarounds (macOS, Windows, Alpine, openSUSE, Arch,
NixOS): <https://emudhra.we-have-a-problem.com/#workarounds>

## Prerequisites

> **Start here if this is your first run.** This playbook needs a working
> Ansible environment *and* an inventory that resolves your hosts. Both
> are set up once, in the repository root — follow these in order:

| # | Step | Repository README | What it gives you |
|---|---|---|---|
| 1 | Install tooling | [Prerequisites → Tooling](../../README.md#tooling) | `pyenv`, `pipenv`, `direnv` |
| 2 | Install and authenticate the Crusoe CLI | [Prerequisites → Crusoe CLI](../../README.md#crusoe-cli) | The credentials the dynamic inventory queries |
| 3 | Bootstrap the project | [Setup](../../README.md#setup) | Pinned Python, virtualenv, Ansible + collections |
| 4 | Understand the inventory | [Inventory](../../README.md#inventory) | How hosts and groups are discovered |

Steps 1–3 are one-time. To confirm you are ready, run both of these
inside the repo.

**1. The virtualenv is active.**

```console
$ ansible-playbook --version
ansible-playbook [core 2.20.2]
  config file = <repo>/crusoe-cs-ansible/ansible.cfg
  ...
  executable location = <repo>/crusoe-cs-ansible/.venv/bin/ansible-playbook
  python version = 3.14.x ...
```

Check two lines: `config file` must be the repo's `ansible.cfg` (otherwise
Ansible won't find the inventory), and `executable location` must be inside
the repo's `.venv/`. If it points elsewhere — e.g. `/opt/homebrew/bin/` — you
are running a system Ansible, not the project's pinned one; run
`direnv allow` in the repo (or `source .venv/bin/activate`) and check again.

**2. The Crusoe CLI is authenticated** — this exercises exactly what Ansible
uses:

```console
$ inventory/crusoe.py --list
{
  "_meta": {
    "hostvars": {
      "vm-example-1": {
        "ansible_host": "203.0.113.10",
        "crusoe_private_ip": "172.27.0.4",
        "crusoe_public_ip": "203.0.113.10",
        "crusoe_project": "8f21c0b4_1a2b_4c3d_9e8f_0123456789ab",
        "crusoe_type": "c1a.2x",
        "crusoe_location": "us-southcentral1-a",
        "crusoe_nodepool": "",
        "crusoe_cluster": "",
        "crusoe_node_labels": {}
      },
      "vm-example-2": { ... }
    }
  },
  "all": {
    "hosts": ["vm-example-1", "vm-example-2"]
  },
  "project_8f21c0b4_1a2b_4c3d_9e8f_0123456789ab": {
    "hosts": ["vm-example-1", "vm-example-2"]
  },
  "type_c1a": {
    "hosts": ["vm-example-1", "vm-example-2"]
  },
  "region_us_southcentral1": {
    "hosts": ["vm-example-1", "vm-example-2"]
  }
}
```

**Reading the output.** `_meta.hostvars` is per-host detail — not something
you target. Every *other* top-level key is a **group name** you can pass as
`target_hosts`. In the example above:

| Group | Built from | Use it to target |
|---|---|---|
| `all` | — | Every VM in the account |
| `project_8f21c0b4_…` | `crusoe_project` (dashes become `_`) | Every VM in that project |
| `type_c1a` | `crusoe_type` with the size suffix dropped (`c1a.2x` → `c1a`) | Every VM of that instance family |
| `region_us_southcentral1` | `crusoe_location` with the AZ dropped (`us-southcentral1-a` → `us_southcentral1`) | Every VM in that region |

Hostnames (`vm-example-1`) work too, to target a single VM. These VMs have an
empty `crusoe_nodepool` and `crusoe_cluster`, so no `nodepool_*` or `k8s_*`
groups appear; Kubernetes nodes would add those. So, for example:

```bash
ansible-playbook playbooks/emudhra-ca/distrust-emudhra-roots.yml -e target_hosts=region_us_southcentral1
```

If the command errors, the `crusoe` CLI is not installed or not
authenticated — revisit step 2. The inventory shells out to
`crusoe compute vms list`, `crusoe kubernetes nodepools list`, and
`crusoe kubernetes clusters list`, so your credentials need read access
to those resources.

### Where `target_hosts` comes from

`ansible.cfg` already points Ansible at the dynamic inventory:

```ini
[defaults]
inventory = inventory/crusoe.py
```

[`inventory/crusoe.py`](../../inventory/crusoe.py) queries the Crusoe Cloud API through the `crusoe`
CLI and builds groups automatically. **You do not write an inventory
file** — you pass one of these generated group names (or a single
hostname) as `target_hosts`:

| Group pattern | Example | Contains |
|---|---|---|
| `all` | `all` | Every VM in your account |
| `project_<project_id>` | `project_8f21c0b4_…` | All VMs in one project (the project **ID**, not its display name) |
| `type_<instance_type>` | `type_c1a` | All VMs of one instance type |
| `region_<region>` | `region_us_east1` | All VMs in a region (AZ suffix stripped) |
| `nodepool_<nodepool>` | `nodepool_gpu_workers` | Kubernetes nodes in one nodepool |
| `k8s_<cluster>` | `k8s_prod_cluster` | All Kubernetes nodes in one cluster |

Results are cached for 120 seconds. If you just created or deleted
hosts, bypass the cache with `inventory/crusoe.py --refresh`.

### Verify your inventory before you remediate

Never let a fleet-wide run be the first time you look at the inventory.
Confirm the group exists and contains exactly the hosts you expect:

```bash
# List every group and its hosts
ansible-inventory --graph

# Show the hosts a given group resolves to — change nothing
ansible-playbook playbooks/emudhra-ca/distrust-emudhra-roots.yml \
  -e target_hosts=<group> --list-hosts

# Prove Ansible can actually reach and authenticate to them
ansible <group> -m ping
```

`ansible -m ping` failing here is an SSH or credentials problem, not a
playbook problem — fix it before continuing. Connections use
`remote_user = ubuntu` from [`ansible.cfg`](../../ansible.cfg); if your hosts sit behind a
bastion, set `ansible_ssh_common_args` in [`inventory/group_vars/all.yml`](../../inventory/group_vars/all.yml)
(there is a commented example in that file).

### Roll out gradually

The playbook is idempotent and safe to re-run, so prove it on a small
slice before the whole fleet:

```bash
# 1. One host first
ansible-playbook playbooks/emudhra-ca/distrust-emudhra-roots.yml \
  -e target_hosts=<group> --limit <single-host>

# 2. Then the group
ansible-playbook playbooks/emudhra-ca/distrust-emudhra-roots.yml \
  -e target_hosts=<group>
```

Unaffected hosts report `changed=0` and are never modified, so a
second run over the same group is a no-op you can use to confirm
convergence.

### Not using the Crusoe dynamic inventory?

If you manage these hosts elsewhere, supply any standard Ansible
inventory with `-i` and it overrides `ansible.cfg`:

```ini
# hosts.ini
[gpu-nodes]
node-01 ansible_host=10.0.0.11
node-02 ansible_host=10.0.0.12

[gpu-nodes:vars]
ansible_user=ubuntu
```

```bash
ansible-playbook -i hosts.ini \
  playbooks/emudhra-ca/distrust-emudhra-roots.yml -e target_hosts=gpu-nodes
```

The role itself has no Crusoe-specific dependencies — it only needs SSH
access and a Python ≥ 3.7 interpreter on the target (the pre-flight
check verifies this and fails with a clear message if it is missing).

## Usage

> Complete the [Prerequisites](#prerequisites) first — in particular,
> confirm `target_hosts` resolves to the hosts you intend to change.

All remote playbooks require `-e target_hosts=<group>`:

```bash
# Remediate a fleet
ansible-playbook playbooks/emudhra-ca/distrust-emudhra-roots.yml -e target_hosts=gpu-nodes

# Skip the live connectivity check (hosts without egress to the advisory test sites)
ansible-playbook playbooks/emudhra-ca/distrust-emudhra-roots.yml \
  -e target_hosts=gpu-nodes -e emudhra_ca_run_connectivity_check=false

# Fail loudly on unsupported OS families instead of skipping
ansible-playbook playbooks/emudhra-ca/distrust-emudhra-roots.yml \
  -e target_hosts=gpu-nodes -e emudhra_ca_fail_on_unsupported_family=true

# Opt out of the certifi/Java extended-store pass
ansible-playbook playbooks/emudhra-ca/distrust-emudhra-roots.yml \
  -e target_hosts=gpu-nodes -e emudhra_ca_extended_stores=false
```

## Variables

| Variable | Default | Description |
|---|---|---|
| `target_hosts` | *(required)* | Inventory host or group to remediate |
| `emudhra_ca_run_connectivity_check` | `true` | Live `s_client` canary on remediated hosts. A single egress pre-check gates it: on a host with no route to the test sites the canary is skipped with an explanatory message (the verify pass already proved the roots are gone) instead of failing the run. |
| `emudhra_ca_fail_on_unsupported_family` | `false` | Fail instead of skip on non-Debian/RedHat families |
| `emudhra_ca_extended_stores` | `true` | Remediate certifi + Java cacerts where present (never installs) |
| `emudhra_ca_tolerate_missing_egress` | `true` | Air-gapped hosts: failed package operations (apt cache refresh, ca-certificates/certifi upgrades) are tolerated and the run continues to the local blocklist fallback. Set `false` to make a failed package operation abort the run (catch unexpected repo breakage on connected hosts). |
| `emudhra_ca_java_keystore_pass` | `changeit` | Password for the Java cacerts keystores the extended-stores pass scans/edits (the JVM default). A wrong password makes keytool fail silently and that keystore is skipped. |
| `emudhra_ca_test_sites` | the 2 advisory canary sites | Sites the canary connects to. Overridable — e.g. point at a private mirror of the advisory test sites. |

## Safety properties

- **Idempotent** — re-runs on clean hosts are zero-change no-ops
  (proven by the e2e clean/mixed scenarios).
- **Fingerprint-only matching** — a certificate is touched only on an
  exact SHA-256 match with `roots.json`; similarly named CAs are safe.
- **No version pins** — package upgrades are unpinned so the role works
  across distro releases; the verify pass handles repos that lag.

## Testing

Full details: [`tests/e2e/emudhra-ca/README.md`](../../tests/e2e/emudhra-ca/README.md).

- Docker e2e ([`run.sh`](../../tests/e2e/emudhra-ca/run.sh)):
  `tests/e2e/emudhra-ca/run.sh all` — 9 scenarios × 5 images (Ubuntu
  22.04/24.04, Rocky 9, Debian 12, AlmaLinux 9).
- Real-VM e2e ([`vms.py`](../../tests/e2e/emudhra-ca/vms.py)):
  `tests/e2e/emudhra-ca/vms.py test` — one VM per latest-tagged Crusoe
  image; pristine VMs genuinely ship the distrusted roots, so this
  exercises the real package-shipped case.

## Sources

- Advisory: <https://emudhra.we-have-a-problem.com/>
- Machine-readable root list:
  [`roots.json`](https://emudhra.we-have-a-problem.com/roots.json)
  (the fingerprints in [`roles/emudhra_ca/vars/main.yml`](../../roles/emudhra_ca/vars/main.yml) are pinned
  verbatim from this file)
- Distro corroboration: Ubuntu USN-8944-1, Debian DSA-6572-1, Rocky 9
  (c9s) `remove-*` patches
