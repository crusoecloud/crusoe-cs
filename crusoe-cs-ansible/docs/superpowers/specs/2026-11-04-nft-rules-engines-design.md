# nft-rules engines — design

**Date:** 2026-11-04
**Status:** approved (approach B, chosen in conversation)
**Scope:** the probe and metrics scripts of stateful nftables
mitigations — DRY extraction + the two reported fixes that
land in them.

## Intent and why

Reported feedback on 0.1.2 (unresolved in 0.1.4) named two script-level
defects, and the follow-up conversation asked for the scripts to be
DRY, extendable, and future-proof. The two goals align: the fixes
should land in **reusable machinery**, not in another copy of a
CVE-specific file.

- **Concern 2 (probe client-side safety):** `probe.py` sets
  `IP_OPTIONS` on a normal TCP client socket. On an unpatched kernel
  the sending socket allocates and frees `inet_opt` on every run —
  the exact free the upstream fix (e3f33b0a1d89) defers to RCU. We
  cannot confirm the client path safe on 5.15.0-185/-194; the
  reporter runs `run_probe: "false"` until we can.
- **Concern 3 (host counters stale in pod mode):** the metrics
  script publishes once after the load; nothing refreshes the host
  series until the next hourly run (no systemd timer in pod mode).
  The conditional-load fix (already landed) preserves counters; the
  **freshness** half is still missing.

## Goals

1. One probe engine and one metrics engine, shared by any stateful
   nft mitigation; `cve_2026_98432` becomes the first consumer.
2. The probe's options-SYN trigger uses a **raw socket with
   `IP_HDRINCL`** — the options live in the packet bytes, no socket
   `inet_opt` alloc/free on the client path (concern 2).
3. The reconciler republishes the **host** series every sweep via
   the metrics engine (concern 3 freshness).
4. The rc contract (1=PASS, 0=not working, 2=collateral, 3=crash)
   and the exposition format are **unchanged** — the wrapper,
   reconciler `--verify`, e2e, and dashboards keep working.
5. Metric series names stay identical (`cve_2026_98432_*`) — no
   dashboard/alert churn.

## Non-goals

- No framework/declarative-spec layer (approach C) — the chart's
  `mitigations[]` list is already the seam; a second nft CVE plugs
  in as a new role + list entry.
- No changes to the reconciler's netns logic, inotify handling, or
  alive contract.
- No new metrics series (host freshness reuses the existing series).
- No chart changes in this round (the sidecar command paths stay).

## Approaches considered

- **A — fix in place, extract later.** Smallest diff, but the
  concern-2/3 fixes land in files the next CVE would copy-paste.
  Rejected: DRY/extendable was an explicit requirement.
- **B — extract the engines now (chosen).** The fixes land in
  shared machinery; the next nft CVE starts from a tested baseline.
  Risk: a bigger diff touching live scripts — mitigated by the rc
  contract and exposition format staying identical, and by the
  existing test suites moving to the engines.
- **C — full mitigation framework.** Declarative specs consumed by
  chart+role+scripts. Rejected: one nft CVE today; most of it
  speculative.

## Design

### 1. The shared role: `roles/nft_rules/`

A role with **no tasks** — only `files/` (the engines) and
`defaults/` (the parameterization contract). The image's
`COPY roles/ /opt/ansible/roles/` bakes it automatically; consumers
reference the engine paths.

```
roles/nft_rules/
  files/nft-probe.py      # the probe engine (python3 — documented, escapable)
  files/nft-metrics.sh    # the ONE metrics engine (POSIX sh — no host deps)
  defaults/main.yml        # documented parameter contract
```

### 2. The probe engine (`nft-probe.py`)

**Parameterization** (CLI flags, mirroring the rc contract):

```
nft-probe.py --mode enforce|observe --table cve_2026_98432
```

- `--table` (default `cve_2026_98432`): the nft table to read
  counters from.
- The **trigger** stays in the engine for now: an options-bearing
  IPv4 TCP SYN. The trigger *mechanism* is what changes (below);
  the trigger *shape* (four NOP options, IHL 6) is the
  cve-2026-98432 match — parameterizing match shapes is the second
  CVE's problem, and the engine's `--table` + the raw-packet builder
  are the seams it plugs into.

**The raw-socket trigger (concern 2):**

- The options SYN is sent from an `AF_INET/SOCK_RAW/IPPROTO_TCP`
  socket with `IP_HDRINCL`: the IPv4 header (IHL 6, options = four
  NOPs) and the TCP header (SYN) are built in userspace; the kernel
  does not allocate `inet_opt` for the socket (there is no
  `setsockopt(IP_OPTIONS)` call at all).
- The plain-SYN control stays a **normal socket** connect — it must
  prove the non-options path still works end-to-end (a raw plain
  SYN would not exercise the listener path the same way).
- Drop detection: the raw SYN gets no SYN-ACK within the timeout
  (the rule drops it at priority raw, before the listener); the
  plain control connects. Observe mode: the raw SYN **is ACKed**
  (the rule logs, not drops) and the match counter increments.
- The listener for the raw SYN: a normal `socket.create_server` on
  loopback; the raw SYN reaches it via the kernel's normal input
  path (the rule's verdict is what we assert, not the listener's
  accept — a SYN-ACK from the kernel proves the packet survived
  the input hook).
- **Baseline unchanged:** the baseline probe (options SYN must
  connect BEFORE the rule loads) uses the same raw trigger — on a
  compliant kernel the raw options SYN is ACKed; on a
  kernel-that-strips-options it would fail loudly (the vacuous-
  pass guard keeps its shape).

**rc contract (unchanged):**

```
0  not working (enforce: options SYN connected; observe: not counting)
1  PASS
2  plain-SYN collateral damage
3  probe could not run (crash)
```

### 3. The metrics engines — split by RUNTIME, not language

The host-side metrics path has a hard constraint the probe doesn't:
the systemd timer runs `ExecStart` on the HOST's userspace, and
metrics is NOT optional (the probe is — `run_probe: "false"` is a
supported config; the evidence pipeline is always on). The original
cve-2026-98432 script was POSIX sh precisely so no host needs
python3 for metrics. That constraint carries to the engine:

- **`nft-metrics.sh`** — the ONE metrics engine (the systemd timer
  on bare VMs + the role's one-shot task): POSIX sh, zero host
  dependencies. Identity via env:
  `NFT_METRICS_TABLE` / `NFT_METRICS_PREFIX` / `NFT_METRICS_MATCH`
  (+ destination dirs; legacy `CVE_METRICS_*` aliases honored).

**POD-side (the reconciler's per-sweep host republish, concern 3):
INLINE, not a second engine file** — the reconciler already reads
the host chain (read_host_mode), parses counters (_COUNTER_RE), and
writes exposition (write_metrics); the host republish is the same
three primitives pointed at the host table. One metrics engine
exists; the reconciler self-publishes pod-side. The HELP text is
byte-identical to the sh engine's (pinned by test — serve-metrics
warns on every scrape when two generators declare one family with
different HELP text).

Exposition format, destination selection, atomic write, and the
no-op-when-no-consumer behavior are **identical** across both
engines and to the current script.

### 4. The reconciler republish (concern 3 freshness)

The reconciler's sweep already reads the host mode every pass
(`read_host_mode`). It gains: call the metrics engine's `publish()`
once per sweep (imported, not shelled out — the engine's `nft list`
flows through the reconciler's `host()`), writing to the chart
hostPath. Failure is logged and never breaks the sweep (the same
contract as `write_metrics`). The host series become as fresh as
the netns series (~10s).

### 5. Wiring (the cve role as first consumer)

- `probe.yml` / `baseline.yml`: `ansible.builtin.script` points at
  the engine with `--table {{ cve_2026_98432_table }}`.
- `metrics.yml`: installs the engine to the same
  `/usr/local/sbin/` path; the systemd units call it with the env
  vars set (unit files updated to pass the table).
- The reconciler's `PROBE_PATH` default moves to the engine path.
- The old `probe.py` and `cve-2026-98432-metrics.sh` are **deleted**
  (the ban on copy-paste: one engine, no forks).
- `vars/main.yml`: the table name stays the single source of truth;
  the match expression becomes a documented var passed to both
  engines.

### 6. Tests

- The existing `test_probe.py` / `test_metrics_script.py` move to
  the engines (same assertions, engine paths + parameters).
- New: raw-packet construction (IHL, options bytes, checksums),
  SYN-ACK detection, the parameterization contract, the reconciler
  republish (FakeHost), and the legacy-env aliases.

## Risks

- **Raw-socket behavior differences across kernels** — mitigated:
  the baseline probe (run before the rule) proves the raw trigger
  works on the target kernel; the e2e suite runs it on real
  kernels (Ubuntu + alpine).
- **The reconciler shelling out per sweep** — one extra
  `nft list chain` per 10s (it already runs several); the metrics
  engine is a shell script, no new process weight.
- **Series-name drift** — pinned by tests: the engine with the
  cve-2026-98432 parameters must produce byte-identical exposition
  to the old script (the test fixtures double as the drift guard).

## What's left to the builder

- The exact raw-packet builder (header layout, checksum functions)
  follows the probe's existing timeout/verdict structure; the
  tests pin the observable contract (SYN-ACK seen/not-seen,
  counter delta), not the byte layout.
- The reconciler's engine invocation: `subprocess.run` with the
  env, logged on failure — mirroring `write_metrics`'s best-effort
  contract.
