#!/usr/bin/env python3
"""eMudhra SCA e2e harness — drives playbooks against real Crusoe VMs.

Python port of vms.sh (same commands, same behavior): targets are real
Crusoe VMs — one per latest-tagged x86_64 VM image. Pristine VMs genuinely
ship the distrusted roots (every image predates the advisory), so this
exercises the REAL package-shipped case end-to-end: detect→affected,
remediate→clean, re-run→idempotent. No injection fixtures.

Usage: tests/e2e/emudhra-ca/vms.py <command> [args]

Commands:
    matrix          Show the image→VM-type mapping (no side effects)
    up              Create + start one VM per matrix image
    down            Delete all e2e VMs created by this harness (by prefix)
    status          Show e2e VM states
    run <scenario>  Run a scenario against the up VMs
                    (detect | remediate | wrapper | all)
    test            up → run all → down (full lifecycle, one command)

Environment:
    EMUDHRA_E2E_VM_LOCATIONS  comma-separated regions, spread round-robin
                              (default us-southcentral1-a,us-east1-a,
                              us-east2-a,us-west1-a); a capacity failure
                              in one region falls back to the next
    EMUDHRA_E2E_VM_LOCATION  single-region override (wins over LOCATIONS)
    EMUDHRA_E2E_VM_TYPE     default c1a.2x (c2a-s2a image always uses c2a.2x)
    EMUDHRA_E2E_VM_PREFIX   default emudhra-e2e-vm-
    EMUDHRA_E2E_VM_JOBS     parallel creates (default 4)
    EMUDHRA_E2E_VM_KEEP=1   skip teardown in `test` (debug the fleet)
    EMUDHRA_E2E_VM_TIMEOUT  seconds to wait for RUNNING/SSH (default 600)

VMs are named {PREFIX}{image-slug} and deleted by that exact prefix — `down`
never touches VMs outside the harness. The dynamic inventory
(inventory/crusoe.py) picks them up; its 120s cache is bypassed with
--refresh after create/delete.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
E2E_DIR = REPO_ROOT / "tests" / "e2e" / "emudhra-ca"
ANSIBLE = REPO_ROOT / ".venv" / "bin" / "ansible-playbook"
ANSIBLE_BIN = REPO_ROOT / ".venv" / "bin" / "ansible"
INVENTORY = REPO_ROOT / "inventory" / "crusoe.py"
ROLE_VARS = REPO_ROOT / "roles" / "emudhra_ca" / "vars" / "main.yml"

# Regions to spread the fleet across (round-robin). A VM whose create
# fails with a capacity error in its assigned region is retried in the
# remaining regions before the run gives up on it.
LOCATIONS = [
    loc.strip()
    for loc in os.environ.get(
        "EMUDHRA_E2E_VM_LOCATIONS",
        "us-southcentral1-a,us-east1-a,us-east2-a,us-west1-a",
    ).split(",")
    if loc.strip()
]
# Back-compat single-region override (wins over LOCATIONS if set).
if os.environ.get("EMUDHRA_E2E_VM_LOCATION"):
    LOCATIONS = [os.environ["EMUDHRA_E2E_VM_LOCATION"]]
VM_TYPE = os.environ.get("EMUDHRA_E2E_VM_TYPE", "c1a.2x")
PREFIX = os.environ.get("EMUDHRA_E2E_VM_PREFIX", "emudhra-e2e-vm-")
TIMEOUT = int(os.environ.get("EMUDHRA_E2E_VM_TIMEOUT", "600"))
SSH_USER = "ubuntu"

# Every playbook/module invocation saves its full output here — the
# empirical evidence for what happened, kept even (especially) on failure.
# One directory per run, named by UTC timestamp. Lives in /tmp so run
# output never touches the repo (no gitignore needed).
REPORT_DIR = (
    Path(os.environ.get("EMUDHRA_E2E_VM_REPORT_DIR"))
    if os.environ.get("EMUDHRA_E2E_VM_REPORT_DIR")
    else Path("/tmp/emudhra-vm-e2e") / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
)
_STEP = 0

# Regex for the fingerprint scan (same logic as run.sh, over SSH).
FP_SCAN = r"""
for bundle in /etc/ssl/certs/ca-certificates.crt \
              /etc/pki/tls/certs/ca-bundle.crt \
              /etc/pki/tls/certs/ca-bundle.trust.crt; do
  [ -f "$bundle" ] || continue
  d="$(mktemp -d)"; i=0; f=""
  awk -v d="$d" '/BEGIN CERTIFICATE/{f=sprintf("%s/c.%d.pem",d,++i)} \
f{print > f} /END CERTIFICATE/{close(f); f=""}' "$bundle"
  for pem in "$d"/*.pem; do
    openssl x509 -in "$pem" -noout -fingerprint -sha256 2>/dev/null |
      tr -d ":" | awk -F= '{print toupper($2)}'
  done
  rm -rf "$d"
done | sort -u
"""


def log(msg: str) -> None:
    print(f"[vm-e2e] {msg}")


def save_output(label: str, output: str) -> None:
    """Persist one invocation's full output under the run's report dir.

    Numbered sequentially so the order of a run is reconstructable:
    01-detect.log, 02-remediate.log, ... Written even on failure — the
    transcript is the evidence for WHY a scenario died.
    """
    global _STEP
    _STEP += 1
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / f"{_STEP:02d}-{label}.log"
    path.write_text(output)
    log(f"output saved: {path}")


def die(msg: str) -> None:
    print(f"[vm-e2e] FAIL: {msg}", file=sys.stderr)
    print(f"[vm-e2e] evidence: {REPORT_DIR}", file=sys.stderr)
    sys.exit(1)


def run_cmd(
    cmd: list[str],
    *,
    check: bool = True,
    quiet: bool = False,
) -> subprocess.CompletedProcess:
    """Run a command, optionally raising on failure."""
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        if not quiet:
            print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"command failed ({proc.returncode}): " f"{shlex.join(cmd)}")
    return proc


def crusoe(*args: str, check: bool = True) -> list | dict:
    """Run a crusoe CLI command and return parsed JSON."""
    proc = run_cmd(
        ["crusoe", *args, "--format", "json"],
        check=check,
    )
    return json.loads(proc.stdout)


# ---------------------------------------------------------------------------
# Matrix: one VM per latest-tagged x86_64 image.
# arm64 images are excluded (no arm64 CPU type exists in the catalog).
# The c2a-s2a image is named for the c2a family → always paired with c2a.2x.
# ---------------------------------------------------------------------------
def is_arm64(image: dict) -> bool:
    name = image["name"]
    return "arm64" in name or "gb200" in name or "gb300" in name


def vm_type_for(image: dict) -> str:
    return "c2a.2x" if "c2a" in image["name"] else VM_TYPE


def slugify(image_name: str) -> str:
    slug = image_name.lower()
    for ch in ".:/":
        slug = slug.replace(ch, "-")
    return slug


def matrix(images_filter: list[str] | None = None) -> list[dict]:
    """Return the image→VM-type matrix as a list of dicts.

    images_filter: optional list of image names — when given, only those
    images are included (used to boot a subset for forensics).
    """
    images = crusoe("compute", "images", "list")
    latest = [i for i in images if "latest" in i.get("tags", [])]
    rows = []
    for img in sorted(latest, key=lambda x: x["name"]):
        if is_arm64(img):
            continue
        if images_filter and img["name"] not in images_filter:
            continue
        rows.append(
            {
                "image": img["name"],
                "type": vm_type_for(img),
                "slug": slugify(img["name"]),
                "id": img["id"],
            }
        )
    return rows


# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------
def vms_list() -> list[dict]:
    return crusoe("compute", "vms", "list")


def vm_by_name(name: str) -> dict | None:
    for vm in vms_list():
        if vm["name"] == name:
            return vm
    return None


def cmd_up(images_filter: list[str] | None = None) -> None:
    rows = matrix(images_filter)
    if not rows:
        die("up: matrix is empty")
    existing = {vm["name"] for vm in vms_list()}
    todo: list[dict] = []
    created: list[str] = []
    for i, row in enumerate(rows):
        name = f"{PREFIX}{row['slug']}"
        created.append(name)
        if name in existing:
            log(f"up: {name} already exists — reusing")
        else:
            # Round-robin across regions so the fleet spreads load.
            row["location"] = LOCATIONS[i % len(LOCATIONS)]
            todo.append(row)
    # Creates are independent API calls (~2-5 min each) — run them in a
    # thread pool instead of sequentially. EMUDHRA_E2E_VM_JOBS caps the
    # concurrency (default 4; each create is I/O-bound, so threads are fine).
    jobs = int(os.environ.get("EMUDHRA_E2E_VM_JOBS", "4"))
    if todo:
        log(
            f"up: creating {len(todo)} VMs ({jobs} in parallel, "
            f"regions: {', '.join(LOCATIONS)})"
        )

        def create(row: dict) -> None:
            name = f"{PREFIX}{row['slug']}"
            # Try the assigned region first, then the others (capacity
            # fallback). A VM that fails EVERYWHERE is skipped with a loud
            # warning — the rest of the run continues.
            tried = [row["location"]] + [
                loc for loc in LOCATIONS if loc != row["location"]
            ]
            for loc in tried:
                log(
                    f"up: creating {name} ({row['type']}, "
                    f"{row['image']}:latest, {loc})"
                )
                proc = run_cmd(
                    [
                        "crusoe",
                        "compute",
                        "vms",
                        "create",
                        "--name",
                        name,
                        "--type",
                        row["type"],
                        "--location",
                        loc,
                        "--image",
                        f"{row['image']}:latest",
                        "--public-ip-type",
                        "dynamic",
                    ],
                    check=False,
                )
                if proc.returncode == 0:
                    return
                err = (proc.stderr + proc.stdout).strip()
                log(f"up: {name} create failed in {loc}: {err[-200:]}")
            log(
                f"up: WARNING — {name} could not be created in ANY region; "
                f"skipping (run continues without it)"
            )

        with ThreadPoolExecutor(max_workers=jobs) as pool:
            list(pool.map(create, todo))
    # A VM skipped everywhere never came up — drop it from the fleet list
    # so waits and scenarios only target real VMs.
    live = {vm["name"] for vm in vms_list()}
    created = [n for n in created if n in live]
    # Create may leave the VM stopped or running — start only the stopped
    # ones (sequential: one cheap API call each, state check via one list).
    states = {vm["name"]: vm.get("state", "") for vm in vms_list()}
    for name in created:
        if states.get(name) != "STATE_RUNNING":
            log(f"up: starting {name}")
            run_cmd(["crusoe", "compute", "vms", "start", name])
    wait_running(created)
    wait_ssh(created)
    log(f"up: {len(created)} VMs ready")


def wait_running(names: list[str]) -> None:
    log(f"wait: for STATE_RUNNING (timeout {TIMEOUT}s)")
    deadline = time.monotonic() + TIMEOUT
    while True:
        states = {vm["name"]: vm.get("state", "") for vm in vms_list()}
        bad = {
            n: states.get(n, "MISSING")
            for n in names
            if states.get(n) != "STATE_RUNNING"
        }
        if not bad:
            log(f"wait: all {len(names)} RUNNING")
            return
        if time.monotonic() > deadline:
            die(f"wait: timeout after {TIMEOUT}s — not all VMs RUNNING: {bad}")
        time.sleep(10)


def wait_ssh(names: list[str]) -> None:
    """Wait for SSH via Ansible's own connection layer.

    ansible.builtin.wait_for_connection is the event-driven readiness
    primitive — it polls the module channel internally and fails with a
    clear per-host message, so no hand-rolled SSH loop is needed.
    """
    log(f"wait: for SSH (timeout {TIMEOUT}s)")
    out = run_playbook(
        names,
        str(E2E_DIR / "wait-connection.yml"),
        "-e",
        f"wait_timeout={TIMEOUT}",
    )
    save_output("wait-connection", out)
    log(f"wait: SSH up on all {len(names)} VMs")


# ---------------------------------------------------------------------------
# Dynamic inventory helpers. Call the script directly with --refresh
# (bypasses its 120s cache) — --refresh is an inventory-script flag, not an
# ansible CLI flag, so it cannot be passed through ansible-playbook.
# ---------------------------------------------------------------------------
def inventory_json(*, refresh: bool = False) -> dict:
    cmd = [sys.executable, str(INVENTORY)]
    if refresh:
        cmd.append("--refresh")
    cmd.append("--list")
    proc = run_cmd(cmd)
    return json.loads(proc.stdout)


def inventory_hosts() -> list[str]:
    inv = inventory_json(refresh=True)
    return sorted(
        h for h in inv.get("all", {}).get("hosts", []) if h.startswith(PREFIX)
    )


# ---------------------------------------------------------------------------
# Playbook runner — same contract as run.sh: capture output, assert on it.
# No --refresh here: that flag belongs to the inventory script, and wait_ssh
# has just refreshed the cache anyway. Targets only harness VMs via a
# comma-joined --limit (ansible treats the whole string as one pattern).
# ---------------------------------------------------------------------------
def run_playbook(names: list[str], *args: str) -> str:
    env = os.environ.copy()
    env["ANSIBLE_CACHE_PLUGIN"] = "memory"
    env["ANSIBLE_CONFIG"] = str(REPO_ROOT / "ansible.cfg")
    limit = ",".join(names)
    proc = subprocess.run(
        [
            str(ANSIBLE),
            "-i",
            str(INVENTORY),
            "-u",
            SSH_USER,
            "-b",
            "--limit",
            limit,
            *args,
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.stdout + proc.stderr


def run_module(names: list[str], module: str, *module_args: str) -> dict[str, str]:
    """Run an ad-hoc module on the fleet; return {host: stdout}.

    Uses --tree so each host's result lands as JSON in its own file —
    structured per-host output without parsing PLAY RECAP lines.
    """
    env = os.environ.copy()
    env["ANSIBLE_CACHE_PLUGIN"] = "memory"
    env["ANSIBLE_CONFIG"] = str(REPO_ROOT / "ansible.cfg")
    with tempfile.TemporaryDirectory() as tree:
        subprocess.run(
            [
                str(ANSIBLE_BIN),
                "-i",
                str(INVENTORY),
                "-u",
                SSH_USER,
                "-b",
                "--limit",
                ",".join(names),
                "--tree",
                tree,
                "all",
                "-m",
                module,
                "-a",
                " ".join(module_args),
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        results: dict[str, str] = {}
        for path in Path(tree).iterdir():
            data = json.loads(path.read_text())
            if data.get("failed") or data.get("unreachable"):
                die(
                    f"{path.stem}: module {module} failed: "
                    f"{data.get('msg') or data.get('stderr')}"
                )
            results[path.stem] = data.get("stdout", "")
        return results


# ---------------------------------------------------------------------------
# Scenarios — pristine VMs ship the roots (images predate the advisory), so
# these assert the REAL package-shipped case. Assertions reuse run.sh's
# fingerprint logic but run over SSH instead of docker exec.
# ---------------------------------------------------------------------------
def load_bad_roots() -> list[str]:
    import yaml

    with open(ROLE_VARS) as f:
        data = yaml.safe_load(f)
    fps = [r["sha256"] for r in data["emudhra_ca_bad_roots"]]
    if not fps:
        die("load_bad_roots: no roots found")
    log(f"loaded {len(fps)} distrusted roots")
    return fps


def assert_all_roots_absent(
    host: str, bad_fps: list[str], scans: dict[str, str]
) -> None:
    """Assert no distrusted root remains in the host's active bundle.

    `scans` is the per-host fingerprint output from run_module (all hosts
    scanned in ONE ad-hoc run — one connection pass, not one per host).
    """
    found = scans.get(host, "")
    if not found.strip():
        die(
            f"assert_all_roots_absent: scan produced no fingerprints on "
            f"{host} (fixture broken)"
        )
    for fp in bad_fps:
        if fp.lower() in found.lower():
            die(f"{host}: distrusted root {fp} still in bundle")


def scenario_detect(names: list[str], bad_fps: list[str]) -> None:
    out = run_playbook(names, str(E2E_DIR / "probe-vars.yml"))
    save_output("detect", out)
    if "affected=True" not in out:
        die(
            "detect: no host reported affected "
            "(expected: pristine VMs ship the root)"
        )
    log("detect: PASS")


def scenario_remediate(names: list[str], bad_fps: list[str]) -> None:
    # State-tolerant: on a pristine fleet the probe run remediates
    # (changed>0); on an already-remediated fleet it is a no-op. Either way
    # the end state must be: all roots absent, re-run reports zero changes.
    out = run_playbook(names, str(E2E_DIR / "probe-vars.yml"))
    save_output("remediate-1", out)
    scans = run_module(names, "shell", FP_SCAN)
    save_output("remediate-scan", json.dumps(scans, indent=2, sort_keys=True))
    for host in names:
        assert_all_roots_absent(host, bad_fps, scans)
    log(f"remediate: all {len(names)} VMs clean " f"(all {len(bad_fps)} roots absent)")

    out = run_playbook(names, str(E2E_DIR / "probe-vars.yml"))
    save_output("remediate-2-idempotency", out)
    if re.search(r"changed=[1-9]", out):
        die("remediate: second run reported changes (not idempotent)")
    log("remediate: second run idempotent")
    log("remediate: PASS")


def scenario_wrapper(names: list[str], bad_fps: list[str]) -> None:
    out = run_playbook(
        names,
        str(REPO_ROOT / "playbooks" / "emudhra-ca" / "distrust-emudhra-roots.yml"),
        "-e",
        "target_hosts=all",
        "-e",
        "emudhra_ca_run_connectivity_check=false",
    )
    save_output("wrapper", out)
    scans = run_module(names, "shell", FP_SCAN)
    save_output("wrapper-scan", json.dumps(scans, indent=2, sort_keys=True))
    for host in names:
        assert_all_roots_absent(host, bad_fps, scans)
    if "s_client" in out:
        die(
            "wrapper: connectivity check ran despite "
            "emudhra_ca_run_connectivity_check=false"
        )
    log("wrapper: PASS")


def cmd_run(scenario: str = "all") -> None:
    # Standalone `run` (separate invocation from `up`): discover the fleet
    # from the inventory so --limit and per-host assertions have names.
    names = inventory_hosts()
    if not names:
        die("run: no harness VMs found — run 'vms.py up' first")
    log(f"run: discovered {len(names)} VM(s) from inventory")
    bad_fps = load_bad_roots()
    scenarios = {
        "detect": scenario_detect,
        "remediate": scenario_remediate,
        "wrapper": scenario_wrapper,
    }
    if scenario == "all":
        for name, fn in scenarios.items():
            log(f"run: scenario {name}")
            fn(names, bad_fps)
        log("all: PASS")
    elif scenario in scenarios:
        scenarios[scenario](names, bad_fps)
    else:
        die(f"unknown scenario: {scenario}")


# ---------------------------------------------------------------------------
# Teardown — delete ONLY VMs created by this harness (exact name prefix).
# ---------------------------------------------------------------------------
def cmd_down() -> None:
    names = [vm["name"] for vm in vms_list() if vm["name"].startswith(PREFIX)]
    if not names:
        log("down: nothing to delete")
        return
    log(f"down: deleting {len(names)} VM(s)")
    # delete accepts up to 25 names per call.
    for i in range(0, len(names), 25):
        run_cmd(["crusoe", "compute", "vms", "delete", "-y", *names[i : i + 25]])
    log("down: done")


def cmd_status() -> None:
    rows = [
        (vm["name"], vm.get("state", "?"), vm.get("type", "?"))
        for vm in vms_list()
        if vm["name"].startswith(PREFIX)
    ]
    for name, state, typ in sorted(rows):
        print(f"{name:55s} {state:20s} {typ}")
    print(f"{len(rows)} VM(s)")


def cmd_matrix(images_filter: list[str] | None = None) -> None:
    rows = matrix(images_filter)
    print(f"{'image':38s} {'vm type':8s} {'vm name'}")
    print("-" * 100)
    for row in rows:
        print(f"{row['image']:38s} {row['type']:8s} {PREFIX}{row['slug']}")
    print(f"\n{len(rows)} image(s) in the matrix")


def cmd_test() -> None:
    keep = os.environ.get("EMUDHRA_E2E_VM_KEEP", "0") == "1"
    try:
        cmd_up()
        cmd_run("all")
        log("test: PASS")
    finally:
        if keep:
            log("cleanup: EMUDHRA_E2E_VM_KEEP=1 — leaving VMs running")
        else:
            cmd_down()


# ---------------------------------------------------------------------------
# Forensics — empirical evidence for WHY a host reports affected or not.
# One ad-hoc module run per fleet, output saved per host. Answers:
#   - which ca-certificates version is installed, and when was it installed
#   - did unattended-upgrades touch it since boot (auto-upgrade theory)
#   - are the distrusted roots present but INACTIVE (package dir, not bundle)
#   - are packages held/pinned (GPU-image theory)
# ---------------------------------------------------------------------------
FORENSICS_SCRIPT = r"""
echo "=== os ==="
. /etc/os-release && echo "$PRETTY_NAME"
echo "=== ca-certificates version ==="
dpkg-query -W -f='${Version}\n' ca-certificates 2>/dev/null || rpm -q --qf '%{VERSION}\n' ca-certificates 2>/dev/null
echo "=== ca-certificates install/upgrade history (dpkg.log, any mention) ==="
grep -h "ca-certificates" /var/log/dpkg.log* 2>/dev/null | tail -8 || echo "(no dpkg.log mentions)"
echo "=== apt history.log ca-certificates entries ==="
zgrep -h -A2 "ca-certificates" /var/log/apt/history.log* 2>/dev/null | tail -12 || echo "(no apt history mentions)"
echo "=== package file timestamps (image-baked vs upgraded) ==="
ls -la /var/lib/dpkg/info/ca-certificates.* 2>/dev/null | head -4
stat -c '%y %n' /etc/ssl/certs/ca-certificates.crt 2>/dev/null
echo "=== unattended-upgrades activity since boot ==="
ls -la /var/log/unattended-upgrades/ 2>/dev/null || echo "no unattended-upgrades log dir"
grep -l "ca-certificates" /var/log/unattended-upgrades/*.log 2>/dev/null || echo "no ua log mentions ca-certificates"
uptime -s 2>/dev/null || uptime
echo "=== held/pinned packages ==="
apt-mark showhold 2>/dev/null || echo "(apt-mark unavailable)"
echo "=== distrusted roots in ACTIVE bundle ==="
for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do
  [ -f "$bundle" ] || continue
  d="$(mktemp -d)"; i=0; f=""
  awk -v d="$d" '/BEGIN CERTIFICATE/{f=sprintf("%s/c.%d.pem",d,++i)} f{print > f} /END CERTIFICATE/{close(f); f=""}' "$bundle"
  for pem in "$d"/*.pem; do
    openssl x509 -in "$pem" -noout -fingerprint -sha256 2>/dev/null | tr -d ":" | awk -F= '{print toupper($2)}'
  done | grep -E "86A1ECBA|D7A7A0FB|7DD78D5F|F2EDAAFF" && echo "  ^ IN $bundle" || true
  rm -rf "$d"
done
echo "=== distrusted roots in PACKAGE CA dir (inactive) ==="
for fp in 86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4; do
  for pem in /usr/share/ca-certificates/mozilla/*.crt /usr/share/pki/ca-trust-source/*.crt; do
    [ -f "$pem" ] || continue
    actual="$(openssl x509 -in "$pem" -noout -fingerprint -sha256 2>/dev/null | tr -d ":" | awk -F= '{print toupper($2)}')"
    [ "$actual" = "$fp" ] && echo "  $pem"
  done
done
echo "=== done ==="
"""


def cmd_forensics() -> None:
    names = inventory_hosts()
    if not names:
        die("forensics: no harness VMs found — run 'vms.py up' first")
    log(f"forensics: gathering evidence on {len(names)} VM(s)")
    scans = run_module(names, "shell", FORENSICS_SCRIPT)
    save_output(
        "forensics",
        json.dumps(scans, indent=2, sort_keys=True),
    )
    # Also print a compact per-host summary to the console.
    for host in sorted(scans):
        lines = scans[host].splitlines()
        version = next((ln for ln in lines if ln and not ln.startswith("=")), "?")
        log(f"forensics: {host}: {version}")
    log(f"forensics: full evidence in {REPORT_DIR}")


def main() -> None:
    if len(sys.argv) < 2:
        die("usage: vms.py <matrix|up|down|status|run|test|forensics> [args]")
    cmd = sys.argv[1]
    rest = sys.argv[2:]
    # --images a,b,c filters every command's matrix (up/test/matrix).
    images_filter: list[str] | None = None
    if "--images" in rest:
        i = rest.index("--images")
        images_filter = [x.strip() for x in rest[i + 1].split(",") if x.strip()]
        rest = rest[:i] + rest[i + 2 :]
    if cmd == "matrix":
        cmd_matrix(images_filter)
    elif cmd == "up":
        cmd_up(images_filter)
    elif cmd == "down":
        cmd_down()
    elif cmd == "status":
        cmd_status()
    elif cmd == "run":
        cmd_run(rest[0] if rest else "all")
    elif cmd == "test":
        cmd_test()
    elif cmd == "forensics":
        cmd_forensics()
    else:
        die(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
