#!/usr/bin/env python3
"""Trust-store e2e for the Ansible image.

Runs the built image (ghcr.io/crusoecloud/crusoe-cs/ansible) and
asserts the eMudhra compromise advisory's requirements hold INSIDE it:

  1. No distrusted root (pinned SHA-256 fingerprints from
     roles/emudhra_ca/vars/main.yml — the single source of truth) in the
     system CA bundle or in any python certifi bundle.
  2. System-trust HTTPS works: a well-known host verifies.
  3. Python-trust HTTPS works: urllib against the same host verifies
     (exercises the ssl module's default context, not just curl).
  4. The advisory's canary sites (chained to the distrusted roots) FAIL
     verification for both curl and python — an image that still trusts
     the compromised intermediates must not pass.

The image itself runs the same fingerprint scan at build time (see
images/ansible/Dockerfile); this e2e re-proves it against the pushed
artifact and adds the functional HTTPS assertions the build gate can't do
offline.

Usage:
    tests/e2e/ansible-image/test_trust.py [--image IMAGE]

Environment:
    CONTROLLER_IMAGE  image to test (default ghcr.io/crusoecloud/crusoe-cs/ansible:latest)
    SKIP_LIVE_TLS=1   skip the live canary checks (no-egress environments)

Exit code 0 = all assertions pass; nonzero = failure (details on stderr).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
ROLE_VARS = REPO_ROOT / "crusoe-cs-ansible" / "roles" / "emudhra_ca" / "vars" / "main.yml"
DEFAULT_IMAGE = "ghcr.io/crusoecloud/crusoe-cs/ansible:latest"

# Advisory canary sites (roles/emudhra_ca/vars/main.yml emudhra_ca_test_sites).
# Trailing dot stripped: many servers reject an SNI value ending in '.'.
CANARY_SITES = [
    "dv-g3b-emudhra.we-have-a-problem.com",
    "dv-g3b-aaa-emudhra.we-have-a-problem.com",
]
# A host that must verify cleanly through the system store.
GOOD_SITE = "pypi.org"

failures: list[str] = []


def log(msg: str) -> None:
    print(f"[trust-e2e] {msg}")


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"[trust-e2e] FAIL: {msg}", file=sys.stderr)


def load_bad_roots() -> list[str]:
    """Pinned fingerprints from the role vars — never duplicate them here."""
    import yaml

    with open(ROLE_VARS) as f:
        data = yaml.safe_load(f)
    fps = [r["sha256"].upper() for r in data["emudhra_ca_bad_roots"]]
    if not fps:
        raise SystemExit("load_bad_roots: no roots found in vars/main.yml")
    log(f"loaded {len(fps)} distrusted roots from {ROLE_VARS.name}")
    return fps


def run_in_container(
    image: str, script: str, env: dict[str, str] | None = None, python: bool = False
) -> tuple[int, str]:
    """Run a shell (or python) script inside the image; return (exit_code, output).

    Overrides the image entrypoint (ansible-playbook) so arbitrary probe
    scripts can run. Python scripts go through the python binary.
    """
    cmd = ["docker", "run", "--rm", "--entrypoint", "python" if python else "bash"]
    for key, value in (env or {}).items():
        cmd += ["-e", f"{key}={value}"]
    cmd += [image, "-c", script]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return proc.returncode, proc.stdout + proc.stderr


# The bundle-splitting fingerprint scan, shared verbatim with the e2e
# harnesses (run.sh / vms.py) and the image build gate.
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

CERTIFI_SCAN = r"""
shopt -s nullglob
for pem in /usr/lib/python3*/site-packages/certifi/cacert.pem \
           /usr/local/lib/python3*/site-packages/certifi/cacert.pem; do
  d="$(mktemp -d)"; i=0; f=""
  awk -v d="$d" '/BEGIN CERTIFICATE/{f=sprintf("%s/c.%d.pem",d,++i)} \
f{print > f} /END CERTIFICATE/{close(f); f=""}' "$pem"
  for c in "$d"/*.pem; do
    openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null |
      tr -d ":" | awk -F= '{print toupper($2)}'
  done
  rm -rf "$d"
done | sort -u
"""


def assert_no_bad_roots(label: str, output: str, bad_fps: list[str]) -> None:
    if not output.strip():
        fail(f"{label}: scan produced no fingerprints (scan broken)")
        return
    found = {line.strip().upper() for line in output.splitlines() if line.strip()}
    hits = found.intersection(bad_fps)
    if hits:
        for fp in sorted(hits):
            fail(f"{label}: distrusted root {fp} present")
    else:
        log(f"{label}: clean ({len(found)} certs scanned, none distrusted)")


def scenario_toolchain(image: str) -> None:
    script = """
set -eu
ansible --version | head -1
ansible-galaxy collection list | grep -q kubernetes.core
echo TOOLCHAIN_OK
"""
    code, out = run_in_container(image, script)
    if "TOOLCHAIN_OK" in out:
        log("toolchain: ansible + collections present")
    else:
        fail(f"toolchain check failed (exit {code}): {out.strip()[-400:]}")


def scenario_env_passthrough(image: str) -> None:
    # ENV declared in the image must be visible to processes in the container.
    code, out = run_in_container(image, 'echo "collections=$ANSIBLE_COLLECTIONS_PATH"')
    if "/usr/share/ansible/collections" in out:
        log("ENV: ANSIBLE_COLLECTIONS_PATH set correctly")
    else:
        fail(f"ENV: ANSIBLE_COLLECTIONS_PATH not visible in container: {out.strip()}")


def scenario_system_bundle(image: str, bad_fps: list[str]) -> None:
    code, out = run_in_container(image, FP_SCAN)
    if code != 0:
        fail(f"system bundle scan exited {code}")
        return
    assert_no_bad_roots("system bundle", out, bad_fps)


def scenario_certifi(image: str, bad_fps: list[str]) -> None:
    code, out = run_in_container(image, CERTIFI_SCAN)
    if code != 0:
        fail(f"certifi scan exited {code}")
        return
    if not out.strip():
        log("certifi: no certifi bundle present (nothing to scan)")
        return
    assert_no_bad_roots("certifi", out, bad_fps)


def scenario_https_system(image: str) -> None:
    # curl uses the system store; a TLS verification failure exits 60
    # (CURLE_PEER_FAILED_VERIFICATION). Distinguish it from network errors
    # so a blip doesn't read as a trust failure.
    script = f"""
curl -fsS -o /dev/null --max-time 30 https://{GOOD_SITE}/simple/ 2>/tmp/err
rc=$?
if [ "$rc" -eq 0 ]; then
  echo PASS
elif [ "$rc" -eq 60 ]; then
  echo TLS_FAIL
else
  echo NET_FAIL rc=$rc
  cat /tmp/err >&2
fi
"""
    code, out = run_in_container(image, script)
    result = out.strip().splitlines()[-1] if out.strip() else f"exit {code}"
    if "PASS" in result:
        log(f"system HTTPS: {GOOD_SITE} verifies (curl)")
    elif "TLS_FAIL" in result:
        fail(f"system HTTPS: {GOOD_SITE} failed TLS verification")
    else:
        fail(f"system HTTPS: network error reaching {GOOD_SITE} (no egress?)")


def scenario_https_python(image: str) -> None:
    # urllib with the default context = python's trust path (stdlib uses the
    # system store; pip-installed certifi consumers use certifi's bundle).
    script = (
        "import urllib.request, ssl\n"
        "try:\n"
        f"    urllib.request.urlopen('https://{GOOD_SITE}/simple/', timeout=30)\n"
        "    print('PASS')\n"
        "except ssl.SSLError as e:\n"
        "    print('TLS_FAIL', e)\n"
        "except Exception as e:\n"
        "    print('NET_FAIL', type(e).__name__, e)\n"
    )
    code, out = run_in_container(image, script, python=True)
    result = out.strip().splitlines()[-1] if out.strip() else f"exit {code}"
    if result.startswith("PASS"):
        log(f"python HTTPS: {GOOD_SITE} verifies (urllib)")
    elif result.startswith("TLS_FAIL"):
        fail(f"python HTTPS: {GOOD_SITE} failed TLS verification: {result}")
    else:
        fail(f"python HTTPS: network error reaching {GOOD_SITE} (no egress?)")


def scenario_canary_rejected(image: str) -> None:
    # Both trust paths must REJECT the canary sites. A successful HTTPS
    # handshake to a site chained to a distrusted root = the image still
    # trusts the compromised intermediates = hard fail.
    for site in CANARY_SITES:
        # curl: TLS verification failure exits 60.
        script = f"""
curl -fsS -o /dev/null --max-time 30 https://{site}/ 2>/tmp/err
rc=$?
if [ "$rc" -eq 0 ]; then
  echo VERIFIED
elif [ "$rc" -eq 60 ]; then
  echo REJECTED
else
  echo NET_FAIL rc=$rc
  cat /tmp/err >&2
fi
"""
        code, out = run_in_container(image, script)
        result = out.strip().splitlines()[-1] if out.strip() else f"exit {code}"
        if "REJECTED" in result:
            log(f"canary {site}: rejected by system store (curl)")
        elif "VERIFIED" in result:
            fail(f"canary {site}: VERIFIED — distrusted root still trusted")
        else:
            fail(f"canary {site}: network error (no egress? cannot assert)")

        # python: CERTIFICATE_VERIFY_FAILED expected; any successful
        # response is a failure. URLError wraps the SSLError.
        script_py = (
            "import urllib.request, ssl\n"
            "try:\n"
            f"    urllib.request.urlopen('https://{site}/', timeout=30)\n"
            "    print('VERIFIED')\n"
            "except Exception as e:\n"
            "    reason = str(e)\n"
            "    if 'CERTIFICATE_VERIFY_FAILED' in reason:\n"
            "        print('REJECTED')\n"
            "    else:\n"
            "        print('NET_FAIL', type(e).__name__, reason[:120])\n"
        )
        code, out = run_in_container(image, script_py, python=True)
        result = out.strip().splitlines()[-1] if out.strip() else f"exit {code}"
        if result.startswith("REJECTED"):
            log(f"canary {site}: rejected by python (urllib)")
        elif result.startswith("VERIFIED"):
            fail(f"canary {site}: VERIFIED via python — distrusted root still trusted")
        else:
            fail(f"canary {site}: network error via python (no egress? cannot assert)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=None, help="image ref to test")
    args = parser.parse_args()
    image = args.image or os.environ.get("CONTROLLER_IMAGE", DEFAULT_IMAGE)

    bad_fps = load_bad_roots()
    log(f"testing image: {image}")

    scenario_toolchain(image)
    scenario_env_passthrough(image)
    scenario_system_bundle(image, bad_fps)
    scenario_certifi(image, bad_fps)

    if os.environ.get("SKIP_LIVE_TLS") == "1":
        log("SKIP_LIVE_TLS=1 — skipping live HTTPS scenarios")
    else:
        scenario_https_system(image)
        scenario_https_python(image)
        scenario_canary_rejected(image)

    if failures:
        print(f"[trust-e2e] {len(failures)} failure(s)", file=sys.stderr)
        return 1
    log("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
