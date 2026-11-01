"""Live probe for the CVE-2026-98432 nftables mitigation.

Opens TCP connections over loopback (loopback traffic traverses the
input hook) and asserts the rule's behavior per mode:

  enforce: a SYN carrying four NOP IP options (IHL 6) must be DROPPED,
           a plain SYN must still CONNECT.
  observe: the options SYN must still CONNECT (the rule must not
           drop), and the rule's matched counter must increment by it
           — proving the rule is present AND counting, i.e. the
           evidence pipeline works end-to-end. A plain SYN must
           connect.

Exit codes (both modes):
  0  the mitigation is NOT working (enforce: options SYN connected;
     observe: not counting, or dropping when it must not)
  1  PASS
  2  the plain SYN timed out -> collateral damage (FAIL)
"""

import argparse
import re
import socket
import subprocess
import sys

NOP_OPTIONS = b"\x01\x01\x01\x01"
TIMEOUT_SECONDS = 2

# The first counter in the chain listing is the rule's match counter —
# present in both verdicts (observe: `counter ... log ... counter`,
# enforce: `counter ... drop`).
_COUNTER_RE = re.compile(r"counter packets (\d+) bytes \d+")


def parse_counter(nft_output):
    """Extract the rule's matched-packet count from a chain listing."""
    match = _COUNTER_RE.search(nft_output)
    return int(match.group(1)) if match else None


def read_counter():
    """Read the rule's current match counter (None if not loaded)."""
    result = subprocess.run(
        ["nft", "list", "chain", "ip", "cve_2026_98432", "input"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return parse_counter(result.stdout)


def connect(options):
    with socket.create_server(("127.0.0.1", 0)) as srv:
        with socket.socket() as client:
            if options:
                client.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, options)
            client.settimeout(TIMEOUT_SECONDS)
            try:
                client.connect(srv.getsockname())
                return True
            except socket.timeout:
                return False


def run(mode):
    """Execute the probe for `mode`; return the exit code."""
    if mode == "enforce":
        if connect(NOP_OPTIONS):
            print("options-probe: CONNECTED — mitigation NOT dropping")
            return 0
        if not connect(None):
            print("plain-probe: TIMEOUT — collateral damage")
            return 2
        print("options-probe: dropped; plain-probe: connected")
        return 1

    # observe
    # NOTE: the before/after counter read has a TOCTOU race — any other
    # option-bearing packet hitting the host between the two reads also
    # increments the counter, so a pass could in principle ride on
    # another packet's increment. This is a sanity check, not a
    # security gate: on a freshly-loaded rule the matched rate is ~0
    # (the Gate-1 evidence), making a false pass vanishingly unlikely.
    before = read_counter()
    options_connected = connect(NOP_OPTIONS)
    after = read_counter()
    if not options_connected:
        print("options-probe: TIMEOUT — rule is DROPPING in observe mode")
        return 0
    if before is None or after is None or after - before < 1:
        print(
            f"counter-probe: matched counter did not increment "
            f"(before={before} after={after}) — rule not counting"
        )
        return 0
    if not connect(None):
        print("plain-probe: TIMEOUT — collateral damage")
        return 2
    print(
        "options-probe: connected; counter-probe: incremented "
        f"({before} -> {after}); plain-probe: connected"
    )
    return 1


def main():
    try:
        _main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — the exit code IS the contract
        # A crash (e.g. OSError: Network is unreachable in a lo-down
        # netns) must NOT read as PASS: Python's default exception exit
        # is 1, the PASS code. Exit 3 = "probe could not run".
        print(f"probe CRASHED: {exc!r}")
        sys.exit(3)


def _main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=["enforce", "observe"],
        default="enforce",
        help="mitigation mode to assert (default: enforce)",
    )
    args = parser.parse_args()
    sys.exit(run(args.mode))


if __name__ == "__main__":
    main()
