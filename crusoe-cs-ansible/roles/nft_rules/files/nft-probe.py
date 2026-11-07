"""Live probe engine for stateful nftables mitigations
(roles/nft_rules/files/nft-probe.py).

The cve-2026-98432 probe generalized: the IDENTITY (which nft table
to read) is a --table argument; the ASSERTION LOGIC and the rc
contract are the engine's.

The options-SYN trigger is a RAW socket with IP_HDRINCL: the IPv4
header (IHL 6, four NOP options) and the TCP SYN are built in
userspace — the sending socket never calls setsockopt(IP_OPTIONS),
so the kernel never allocates/frees inet_opt on the client path.
On unpatched kernels (the upstream fix e3f33b0a1d89 defers that free
to an RCU grace period) a normal socket's options handling is not
an exploit — one probe SYN an hour is no attack — but its safety
on the target kernel is UNATTESTABLE: the probe's own socket
walked the exact free the fix patches. The raw trigger converts
that unanswerable question into a non-question: no inet_opt exists
on the path, so the client side is safe by construction. The
plain-SYN control stays a normal connect (no options at all —
nothing to allocate).

Verdicts per mode (loopback traffic traverses the input hook):
  enforce: the options SYN must get NO SYN-ACK (dropped at priority
           raw, before the listener); a plain SYN must still CONNECT.
  observe: the options SYN must be ACKed (the rule logs, not drops)
           AND the rule's match counter must increment (the rule is
           present AND counting — the evidence pipeline end-to-end);
           a plain SYN must connect.

Exit codes (both modes — the contract the wrapper, the reconciler's
--verify, and the e2e suite key off):
  0  the mitigation is NOT working (enforce: options SYN connected;
     observe: not counting, or dropping when it must not)
  1  PASS
  2  the plain SYN timed out -> collateral damage (FAIL)
  3  the probe could not run (crash — must NOT read as PASS)
"""

import argparse
import re
import socket
import struct
import subprocess
import sys
import time

TIMEOUT_SECONDS = 2

# The VERDICT rule's match counter: the first `counter packets N`
# in the chain listing whose line carries a VERDICT (drop / log
# prefix) — present in both verdicts (observe: `counter ... log
# ... counter`, enforce: `counter ... drop`). The probe/local split
# renders a count-only loopback rule FIRST whose counter must NOT
# be read here (the observe-mode before/after delta would ride the
# loopback counter and the probe would pass vacuously against a
# missing verdict rule).
_COUNTER_RE = re.compile(r"counter packets (\d+) bytes \d+[^\n]*(?:drop|log prefix)")

# Four NOP options (type 1, no length byte) — IHL 6.
NOP_OPTIONS = b"\x01\x01\x01\x01"


def parse_counter(nft_output):
    """Extract the rule's matched-packet count from a chain listing."""
    match = _COUNTER_RE.search(nft_output)
    return int(match.group(1)) if match else None


def read_counter(table):
    """Read the rule's current match counter (None if not loaded)."""
    result = subprocess.run(
        ["nft", "list", "chain", "ip", table, "input"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return parse_counter(result.stdout)


def _checksum(data):
    """The Internet checksum: 16-bit ones' complement of the ones'
    complement sum. Zero is encoded as 0xFFFF (a bare 0 means 'no
    checksum')."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_options_syn(src_ip, src_port, dst_ip, dst_port):
    """The options-bearing SYN, built in userspace: IPv4 header with
    four NOP options (IHL 6) + a bare TCP SYN. The kernel sends this
    verbatim (IP_HDRINCL) — no socket inet_opt is ever allocated."""
    # TCP header: SYN, no options, data offset 5.
    tcp = struct.pack(
        "!HHIIHHHH",
        src_port,  # source port
        dst_port,  # destination port
        0,  # sequence number
        0,  # ack number
        (5 << 12) | 0x02,  # data offset 5, SYN
        8192,  # window
        0,  # checksum (filled below)
        0,  # urgent pointer
    )
    # Pseudo-header for the TCP checksum.
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
    )
    tcp_checksum = _checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", tcp_checksum) + tcp[18:]

    total_len = 24 + len(tcp)  # 24 = IPv4 header with 4 bytes of options
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x46,  # version 4, IHL 6 (24 bytes)
        0,  # TOS
        total_len,
        0,  # ID
        0x4000,  # DF
        64,  # TTL
        socket.IPPROTO_TCP,
        0,  # checksum (filled below)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip += NOP_OPTIONS
    ip_checksum = _checksum(ip)
    ip = ip[:10] + struct.pack("!H", ip_checksum) + ip[12:]
    return ip + tcp


def send_options_syn(dst_ip, dst_port):
    """Send the raw options SYN; True when a SYN-ACK comes back (the
    packet survived the input hook), False on timeout (dropped).

    The raw socket carries IP_HDRINCL — the packet bytes are ours;
    the kernel adds nothing (no inet_opt on this path). A SYN-ACK
    from the kernel proves the SYN traversed the input hook and was
    accepted; silence within the timeout means a drop.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as raw:
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.settimeout(TIMEOUT_SECONDS)
        # The source: a normal UDP bind gives us a kernel-chosen local
        # port on loopback without touching TCP state.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as picker:
            picker.bind(("127.0.0.1", 0))
            src_port = picker.getsockname()[1]
        pkt = build_options_syn("127.0.0.1", src_port, dst_ip, dst_port)
        raw.sendto(pkt, (dst_ip, dst_port))
        # The SYN-ACK comes back to our chosen source port; the kernel
        # would RST it (no listener) — either way, ANY packet from the
        # destination port within the timeout proves the SYN was
        # accepted (observe); silence proves a drop (enforce).
        # WALL-CLOCK deadline, not the socket timeout: a raw IPPROTO_TCP
        # socket receives EVERY TCP packet on the host, each recvfrom
        # returns instantly with non-matching traffic, the socket
        # never blocks, and settimeout NEVER FIRES (it is a per-recv
        # blocking timeout, not a deadline) — the loop would spin
        # forever exactly in the enforce-PASS case (the rule dropped
        # our SYN; no reply ever comes). The deadline bounds the loop
        # regardless of the traffic rate.
        deadline = time.monotonic() + TIMEOUT_SECONDS
        try:
            while time.monotonic() < deadline:
                # Clamp each blocking wait to the time LEFT: a fixed
                # settimeout(2) lets a packet arriving at t≈1.9s block
                # recvfrom for another full 2s — a ~2× overshoot on
                # the enforce-PASS path (the common case), and
                # --verify pays it per netns (~200s → ~400s on a
                # 100-netns node).
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                raw.settimeout(remaining)
                data, _ = raw.recvfrom(4096)
                ihl = (data[0] & 0x0F) * 4
                tcp = data[ihl:]
                sport, dport = struct.unpack("!HH", tcp[:4])
                if sport == dst_port and dport == src_port:
                    return True  # a reply from the listener: SYN-ACK'd
        except socket.timeout:
            pass
        return False


def plain_connect(port):
    """The plain-SYN control: a NORMAL TCP connect with no options —
    it must succeed in both modes (collateral damage otherwise).
    A normal socket with no IP_OPTIONS allocates no inet_opt."""
    with socket.create_server(("127.0.0.1", port)) as srv:
        with socket.socket() as client:
            client.settimeout(TIMEOUT_SECONDS)
            try:
                client.connect(srv.getsockname())
                return True
            except OSError:
                # socket.timeout IS an OSError (subclass) — one catch
                # covers both; the paren-less tuple form is PEP 758
                # (3.14+ only) and a SyntaxError on 3.10 (Ubuntu 22.04).
                return False


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(mode, table="cve_2026_98432"):
    """Execute the probe for `mode`; return the exit code.

    baseline: the PRE-rule trigger proof — the raw options SYN must
    be ACKed with NO rule loaded. Guards the raw-packet false
    positive: a malformed packet is silently discarded by the
    kernel, which enforce mode would misread as 'dropped'. Only a
    baseline PASS makes a post-rule drop the rule's doing.
    """
    port = _free_port()
    if mode == "baseline":
        if not send_options_syn("127.0.0.1", port):
            print("options-probe: TIMEOUT before the rule — vacuous baseline")
            return 0
        if not plain_connect(port):
            print("plain-probe: TIMEOUT — collateral damage")
            return 2
        print("options-probe: connected; plain-probe: connected (baseline)")
        return 1

    if mode == "enforce":
        if send_options_syn("127.0.0.1", port):
            print("options-probe: CONNECTED — mitigation NOT dropping")
            return 0
        if not plain_connect(port):
            print("plain-probe: TIMEOUT — collateral damage")
            return 2
        print("options-probe: dropped; plain-probe: connected")
        return 1

    # observe
    # NOTE: the before/after counter read has a TOCTOU race — any
    # other option-bearing packet hitting the host between the two
    # reads also increments the counter. This is a sanity check, not
    # a security gate: on a freshly-loaded rule the matched rate is ~0,
    # making a false pass vanishingly unlikely.
    before = read_counter(table)
    options_acked = send_options_syn("127.0.0.1", port)
    after = read_counter(table)
    if not options_acked:
        print("options-probe: TIMEOUT — rule is DROPPING in observe mode")
        return 0
    if before is None or after is None or after - before < 1:
        print(
            f"counter-probe: matched counter did not increment "
            f"(before={before} after={after}) — rule not counting"
        )
        return 0
    if not plain_connect(port):
        print("plain-probe: TIMEOUT — collateral damage")
        return 2
    print(
        "options-probe: connected; counter-probe: incremented "
        f"({before} -> {after}); plain-probe: connected"
    )
    return 1


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=["enforce", "observe", "baseline"],
        default="enforce",
        help="mitigation mode to assert (default: enforce; baseline = "
        "the pre-rule trigger proof)",
    )
    parser.add_argument(
        "--table",
        default="cve_2026_98432",
        help="the nft table to read the match counter from",
    )
    return parser.parse_args(argv)


def main(argv=None):
    try:
        args = parse_args(argv)
        sys.exit(run(args.mode, args.table))
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — the exit code IS the contract
        # A crash must NOT read as PASS: Python's default exception exit
        # is 1, the PASS code. Exit 3 = "probe could not run".
        print(f"probe CRASHED: {exc!r}")
        sys.exit(3)


if __name__ == "__main__":
    main()
