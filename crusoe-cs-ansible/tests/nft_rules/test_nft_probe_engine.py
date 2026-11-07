"""Unit tests for the nft-probe engine
(roles/nft_rules/files/nft-probe.py).

The engine is the cve-2026-98432 probe with two changes:
1. The IDENTITY is parameterized (--table; the series the counter is
   read from).
2. The options-SYN trigger is a RAW socket with IP_HDRINCL — the
   IPv4 options live in the packet bytes built in userspace; the
   sending socket never calls setsockopt(IP_OPTIONS), so the kernel
   never allocates/frees inet_opt on the client path (on unpatched
   5.15 kernels that free is a plain kfree, the exact free the
   upstream fix defers to RCU).

Exit-code contract (UNCHANGED — the wrapper, the reconciler's
--verify, and the e2e suite all key off it):
  0  the mitigation is NOT working
  1  PASS
  2  plain-SYN collateral damage
  3  probe could not run (crash)
"""

import importlib.util
import socket
import struct
from unittest.mock import patch

import pytest

from conftest import COMPONENT_ROOT

PROBE = COMPONENT_ROOT / "roles" / "nft_rules" / "files" / "nft-probe.py"


@pytest.fixture()
def probe():
    spec = importlib.util.spec_from_file_location("nft_probe", PROBE)
    assert spec and spec.loader, f"probe engine not found at {PROBE}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CHAIN_OBSERVE = (
    "table ip cve_2026_98432 {\n\tchain input {\n\t\t"
    "ip protocol 6 ip hdrlength != 5 counter packets 7 bytes 336 "
    "limit rate 6/minute burst 12 packets log prefix "
    '"cve-2026-98432-observe " counter packets 7 bytes 336\n\t}\n}'
)


class TestRawPacketConstruction:
    """The options SYN is built in userspace — the kernel must not be
    asked to allocate inet_opt (no setsockopt(IP_OPTIONS) anywhere)."""

    def test_builds_ipv4_header_with_options(self, probe):
        pkt = probe.build_options_syn("127.0.0.1", 12345, "127.0.0.1", 54321)
        # 20-byte fixed header + 4 bytes of NOP options = IHL 6
        ihl = (pkt[0] & 0x0F) * 4
        assert ihl == 24, "IHL 6 (24 bytes) — the options-bearing shape"
        assert pkt[0] >> 4 == 4, "IPv4"
        assert pkt[1] == 0, "TOS 0"
        assert struct.unpack("!H", pkt[2:4])[0] == len(pkt), "total length"
        assert pkt[9] == socket.IPPROTO_TCP, "protocol TCP"
        # The options: four NOPs (type 1, no length)
        assert pkt[20:24] == b"\x01\x01\x01\x01"

    def test_tcp_header_is_a_syn(self, probe):
        pkt = probe.build_options_syn("127.0.0.1", 12345, "127.0.0.1", 54321)
        ihl = (pkt[0] & 0x0F) * 4
        tcp = pkt[ihl:]
        flags = tcp[13]
        assert flags & 0x02, "SYN set"
        assert not flags & 0x10, "ACK clear (a bare SYN)"

    def test_checksums_are_consistent(self, probe):
        pkt = probe.build_options_syn("127.0.0.1", 12345, "127.0.0.1", 54321)
        # The IPv4 header checksum must verify: the ones' complement
        # sum over the header's 16-bit words (checksum included) folds
        # to 0xFFFF (zero in ones' complement).
        ihl = (pkt[0] & 0x0F) * 4
        header = pkt[:ihl]
        words = struct.unpack(f"!{ihl // 2}H", header)
        total = sum(words)
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        assert total == 0xFFFF, "IPv4 header checksum verifies"

    def test_no_setsockopt_ip_options_anywhere(self, probe):
        # THE concern-2 contract: the engine must never call
        # setsockopt(IP_OPTIONS) — that would allocate inet_opt on
        # the client socket, whose safety on unpatched kernels is
        # unattestable (the probe's own socket would walk the exact
        # free the upstream fix patches). Mentions in prose are fine;
        # the CALL is the contract. (The plain-SYN control uses a
        # normal connect with no options at all.)
        import ast
        import inspect

        tree = ast.parse(inspect.getsource(probe))
        calls = []
        for node in ast.walk(tree):
            # Only real setsockopt CALLS — docstrings and comments are
            # prose, not code.
            if isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "attr", getattr(func, "id", ""))
                if name == "setsockopt":
                    calls.append(" ".join(ast.dump(a) for a in node.args))
        assert calls, "the raw socket must set IP_HDRINCL"
        assert all("IP_HDRINCL" in args for args in calls), (
            "the engine's only setsockopt must be IP_HDRINCL — "
            "setsockopt(IP_OPTIONS) would allocate inet_opt on the "
            "client socket, whose safety on unpatched kernels is "
            "unattestable; the raw trigger builds options into the "
            "packet bytes instead"
        )


class TestParameterization:
    def test_table_argument(self, probe):
        parser_args = probe.parse_args(["--mode", "enforce", "--table", "other_table"])
        assert parser_args.table == "other_table"

    def test_table_defaults_to_cve_2026_98432(self, probe):
        parser_args = probe.parse_args(["--mode", "enforce"])
        assert parser_args.table == "cve_2026_98432"


class TestVerdicts:
    """The mode-aware verdicts — same contract as the cve-2026-98432
    probe, keyed off the raw SYN's fate and the counter delta."""

    def _run(self, probe, mode, raw_syn_acked, plain_ok=True, before=3, after=4):
        counters = iter([before, after])
        with (
            patch.object(
                probe.subprocess,
                "run",
                return_value=type(
                    "R",
                    (),
                    {"returncode": 0, "stdout": CHAIN_OBSERVE, "stderr": ""},
                )(),
            ),
            patch.object(probe, "send_options_syn", return_value=raw_syn_acked),
            patch.object(probe, "plain_connect", return_value=plain_ok),
            patch.object(
                probe, "read_counter", side_effect=lambda table: next(counters)
            ),
        ):
            return probe.run(mode)

    def test_enforce_pass_raw_syn_dropped(self, probe):
        assert self._run(probe, "enforce", raw_syn_acked=False) == 1

    def test_enforce_fail_raw_syn_acked(self, probe):
        assert self._run(probe, "enforce", raw_syn_acked=True) == 0

    def test_enforce_fail_plain_collateral(self, probe):
        assert self._run(probe, "enforce", raw_syn_acked=False, plain_ok=False) == 2

    def test_observe_pass_acked_and_counting(self, probe):
        assert self._run(probe, "observe", raw_syn_acked=True) == 1

    def test_observe_fail_not_counting(self, probe):
        assert self._run(probe, "observe", raw_syn_acked=True, before=5, after=5) == 0

    def test_observe_fail_dropped(self, probe):
        # The raw SYN got no SYN-ACK in observe mode → the rule is
        # dropping when it must only count.
        assert self._run(probe, "observe", raw_syn_acked=False, before=0, after=0) == 0

    def test_observe_fail_plain_collateral(self, probe):
        assert self._run(probe, "observe", raw_syn_acked=True, plain_ok=False) == 2


class TestBaselineMode:
    """--mode baseline: the PRE-rule trigger proof. The raw options
    SYN must be ACKed with NO rule loaded — the guard against the
    raw-packet false positive (a malformed packet is silently
    discarded by the kernel, which enforce mode would misread as
    'dropped'). rc 1 = connected (trigger well-formed on THIS
    kernel), rc 0 = something already drops options (vacuous), rc 2
    = plain-SYN collateral."""

    def _run_baseline(self, probe, raw_syn_acked, plain_ok=True):
        with (
            patch.object(probe, "send_options_syn", return_value=raw_syn_acked),
            patch.object(probe, "plain_connect", return_value=plain_ok),
        ):
            return probe.run("baseline")

    def test_baseline_pass_when_acked(self, probe):
        assert self._run_baseline(probe, raw_syn_acked=True) == 1

    def test_baseline_vacuous_when_already_dropped(self, probe):
        assert self._run_baseline(probe, raw_syn_acked=False) == 0

    def test_baseline_collateral(self, probe):
        assert self._run_baseline(probe, raw_syn_acked=True, plain_ok=False) == 2

    def test_baseline_mode_is_a_choice(self, probe):
        args = probe.parse_args(["--mode", "baseline"])
        assert args.mode == "baseline"


class TestRawSynReplyLoop:
    """A raw IPPROTO_TCP socket receives EVERY TCP packet on the
    host. Each recvfrom returns immediately with a non-matching
    packet — the socket never blocks, so settimeout NEVER FIRES
    (it is a per-recv blocking timeout, not a deadline), and the
    reply loop would spin FOREVER waiting for a matching SYN-ACK
    that never comes — which is exactly the enforce-PASS case (the
    rule dropped our SYN). Quiet test containers never surface this;
    busy nodes do.

    The contract: the loop must honor a WALL-CLOCK deadline —
    bounded runtime on a busy node regardless of traffic rate."""

    def test_send_options_syn_bounded_on_busy_node(self, probe):
        # A socket that ALWAYS returns non-matching traffic instantly
        # (the busy-node shape): send_options_syn must still return
        # within the deadline — False (no matching reply), not hang.
        import time

        calls = {"n": 0}

        class BusyRaw:
            def __init__(self):
                self.timeout = None

            def setsockopt(self, *a):
                pass

            def settimeout(self, t):
                self.timeout = t

            def bind(self, *a):
                pass

            def getsockname(self):
                return ("127.0.0.1", 55555)

            def sendto(self, pkt, addr):
                pass

            def recvfrom(self, bufsize):
                calls["n"] += 1
                # Non-matching traffic: wrong ports, arrives instantly
                return (
                    b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x06\x00\x00"
                    + b"\x7f\x00\x00\x01\x7f\x00\x00\x01"
                    + struct.pack("!HH", 9999, 8888)
                    + b"\x00" * 16
                ), ("127.0.0.1", 9999)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with patch.object(probe.socket, "socket", return_value=BusyRaw()):
            t0 = time.monotonic()
            result = probe.send_options_syn("127.0.0.1", 12345)
            elapsed = time.monotonic() - t0
        assert elapsed < probe.TIMEOUT_SECONDS + 1.0, (
            f"send_options_syn took {elapsed:.1f}s on a busy node — "
            "the reply loop must honor a wall-clock deadline, not the "
            "socket timeout (which never fires when recvfrom always "
            "returns instantly)"
        )
        assert result is False, "no matching reply → dropped (enforce PASS)"

    def test_bounded_at_gpu_node_traffic_rates(self, probe):
        # The stress case: the
        # deadline must bound the loop at ANY traffic rate — the
        # recvfrom call count scales with the rate, the runtime must
        # not. Rates: 45 (the live hang), 10k (busy cluster), 1M
        # (pathological — a tight-loop local flood).
        import time

        for rate in (45, 10_000, 1_000_000):

            class FloodRaw:
                def __init__(self):
                    self.timeout = None

                def setsockopt(self, *a):
                    pass

                def settimeout(self, t):
                    self.timeout = t

                def bind(self, *a):
                    pass

                def getsockname(self):
                    return ("127.0.0.1", 55555)

                def sendto(self, pkt, addr):
                    pass

                def recvfrom(self, bufsize):
                    return (
                        b"\x45\x00\x00\x28\x00\x00\x00\x00\x40\x06\x00\x00"
                        + b"\x7f\x00\x00\x01\x7f\x00\x00\x01"
                        + struct.pack("!HH", 9999, 8888)
                        + b"\x00" * 16
                    ), ("127.0.0.1", 9999)

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            with patch.object(probe.socket, "socket", return_value=FloodRaw()):
                t0 = time.monotonic()
                result = probe.send_options_syn("127.0.0.1", 12345)
                elapsed = time.monotonic() - t0
            assert elapsed < probe.TIMEOUT_SECONDS + 1.0, (
                f"rate {rate:,} pkt/s: loop took {elapsed:.1f}s — the "
                "wall-clock deadline must bound runtime at ANY traffic "
                "rate (GPU-heavy nodes under big jobs)"
            )
            assert result is False

    def test_crash_exits_three(self, probe, capsys):
        # A crash must NOT read as PASS (Python's default exception
        # exit is 1) — exit 3 = "probe could not run".
        with patch.object(probe, "run", side_effect=OSError("network unreachable")):
            with pytest.raises(SystemExit) as excinfo:
                probe.main(["--mode", "enforce"])
        assert excinfo.value.code == 3
