"""The options-SYN craft and its verdicts — generic over the rule.

The payload: setsockopt(IP_OPTIONS, 4x NOP) — RFC 793 no-operation
padding, 4 bytes. ip_options_build() writes them into the IHL area:
20 + 4 = 24 bytes = hdrlength 6 != 5, the cve-2026-98432 rule's
match. Verified on the wire (raw-socket capture: first byte 0x46,
options 01010101 in the header tail; the plain SYN is 0x45).

The craft itself is rule-agnostic: any nft rule matching
option-bearing IPv4 TCP (hdrlength != 5) sees this SYN. The caller
supplies the counter reader for the corroborating evidence.
"""

from __future__ import annotations

NOP_OPTIONS = b"\x01\x01\x01\x01"

_OPTIONS_BLOCK = (
    "client.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, b'\\x01\\x01\\x01\\x01')\n"
)

_SYN_SCRIPT = """
import socket
client = socket.socket()
{options}client.settimeout({timeout})
try:
    client.connect(('{target}', {port}))
    print('CONNECTED')
except socket.timeout:
    print('BLOCKED')
except Exception as e:
    print(type(e).__name__)
finally:
    client.close()
"""


def syn_script(
    target: str, port: int, *, options: bool = True, timeout: float = 2.0
) -> str:
    """The python3 -c body for one SYN from a vantage. options=False
    emits the PLAIN control (no setsockopt line at all)."""
    return _SYN_SCRIPT.format(
        options=_OPTIONS_BLOCK if options else "",
        timeout=timeout,
        target=target,
        port=port,
    )


def classify(result: str) -> str:
    """Map the script's stdout to a verdict."""
    return result.strip()


def is_blocked(result: str) -> bool:
    return classify(result) == "BLOCKED"


def is_connected(result: str) -> bool:
    return classify(result) == "CONNECTED"
