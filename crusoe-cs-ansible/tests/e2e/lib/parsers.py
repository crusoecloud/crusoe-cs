"""Pure parsers for the outputs the live cluster produces.

Pure functions: canned output in, structured value out. Every
parsing trap lives here, unit-tested:
  - the prom anchor (HELP/TYPE lines contain the family names; a
    bare grep picks up 'gauge' from the TYPE line as the value)
  - the nft counter (the rule's own match count — the evidence)
  - the install-line regex (the optional '(pod <name>)' part — an
    exact-string grep reads a healthy node as a regression)
  - the netns inode (readlink output: 'net:[4026533106]')
"""

from __future__ import annotations

import datetime as dt
import re

# nft: "counter packets 6 bytes 368" — the packets field. Anchored on
# the VERDICT rule (drop / log prefix): the loopback split renders a
# count-only rule FIRST whose counter must not be read here.
NFT_COUNTER_RE = re.compile(r"counter packets (\d+) bytes \d+[^\n]*(?:drop|log prefix)")

# readlink /proc/<pid>/ns/net -> "net:[4026533106]"
NETNS_INODE_RE = re.compile(r"\[(\d+)\]")

# The install line carries "(pod <name>)" whenever the name resolves
# (the sweep path, or a late first-sight retry) — the regex accepts
# the OPTIONAL pod part or a HEALTHY node reads as a regression
# .
INSTALL_LINE_RE = r"netns {netns}( \(pod [^)]*\))?: rule installed"

# The proc-scan fallback line: "netns proc/<pid> (pod <name>)".
FALLBACK_LINE_RE = r"netns proc/[0-9]+ \(pod {pod}\)"


def nft_counter(nft_output: str) -> int:
    """The rule's match counter from an `nft list chain` output, or
    -1 when the rule is absent."""
    m = NFT_COUNTER_RE.search(nft_output)
    return int(m.group(1)) if m else -1


def netns_inode(readlink_output: str) -> int:
    """The inode number from readlink's 'net:[<ino>]' output."""
    m = NETNS_INODE_RE.search(readlink_output)
    return int(m.group(1)) if m else -1


def prom_value(prom_text: str, family: str, *label_filters: str) -> str | None:
    """The value of the first ANCHORED metric line matching the
    family and ALL label substrings — or None.

    The anchor matters: the prom file's HELP/TYPE lines also contain
    the family names, and a bare grep picks up 'gauge' from the TYPE
    line as the value.
    """
    for line in prom_text.splitlines():
        if not line.startswith(family):
            continue
        if all(f in line for f in label_filters):
            return line.rsplit(" ", 1)[1]
    return None


def install_line_present(log_text: str, netns: str) -> bool:
    """The event-path install line for a netns (pod-qualified or
    bare) appears in the sidecar log."""
    return bool(re.search(INSTALL_LINE_RE.format(netns=re.escape(netns)), log_text))


def fallback_line_present(log_text: str, pod: str) -> bool:
    """The proc-scan FALLBACK covered this pod — the ~10s gap."""
    return bool(re.search(FALLBACK_LINE_RE.format(pod=re.escape(pod)), log_text))


def log_timestamp_before(log_text: str, pattern: str) -> str | None:
    """The timestamp of the LAST line matching pattern (the line's
    first whitespace-separated field)."""
    matches = [ln for ln in log_text.splitlines() if re.search(pattern, ln)]
    if not matches:
        return None
    return matches[-1].split()[0]


def parse_rfc3339(timestamp: str) -> dt.datetime:
    """Parse an RFC3339 timestamp in EITHER wire form: kubectl's
    trailing-Z ('2026-11-03T07:25:41Z') or the python client's
    offset form ('2026-11-03T07:25:41+00:00') — the two transports
    serialize the same instant differently."""
    ts = timestamp.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return dt.datetime.fromisoformat(ts)
