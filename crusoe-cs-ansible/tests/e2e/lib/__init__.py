"""The e2e foundation: typed, reusable primitives for live-cluster
validations — CVE-agnostic by design.

Location: tests/e2e/lib/ (shared by every validation that needs a
real cluster — cve-2026-98432 today, emudhra and future CVEs next).

Layers:
  runner — subprocess execution with retries (API-blip tolerance)
  cluster — kubectl/cluster queries (pods, nodes, scheduling math)
  syn — the options-SYN craft (IP_OPTIONS = 4x NOP) and verdicts;
        generic over the RULE that matches it (the caller supplies
        the counter reader)
  waits — bounded, event-driven polling (the no-sleep rule)

Every live-found rule from the shell era is preserved here as code:
API-blip retries, exec settle, init-container-aware node picking,
anchored prom parsing, the nc-listener loop.
"""

from . import cluster, logging_setup, parsers, runner, syn, waits

__all__ = ["cluster", "logging_setup", "parsers", "runner", "syn", "waits"]
