"""THE single source of truth for the ruleset's shape in tests.

Every test that needs "what does the ruleset look like" or "what does
nft print for it" derives it from HERE. Nothing hand-writes a rule
line.

WHY: the generation-signature bug survived a full unit suite because
the fixtures wrote the loopback rule as `ip saddr 127.0.0.0/8 ...`
while the template renders `iif lo ip saddr ...`. The fixtures were
plausible and wrong, so the parsers agreed with the fixtures and
disagreed with production. A hand-written fixture is a second source
of truth, and it drifts silently.

THE DESIGN: `Ruleset` is a frozen dataclass whose only public
constructor is `Ruleset.render(mode)`, which renders the real
template. A test therefore cannot hand-write a listing — there is no
supported way to build one. That is stronger than banning the
practice: the wrong thing is unrepresentable.

  Ruleset.render(mode)      the ruleset FILE the role deploys
  .listing(counters=...)    what `nft list chain` prints for it
  .empty_listing()          a flushed chain (table + chain, no rules)
  .rule_lines               the rule lines, comments stripped
  .rule_count               how many rules

`listing()` is a faithful transformation, not a fixture: it applies
the same rewrites nft does (interface names quoted, protocol names
numeric, counter bytes interleaved between the match and the verdict).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cached_property

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from conftest import COMPONENT_ROOT

__all__ = ["MODES", "Ruleset"]

TEMPLATE_DIR = COMPONENT_ROOT / "roles" / "cve_2026_98432" / "templates"
TEMPLATE_NAME = "cve-2026-98432.nft.j2"

MODES = ("enforce", "observe")

# A rule line in a ruleset file: a non-comment line carrying a counter
# (the template's own idiom — every rule counts).
_RULE_LINE = re.compile(r"^(?:iif|oif|ip|ip6|tcp|udp|meta|ct)\b.*\bcounter\b")


@dataclass(frozen=True)
class Ruleset:
    """A rendered ruleset. Construct via `Ruleset.render`."""

    mode: str
    text: str

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"unknown mode {self.mode!r}; expected one of {MODES}")

    @classmethod
    def render(cls, mode: str) -> "Ruleset":
        """The ruleset file the role deploys for `mode`."""
        env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            keep_trailing_newline=True,
            undefined=StrictUndefined,
        )
        text = env.get_template(TEMPLATE_NAME).render(cve_2026_98432_resolved_mode=mode)
        return cls(mode=mode, text=text)

    @cached_property
    def rule_lines(self) -> tuple[str, ...]:
        """The rule lines, comments and structure stripped."""
        return tuple(
            s
            for line in self.text.splitlines()
            if (s := line.strip()) and not s.startswith("#") and _RULE_LINE.match(s)
        )

    @property
    def rule_count(self) -> int:
        return len(self.rule_lines)

    def listing(self, counters: dict[int, int] | None = None) -> str:
        """What `nft list chain ip cve_2026_98432 input` prints.

        The rewrites nft applies, and nothing else:
          - interface names are quoted: `iif lo` -> `iif "lo"`
          - protocol names are numeric: `ip protocol tcp` -> `ip protocol 6`
          - a counter's bytes are interleaved: `counter` ->
            `counter packets N bytes M`

        `counters` maps a rule's 0-based index to its packet count.
        """
        counters = counters or {}
        body = []
        for i, rule in enumerate(self.rule_lines):
            packets = counters.get(i, 0)
            line = rule.replace("iif lo ", 'iif "lo" ')
            line = line.replace("ip protocol tcp", "ip protocol 6")
            line = re.sub(
                r"\bcounter\b",
                f"counter packets {packets} bytes {packets * 44}",
                line,
            )
            body.append(f"\t\t{line}")
        inner = "\n".join(body)
        return (
            "table ip cve_2026_98432 {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority raw; policy accept;\n"
            f"{inner}\n"
            "\t}\n"
            "}"
        )

    def empty_listing(self) -> str:
        """A FLUSHED chain: the table and chain exist, the rules are
        gone. The self-heal state."""
        return (
            "table ip cve_2026_98432 {\n"
            "\tchain input {\n"
            "\t\ttype filter hook input priority raw; policy accept;\n"
            "\t}\n"
            "}"
        )
