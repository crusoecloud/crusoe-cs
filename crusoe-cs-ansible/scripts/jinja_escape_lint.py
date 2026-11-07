#!/usr/bin/env python3
"""Lint: no C-string escapes inside Jinja blocks.

Jinja's lexer unescapes C-string escapes in string literals: \\b
becomes a backspace, \\n a newline, \\t a tab, \\r a CR. A regex
written inline in a Jinja expression therefore silently becomes a
DIFFERENT regex — the generation-signature bug counted 0 rules for
exactly this reason. The regex character classes (\\d \\w \\s) and
punctuation escapes survive; only the C-string escapes are eaten.

One module, two uses:
  - imported:  `from jinja_escape_lint import lint_file` (the pytest ban)
  - executed:  `python3 scripts/jinja_escape_lint.py [paths...]`
               (pre-push, ad-hoc; exit 1 on any finding)

Usage defaults to roles/ playbooks/ charts/ (the YAML/Jinja surface).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

DANGEROUS = re.compile(r"\\[bntr]")
BLOCK = re.compile(r"\{\{.*?\}\}", re.DOTALL)


def lint_file(path: Path) -> list[int]:
    """The 1-based line numbers of offending Jinja blocks."""
    text = path.read_text()
    return [
        text[: m.start()].count("\n") + 1
        for m in BLOCK.finditer(text)
        if DANGEROUS.search(m.group())
    ]


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parent.parent
    args = argv if argv is not None else sys.argv[1:]
    targets = [Path(p) for p in args] or [
        root / p for p in ("roles", "playbooks", "charts")
    ]

    findings = []
    for target in targets:
        paths = (
            [target]
            if target.is_file()
            else [
                p
                for pat in ("*.yml", "*.yaml", "*.j2")
                for p in target.rglob(pat)
                if "__pycache__" not in str(p)
            ]
        )
        for path in paths:
            for line_no in lint_file(path):
                findings.append((path, line_no))

    if findings:
        print("C-string escape inside a Jinja block (Jinja's lexer unescapes it):")
        for path, line_no in findings:
            try:
                shown = path.relative_to(root)
            except ValueError:
                shown = path
            print(f"  {shown}:{line_no}")
        print(
            "\nUse a role var (a YAML scalar has no lexer) or a surviving escape "
            "(\\d \\w \\s and punctuation are safe)."
        )
        return 1
    print("jinja-escape-lint: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
