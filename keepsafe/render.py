"""Terminal rendering: colour vocabulary, tables, masking, JSON output.

This is the ONLY module allowed to emit ANSI escape codes (DESIGN.md
"Colour"): one semantic token set, two themes, plain mode, 16-colour
SGR codes only - never 256-colour or truecolour. Human notices never
contaminate data streams: say() writes stdout while warn()/fail()
always write stderr (DESIGN.md "Machine-readable output"). Sanitize()
implements the traceback-side secret masking rule from DESIGN.md
"Secret masking rule": every loaded secret substring becomes
[redacted], longest secrets replaced first.
"""

from __future__ import annotations

import json
import os
import sys
import unicodedata

MASK = "********"
RESET = "\x1b[0m"
REDACTED = "[redacted]"
THEMES = {
    "dark": {
        "accent": "\x1b[36m",
        "dim": "\x1b[90m",
        "success": "\x1b[32m",
        "warning": "\x1b[33m\x1b[1m",
        "danger": "\x1b[31m\x1b[1m",
    },
    "light": {
        "accent": "\x1b[34m",
        "dim": "\x1b[90m",
        "success": "\x1b[32m",
        "warning": "\x1b[33m\x1b[1m",
        "danger": "\x1b[35m\x1b[1m",
    },
}
PLAIN_WORDS = {"success": "ok:", "warning": "warning:", "danger": "error:"}


def should_use_color(no_color_flag: bool, stream: object) -> bool:
    """Colour survives only when the --no-color flag is absent, the
    NO_COLOR environment variable is unset or empty, and the stream
    claims to be a TTY."""
    if no_color_flag:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except (OSError, ValueError):
        return False


class Renderer:
    """Semantic paint and notice routing for one command invocation."""

    def __init__(
        self,
        theme_name: str = "dark",
        no_color_flag: bool = False,
        stream: object | None = None,
    ) -> None:
        if theme_name not in THEMES:
            theme_name = "dark"
        self.theme_name = theme_name
        self.theme = THEMES[theme_name]
        self.stream = sys.stdout if stream is None else stream
        self.use_color = should_use_color(no_color_flag, self.stream)

    def paint(self, token: str, text: str) -> str:
        """Wrap text in the token's escape codes, or apply the plain
        word for success/warning/danger; accent/dim pass through in
        plain mode because they are structure, not semantics."""
        if self.use_color:
            return self.theme[token] + text + RESET
        word = PLAIN_WORDS.get(token)
        if word is not None:
            return word + " " + text
        return text

    def success_line(self, text: str) -> str:
        return self.paint("success", text)

    def warning_line(self, text: str) -> str:
        return self.paint("warning", text)

    def danger_line(self, text: str) -> str:
        return self.paint("danger", text)

    def say(self, text: str) -> None:
        print(text, file=sys.stdout)

    def warn(self, text: str) -> None:
        print(self.warning_line(text), file=sys.stderr)

    def warn_block(self, lines) -> None:
        """Multi-line warning: the warning word appears once, on the first
        line; continuation lines are dimmed so the block reads as one
        notice instead of a stack of repeated prefixes."""
        lines = list(lines)
        if not lines:
            return
        first = self.paint("warning", lines[0])
        rest = [self.paint("dim", "  " + line) for line in lines[1:]]
        print("\n".join([first] + rest), file=sys.stderr)

    def fail(self, text: str) -> None:
        print(self.danger_line(text), file=sys.stderr)


def display_width(text: str) -> int:
    """Terminal cells a string occupies: East Asian wide/fullwidth
    characters count 2, combining marks (categories Mn/Mc/Me) count 0,
    everything else counts 1."""
    width = 0
    for char in text:
        if unicodedata.category(char) in ("Mn", "Mc", "Me"):
            continue
        width += 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
    return width


def pad(text: str, width: int) -> str:
    """Left-justify to the requested display width; never truncates."""
    shortfall = width - display_width(text)
    if shortfall <= 0:
        return text
    return text + " " * shortfall


def table(
    headers: list[str],
    rows: list[list[str]],
    min_widths: list[int] | None = None,
    gutter: str = "  ",
) -> str:
    """Aligned plain-text table with unicode-safe column widths.

    Each column is as wide as its header, its widest cell, and its
    optional minimum width. Cells are padded on the right; interior
    padding survives, trailing whitespace on each line is stripped.
    """
    count = len(headers)
    minimums = list(min_widths) if min_widths is not None else []
    widths: list[int] = []
    for index in range(count):
        candidates = [display_width(headers[index])]
        candidates.extend(
            display_width(row[index] if index < len(row) else "")
            for row in rows
        )
        floor = minimums[index] if index < len(minimums) else 0
        widths.append(max(max(candidates), floor))

    def format_row(cells: list[str]) -> str:
        padded = (
            pad(cells[index] if index < len(cells) else "", widths[index])
            for index in range(count)
        )
        return gutter.join(padded).rstrip()

    lines = [format_row(headers)]
    lines.extend(format_row(row) for row in rows)
    return "\n".join(lines)


def sanitize(text: str, secrets) -> str:
    """Replace every occurrence of each secret string with [redacted].

    Longer secrets are replaced first so that one secret containing
    another leaves no partial leak behind. Empty or whitespace-only
    candidates are ignored; with no usable secrets the text returns
    unchanged.
    """
    usable = sorted(
        {
            secret
            for secret in (secrets or [])
            if isinstance(secret, str) and secret.strip()
        },
        key=len,
        reverse=True,
    )
    for secret in usable:
        text = text.replace(secret, REDACTED)
    return text


def machine_json(obj: object) -> str:
    """The one JSON form for --output json: stable key order, indented,
    non-ASCII kept raw so scripts read exactly what was stored."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
