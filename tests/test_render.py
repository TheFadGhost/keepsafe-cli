"""Tests for keepsafe.render: colour gating, tables, masking, JSON."""

from __future__ import annotations

import io
import json
import re
import sys

import pytest

from keepsafe.render import (
    MASK,
    RESET,
    THEMES,
    Renderer,
    display_width,
    machine_json,
    pad,
    sanitize,
    should_use_color,
    table,
)

_SGR = re.compile(r"\x1b\[[0-9;]*m")
_ALLOWED_SGR = (
    {"\x1b[0m", "\x1b[1m"}
    | {f"\x1b[{code}m" for code in range(30, 38)}
    | {f"\x1b[{code}m" for code in range(90, 98)}
)

_EXPECTED_THEMES = {
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


class FakeTty:
    def isatty(self):
        return True


class FakeNotTty:
    def isatty(self):
        return False


class StreamWithoutIsatty:
    pass


@pytest.fixture(autouse=True)
def _no_no_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)


# ---------------------------------------------------------------------------
# 1. should_use_color: flag, env var, tty detection
# ---------------------------------------------------------------------------


def test_no_color_flag_wins_over_everything(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "0")
    assert should_use_color(True, FakeTty()) is False


def test_env_no_color_non_empty_disables(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert should_use_color(False, FakeTty()) is False


def test_env_no_color_any_non_empty_value_disables(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "false")
    assert should_use_color(False, FakeTty()) is False


def test_env_no_color_empty_does_not_disable(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "")
    assert should_use_color(False, FakeTty()) is True


def test_non_tty_stream_disables():
    assert should_use_color(False, io.StringIO()) is False
    assert should_use_color(False, FakeNotTty()) is False
    assert should_use_color(False, StreamWithoutIsatty()) is False
    assert should_use_color(False, None) is False


def test_tty_stream_enables():
    assert should_use_color(False, FakeTty()) is True


# ---------------------------------------------------------------------------
# 2. Exact escape sequences for every token in both themes
# ---------------------------------------------------------------------------


def test_theme_tables_match_design_literals():
    assert THEMES == _EXPECTED_THEMES
    assert MASK == "********"
    assert RESET == "\x1b[0m"


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("token", ["accent", "dim", "success", "warning", "danger"])
def test_paint_uses_exact_escape_sequences(theme, token):
    renderer = Renderer(theme_name=theme, no_color_flag=False, stream=FakeTty())
    expected = _EXPECTED_THEMES[theme][token] + "body" + RESET
    assert renderer.paint(token, "body") == expected


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize(
    "method,token",
    [
        ("success_line", "success"),
        ("warning_line", "warning"),
        ("danger_line", "danger"),
    ],
)
def test_convenience_lines_colour_mode_exact(theme, method, token):
    renderer = Renderer(theme_name=theme, no_color_flag=False, stream=FakeTty())
    code = _EXPECTED_THEMES[theme][token]
    assert getattr(renderer, method)("text") == code + "text" + RESET


def test_unknown_theme_falls_back_to_dark_silently():
    renderer = Renderer(theme_name="solarized", no_color_flag=False, stream=FakeTty())
    assert renderer.theme_name == "dark"
    assert renderer.paint("accent", "x") == "\x1b[36mx" + RESET


# ---------------------------------------------------------------------------
# 3. Plain mode: literal words, no ANSI anywhere
# ---------------------------------------------------------------------------


@pytest.fixture
def plain_renderer():
    return Renderer(theme_name="dark", no_color_flag=True, stream=FakeTty())


def test_plain_lines_use_literal_words(plain_renderer):
    assert plain_renderer.success_line("done") == "ok: done"
    assert plain_renderer.warning_line("careful") == "warning: careful"
    assert plain_renderer.danger_line("bad") == "error: bad"


def test_plain_warning_and_danger_prefixes(plain_renderer):
    assert plain_renderer.warning_line("careful").startswith("warning: ")
    assert plain_renderer.danger_line("bad").startswith("error: ")
    assert plain_renderer.success_line("done").startswith("ok: ")


def test_plain_mode_accent_and_dim_pass_through_unchanged(plain_renderer):
    assert plain_renderer.paint("accent", "keepsafe") == "keepsafe"
    assert plain_renderer.paint("dim", "(metadata)") == "(metadata)"


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_plain_mode_has_no_ansi_anywhere(theme):
    renderer = Renderer(theme_name=theme, no_color_flag=True, stream=FakeTty())
    outputs = [
        renderer.success_line("done"),
        renderer.warning_line("careful"),
        renderer.danger_line("bad"),
        renderer.paint("accent", "accented"),
        renderer.paint("dim", "dimmed"),
        table(["NAME"], [["web/github"]]),
    ]
    joined = "".join(outputs)
    assert "\x1b" not in joined


# ---------------------------------------------------------------------------
# 4. Vocabulary scan: only 16-colour SGR codes can ever be emitted
# ---------------------------------------------------------------------------


def _sample_outputs(renderer):
    return [
        renderer.success_line("copied to clipboard"),
        renderer.warning_line("weak passphrase"),
        renderer.danger_line("unlock failed"),
        renderer.paint("accent", "keepsafe"),
        renderer.paint("dim", "(updated 2026-08-01)"),
        table(
            ["NAME", "USERNAME"],
            [["邮件/servers", "root"], ["web/github", "octocat"]],
        ),
    ]


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_only_sixteen_colour_sgr_sequences_possible(theme):
    renderer = Renderer(theme_name=theme, no_color_flag=False, stream=FakeTty())
    seen = set()
    for chunk in _sample_outputs(renderer):
        seen.update(_SGR.findall(chunk))
    assert seen <= _ALLOWED_SGR
    assert seen, "colour mode must emit some SGR sequences"


def test_plain_mode_emits_zero_sgr_sequences():
    renderer = Renderer(theme_name="dark", no_color_flag=True, stream=FakeTty())
    seen = set()
    for chunk in _sample_outputs(renderer):
        seen.update(_SGR.findall(chunk))
    assert seen == set()


# ---------------------------------------------------------------------------
# 5. display_width and pad: unicode-safe cells
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,width",
    [("邮件", 4), ("abc", 3), ("e\u0301", 1), ("", 0), ("ＡＢ", 4)],
)
def test_display_width_values(text, width):
    assert display_width(text) == width


def test_pad_reaches_target_width_for_wide_text():
    padded = pad("邮件/x", 10)
    assert display_width(padded) == 10
    assert padded.startswith("邮件/x")
    assert display_width(pad("邮件/x", 6)) == 6


def test_pad_never_truncates():
    long_ascii = "servers/prod/database-master"
    assert pad(long_ascii, 5) == long_ascii
    assert pad("邮件备份", 4) == "邮件备份"
    assert pad("", 3) == "   "


def test_padded_cells_share_equal_display_width_in_row():
    headers = ["NAME", "USERNAME"]
    rows = [["邮件/x", "u1"], ["servers/prod/database-master", "u2"]]
    name_width = max(
        [display_width(headers[0])] + [display_width(r[0]) for r in rows]
    )
    rendered = table(headers, rows)
    for line in rendered.splitlines():
        first_cell = _take_display(line, 0, name_width)
        assert display_width(first_cell) == name_width


def _take_display(line, start, length):
    collected = []
    column = 0
    for char in line:
        width = display_width(char)
        if column >= start + length:
            break
        if column >= start:
            collected.append(char)
        column += width
    return "".join(collected)


# ---------------------------------------------------------------------------
# 6. table: aligned columns across header and rows
# ---------------------------------------------------------------------------


def _column_starts(headers, rows, gutter="  "):
    widths = [
        max([display_width(headers[i])] + [display_width(r[i]) for r in rows])
        for i in range(len(headers))
    ]
    starts = []
    offset = 0
    for width in widths[:-1]:
        offset += width
        starts.append(offset)
        offset += len(gutter)
    return widths, starts


def test_table_columns_start_at_identical_display_columns():
    headers = ["NAME", "USERNAME", "UPDATED", "TAGS"]
    rows = [
        ["web/github", "octocat", "2026-08-01", "dev"],
        ["邮件/servers", "root", "2026-07-12", "prod,db"],
        ["servers/prod/database-master", "-", "2026-06-30", ""],
    ]
    rendered = table(headers, rows)
    lines = rendered.splitlines()
    assert len(lines) == 1 + len(rows)
    widths, starts = _column_starts(headers, rows)
    gutter = "  "
    for line in lines:
        for start in starts:
            if display_width(line) <= start:
                break
            assert _take_display(line, start, len(gutter)) == gutter
        assert line == line.rstrip()
    assert widths == [28, 8, 10, 7]


def test_table_design_example_shape():
    headers = ["NAME", "USERNAME", "UPDATED", "TAGS"]
    rows = [["mail/bank", "", "2026-06-30", "finance"]]
    rendered = table(headers, rows)
    lines = rendered.splitlines()
    assert lines[0] == (
        "NAME".ljust(9) + "  " + "USERNAME" + "  " + "UPDATED".ljust(10) + "  " + "TAGS"
    )
    assert lines[1] == (
        "mail/bank" + "  " + " " * 8 + "  " + "2026-06-30".ljust(10) + "  " + "finance"
    )


def test_table_min_widths_enforced_on_interior_columns():
    rendered = table(["NAME", "TAGS"], [["a", "t"]], min_widths=[24, 1])
    lines = rendered.splitlines()
    assert lines[0] == "NAME" + " " * 20 + "  " + "TAGS"
    assert lines[1] == "a" + " " * 23 + "  " + "t"


def test_table_empty_rows_still_render_header():
    assert table(["NAME"], []) == "NAME"


# ---------------------------------------------------------------------------
# 7. sanitize: longest-first secret removal
# ---------------------------------------------------------------------------


def test_sanitize_removes_multiple_different_secrets():
    text = "login with alpha or beta now"
    assert sanitize(text, ["beta", "alpha"]) == (
        "login with [redacted] or [redacted] now"
    )


def test_sanitize_longest_first_overlap():
    text = "key=supersecret and secret alone"
    result = sanitize(text, ["secret", "supersecret"])
    assert result == "key=[redacted] and [redacted] alone"


def test_sanitize_order_independent():
    text = "key=supersecret and secret alone"
    forward = sanitize(text, ["supersecret", "secret"])
    backward = sanitize(text, ["secret", "supersecret"])
    assert forward == backward


def test_sanitize_multiline_all_occurrences():
    text = "alpha\nmiddle alpha\nend alpha"
    assert sanitize(text, ["alpha"]) == (
        "[redacted]\nmiddle [redacted]\nend [redacted]"
    )


def test_sanitize_no_secret_present_returns_text_unchanged():
    text = "nothing hidden here"
    assert sanitize(text, ["missing"]) == text


def test_sanitize_ignores_empty_and_whitespace_only_secrets():
    text = "keep me"
    assert sanitize(text, []) == text
    assert sanitize(text, [""]) == text
    assert sanitize(text, ["", "   ", "\t"]) == text


# ---------------------------------------------------------------------------
# 8. machine_json: sorted keys, raw unicode
# ---------------------------------------------------------------------------


def test_machine_json_sorts_keys_and_preserves_unicode_raw():
    out = machine_json({"b": 1, "a": "邮件", "c": ["x"]})
    assert out.index('"a"') < out.index('"b"')
    assert "邮件" in out
    assert "\\u" not in out
    assert json.loads(out) == {"b": 1, "a": "邮件", "c": ["x"]}


def test_machine_json_nested_structures_deterministic():
    first = machine_json({"z": {"b": 1, "a": 2}, "list": [3, 1]})
    second = machine_json({"list": [3, 1], "z": {"a": 2, "b": 1}})
    assert first == second


# ---------------------------------------------------------------------------
# 9. Notice routing: stdout vs stderr discipline
# ---------------------------------------------------------------------------


def test_warn_and_fail_go_to_stderr_never_stdout(capsys):
    renderer = Renderer(theme_name="dark", no_color_flag=True, stream=FakeTty())
    renderer.warn("careful")
    renderer.fail("bad")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "warning: careful\nerror: bad\n"


def test_say_goes_to_stdout_not_stderr(capsys):
    renderer = Renderer(theme_name="dark", no_color_flag=True, stream=FakeTty())
    renderer.say("hello")
    captured = capsys.readouterr()
    assert captured.out == "hello\n"
    assert captured.err == ""


def test_stderr_notices_carry_styling_under_colour_mode(monkeypatch):
    buffer = io.StringIO()
    monkeypatch.setattr(sys, "stderr", buffer)
    renderer = Renderer(no_color_flag=False, stream=FakeTty())
    renderer.warn("careful")
    assert buffer.getvalue() == "\x1b[33m\x1b[1mcareful\x1b[0m\n"
