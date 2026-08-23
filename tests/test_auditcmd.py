"""Tests for keepsafe.auditcmd: analysis categories and report rendering."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

import keepsafe.auditcmd as auditcmd
from keepsafe.auditcmd import Finding, analyze, render_report
from keepsafe.model import Entry, Field

NOW = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)
SECRET_A = "Alpha-Secret-Value-#1"
SECRET_B = "Beta-Secret-Value-#2"
SHARED = "shared-among-many-entries"
FIELD_SHARED = "field-shared-value"


def entry(
    name,
    *,
    secret="",
    username="",
    url="",
    notes="",
    updated="2026-06-01T00:00:00+00:00",
    fields=None,
):
    return Entry(
        name=name,
        username=username,
        secret=secret,
        url=url,
        notes=notes,
        created=updated,
        updated=updated,
        fields=fields or [],
    )


# ---------------------------------------------------------------------------
# 1. Weak secrets
# ---------------------------------------------------------------------------


def test_weak_by_length_boundary():
    short = entry("a/short", secret="abcdefghijk", username="u", url="https://x")
    exact = entry("b/exact", secret="abcdefghijkl", username="u", url="https://x")
    report = analyze([short, exact], min_length=12, now=NOW)
    assert [f.name for f in report.weak] == ["a/short"]
    assert report.counts["weak"] == 1


def test_weak_detail_format():
    e = entry("web/x", secret="abc", updated="2025-01-04T09:30:00+00:00")
    (finding,) = analyze([e], min_length=12, now=NOW).weak
    assert finding.detail == "3 characters, changed 2025-01-04"
    assert finding.category == "weak"
    assert "abc" not in finding.detail


@pytest.mark.parametrize(
    "secret,expected_weak",
    [
        ("abcdefghijklmnop", True),
        ("abcdefghijklmnopq", True),
        ("abcdefghijklmno", False),
        ("abcdefghijklmnop1", False),
        ("ABCDEFGHIJKL1234", False),
    ],
)
def test_weak_complexity_rule_needs_16_chars_and_two_classes(secret, expected_weak):
    assert len(secret) >= 12
    e = entry("c/complexity", secret=secret, username="u", url="https://x")
    report = analyze([e], min_length=12, now=NOW)
    assert (len(report.weak) == 1) is expected_weak


def test_weak_common_password_caught_even_above_min_length():
    e = entry("d/common", secret="letmein", username="u", url="https://x")
    report = analyze([e], min_length=4, now=NOW)
    assert len(report.weak) == 1
    assert "7 characters" in report.weak[0].detail


def test_common_password_match_is_case_insensitive():
    e = entry("d/common2", secret="LetMeIn", username="u", url="https://x")
    assert len(analyze([e], min_length=4, now=NOW).weak) == 1


# ---------------------------------------------------------------------------
# 2. Reused secrets
# ---------------------------------------------------------------------------


def test_reused_group_across_entries_and_secret_fields():
    entries = [
        entry("a/one", secret=SHARED, username="u", url="https://x"),
        entry("b/two", secret=SHARED, username="u", url="https://x"),
        entry("c/three", secret="unique-c-three", fields=[
            Field(key="pin", value=FIELD_SHARED, secret=True)
        ], username="u", url="https://x"),
        entry("d/four", secret="unique-d-four", fields=[
            Field(key="pin", value=FIELD_SHARED, secret=True)
        ], username="u", url="https://x"),
        entry("e/five", secret="unique-e-five", fields=[
            Field(key="pub", value=FIELD_SHARED, secret=False)
        ], username="u", url="https://x"),
    ]
    report = analyze(entries, now=NOW)
    prefixes = {f.detail.split("[sha256 prefix ")[1][:6] for f in report.reused}
    expected_shared = hashlib.sha256(SHARED.encode()).hexdigest()[:6]
    expected_field = hashlib.sha256(FIELD_SHARED.encode()).hexdigest()[:6]
    assert prefixes == {expected_shared, expected_field}
    by_prefix = {
        f.detail.split("[sha256 prefix ")[1][:6]: f for f in report.reused
    }
    shared_finding = by_prefix[expected_shared]
    assert shared_finding.category == "reused"
    assert shared_finding.name == "a/one, b/two"
    assert shared_finding.detail == f"[sha256 prefix {expected_shared}] used by 2 entries"
    field_finding = by_prefix[expected_field]
    assert field_finding.name == "c/three, d/four"
    assert report.counts["reused_groups"] == 2
    assert report.counts["reused_entries"] == 4


def test_non_secret_field_values_are_not_grouped():
    entries = [
        entry("a/one", secret="solo-a", username="u", url="https://x", fields=[
            Field(key="pub", value="visible-note", secret=False)
        ]),
        entry("b/two", secret="solo-b", username="u", url="https://x", fields=[
            Field(key="pub", value="visible-note", secret=False)
        ]),
    ]
    report = analyze(entries, now=NOW)
    assert report.reused == []
    assert report.counts["reused_groups"] == 0


def test_empty_secrets_are_never_reported_as_reused():
    entries = [
        entry("a/none", username="u", url="https://x"),
        entry("b/none", username="u", url="https://x"),
    ]
    report = analyze(entries, now=NOW)
    assert report.reused == []


def test_hash_prefix_is_stable_and_short():
    e1 = entry("a/one", secret=SHARED, username="u", url="https://x")
    e2 = entry("b/two", secret=SHARED, username="u", url="https://x")
    full_digest = hashlib.sha256(SHARED.encode()).hexdigest()
    text = render_report(analyze([e1, e2], now=NOW), "v", 12, 365)
    assert f"[sha256 prefix {full_digest[:6]}]" in text
    assert full_digest not in text
    assert SHARED not in text


def test_name_list_truncates_at_five_with_ellipsis():
    entries = [
        entry(f"g/{i}", secret=SHARED, username="u", url="https://x")
        for i in range(6)
    ]
    (finding,) = analyze(entries, now=NOW).reused
    assert finding.name == (
        "g/0, g/1, g/2, g/3, g/4, ..."
    )
    assert "g/5" not in finding.name
    assert finding.detail.endswith("used by 6 entries")


def test_exactly_five_names_get_no_ellipsis():
    entries = [
        entry(f"g/{i}", secret=SHARED, username="u", url="https://x")
        for i in range(5)
    ]
    (finding,) = analyze(entries, now=NOW).reused
    assert finding.name == "g/0, g/1, g/2, g/3, g/4"
    assert "..." not in finding.name


# ---------------------------------------------------------------------------
# 3. Stale entries
# ---------------------------------------------------------------------------


def test_stale_boundary_day_is_not_stale_one_second_before_is():
    boundary = entry(
        "t/boundary",
        secret="s",
        username="u",
        url="https://x",
        updated="2025-08-23T12:00:00+00:00",
    )
    just_before = entry(
        "t/just-before",
        secret="s",
        username="u",
        url="https://x",
        updated="2025-08-23T11:59:59+00:00",
    )
    report = analyze([boundary, just_before], stale_days=365, now=NOW)
    assert [f.name for f in report.stale] == ["t/just-before"]
    assert report.stale[0].detail == "changed 2025-08-23"


def test_unparseable_timestamp_treated_as_stale():
    e = entry("t/broken", secret="s", username="u", url="https://x", updated="garbage")
    (finding,) = analyze([e], now=NOW).stale
    assert finding.detail == "unknown timestamp"


def test_naive_timestamp_assumed_utc():
    e = entry(
        "t/naive",
        secret="s",
        username="u",
        url="https://x",
        updated="2020-01-01T00:00:00",
    )
    (finding,) = analyze([e], now=NOW).stale
    assert finding.detail == "changed 2020-01-01"


def test_z_suffix_timestamp_parses():
    fresh = entry(
        "t/fresh",
        secret="s",
        username="u",
        url="https://x",
        updated="2026-08-23T00:00:00Z",
    )
    assert analyze([fresh], stale_days=365, now=NOW).stale == []


# ---------------------------------------------------------------------------
# 4. Missing username / url
# ---------------------------------------------------------------------------


def test_missing_username_and_url_detected_with_empty_details():
    e = entry("m/incomplete", secret="s")
    complete = entry("m/complete", secret="s", username="u", url="https://x")
    report = analyze([e, complete], now=NOW)
    assert [f.name for f in report.missing_username] == ["m/incomplete"]
    assert [f.name for f in report.missing_url] == ["m/incomplete"]
    assert all(f.detail == "" for f in report.missing_username + report.missing_url)


# ---------------------------------------------------------------------------
# 5. Counts arithmetic
# ---------------------------------------------------------------------------


def test_counts_exact_on_mixed_fixture():
    entries = [
        entry("w/short", secret="tiny", username="u", url="https://x"),
        entry("r/one", secret=SHARED, username="u", url="https://x"),
        entry("r/two", secret=SHARED, username="u", url="https://x"),
        entry("s/old", secret="Str0ng-Passphrase!", username="u",
              url="https://x", updated="2024-02-11T00:00:00+00:00"),
        entry("mu/nouser", secret="An0ther-L0ng-Pass!", url="https://x"),
        entry("murl/nourl", secret="Yet-An0ther-L0ng-One", username="u"),
    ]
    report = analyze(entries, now=NOW)
    assert report.counts == {
        "weak": 1,
        "reused_groups": 1,
        "reused_entries": 2,
        "stale": 1,
        "missing_username": 1,
        "missing_url": 1,
        "entries": 6,
    }


def test_clean_vault_has_zero_counts_and_no_findings():
    good = entry("ok/entry", secret="GoodSecret#123", username="u", url="https://x")
    report = analyze([good], now=NOW)
    assert all(
        section == [] for section in (
            report.weak, report.reused, report.stale,
            report.missing_username, report.missing_url,
        )
    )
    assert report.counts["entries"] == 1
    assert sum(v for k, v in report.counts.items() if k != "entries") == 0


# ---------------------------------------------------------------------------
# 6. render_report layout
# ---------------------------------------------------------------------------


def build_mixed_fixture():
    return [
        entry("servers/prod/db", secret="8char", username="root",
              updated="2025-01-04T00:00:00+00:00"),
        entry("web/github", secret=SHARED, username="octocat",
              updated="2026-08-01T00:00:00+00:00"),
        entry("web/gitlab", secret=SHARED, username="gitlabber",
              updated="2026-07-12T00:00:00+00:00"),
        entry("old/misc/dialup", secret="LongEnoughSecret!", username="-",
              url="https://old.example", updated="2024-02-11T00:00:00+00:00"),
        entry("web/forum", secret="ForumPass9!", username="",
              updated="2026-08-20T00:00:00+00:00"),
    ]


MIXED_COUNTS = {"weak": 2, "reused_groups": 1, "reused_entries": 2, "stale": 2,
                "missing_username": 1, "missing_url": 4, "entries": 5}


def mixed_text(min_length=12, stale_days=365):
    report = analyze(build_mixed_fixture(), min_length=min_length,
                     stale_days=stale_days, now=NOW)
    return render_report(report, r"C:\Users\me\vault.kpsf",
                         min_length, stale_days)


def test_counts_exact_on_mixed_render_fixture():
    report = analyze(build_mixed_fixture(), now=NOW)
    assert report.counts == MIXED_COUNTS


def test_render_header_and_section_headers_exact():
    text = mixed_text()
    lines = text.splitlines()
    assert lines[0] == r"Audit of C:\Users\me\vault.kpsf - 5 entries"
    assert "weak secrets (length under 12 characters)" in lines
    assert "reused secrets (same value in multiple entries)" in lines
    assert "not rotated in 365 days (--stale-days)" in lines
    assert "missing username" in lines
    assert "missing url" in lines


def test_render_thresholds_appear_in_headers():
    text = mixed_text(min_length=8, stale_days=90)
    assert "weak secrets (length under 8 characters)" in text
    assert "not rotated in 90 days (--stale-days)" in text


def test_render_summary_and_final_line_exact():
    text = mixed_text()
    lines = text.splitlines()
    assert lines[-2] == (
        "summary: 2 weak, 1 reused group (2 entries), 2 stale, "
        "1 missing username, 4 missing url"
    )
    assert lines[-1] == "all checks computed locally; no external lookups of any kind"


def test_render_reused_block_shape():
    text = mixed_text()
    lines = text.splitlines()
    idx = lines.index("reused secrets (same value in multiple entries)")
    prefix = hashlib.sha256(SHARED.encode()).hexdigest()[:6]
    assert lines[idx + 1] == f"  [sha256 prefix {prefix}] used by 2 entries"
    assert lines[idx + 2] == "    web/github, web/gitlab"


def test_render_weak_lines_indented_and_aligned():
    text = mixed_text()
    longest = max(auditcmd._display_width(f.name)
                  for f in auditcmd.analyze(build_mixed_fixture(), now=NOW).weak)
    width = max(longest, auditcmd._NAME_COLUMN_MIN)
    assert "  " + auditcmd._pad("servers/prod/db", width) + \
        "  5 characters, changed 2025-01-04" in text


def test_render_stale_line_format():
    text = mixed_text()
    assert "  old/misc/dialup" in text
    assert "changed 2024-02-11" in text
    assert "  servers/prod/db" in text
    assert "changed 2025-01-04" in text


def test_render_missing_sections_list_names_only():
    text = mixed_text()
    lines = text.splitlines()
    muidx = lines.index("missing username")
    assert lines[muidx + 1] == "  web/forum"
    assert lines[muidx + 2] == ""
    muridx = lines.index("missing url")
    assert lines[muridx + 1] == "  servers/prod/db"
    assert lines[muridx + 2] == "  web/github"
    assert lines[muridx + 3] == "  web/gitlab"
    assert lines[muridx + 4] == "  web/forum"


def test_render_omits_empty_sections():
    clean = entry("ok/entry", secret="GoodSecret#123", username="u", url="https://x")
    text = render_report(analyze([clean], now=NOW), "v.kpsf", 12, 365)
    lines = text.splitlines()
    assert lines[0] == "Audit of v.kpsf - 1 entries"
    assert lines[1] == ""
    assert lines[-2] == "summary: 0 weak, 0 reused groups (0 entries), 0 stale, 0 missing username, 0 missing url"
    for header in (
        "weak secrets (length under 12 characters)",
        "reused secrets (same value in multiple entries)",
        "not rotated in 365 days (--stale-days)",
        "missing username",
        "missing url",
    ):
        assert header not in set(lines)


def test_render_pluralizes_reused_groups():
    entries = [
        entry("p/one", secret="dup-one-aaaaaa", username="u", url="https://x"),
        entry("p/two", secret="dup-one-aaaaaa", username="u", url="https://x"),
        entry("q/one", secret="dup-two-bbbbbb", username="u", url="https://x"),
        entry("q/two", secret="dup-two-bbbbbb", username="u", url="https://x"),
    ]
    text = render_report(analyze(entries, now=NOW), "v", 12, 365)
    assert "summary: 0 weak, 2 reused groups (4 entries)" in text


def test_render_never_contains_any_secret_value():
    secrets_in_play = [SECRET_A, SECRET_B, SHARED, FIELD_SHARED]
    entries = [
        entry("n/alpha", secret=SECRET_A, username=f"user-{SECRET_A}",
              url=f"https://x/?token={SECRET_A}",
              notes=f"note mentioning {SECRET_A}",
              fields=[Field(key="k", value=FIELD_SHARED, secret=True)]),
        entry("n/beta", secret=SECRET_B, username="user-b",
              url="https://y", fields=[
                  Field(key="k", value=FIELD_SHARED, secret=True)]),
    ]
    text = render_report(analyze(entries, now=NOW), "v.kpsf", 12, 365)
    for secret in secrets_in_play:
        assert secret not in text


def test_render_wide_names_keep_alignment():
    narrow = entry("a", secret="tiny", username="u", url="https://x",
                   updated="2025-01-01T00:00:00+00:00")
    wide = entry("web/" + "\u65e5\u672c\u8a9e" * 3, secret="small",
                 username="u", url="https://x",
                 updated="2025-02-02T00:00:00+00:00")
    report = analyze([narrow, wide], now=NOW)
    width = max(
        [auditcmd._display_width(f.name) for f in report.weak]
        + [auditcmd._NAME_COLUMN_MIN]
    )
    text = render_report(report, "v", 12, 365)
    assert "  " + auditcmd._pad(narrow.name, width) + \
        "  4 characters, changed 2025-01-01" in text
    assert "  " + auditcmd._pad(wide.name, width) + \
        "  5 characters, changed 2025-02-02" in text


def test_dataclasses_hold_declared_shapes():
    f = Finding(category="weak", name="x", detail="d")
    assert (f.category, f.name, f.detail) == ("weak", "x", "d")
    report = auditcmd.AuditReport(weak=[], reused=[], stale=[],
                                  missing_username=[], missing_url=[], counts={})
    assert report.counts == {}
