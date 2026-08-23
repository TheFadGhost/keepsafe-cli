"""Tests for keepsafe.transfer: export/import round trips, planning, masking."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from keepsafe.errors import UsageError
from keepsafe.model import Entry, Field, payload_from_entries
from keepsafe.transfer import (
    EXPORT_FORMATS,
    ImportPlan,
    export_entries,
    import_report_lines,
    parse_import,
    plan_import,
    sniff_format,
)

TS = "2026-05-01T10:00:00+00:00"


def rich_entry(**overrides) -> Entry:
    kwargs = dict(
        name="web/日本語/ünïcode",
        username="user@example.com",
        secret="pässwörd-日本語-🔑",
        url="https://example.com/a?b=c",
        notes='line1\nline2\twith "quotes", commas; and = signs',
        tags=["dev", "日本語"],
        created=TS,
        updated=TS,
        fields=[
            Field(key="api key", value="AKIA-EXAMPLE-123", secret=True),
            Field(key="region", value="eu-west-1", secret=False),
        ],
    )
    kwargs.update(overrides)
    return Entry(**kwargs)


def plain_entry(name="web/plain", secret="plain-secret-value") -> Entry:
    return Entry(
        name=name,
        username="u",
        secret=secret,
        url="https://plain.example",
        notes="simple note",
        tags=["a", "b"],
        created=TS,
        updated=TS,
        fields=[],
    )


# ---------------------------------------------------------------------------
# 1. JSON export / import round-trip fidelity
# ---------------------------------------------------------------------------


def test_json_round_trip_preserves_everything():
    e = rich_entry()
    text = export_entries([e], "json", include_secrets=True)
    payload = json.loads(text)
    assert payload["format"] == 1
    datetime.fromisoformat(payload["exported"])
    assert payload["entries"][0] == e.to_dict()
    (parsed,) = parse_import(text, "json")
    assert parsed.to_dict() == e.to_dict()


def test_json_round_trip_multiple_entries_and_order():
    entries = [rich_entry(), plain_entry("a/one"), plain_entry("z/last")]
    text = export_entries(entries, "json", True)
    parsed = parse_import(text, "json")
    assert [e.to_dict() for e in parsed] == [e.to_dict() for e in entries]


def test_json_vault_payload_shape_accepted():
    e = plain_entry()
    payload = payload_from_entries([e])
    text = json.dumps(payload, ensure_ascii=False)
    parsed = parse_import(text)
    assert len(parsed) == 1
    assert parsed[0].to_dict() == e.to_dict()


def test_masked_json_export_contains_no_secret_substrings():
    e = rich_entry()
    text = export_entries([e], "json", include_secrets=False)
    for leak in (e.secret, "AKIA-EXAMPLE-123"):
        assert leak not in text
    payload = json.loads(text)
    exported = payload["entries"][0]
    assert exported["secret"] == ""
    assert {"key": "api key", "value": "", "secret": True} in exported["fields"]
    assert {"key": "region", "value": "eu-west-1", "secret": False} \
        in exported["fields"]
    assert exported["username"] == e.username
    assert exported["tags"] == e.tags
    (parsed,) = parse_import(text, "json")
    assert parsed.name == e.name
    assert parsed.secret == ""


def test_masked_csv_export_contains_no_secret_substrings():
    e = rich_entry()
    text = export_entries([e], "csv", include_secrets=False)
    for leak in (e.secret, "AKIA-EXAMPLE-123"):
        assert leak not in text
    lines = text.split("\r\n")
    header, row = lines[0], lines[1]
    assert header == "name,url,username,password,notes,tags"
    cells = next(iter(__import__("csv").reader([row])))
    password_cell = cells[3]
    assert password_cell == ""


# ---------------------------------------------------------------------------
# 2. CSV export details
# ---------------------------------------------------------------------------


def test_csv_header_newline_and_minimal_quoting():
    e = plain_entry()
    text = export_entries([e], "csv", True)
    assert text.startswith("name,url,username,password,notes,tags\r\n")
    assert text.endswith("\r\n")
    assert '"simple note"' not in text
    comma_note = plain_entry("web/c")
    comma_note.notes = "note, with comma"
    text2 = export_entries([comma_note], "csv", False)
    assert '"note, with comma"' in text2


def test_csv_formula_injection_defense_prefixes_apostrophe():
    tricky = Entry(
        name="-leading-dash",
        username="+441234567",
        secret="=cmd|' /C calc'!A0",
        url="@at-sign",
        notes="=SUM(A1:A2)\n-tabbed line",
        tags=["=tag"],
        created=TS,
        updated=TS,
    )
    text = export_entries([tricky], "csv", True)
    assert "'-leading-dash" in text
    assert "'+441234567" in text
    assert "'@at-sign" in text
    assert "\"'=SUM(A1:A2)\n-tabbed line\"" in text
    assert "'=tag" in text


def test_csv_password_column_masked_unless_included():
    e = plain_entry(secret="visible-on-request")
    masked = export_entries([e], "csv", include_secrets=False)
    full = export_entries([e], "csv", include_secrets=True)
    assert "visible-on-request" not in masked
    assert ",visible-on-request," in full


def test_csv_export_empty_vault_still_writes_header():
    assert export_entries([], "csv", True) == \
        "name,url,username,password,notes,tags\r\n"


# ---------------------------------------------------------------------------
# 3. CSV import: flexible headers and dedup
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "name,url,username,password,notes,tags",
        "Name,URL,Username,Password,Notes,Tags",
        "title,website,user,pass,note,tags",
        "\ufeffname,url,username,password,notes,tags",
    ],
)
def test_flexible_headers_chrome_style(header):
    text = (
        f"{header}\r\n"
        "web/x,https://x,u1,pw1,a note,dev|prod\r\n"
    )
    (parsed,) = parse_import(text, "csv")
    assert (parsed.name, parsed.url, parsed.username, parsed.secret) == (
        "web/x", "https://x", "u1", "pw1"
    )
    assert parsed.notes == "a note"
    assert parsed.tags == ["dev", "prod"]


def test_bitwarden_style_headers_map():
    text = (
        "folder,favorite,type,name,notes,login_uri,login_username,"
        "login_password\r\n"
        ",,login,bw/site,,https://bw.example,bwuser,bwpass\r\n"
    )
    (parsed,) = parse_import(text, "csv")
    assert parsed.name == "bw/site"
    assert parsed.url == "https://bw.example"
    assert parsed.username == "bwuser"
    assert parsed.secret == "bwpass"
    assert parsed.notes == ""


def test_tags_split_on_pipes_and_semicolons():
    text = (
        "name,tags\r\n"
        "t/one,dev|prod\r\n"
        "t/two,dev;stage\r\n"
    )
    parsed = parse_import(text, "csv")
    assert parsed[0].tags == ["dev", "prod"]
    assert parsed[1].tags == ["dev", "stage"]


def test_missing_names_get_generated_row_numbers():
    text = "name,username,password\r\n,u1,p1\r\n,u2,p2\r\n"
    parsed = parse_import(text, "csv")
    assert [e.name for e in parsed] == ["imported/row-2", "imported/row-3"]


def test_duplicate_resulting_paths_get_numeric_suffixes():
    text = "name,password\r\ndupe,p1\r\ndupe,p2\r\ndupe,p3\r\n"
    parsed = parse_import(text, "csv")
    assert [e.name for e in parsed] == ["dupe", "dupe-2", "dupe-3"]


def test_blank_rows_skipped_and_short_rows_tolerated():
    text = "name,url,username,password,notes,tags\r\n\r\njustname,,,,,\r\n"
    (parsed,) = parse_import(text, "csv")
    assert parsed.name == "justname"
    assert parsed.tags == []


def test_multiline_notes_survive_csv_round_trip():
    e = plain_entry("web/multiline")
    e.notes = "first line\nsecond line"
    text = export_entries([e], "csv", True)
    (parsed,) = parse_import(text, "csv")
    assert parsed.notes == e.notes
    assert parsed.secret == e.secret


def test_csv_round_trip_with_quotes_and_commas():
    e = plain_entry("web/quotes")
    e.notes = 'he said "hi", twice'
    e.tags = ["tag-a"]
    text = export_entries([e], "csv", True)
    (parsed,) = parse_import(text, "csv")
    assert parsed.notes == 'he said "hi", twice'
    assert parsed.tags == ["tag-a"]


def test_formula_prefixed_cells_import_verbatim():
    e = Entry(name="web/guarded", notes="=keepme", created=TS, updated=TS)
    text = export_entries([e], "csv", False)
    (parsed,) = parse_import(text, "csv")
    assert parsed.notes == "'=keepme"


# ---------------------------------------------------------------------------
# 4. Problem collection and error paths
# ---------------------------------------------------------------------------


def test_json_problems_capped_at_ten():
    bad_items = [{"nope": 1}] * 12
    text = json.dumps({"format": 1, "entries": bad_items})
    with pytest.raises(UsageError) as excinfo:
        parse_import(text, "json")
    message = str(excinfo.value)
    assert "12 problem(s)" in message
    assert "- entry 10:" in message
    assert "- entry 11:" not in message
    assert "and 2 more problem(s)" in message


def test_json_key_name_mismatch_rejected():
    e = plain_entry("right/name").to_dict()
    e["name"] = "wrong/name"
    text = json.dumps({"entries": {"right/name": e}})
    with pytest.raises(UsageError) as excinfo:
        parse_import(text, "json")
    assert "does not match" in str(excinfo.value)


def test_invalid_json_gives_line_hint():
    with pytest.raises(UsageError) as excinfo:
        parse_import("{\n  \"entries\": [\n    oops\n  ]\n}", "json")
    assert "line 3" in str(excinfo.value)


def test_missing_entries_key_rejected():
    with pytest.raises(UsageError):
        parse_import('{"format": 1}', "json")


def test_bad_header_without_name_column_rejected():
    with pytest.raises(UsageError) as excinfo:
        parse_import("login,mail\r\na,b\r\n", "csv")
    assert "name column" in str(excinfo.value)


def test_malformed_csv_quoting_rejected():
    with pytest.raises(UsageError) as excinfo:
        parse_import('name,url\r\n"unterminated,a,b\r\n', "csv")
    assert "CSV" in str(excinfo.value)


def test_unknown_format_argument_rejected():
    with pytest.raises(UsageError):
        parse_import("whatever", "xml")
    with pytest.raises(UsageError):
        export_entries([], "yaml", True)


# ---------------------------------------------------------------------------
# 5. sniff_format
# ---------------------------------------------------------------------------


def test_sniff_detects_json_text():
    assert sniff_format('{"entries": []}') == "json"


def test_sniff_detects_csv_text():
    assert sniff_format("name,url,username,password\r\na,b,c,d\r\n") == "csv"


def test_sniff_reads_file_content_not_extension(tmp_path):
    json_path = tmp_path / "looks-csv.txt"
    json_path.write_text('{"entries": []}', encoding="utf-8")
    csv_path = tmp_path / "looks-json.csv"
    csv_path.write_bytes(
        b"name,url,username,password\r\na,b,c,d\r\n"
    )
    assert sniff_format(str(json_path)) == "json"
    assert sniff_format(str(csv_path)) == "csv"


def test_sniff_rejects_unrecognizable_text():
    with pytest.raises(UsageError):
        sniff_format("absolutely-no-delimiter-here")


def test_sniff_rejects_empty_input():
    with pytest.raises(UsageError):
        sniff_format("")


# ---------------------------------------------------------------------------
# 6. plan_import buckets
# ---------------------------------------------------------------------------


def test_plan_import_three_buckets():
    new_a = plain_entry("new/a")
    new_b = plain_entry("new/b")
    existing = plain_entry("existing/one")
    plan = plan_import([new_a, existing, new_b], {"existing/one"})
    assert plan.add == [new_a, new_b]
    assert plan.overwrite == []
    assert plan.skip == [existing]


def test_plan_import_overwrite_flag_moves_bucket():
    existing = plain_entry("existing/one")
    fresh = plain_entry("fresh")
    skipped_plan = plan_import([existing, fresh], {"existing/one"}, overwrite=False)
    overwrite_plan = plan_import([existing, fresh], {"existing/one"}, overwrite=True)
    assert skipped_plan.skip == [existing]
    assert overwrite_plan.overwrite == [existing]
    assert overwrite_plan.skip == []


def test_summary_line_exact():
    plan = ImportPlan(add=[plain_entry(), plain_entry()],
                      overwrite=[plain_entry()], skip=[])
    assert plan.summary_line() == "2 to add, 1 to overwrite, 0 skipped"


# ---------------------------------------------------------------------------
# 7. Report lines carry the standing warning verbatim
# ---------------------------------------------------------------------------


def test_import_report_lines_contain_warning_verbatim():
    source = r"C:\tmp\password dump.csv"
    plan = plan_import([plain_entry()], set())
    lines = import_report_lines(plan, source)
    assert plan.summary_line() in lines
    assert f"source: {source}" in lines
    assert (
        f"the source file {source} still contains plaintext "
        "secrets; delete it securely when done."
    ) in lines


# ---------------------------------------------------------------------------
# 8. Format table contract
# ---------------------------------------------------------------------------


def test_export_formats_table():
    assert EXPORT_FORMATS == ("json", "csv")


def test_parse_import_defaults_to_sniffing():
    csv_text = "name,url,username,password,notes,tags\r\ns/a,,u,p,,\r\n"
    (parsed,) = parse_import(csv_text)
    assert parsed.name == "s/a"
