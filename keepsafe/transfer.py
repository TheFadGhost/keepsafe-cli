"""Plaintext import/export between the vault and JSON or CSV files.

Export is the only sanctioned plaintext boundary (typed confirmation
happens in the CLI layer, not here; --dry-run previews share these code
paths per PLAN.md). Masking rule: when include_secrets is false, secret
and secret-custom-field VALUES become empty strings - keys stay so both
shapes round-trip. CSV has no custom-field column by design.

CSV cells are guarded against formula injection: spreadsheet apps treat
a cell starting with '=', '+', '-', '@' or a tab as a formula or command
when the file is opened, so such cells are prefixed with one apostrophe
on export to force plain-text treatment. The guard character stays on
import (stripping it would corrupt legitimate notes and re-enable the
attack on re-export).
"""

from __future__ import annotations

import csv
import io
import json
import os
from dataclasses import dataclass

from keepsafe.errors import UsageError
from keepsafe.model import Entry, utc_now_iso

EXPORT_FORMATS = ("json", "csv")

_CSV_HEADER = ["name", "url", "username", "password", "notes", "tags"]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t")
_HEADER_ALIASES = {
    "name": ("name", "title", "account"),
    "url": ("url", "login_uri", "uri", "website"),
    "username": ("username", "login_username", "user", "login"),
    "password": ("password", "login_password", "secret", "pass"),
    "notes": ("notes", "note", "comment"),
    "tags": ("tags",),
}
_MAX_PROBLEMS = 10


@dataclass
class ImportPlan:
    """Dry-run preview of an import: three disjoint buckets."""

    add: list[Entry]
    overwrite: list[Entry]
    skip: list[Entry]

    def summary_line(self) -> str:
        return (
            f"{len(self.add)} to add, {len(self.overwrite)} to overwrite, "
            f"{len(self.skip)} skipped"
        )


def export_entries(entries: list[Entry], fmt: str, include_secrets: bool) -> str:
    """Serialize entries to JSON or CSV text; mask secrets when asked."""
    if fmt == "json":
        return _export_json(entries, include_secrets)
    if fmt == "csv":
        return _export_csv(entries, include_secrets)
    raise UsageError(
        f"unknown format {fmt!r}; valid formats: {', '.join(EXPORT_FORMATS)}"
    )


def sniff_format(path_or_text: str) -> str:
    """Return "json" or "csv" for a file path or literal text."""
    text = path_or_text
    try:
        # Guard ValueError too: on POSIX a NUL byte inside a "path" raises
        # ValueError rather than returning False.
        if os.path.isfile(path_or_text):
            with open(path_or_text, encoding="utf-8-sig", newline="") as fh:
                text = fh.read()
    except (OSError, ValueError):
        text = path_or_text
    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith("{"):
        return "json"
    try:
        csv.Sniffer().sniff(stripped[:4096], delimiters=",")
    except csv.Error:
        raise UsageError(
            "could not tell whether the input is JSON or CSV; provide a JSON "
            'object (starting with "{") or a CSV file with a header row'
        ) from None
    return "csv"


def parse_import(text: str, fmt: str | None = None) -> list[Entry]:
    """Parse import text into validated Entries; collect up to 10 problems."""
    if fmt is None:
        fmt = sniff_format(text)
    if fmt == "json":
        return _parse_json(text)
    if fmt == "csv":
        return _parse_csv(text)
    raise UsageError(
        f"unknown format {fmt!r}; valid formats: {', '.join(EXPORT_FORMATS)}"
    )


def plan_import(
    incoming: list[Entry], existing_names: set[str], overwrite: bool = False
) -> ImportPlan:
    """Split incoming entries into add / overwrite / skip buckets.

    Same-path collisions with existing_names go to overwrite when
    overwrite is true, otherwise to skip; everything else is added.
    """
    plan = ImportPlan(add=[], overwrite=[], skip=[])
    for entry in incoming:
        if entry.name not in existing_names:
            plan.add.append(entry)
        elif overwrite:
            plan.overwrite.append(entry)
        else:
            plan.skip.append(entry)
    return plan


def import_report_lines(plan: ImportPlan, source_path: str) -> list[str]:
    """Human-readable import result lines, including the standing warning.

    Lines are bare text WITHOUT a "warning:" prefix; the caller's renderer
    adds styling/prefix so it is never doubled.
    """
    return [
        plan.summary_line(),
        f"source: {source_path}",
        "the source file "
        + source_path
        + " still contains plaintext secrets; delete it securely when done.",
    ]


def _export_json(entries: list[Entry], include_secrets: bool) -> str:
    payload = {
        "format": 1,
        "exported": utc_now_iso(),
        "entries": [
            entry.to_dict() if include_secrets else _masked(entry.to_dict())
            for entry in entries
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def _masked(entry_dict: dict) -> dict:
    entry_dict["secret"] = ""
    for custom in entry_dict["fields"]:
        if custom["secret"]:
            custom["value"] = ""
    return entry_dict


def _export_csv(entries: list[Entry], include_secrets: bool) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(_CSV_HEADER)
    for entry in entries:
        writer.writerow(
            [
                _formula_safe(entry.name),
                _formula_safe(entry.url),
                _formula_safe(entry.username),
                _formula_safe(entry.secret if include_secrets else ""),
                _formula_safe(entry.notes),
                _formula_safe("|".join(entry.tags)),
            ]
        )
    return buffer.getvalue()


def _formula_safe(cell: str) -> str:
    # Spreadsheet applications execute cells beginning with = + - @ or tab
    # as formulas or commands on open; the apostrophe prefix forces them to
    # read the cell as plain text.
    if cell.startswith(_FORMULA_PREFIXES):
        return "'" + cell
    return cell


def _parse_json(text: str) -> list[Entry]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsageError(
            f"input is not valid JSON at line {exc.lineno}, column "
            f"{exc.colno}: {exc.msg}; expected a Keepsafe export "
            '({"entries": [...]}) or vault payload ({"entries": {...}})'
        ) from None
    if not isinstance(payload, dict) or "entries" not in payload:
        raise UsageError(
            "JSON must be an object with an 'entries' key; run keepsafe "
            "export to see the exact shape"
        )
    raw_entries = payload["entries"]
    entries: list[Entry] = []
    problems: list[str] = []
    if isinstance(raw_entries, dict):
        for position, (key, raw) in enumerate(raw_entries.items(), start=1):
            try:
                entry = Entry.from_dict(raw)
                if entry.name != key:
                    raise ValueError(
                        f"entry name '{entry.name}' does not match its key '{key}'"
                    )
            except (TypeError, ValueError) as exc:
                problems.append(f"- entry {position} ('{key}'): {exc}")
            else:
                entries.append(entry)
    elif isinstance(raw_entries, list):
        for position, raw in enumerate(raw_entries, start=1):
            try:
                entries.append(Entry.from_dict(raw))
            except (TypeError, ValueError) as exc:
                problems.append(f"- entry {position}: {exc}")
    else:
        raise UsageError(
            "'entries' must be a list (export shape) or an object keyed by "
            "path (vault payload shape)"
        )
    if problems:
        raise UsageError(_problems_message(problems))
    return entries


def _parse_csv(text: str) -> list[Entry]:
    cleaned = text.lstrip("\ufeff")
    reader = csv.reader(io.StringIO(cleaned, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration:
        raise UsageError(
            "the CSV input is empty; expected a header row such as: "
            + ",".join(_CSV_HEADER)
        ) from None
    except csv.Error as exc:
        raise UsageError(f"malformed CSV header: {exc}; fix quoting and retry") from None
    mapping: dict[str, int] = {}
    for idx, cell in enumerate(header):
        field_name = _match_header(cell)
        if field_name is not None and field_name not in mapping:
            mapping[field_name] = idx
    if "name" not in mapping:
        raise UsageError(
            "no name column found in the CSV header (looked for: "
            + ", ".join(_HEADER_ALIASES["name"])
            + "); expected a header row such as: "
            + ",".join(_CSV_HEADER)
        )
    entries: list[Entry] = []
    problems: list[str] = []
    seen_names: set[str] = set()
    try:
        for row in reader:
            if not any(cell.strip() for cell in row):
                continue

            def cell(field_name: str, row: list[str] = row) -> str:
                idx = mapping.get(field_name)
                if idx is None or idx >= len(row):
                    return ""
                return row[idx].strip()

            name = cell("name") or f"imported/row-{reader.line_num}"
            tags_raw = cell("tags").replace(";", "|")
            tags = [tag for tag in (t.strip() for t in tags_raw.split("|")) if tag]
            try:
                entries.append(
                    Entry(
                        name=_unique_name(name, seen_names),
                        username=cell("username"),
                        secret=cell("password"),
                        url=cell("url"),
                        notes=cell("notes"),
                        tags=tags,
                    )
                )
            except (TypeError, ValueError) as exc:
                problems.append(f"- line {reader.line_num}: {exc}")
    except csv.Error as exc:
        raise UsageError(
            f"malformed CSV near line {reader.line_num}: {exc}; check quoting "
            "and retry"
        ) from None
    if problems:
        raise UsageError(_problems_message(problems))
    return entries


def _match_header(cell: object) -> str | None:
    normalized = str(cell).strip().lstrip("\ufeff").strip().lower()
    for field_name, aliases in _HEADER_ALIASES.items():
        if normalized in aliases:
            return field_name
    return None


def _unique_name(base: str, seen: set[str]) -> str:
    if base not in seen:
        seen.add(base)
        return base
    counter = 2
    while f"{base}-{counter}" in seen:
        counter += 1
    candidate = f"{base}-{counter}"
    seen.add(candidate)
    return candidate


def _problems_message(problems: list[str]) -> str:
    shown = problems[:_MAX_PROBLEMS]
    hidden = len(problems) - len(shown)
    lines = [f"{len(problems)} problem(s) found in the import file:"]
    lines.extend(shown)
    if hidden:
        lines.append(f"- ... and {hidden} more problem(s) not shown")
    lines.append("fix these and try again; nothing was imported")
    return "\n".join(lines)
