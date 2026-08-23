"""Audit analysis and report rendering.

Every check is computed locally against the loaded entries only; nothing
here ever performs an external lookup (see PLAN.md, breach-database
lookup rejected). Findings name entry paths and reasons in words; secret
VALUES never appear in findings or in rendered reports - reused secrets
are represented by a 6-hex-character sha256 prefix only. Layout follows
DESIGN.md "Audit report layout".
"""

from __future__ import annotations

import hashlib
import string
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from keepsafe.commonpasswords import COMMON_PASSWORDS
from keepsafe.model import Entry

_COMPLEXITY_MIN_LENGTH = 16
_NAME_COLUMN_MIN = 24
_NAME_LIST_LIMIT = 5
_LOCAL_ONLY_LINE = "all checks computed locally; no external lookups of any kind"
_CLASS_UPPERS = set(string.ascii_uppercase)
_CLASS_LOWERS = set(string.ascii_lowercase)
_CLASS_DIGITS = set(string.digits)


@dataclass
class Finding:
    """One audit finding; detail never contains a secret VALUE."""

    category: str
    name: str
    detail: str


@dataclass
class AuditReport:
    weak: list[Finding]
    reused: list[Finding]
    stale: list[Finding]
    missing_username: list[Finding]
    missing_url: list[Finding]
    counts: dict


def analyze(
    entries: list[Entry],
    min_length: int = 12,
    stale_days: int = 365,
    now: datetime | None = None,
) -> AuditReport:
    """Run every local check over entries and return the report."""
    now = now if now is not None else datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    cutoff = now - timedelta(days=stale_days)

    weak: list[Finding] = []
    stale: list[Finding] = []
    missing_username: list[Finding] = []
    missing_url: list[Finding] = []
    reuse_groups: dict[str, list[str]] = {}

    for entry in entries:
        if _is_weak(entry.secret, min_length):
            weak.append(
                Finding(
                    "weak",
                    entry.name,
                    f"{len(entry.secret)} characters, changed {entry.updated[:10]}",
                )
            )
        for value in _secret_values(entry):
            if not value:
                continue
            prefix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:6]
            reuse_groups.setdefault(prefix, []).append(entry.name)
        stamp = _parse_timestamp(entry.updated)
        if stamp is None:
            stale.append(Finding("stale", entry.name, "unknown timestamp"))
        elif stamp < cutoff:
            stale.append(Finding("stale", entry.name, f"changed {entry.updated[:10]}"))
        if entry.username == "":
            missing_username.append(Finding("missing_username", entry.name, ""))
        if entry.url == "":
            missing_url.append(Finding("missing_url", entry.name, ""))

    reused: list[Finding] = []
    reused_entries = 0
    for prefix, names in reuse_groups.items():
        if len(names) < 2:
            continue
        shown = ", ".join(names[:_NAME_LIST_LIMIT])
        if len(names) > _NAME_LIST_LIMIT:
            shown += ", ..."
        reused.append(
            Finding(
                "reused",
                shown,
                f"[sha256 prefix {prefix}] used by {len(names)} entries",
            )
        )
        reused_entries += len(names)

    counts = {
        "weak": len(weak),
        "reused_groups": len(reused),
        "reused_entries": reused_entries,
        "stale": len(stale),
        "missing_username": len(missing_username),
        "missing_url": len(missing_url),
        "entries": len(entries),
    }
    return AuditReport(weak, reused, stale, missing_username, missing_url, counts)


def render_report(
    report: AuditReport, vault_label: str, min_length: int, stale_days: int
) -> str:
    """Render the DESIGN.md audit layout as plain text.

    Sections appear only when non-empty. The NAME column is padded to a
    shared width using east-asian-aware display width so wide characters
    do not break alignment.
    """
    lines = [f"Audit of {vault_label} - {report.counts['entries']} entries"]
    width = max(
        [_display_width(f.name) for f in (*report.weak, *report.stale)]
        + [_NAME_COLUMN_MIN]
    )
    if report.weak:
        lines.append("")
        lines.append(f"weak secrets (length under {min_length} characters)")
        lines.extend(f"  {_pad(f.name, width)}  {f.detail}" for f in report.weak)
    if report.reused:
        lines.append("")
        lines.append("reused secrets (same value in multiple entries)")
        for f in report.reused:
            lines.append(f"  {f.detail}")
            lines.append(f"    {f.name}")
    if report.stale:
        lines.append("")
        lines.append(f"not rotated in {stale_days} days (--stale-days)")
        lines.extend(f"  {_pad(f.name, width)}  {f.detail}" for f in report.stale)
    if report.missing_username:
        lines.append("")
        lines.append("missing username")
        lines.extend(f"  {f.name}" for f in report.missing_username)
    if report.missing_url:
        lines.append("")
        lines.append("missing url")
        lines.extend(f"  {f.name}" for f in report.missing_url)
    c = report.counts
    groups = "group" if c["reused_groups"] == 1 else "groups"
    lines.append("")
    lines.append(
        f"summary: {c['weak']} weak, {c['reused_groups']} reused {groups} "
        f"({c['reused_entries']} entries), {c['stale']} stale, "
        f"{c['missing_username']} missing username, {c['missing_url']} missing url"
    )
    lines.append(_LOCAL_ONLY_LINE)
    return "\n".join(lines) + "\n"


def _is_weak(secret: str, min_length: int) -> bool:
    if len(secret) < min_length:
        return True
    if len(secret) >= _COMPLEXITY_MIN_LENGTH and _count_classes(secret) < 2:
        return True
    return secret.lower() in COMMON_PASSWORDS


def _count_classes(secret: str) -> int:
    classes = 0
    if any(char in _CLASS_UPPERS for char in secret):
        classes += 1
    if any(char in _CLASS_LOWERS for char in secret):
        classes += 1
    if any(char in _CLASS_DIGITS for char in secret):
        classes += 1
    if any(
        char not in _CLASS_UPPERS
        and char not in _CLASS_LOWERS
        and char not in _CLASS_DIGITS
        for char in secret
    ):
        classes += 1
    return classes


def _secret_values(entry: Entry) -> list[str]:
    values = [entry.secret]
    values.extend(f.value for f in entry.fields if f.secret)
    return values


def _parse_timestamp(text: object) -> datetime | None:
    raw = str(text).strip()
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    try:
        stamp = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def _display_width(text: str) -> int:
    return sum(
        2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        for char in text
    )


def _pad(text: str, width: int) -> str:
    return text + " " * max(width - _display_width(text), 0)
