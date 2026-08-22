"""Entry model and path semantics for Keepsafe.

An entry lives at a slash-separated path such as ``web/github`` or
``servers/prod/db``. Folders have no independent existence; they are
implied by paths. Paths are case-sensitive, forward-slash-separated on
every platform (including Windows), and never contain drive letters or
backslashes - this is a namespace inside one file, not filesystem paths.

This module is pure data: no I/O, no crypto, no terminal output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

MAX_PATH_LEN = 512
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def utc_now_iso() -> str:
    """Current UTC time as ISO 8601 with explicit offset."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_path(name: object) -> str:
    """Validate and return an entry path unchanged (str in, str out).

    Raises ValueError with a precise reason on invalid input. Rules:
    1..MAX_PATH_LEN characters; split on '/'; every segment non-empty;
    segments '.' and '..' forbidden; backslash forbidden anywhere;
    control characters forbidden; no leading/trailing whitespace.
    """
    if not isinstance(name, str):
        raise ValueError("entry path must be a string")
    if not name:
        raise ValueError("entry path must not be empty")
    if len(name) > MAX_PATH_LEN:
        raise ValueError(f"entry path longer than {MAX_PATH_LEN} characters")
    if name != name.strip():
        raise ValueError("entry path must not start or end with whitespace")
    if "\\" in name:
        raise ValueError("backslash is not valid in an entry path; use '/'")
    if _CONTROL_CHARS.search(name):
        raise ValueError("control characters are not valid in an entry path")
    segments = name.split("/")
    for segment in segments:
        if not segment:
            raise ValueError("empty path segment (repeated or edge '/')")
        if segment in (".", ".."):
            raise ValueError("'.' and '..' are not valid path segments")
        if segment != segment.strip():
            raise ValueError("path segments must not start or end with whitespace")
    return name


def parent_path(name: str) -> str | None:
    """Parent folder of a path, or None for a top-level entry."""
    validate_path(name)
    idx = name.rfind("/")
    return None if idx == -1 else name[:idx]


def leaf_name(name: str) -> str:
    """Final segment of a path ('servers/prod/db' -> 'db')."""
    validate_path(name)
    return name.rsplit("/", 1)[-1]


def join_path(folder: str | None, leaf: str) -> str:
    """Join an optional folder prefix and a validated single segment."""
    if "/" in leaf or not leaf or leaf.strip() != leaf:
        raise ValueError(f"invalid entry name segment: {leaf!r}")
    leaf = validate_path(leaf)
    if folder is None or folder == "":
        return leaf
    return f"{validate_path(folder)}/{leaf}"


@dataclass
class Field:
    """A custom field attached to an entry."""

    key: str
    value: str = ""
    secret: bool = False


@dataclass
class Entry:
    """One vault entry: identity, secret material, metadata."""

    name: str
    username: str = ""
    secret: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    created: str = field(default_factory=utc_now_iso)
    updated: str = field(default_factory=utc_now_iso)
    fields: list[Field] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.name = validate_path(self.name)
        if not isinstance(self.username, str):
            raise ValueError("username must be a string")
        if not isinstance(self.secret, str):
            raise ValueError("secret must be a string")
        if not isinstance(self.url, str):
            raise ValueError("url must be a string")
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")
        self.tags = _validated_tags(self.tags)
        self.fields = [_validated_field(f) for f in self.fields]

    def touch(self, when: str | None = None) -> None:
        """Mark the entry updated now (or at an explicit ISO timestamp)."""
        self.updated = when or utc_now_iso()

    def to_dict(self) -> dict:
        """Full representation used inside encrypted payloads."""
        return {
            "name": self.name,
            "username": self.username,
            "secret": self.secret,
            "url": self.url,
            "notes": self.notes,
            "tags": list(self.tags),
            "created": self.created,
            "updated": self.updated,
            "fields": [
                {"key": f.key, "value": f.value, "secret": bool(f.secret)}
                for f in self.fields
            ],
        }

    def redacted_dict(self) -> dict:
        """Representation safe for display and machine output.

        Secret-valued keys are replaced by the fixed mask; lengths and
        content stay hidden. Machine-readable output omits these keys
        entirely instead (see render.py), but this form exists for any
        caller that needs shape parity with to_dict().
        """
        mask = "********"
        return {
            "name": self.name,
            "username": self.username,
            "secret": mask if self.secret else "",
            "url": self.url,
            "notes": self.notes,
            "tags": list(self.tags),
            "created": self.created,
            "updated": self.updated,
            "fields": [
                {
                    "key": f.key,
                    "value": mask if f.secret else f.value,
                    "secret": bool(f.secret),
                }
                for f in self.fields
            ],
        }

    @classmethod
    def from_dict(cls, data: object) -> "Entry":
        """Build an Entry from payload JSON, validating everything.

        Unknown keys raise ValueError: the payload is authenticated at
        this point, so weird shapes mean a bug, and failing loudly beats
        silently dropping data.
        """
        if not isinstance(data, dict):
            raise ValueError("entry must be a JSON object")
        required = {
            "name", "username", "secret", "url", "notes",
            "tags", "created", "updated", "fields",
        }
        missing = required - set(data)
        extra = set(data) - required
        if missing:
            raise ValueError(f"entry missing fields: {sorted(missing)}")
        if extra:
            raise ValueError(f"entry has unknown fields: {sorted(extra)}")
        for key in ("name", "username", "secret", "url", "notes", "created", "updated"):
            if not isinstance(data[key], str):
                raise ValueError(f"entry field '{key}' must be a string")
        return cls(
            name=data["name"],
            username=data["username"],
            secret=data["secret"],
            url=data["url"],
            notes=data["notes"],
            tags=_validated_tags(data["tags"]),
            created=data["created"],
            updated=data["updated"],
            fields=[_validated_field(f) for f in data["fields"]],
        )


def new_payload() -> dict:
    """Empty vault payload matching FORMAT.md."""
    return {"format": 1, "entries": {}}


def payload_from_entries(entries: list[Entry]) -> dict:
    """Build a payload dict from entries, keyed by path."""
    payload = new_payload()
    for entry in entries:
        if entry.name in payload["entries"]:
            raise ValueError(f"duplicate entry path: {entry.name}")
        payload["entries"][entry.name] = entry.to_dict()
    return payload


def entries_from_payload(payload: object) -> list[Entry]:
    """Parse and validate a payload dict into a list of Entries."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    fmt = payload.get("format")
    if not isinstance(fmt, int):
        raise ValueError("payload 'format' must be an integer")
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, dict):
        raise ValueError("payload 'entries' must be an object")
    result = []
    for key, value in raw_entries.items():
        if not isinstance(key, str) or not key:
            raise ValueError("entry keys must be non-empty strings")
        entry = Entry.from_dict(value)
        if entry.name != key:
            raise ValueError(
                f"entry key '{key}' does not match entry name '{entry.name}'"
            )
        result.append(entry)
    result.sort(key=lambda e: e.name)
    return result


def _validated_tags(tags: object) -> list[str]:
    if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
        raise ValueError("tags must be a list of strings")
    out = []
    for tag in tags:
        cleaned = tag.strip()
        if not cleaned:
            continue
        if "," in cleaned:
            raise ValueError("tags must not contain commas")
        if cleaned not in out:
            out.append(cleaned)
    return out


def _validated_field(raw: object) -> Field:
    if isinstance(raw, Field):
        if not raw.key or _CONTROL_CHARS.search(raw.key):
            raise ValueError("custom field key must be non-empty printable text")
        return Field(key=raw.key, value=str(raw.value), secret=bool(raw.secret))
    if not isinstance(raw, dict):
        raise ValueError("custom field must be an object")
    unknown = set(raw) - {"key", "value", "secret"}
    if unknown:
        raise ValueError(f"custom field has unknown keys: {sorted(unknown)}")
    key = raw.get("key")
    if not isinstance(key, str) or not key or _CONTROL_CHARS.search(key):
        raise ValueError("custom field key must be non-empty printable text")
    value = raw.get("value", "")
    if not isinstance(value, str):
        raise ValueError("custom field value must be a string")
    return Field(key=key, value=value, secret=bool(raw.get("secret", False)))
