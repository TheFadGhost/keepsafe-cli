"""Pure query helpers over lists of entries.

Sorting, folder scoping, substring search, tag filtering, and tree
building for the list/search commands. Everything here is pure: no I/O,
no terminal output, no colour (rendering lives in render.py per
DESIGN.md "Colour"). Canonical ordering everywhere is entry-name
codepoint order, matching DESIGN.md "List and search layout".
"""

from __future__ import annotations

from keepsafe.errors import UsageError
from keepsafe.model import Entry, validate_path


def sort_entries(entries: list[Entry]) -> list[Entry]:
    """Entries sorted by name in codepoint order; the input list is
    never mutated and ties keep their original relative order."""
    return sorted(entries, key=lambda entry: entry.name)


def filter_folder(entries: list[Entry], folder: str | None) -> list[Entry]:
    """Entries at ``folder`` itself plus every deeper descendant.

    ``None`` or "" selects everything (sorted). A concrete folder must
    obey the same shape rules as an entry path used as a prefix: in
    particular no leading or trailing slash, no empty segments, no
    backslash or control characters; violations raise UsageError. A
    folder with no matches yields an empty list, not an error.
    """
    if folder is None or folder == "":
        return sort_entries(entries)
    try:
        validate_path(folder)
    except ValueError as exc:
        raise UsageError(f"invalid folder: {exc}") from None
    prefix = folder + "/"
    matched = [
        entry
        for entry in entries
        if entry.name == folder or entry.name.startswith(prefix)
    ]
    return sorted(matched, key=lambda entry: entry.name)


def search(entries: list[Entry], query: str) -> list[tuple[Entry, str]]:
    """Case-insensitive substring search across the visible fields.

    Each entry's fields are tried in fixed order - name, username, url,
    notes, then any single tag - and the first field that contains the
    query decides the reported match name, which is one of "name",
    "username", "url", "notes", "tag". Results are sorted by entry name.
    An empty or whitespace-only query raises UsageError.
    """
    if not isinstance(query, str) or not query.strip():
        raise UsageError("search query must not be empty")
    needle = query.casefold()
    hits: list[tuple[Entry, str]] = []
    for entry in entries:
        field_name = _match_entry(entry, needle)
        if field_name is not None:
            hits.append((entry, field_name))
    hits.sort(key=lambda pair: pair[0].name)
    return hits


def filter_tags(entries: list[Entry], tags: set[str]) -> list[Entry]:
    """Entries carrying EVERY requested tag; comparison is exact and
    therefore case-sensitive. Output is sorted by entry name."""
    required = set(tags)
    matched = [entry for entry in entries if required <= set(entry.tags)]
    return sorted(matched, key=lambda entry: entry.name)


def build_tree(entries: list[Entry]) -> dict:
    """Nested folder tree shaped ``{"folders": {name: subnode},
    "entries": [leaf names]}``, recursing to arbitrary depth. Leaf name
    lists come out sorted because entries are visited in name order."""
    root: dict = {"folders": {}, "entries": []}
    for entry in sort_entries(entries):
        segments = entry.name.split("/")
        node = root
        for segment in segments[:-1]:
            node = node["folders"].setdefault(
                segment, {"folders": {}, "entries": []}
            )
        node["entries"].append(segments[-1])
    return root


def render_tree(node: dict) -> list[str]:
    """Tree lines for ``--tree`` output: folders first (sorted), then
    entries (sorted), indented two spaces per depth level. No
    box-drawing characters, indentation only (DESIGN.md "List and
    search layout")."""
    lines: list[str] = []
    _walk_tree(node, 0, lines)
    return lines


def _walk_tree(node: dict, depth: int, lines: list[str]) -> None:
    folders = node.get("folders", {})
    for name in sorted(folders):
        lines.append("  " * depth + name)
        _walk_tree(folders[name], depth + 1, lines)
    for leaf in sorted(node.get("entries", [])):
        lines.append("  " * depth + leaf)


def _match_entry(entry: Entry, needle: str) -> str | None:
    for attribute in ("name", "username", "url", "notes"):
        if needle in getattr(entry, attribute).casefold():
            return attribute
    for tag in entry.tags:
        if needle in tag.casefold():
            return "tag"
    return None
