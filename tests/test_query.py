"""Tests for keepsafe.query: sorting, folders, search, tags, trees."""

from __future__ import annotations

import pytest

from keepsafe.errors import UsageError
from keepsafe.model import Entry
from keepsafe.query import (
    build_tree,
    filter_folder,
    filter_tags,
    render_tree,
    search,
    sort_entries,
)


def make(names, **shared):
    return [Entry(name=name, **shared) for name in names]


def vault():
    return make(
        [
            "mail/bank",
            "mail/work/list",
            "mailbox/a",
            "servers/prod/db",
            "standalone",
            "web/github",
        ]
    )


# ---------------------------------------------------------------------------
# 1. sort_entries: codepoint order, stability, no mutation
# ---------------------------------------------------------------------------


def test_sort_entries_codepoint_order_case_and_unicode():
    entries = make(
        ["web/github", "Zebra", "apple", "Apple", "zebra", "éclair"]
    )
    assert [e.name for e in sort_entries(entries)] == [
        "Apple",
        "Zebra",
        "apple",
        "web/github",
        "zebra",
        "éclair",
    ]


def test_sort_entries_is_stable_for_equal_names():
    tie_b = Entry(name="dup", username="was-listed-first")
    tie_a = Entry(name="dup", username="was-listed-second")
    entries = [tie_b, Entry(name="aaa"), tie_a]
    ordered = sort_entries(entries)
    assert [e.username for e in ordered if e.name == "dup"] == [
        "was-listed-first",
        "was-listed-second",
    ]
    assert ordered is not entries


def test_sort_entries_does_not_mutate_input():
    entries = make(["b/x", "a/y"])
    original = [e.name for e in entries]
    sort_entries(entries)
    assert [e.name for e in entries] == original


def test_sort_entries_empty():
    assert sort_entries([]) == []


# ---------------------------------------------------------------------------
# 2. filter_folder: subtree selection and validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("folder", [None, ""])
def test_filter_folder_none_or_empty_selects_all_sorted(folder):
    entries = list(reversed(vault()))
    expected = sorted(e.name for e in entries)
    assert [e.name for e in filter_folder(entries, folder)] == expected


def test_filter_folder_selects_entry_at_folder_and_deep_descendants():
    result = filter_folder(vault(), "mail")
    assert [e.name for e in result] == ["mail/bank", "mail/work/list"]


def test_filter_folder_never_matches_sibling_prefix():
    names = [e.name for e in filter_folder(vault(), "mail")]
    assert "mailbox/a" not in names


def test_filter_folder_exact_entry_path_returns_single_entry():
    result = filter_folder(vault(), "servers/prod/db")
    assert [e.name for e in result] == ["servers/prod/db"]


def test_filter_folder_returns_path_and_its_children_together():
    entries = make(["web/github", "web/github/cli", "web/gitlab"])
    result = filter_folder(entries, "web/github")
    assert [e.name for e in result] == ["web/github", "web/github/cli"]


def test_filter_folder_unknown_folder_yields_empty_list_not_error():
    assert filter_folder(vault(), "nope") == []
    assert filter_folder(vault(), "mail/sub/none") == []


@pytest.mark.parametrize(
    "folder",
    ["/mail", "mail/", "mail//x", ".", "..", "a/../b", "a\\b", " mail"],
)
def test_filter_folder_rejects_malformed_prefixes(folder):
    with pytest.raises(UsageError):
        filter_folder(vault(), folder)


# ---------------------------------------------------------------------------
# 3. search: field coverage, precedence, ordering, validation
# ---------------------------------------------------------------------------


def searchable_vault():
    return [
        Entry(
            name="web/github",
            username="octocat",
            url="https://github.com",
            notes="code hosting",
            tags=["dev", "git"],
        ),
        Entry(
            name="mail/bank",
            username="user@example.com",
            url="https://bank.example",
            notes="",
            tags=["finance"],
        ),
        Entry(
            name="servers/prod",
            username="admin",
            url="",
            notes="primary database server",
            tags=["prod"],
        ),
        Entry(name="Alpha", username="beta", url="", notes="", tags=["Gamma"]),
    ]


def test_search_hits_name_field():
    hits = search(searchable_vault(), "github")
    assert [(e.name, field) for e, field in hits] == [("web/github", "name")]


def test_search_hits_username_case_insensitively():
    hits = search(searchable_vault(), "OCTOCAT")
    assert [(e.name, field) for e, field in hits] == [
        ("web/github", "username")
    ]


def test_search_hits_url_case_insensitively():
    hits = search(searchable_vault(), "Bank.Example")
    assert [(e.name, field) for e, field in hits] == [("mail/bank", "url")]


def test_search_hits_notes():
    hits = search(searchable_vault(), "DATABASE")
    assert [(e.name, field) for e, field in hits] == [
        ("servers/prod", "notes")
    ]


def test_search_tag_match_reported_as_tag():
    hits = search(searchable_vault(), "gamma")
    assert [(e.name, field) for e, field in hits] == [("Alpha", "tag")]
    hits = search(searchable_vault(), "FIN")
    assert [(e.name, field) for e, field in hits] == [("mail/bank", "tag")]


def test_search_first_matching_field_wins():
    entry = Entry(name="octo", username="octo-cat", notes="octo notes")
    hits = search([entry], "octo")
    assert hits[0][1] == "name"


def test_search_results_sorted_by_entry_name():
    entries = [
        Entry(name="zzz/user", username="needle"),
        Entry(name="aaa/user", username="needle"),
    ]
    hits = search(entries, "needle")
    assert [e.name for e, _ in hits] == ["aaa/user", "zzz/user"]


def test_search_no_match_returns_empty_list_not_error():
    assert search(searchable_vault(), "does-not-exist") == []


@pytest.mark.parametrize("query", ["", "   ", "\t\n "])
def test_search_blank_query_raises_usage_error(query):
    with pytest.raises(UsageError):
        search(searchable_vault(), query)


# ---------------------------------------------------------------------------
# 4. filter_tags: AND semantics, case-sensitivity
# ---------------------------------------------------------------------------


def tagged_vault():
    return [
        Entry(name="a/dev", tags=["dev"]),
        Entry(name="a/dev-prod", tags=["dev", "prod"]),
        Entry(name="a/prod", tags=["prod"]),
        Entry(name="a/all", tags=["dev", "prod", "ops"]),
    ]


def test_filter_tags_requires_every_requested_tag():
    result = filter_tags(tagged_vault(), {"dev", "prod"})
    assert [e.name for e in result] == ["a/all", "a/dev-prod"]


def test_filter_tags_single_tag():
    result = filter_tags(tagged_vault(), {"ops"})
    assert [e.name for e in result] == ["a/all"]


def test_filter_tags_is_case_sensitive():
    entries = [Entry(name="x", tags=["DEV"])]
    assert filter_tags(entries, {"dev"}) == []
    assert [e.name for e in filter_tags(entries, {"DEV"})] == ["x"]


def test_filter_tags_empty_set_selects_all_sorted():
    entries = list(reversed(tagged_vault()))
    result = filter_tags(entries, set())
    assert [e.name for e in result] == [
        "a/all",
        "a/dev",
        "a/dev-prod",
        "a/prod",
    ]


def test_filter_tags_no_matches_returns_empty_list():
    assert filter_tags(tagged_vault(), {"missing"}) == []


# ---------------------------------------------------------------------------
# 5. build_tree + render_tree: nesting, sorting, indentation
# ---------------------------------------------------------------------------


TREE_NAMES = [
    "standalone",
    "web/gitlab",
    "servers/staging",
    "servers/prod/db",
    "mail/bank",
    "servers/prod/api",
    "web/github",
]


def test_build_tree_shape_nested_folders_and_sorted_leaves():
    root = build_tree(make(TREE_NAMES))
    assert set(root["folders"]) == {"mail", "servers", "web"}
    assert root["entries"] == ["standalone"]
    servers = root["folders"]["servers"]
    assert set(servers["folders"]) == {"prod"}
    assert servers["entries"] == ["staging"]
    assert servers["folders"]["prod"]["entries"] == ["api", "db"]
    web = root["folders"]["web"]
    assert web["entries"] == ["github", "gitlab"]


def test_build_tree_empty_vault():
    assert build_tree([]) == {"folders": {}, "entries": []}


def test_render_tree_folders_first_then_entries_two_space_indent():
    lines = render_tree(build_tree(make(TREE_NAMES)))
    assert lines == [
        "mail",
        "  bank",
        "servers",
        "  prod",
        "    api",
        "    db",
        "  staging",
        "web",
        "  github",
        "  gitlab",
        "standalone",
    ]


def test_render_tree_no_box_characters():
    lines = render_tree(build_tree(make(TREE_NAMES)))
    banned = set("─│┌┐└┘├┤┬┴┼═║╔╗╚╝╠╣╦╩╬▏▕")
    joined = "".join(lines)
    assert not (set(joined) & banned)
    for line in lines:
        stripped = len(line) - len(line.lstrip(" "))
        assert stripped % 2 == 0
