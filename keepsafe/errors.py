"""Exception taxonomy shared by every Keepsafe module.

Each class maps to exactly one exit code (see DESIGN.md). Modules raise
these instead of bare Exceptions so the CLI can produce the canonical
phrasing and never leak whether an entry exists or a passphrase was
partially correct. Exception argument text must obey the no-leak rule:
never embed secret values, passphrases, or entry-existence hints beyond
what the user themselves just typed.
"""

from __future__ import annotations


class KeepsafeError(Exception):
    """Base class. Exit code 4 (usage/configuration family)."""

    exit_code = 4


class UsageError(KeepsafeError):
    """The command was invoked incorrectly."""

    exit_code = 4


class ConfigError(KeepsafeError):
    """The configuration file is unreadable or invalid."""

    exit_code = 4


class VaultMissing(KeepsafeError):
    """No vault file exists at the requested path."""

    exit_code = 4


class UnlockFailed(KeepsafeError):
    """Authentication failed: wrong passphrase, damaged, or tampered file.

    Deliberately one message for all three causes; see DESIGN.md.
    """

    exit_code = 2


class VaultTooNew(KeepsafeError):
    """The vault's format version is newer than this software knows."""

    exit_code = 2


class NotAKeepsafeVault(KeepsafeError):
    """The file exists but its magic bytes are not a Keepsafe vault."""

    exit_code = 2


class NotMatched(KeepsafeError):
    """No entry matched the requested name or query."""

    exit_code = 3


class Unavailable(KeepsafeError):
    """A required facility is missing on this platform/environment.

    Examples: no clipboard mechanism, read-only directory, disk full.
    """

    exit_code = 5


class InternalError(KeepsafeError):
    """An unexpected internal condition. Output is sanitized upstream."""

    exit_code = 10


class AbortedByUser(KeepsafeError):
    """The user declined a confirmation or interrupted a prompt.

    Nothing was changed, so this is not an error: exit code 0.
    """

    exit_code = 0
