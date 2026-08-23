"""Terminal prompts for Keepsafe.

Every prompt is explicit about hidden input. Passphrases and secrets are
read through getpass, so nothing echoes - not dots, not asterisks, nothing.
Prompt text never contains secret values. Nothing here writes to logs.
"""

from __future__ import annotations

import getpass
import sys

from . import errors

# Indirection so tests can feed scripted input without a tty.
getpass_fn = getpass.getpass
input_fn = input


def _read_hidden(label: str) -> str:
    try:
        return getpass_fn(label)
    except EOFError:
        raise AbortedByUserEOF() from None
    except StopIteration:
        # A scripted/exhausted input stream means the user could not
        # answer; treat it exactly like a closed stdin.
        raise AbortedByUserEOF() from None


def _read_visible(label: str) -> str:
    try:
        return input_fn(label)
    except EOFError:
        raise AbortedByUserEOF() from None
    except StopIteration:
        raise AbortedByUserEOF() from None


class AbortedByUserEOF(errors.AbortedByUser):
    """Input stream ended during a prompt; nothing was changed."""

    def __init__(self) -> None:
        super().__init__("input ended before the prompt was answered; nothing was changed")


def ask_passphrase(vault_label: str) -> str:
    """Prompt for an existing vault's passphrase (hidden input)."""
    return _read_hidden(f"Passphrase for {vault_label} (input hidden): ")


def ask_new_passphrase(confirm: bool = True) -> str:
    """Prompt for a new passphrase, asking once more on mismatch.

    On a mismatch the prompt repeats once with the wording below before
    aborting, so one slipped keystroke does not throw away the whole
    form. Aborts without writing anything after the retry fails.
    """
    attempts = 2 if confirm else 1
    first = ""
    for attempt in range(attempts):
        first = _read_hidden("New passphrase (input hidden): ")
        if not first:
            raise errors.UsageError(
                "passphrase must not be empty; nothing was written"
            )
        if not confirm:
            return first
        second = _read_hidden("Confirm passphrase (input hidden): ")
        if first == second:
            return first
        remaining = attempts - attempt - 1
        if remaining > 0:
            print("did not match, try again", file=sys.stderr)
    raise errors.UsageError(
        "the two passphrases did not match; nothing was written"
    )


def ask_optional_visible(label: str) -> str:
    """Visible single-line input; empty answer means 'leave empty'."""
    return _read_visible(f"{label}: ")


def ask_secret_value(label: str = "Secret") -> str:
    """Hidden input for an entry secret."""
    value = _read_hidden(f"{label} (input hidden): ")
    if not value:
        raise errors.UsageError("secret must not be empty")
    return value


def ask_yes_no(question: str, default: bool = False) -> bool:
    """y/n confirmation for reversible-but-risky actions."""
    suffix = " [y/n] " if default is None else (" [Y/n] " if default else " [y/N] ")
    for _ in range(3):
        try:
            answer = _read_visible(question + suffix).strip().lower()
        except AbortedByUserEOF:
            return False
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no", ""):
            return False
    return False


def confirm_phrase(statement_lines: list[str], phrase: str, attempts: int = 2) -> bool:
    """Typed-phrase gate for irreversible actions.

    Prints the warning block, then requires typing the exact phrase.
    A bare y/n is insufficient here: one keystroke of habit must not be
    able to trigger an irreversible action (DESIGN.md). An exhausted or
    closed input stream counts as a decline, never as consent.
    """
    for line in statement_lines:
        print(line, file=sys.stderr)
    for attempt in range(attempts):
        try:
            typed = _read_visible(
                f"Type '{phrase}' to proceed (anything else aborts): "
            )
        except AbortedByUserEOF:
            return False
        if typed == phrase:
            return True
        remaining = attempts - attempt - 1
        if remaining > 0:
            print(
                f"Did not match. {remaining} attempt(s) left, then this aborts.",
                file=sys.stderr,
            )
    return False


def ask_visible_default(label: str) -> str:
    """Visible input where an empty answer means 'keep as is'."""
    return _read_visible(f"{label}: ")
