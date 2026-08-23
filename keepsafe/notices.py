"""Shared notice text for Keepsafe.

These strings appear in --help output, on first init, in onboarding, and
in the README. They live in one place so the honest wording never drifts
between surfaces. No marketing language, no reassurance, no emoji.
"""

from __future__ import annotations

UNAUDITED_LINE = (
    "Keepsafe is unaudited software: it has not received professional "
    "cryptographic review. Do not rely on it for high-risk situations."
)

THREAT_MODEL_LINES = [
    "What Keepsafe protects:",
    "  The confidentiality of the vault file at rest, against someone",
    "  who obtains the file but not your passphrase.",
    "",
    "What it does not protect against:",
    "  - malware or any other compromise of this machine",
    "  - keyloggers recording your passphrase as you type it",
    "  - memory inspection of a running Keepsafe process",
    "  - other applications reading your clipboard after a copy",
    "  - anyone using this terminal while a session is unlocked",
    "",
    LOST_PASSPHRASE_LINE := (
        "If you lose the passphrase, the data is gone. There is no recovery, "
        "no reset, and no back door."
    ),
]


def derivation_notice(memory_kib: int, iterations: int) -> str:
    """Explains that slow key derivation is intentional, once per run."""
    mib = memory_kib / 1024
    return (
        f"Deriving key from passphrase (Argon2id, {mib:g} MiB x{iterations}). "
        "This takes a moment by design."
    )


def session_tradeoff_line() -> str:
    return (
        "While a session is unlocked, any process running as your user can use "
        "it; memory inspection of the helper could reveal the key."
    )


def plaintext_export_lines(target: str) -> list[str]:
    """STATE / EFFECT / SCOPE / COST warning shown before export."""
    return [
        f"This will write EVERY entry, including all secret values, to '{target}'.",
        "The output file is plaintext: anything on this machine that can read",
        "your files will be able to read it, including backup tools and sync",
        "clients. This cannot be undone by Keepsafe.",
        "Type 'export-plaintext' (without quotes) to proceed.",
    ]


def rekey_lines() -> list[str]:
    return [
        "Re-keying creates a new vault file with a new salt and KDF parameters.",
        "Existing automatic backups stay encrypted with the OLD parameters and",
        "open only with the OLD passphrase. Keep them until the new file is verified.",
        "Type 'rekey' (without quotes) to proceed.",
    ]
