"""Configuration file handling: ~/.keepsafe/config.json (JSON, UTF-8).

KEEPSAFE_HOME relocates all Keepsafe state (config + default vault
location) to the given directory; this is a documented feature and is
what tests use to stay hermetic. Validation is strict: unknown keys are
ignored with a warning, but known keys with wrong types or out-of-range
values are ConfigError with an exact fix hint -- a silently misread
timeout in a security tool is worse than a loud refusal.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from . import errors
from .storage import atomic_write_bytes

DEFAULTS = {
    "vault_path": "",
    "backup_count": 5,
    "clipboard_timeout": 30,
    "session_timeout": 900,
    "audit_min_length": 12,
    "audit_stale_days": 365,
    "color_theme": "dark",
    "output_mode": "text",
}

# key -> inclusive (minimum, maximum)
_INT_RANGES = {
    "backup_count": (0, 100),
    "clipboard_timeout": (1, 3600),
    "session_timeout": (60, 86400),
    "audit_min_length": (4, 128),
    "audit_stale_days": (1, 36500),
}

_ENUM_CHOICES = {
    "color_theme": ("dark", "light"),
    "output_mode": ("text", "json"),
}


def config_dir() -> Path:
    """Directory holding config.json and the default vault.

    KEEPSAFE_HOME wins when set to a non-empty value (documented way to
    relocate state); otherwise the user's home directory.
    """
    home = os.environ.get("KEEPSAFE_HOME")
    if home:
        return Path(home)
    return Path.home() / ".keepsafe"


def config_path() -> Path:
    return config_dir() / "config.json"


def _display(value: object) -> str:
    # JSON rendering keeps types unambiguous ("5" vs 5 vs true) without
    # ever echoing anything sensitive: config values are not secrets.
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return repr(value)


def _validate(key: str, value: object, path: Path) -> object:
    if key in _INT_RANGES:
        low, high = _INT_RANGES[key]
        # bool is an int subclass; True must not sneak through as 1.
        if isinstance(value, bool) or not isinstance(value, int):
            raise errors.ConfigError(
                f'Config key "{key}" must be a whole number between {low} and '
                f'{high}, found {_display(value)} in {path}. Fix it there, or '
                f'reset it to the default {DEFAULTS[key]}.'
            )
        if not low <= value <= high:
            raise errors.ConfigError(
                f'Config key "{key}" must be between {low} and {high} '
                f'(inclusive), found {value} in {path}. Fix it there, or '
                f'reset it to the default {DEFAULTS[key]}.'
            )
        return value
    if key in _ENUM_CHOICES:
        choices = _ENUM_CHOICES[key]
        if value not in choices:
            raise errors.ConfigError(
                f'Config key "{key}" must be one of '
                f'{", ".join(json.dumps(c) for c in choices)}, found '
                f'{_display(value)} in {path}. Fix it there, or reset it to '
                f'the default "{DEFAULTS[key]}".'
            )
        return value
    # Remaining key: vault_path. Empty string means "use the default place".
    if not isinstance(value, str):
        raise errors.ConfigError(
            f'Config key "vault_path" must be a string (empty string means '
            f'the default location), found {_display(value)} in {path}. Fix '
            f'it there, or reset it to the default "".'
        )
    return value


def load() -> tuple[dict, list[str]]:
    """Load configuration; returns (cfg, warnings).

    Missing file -> a copy of DEFAULTS with no warnings. Invalid JSON ->
    ConfigError. Unknown keys produce warning strings and are dropped.
    Known keys with wrong types or out-of-range values raise ConfigError
    naming the exact fix.
    """
    path = config_path()
    if not path.is_file():
        return dict(DEFAULTS), []
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise errors.ConfigError(
            f"Cannot read configuration file {path}: {exc}. "
            f"Check file permissions, or delete the file to restore defaults."
        ) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise errors.ConfigError(
            f"Configuration file {path} is not valid JSON "
            f"(line {exc.lineno}, column {exc.colno}): {exc.msg}. Fix the "
            f"file, or delete it to restore defaults."
        ) from exc
    if not isinstance(data, dict):
        raise errors.ConfigError(
            f"Configuration file {path} must contain a single JSON object "
            f'with keys such as "vault_path" and "backup_count". Fix the '
            f"file, or delete it to restore defaults."
        )

    cfg = dict(DEFAULTS)
    warnings: list[str] = []
    for key, value in data.items():
        if key not in DEFAULTS:
            warnings.append(
                f'Ignoring unknown configuration key "{key}" in {path}.'
            )
            continue
        cfg[key] = _validate(key, value, path)
    return cfg, warnings


def save(cfg: dict) -> None:
    """Write *cfg* atomically as indented, sorted, UTF-8 JSON."""
    data = json.dumps(cfg, indent=2, sort_keys=True).encode("utf-8")
    atomic_write_bytes(config_path(), data)


def resolve_vault_path(cfg: dict) -> Path:
    """Configured vault location, or <config_dir>/vault.kpsf by default."""
    configured = cfg.get("vault_path") or ""
    if configured:
        return Path(configured)
    return config_dir() / "vault.kpsf"
