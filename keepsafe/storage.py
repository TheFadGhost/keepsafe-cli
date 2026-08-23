"""Vault persistence: atomic writes, backups, restore, rekey.

Durability contract (DESIGN.md "Terminal integrity"): vault writes are
atomic (temp file + os.replace) so a crash leaves either the old or the
new file, never a truncated one, and every mutating action takes an
automatic backup first. ``os.replace`` is the ONLY step that ever touches
the target path, so no failure mode can leave a half-written vault.

This module does file I/O only; entry-level parsing stays with the caller
(``unlock`` returns the raw payload dict; apply model.entries_from_payload
yourself).
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import crypto, errors, model
from .format import KdfParams, VaultHeader, pack_header, serialize_payload
from .format import build_vault_file, open_vault_file

# Microsecond resolution keeps filenames unique across rapid successive
# saves AND sorts lexicographically in chronological order (fixed width,
# zero padded), which is what makes newest-first enumeration trivial.
_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%S%f"
_BACKUP_SUFFIX = ".bak.kpsf"
_TEMP_PREFIX = ".keepsafe-tmp-"


@dataclass
class BackupInfo:
    """One automatic backup, parsed from its filename."""

    path: Path
    timestamp: str


def _timestamp_now() -> str:
    return datetime.now(timezone.utc).strftime(_TIMESTAMP_FORMAT)


def _backups_dir(vault_path: Path) -> Path:
    return vault_path.parent / "backups"


def _scan_backups(vault_path: Path) -> list[BackupInfo]:
    """All well-formed backups for this vault, NEWEST FIRST."""
    backups_dir = _backups_dir(vault_path)
    if not backups_dir.is_dir():
        return []
    prefix = vault_path.stem + "."
    infos: list[BackupInfo] = []
    for p in backups_dir.iterdir():
        name = p.name
        if not p.is_file():
            continue
        if not name.startswith(prefix) or not name.endswith(_BACKUP_SUFFIX):
            continue
        ts = name[len(prefix):-len(_BACKUP_SUFFIX)]
        if not ts:
            continue
        infos.append(BackupInfo(path=p, timestamp=ts))
    # Fixed-width zero-padded UTC timestamps: lexicographic == chronological.
    infos.sort(key=lambda b: b.timestamp, reverse=True)
    return infos


def _prune(vault_path: Path, backup_count: int) -> None:
    for stale in _scan_backups(vault_path)[max(0, backup_count):]:
        try:
            stale.path.unlink()
        except OSError:
            pass


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write *data* to *path* atomically; the target is never left truncated.

    Writes to a uniquely named temp file in the target's directory, flushes,
    fsyncs, closes, then ``os.replace``s it over the target -- replace is
    the only step that touches the target. On ANY failure the temp file is
    removed and errors.Unavailable is raised stating the cause (read-only
    directory, disk full, ...); the previous content of *path* survives
    untouched. Non-Exception interruptions (KeyboardInterrupt) are cleaned
    up after and re-raised unchanged.
    """
    path = Path(path)
    tmp_file = None
    tmp_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=_TEMP_PREFIX, delete=False
        )
        tmp_path = Path(tmp_file.name)
        tmp_file.write(data)
        tmp_file.flush()
        os.fsync(tmp_file.fileno())
        tmp_file.close()
        tmp_file = None
        os.replace(tmp_path, path)
        tmp_path = None
    except BaseException as exc:
        if tmp_file is not None:
            try:
                tmp_file.close()
            except OSError:
                pass
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass
        if isinstance(exc, Exception):
            raise errors.Unavailable(
                f"Could not write '{path}': {exc}. "
                f"Check disk space and folder permissions."
            ) from exc
        raise


def backup_current(vault_path: Path, backup_count: int) -> BackupInfo | None:
    """Copy the current vault into the backups dir, prune to *backup_count*.

    No-op when the vault file does not exist (returns None). The copy
    preserves exact bytes (shutil.copy2). Oldest backups beyond
    *backup_count* are deleted.
    """
    vault_path = Path(vault_path)
    if not vault_path.is_file():
        return None
    backups_dir = _backups_dir(vault_path)
    backups_dir.mkdir(parents=True, exist_ok=True)
    ts = _timestamp_now()
    dest = backups_dir / f"{vault_path.stem}.{ts}{_BACKUP_SUFFIX}"
    shutil.copy2(vault_path, dest)
    _prune(vault_path, backup_count)
    return BackupInfo(path=dest, timestamp=ts)


def _build_blob(key: bytes, salt: bytes, kdf_params: KdfParams, payload: dict) -> bytes:
    """Header + ciphertext using the GIVEN key/salt/params and a fresh nonce.

    Same salt and parameters as the current generation keep unlock costs and
    identity stable; the fresh nonce keeps each encryption unique (the save
    analogue of crypto.seal, with the nonce stored at its header offset).
    """
    payload_bytes = serialize_payload(payload)
    header = VaultHeader(
        version=crypto.FORMAT_VERSION,
        kdf_type=crypto.KDF_TYPE_ARGON2ID,
        salt=salt,
        params=kdf_params,
        nonce=crypto.generate_nonce(),
    )
    header_bytes = pack_header(header, payload_len=len(payload_bytes) + crypto.TAG_SIZE)
    ciphertext = crypto.encrypt(key, header.nonce, payload_bytes, aad=header_bytes)
    return header_bytes + ciphertext


class VaultStore:
    """File-level operations on one vault path plus its backups directory."""

    def __init__(self, vault_path: Path, backup_count: int = 5):
        self.vault_path = Path(vault_path)
        self.backup_count = backup_count

    def exists(self) -> bool:
        return self.vault_path.is_file()

    def read_bytes(self) -> bytes:
        """Raw vault bytes; VaultMissing with the canonical hint if absent."""
        if not self.vault_path.is_file():
            raise errors.VaultMissing(
                f"No vault found at {self.vault_path}. Run: keepsafe init"
            )
        return self.vault_path.read_bytes()

    def create(self, passphrase: str, payload: dict | None = None, force: bool = False) -> None:
        """Create a new vault file; refuses to clobber without *force*.

        Uses the crypto module's default KDF parameters read at call time.
        Ensures the parent directory exists, then writes atomically.
        """
        if self.exists() and not force:
            raise errors.UsageError(
                f"A vault already exists at {self.vault_path}. "
                f"Use force=True (CLI: --force) to overwrite it."
            )
        if payload is None:
            payload = model.new_payload()
        blob, _header = build_vault_file(passphrase, payload)
        atomic_write_bytes(self.vault_path, blob)

    def unlock(self, passphrase: str) -> tuple[VaultHeader, dict]:
        """Authenticate and decrypt; returns (header, payload dict).

        Entry parsing is the caller's job (model.entries_from_payload).
        """
        return open_vault_file(self.read_bytes(), passphrase)

    def save(self, key: bytes, salt: bytes, kdf_params: KdfParams, payload: dict) -> BackupInfo:
        """Back up the current file, then atomically write a new generation.

        Re-encrypts *payload* under the SAME salt and KDF parameters with a
        FRESH nonce; the caller supplies the key it already derived while
        unlocked (no second Argon2 run). Returns the BackupInfo describing
        the pre-write backup.
        """
        if not self.exists():
            raise errors.VaultMissing(
                f"No vault found at {self.vault_path}. Run: keepsafe init"
            )
        info = backup_current(self.vault_path, self.backup_count)
        if info is None:  # vanished between the existence check and backup
            raise errors.InternalError("vault file disappeared during save")
        blob = _build_blob(key, salt, kdf_params, payload)
        atomic_write_bytes(self.vault_path, blob)
        return info

    def rekey(
        self,
        old_passphrase: str,
        new_passphrase: str,
        new_params: KdfParams | None = None,
    ) -> BackupInfo:
        """Rewrite the vault under a new passphrase and/or KDF parameters.

        Opens with *old_passphrase* (wrong passphrase or damage ->
        UnlockFailed before anything is written), then writes with a fresh
        salt and nonce. Keeps the old parameters unless *new_params* is
        given. Backs up the current file first.
        """
        header, payload = self.unlock(old_passphrase)
        params = new_params if new_params is not None else header.params
        salt = crypto.generate_salt()
        key = crypto.derive_key(
            new_passphrase,
            salt,
            memory_kib=params.memory_kib,
            iterations=params.iterations,
            parallelism=params.parallelism,
        )
        info = backup_current(self.vault_path, self.backup_count)
        if info is None:
            raise errors.InternalError("vault file disappeared during rekey")
        atomic_write_bytes(self.vault_path, _build_blob(key, salt, params, payload))
        return info

    def backups(self) -> list[BackupInfo]:
        """Enumerate automatic backups for this vault, newest first."""
        return _scan_backups(self.vault_path)

    def restore_backup(self, info: BackupInfo) -> None:
        """Replace the vault with *info*'s content, backing up current first.

        The current file is backed up BEFORE the restore so a mistaken
        restore is itself reversible. Raises Unavailable if the backup file
        has been pruned or deleted since it was enumerated.
        """
        if not info.path.is_file():
            raise errors.Unavailable(
                f"Backup file not found: {info.path}. It may have been pruned or "
                f"deleted; list backups again to see what remains."
            )
        backup_current(self.vault_path, self.backup_count)
        atomic_write_bytes(self.vault_path, info.path.read_bytes())
