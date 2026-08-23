"""Tests for keepsafe.storage (atomicity, backups, rekey) and keepsafe.config.

Crash-simulation section proves the durability contract: when a write
fails at any stage -- replace, mid-write, fsync -- the previous vault file
is byte-for-byte intact and no temp files are left behind.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

import keepsafe.crypto as crypto
import keepsafe.errors as errors
import keepsafe.storage as storage
from keepsafe import config
from keepsafe.format import GENERIC_UNLOCK_MESSAGE, KdfParams
from keepsafe.model import Entry, Field, entries_from_payload, new_payload, payload_from_entries
from keepsafe.storage import BackupInfo, VaultStore, atomic_write_bytes, backup_current

from tests.kdf_seam import use_fast_kdf  # noqa: F401  (fixture)

PASSPHRASE = "correct horse battery staple"
PASSPHRASE_2 = "second secret passphrase"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_entry(name: str, secret: str, when: str = "2026-08-22T12:00:00+00:00") -> Entry:
    return Entry(
        name=name,
        username="user@example.com",
        secret=secret,
        url="https://example.com",
        notes=f"notes for {name}",
        tags=["tag1"],
        created=when,
        updated=when,
        fields=[Field(key="recovery", value="abcd", secret=True)],
    )


def derived_key_for(passphrase: str, store: VaultStore):
    """Key/salt/params triple matching the vault currently on disk."""
    header, _payload = store.unlock(passphrase)
    key = crypto.derive_key(
        passphrase,
        header.salt,
        memory_kib=header.params.memory_kib,
        iterations=header.params.iterations,
        parallelism=header.params.parallelism,
    )
    return key, header.salt, header.params


@pytest.fixture
def store(tmp_path, use_fast_kdf) -> VaultStore:
    s = VaultStore(tmp_path / "vault.kpsf", backup_count=3)
    s.create(PASSPHRASE)
    return s


# ---------------------------------------------------------------------------
# Basic lifecycle
# ---------------------------------------------------------------------------

class TestCreateUnlockSave:
    def test_round_trip_preserves_entries_exactly(self, store):
        entries_v1 = [make_entry("web/github", "gh-secret"), make_entry("邮件/bank", "银行🔑")]
        store.unlock(PASSPHRASE)
        key, salt, params = derived_key_for(PASSPHRASE, store)
        store.save(key, salt, params, payload_from_entries(entries_v1))
        header, payload = store.unlock(PASSPHRASE)
        assert header.params == params
        assert entries_from(payload) == sorted(entries_v1, key=lambda e: e.name)

    def test_save_rewrites_with_same_salt_fresh_nonce(self, store):
        key, salt, params = derived_key_for(PASSPHRASE, store)
        before_header, _ = store.unlock(PASSPHRASE)
        info = store.save(key, salt, params, new_payload())
        after_header, _ = store.unlock(PASSPHRASE)
        assert isinstance(info, BackupInfo)
        assert after_header.salt == before_header.salt == salt
        assert after_header.nonce != before_header.nonce
        assert after_header.params == params

    def test_unlock_returns_payload_dict_caller_parses(self, store):
        _header, payload = store.unlock(PASSPHRASE)
        assert payload == new_payload()
        assert payload["format"] == 1 and payload["entries"] == {}

    def test_create_twice_without_force_fails_with_force_succeeds(self, tmp_path, use_fast_kdf):
        s = VaultStore(tmp_path / "v.kpsf")
        s.create(PASSPHRASE)
        with pytest.raises(errors.UsageError):
            s.create(PASSPHRASE_2)
        assert s.exists()
        s.create(PASSPHRASE_2, force=True)
        # opens under the NEW passphrase, not the old
        _header, payload = s.unlock(PASSPHRASE_2)
        assert payload == new_payload()
        with pytest.raises(errors.UnlockFailed):
            s.unlock(PASSPHRASE)

    def test_create_makes_parent_directories(self, tmp_path, use_fast_kdf):
        deep = tmp_path / "a" / "b" / "vault.kpsf"
        VaultStore(deep).create(PASSPHRASE)
        assert deep.is_file()

    def test_missing_vault_exact_design_md_phrasing(self, tmp_path, use_fast_kdf):
        s = VaultStore(tmp_path / "nope.kpsf")
        expected = f"No vault found at {tmp_path / 'nope.kpsf'}. Run: keepsafe init"
        with pytest.raises(errors.VaultMissing) as excinfo:
            s.read_bytes()
        assert str(excinfo.value) == expected
        with pytest.raises(errors.VaultMissing):
            s.unlock(PASSPHRASE)
        with pytest.raises(errors.VaultMissing):
            s.save(b"k" * 32, b"s" * 32, KdfParams(**crypto.get_default_kdf_params()), new_payload())


def entries_from(payload: dict):
    return entries_from_payload(payload)


# ---------------------------------------------------------------------------
# Backups: creation, ordering, pruning, restore
# ---------------------------------------------------------------------------

class TestBackupsAndRestore:
    def test_each_save_creates_exactly_one_new_backup_newest_first(self, store):
        assert store.backups() == []
        key, salt, params = derived_key_for(PASSPHRASE, store)
        first = store.save(key, salt, params, new_payload())
        second = store.save(key, salt, params, new_payload())
        infos = store.backups()
        assert len(infos) == 2
        assert infos[0].timestamp > infos[1].timestamp
        assert infos[0].path == second.path
        assert infos[1].path == first.path

    def test_pruning_respects_backup_count(self, tmp_path, use_fast_kdf):
        s = VaultStore(tmp_path / "vault.kpsf", backup_count=3)
        s.create(PASSPHRASE)
        key, salt, params = derived_key_for(PASSPHRASE, s)
        for i in range(7):
            payload = {"format": 1, "entries": {f"e{i}": make_entry(f"e{i}", f"s{i}").to_dict()}}
            s.save(key, salt, params, payload)
        infos = s.backups()
        assert len(infos) == 3
        assert all(i.timestamp > j.timestamp for i, j in zip(infos, infos[1:]))

    def test_restore_backup_restores_previous_content_at_entry_level(self, store):
        entries_v1 = [make_entry("alpha/one", "secret-one")]
        store.create(PASSPHRASE, payload_from_entries(entries_v1), force=True)
        key, salt, params = derived_key_for(PASSPHRASE, store)
        entries_v2 = entries_v1 + [make_entry("beta/two", "secret-two")]
        store.save(key, salt, params, payload_from_entries(entries_v2))

        _header, payload_now = store.unlock(PASSPHRASE)
        assert {e.name for e in entries_from(payload_now)} == {"alpha/one", "beta/two"}

        before_restore = len(store.backups())
        store.restore_backup(store.backups()[0])
        assert len(store.backups()) == before_restore + 1  # current backed up first

        _header, payload_restored = store.unlock(PASSPHRASE)
        restored = entries_from(payload_restored)
        assert restored == entries_v1
        assert restored[0].secret == "secret-one"
        assert restored[0].created == "2026-08-22T12:00:00+00:00"

    def test_backups_scans_only_this_stem_and_ignores_junk(self, store, tmp_path):
        backups_dir = tmp_path / "backups"
        backups_dir.mkdir(parents=True, exist_ok=True)
        (backups_dir / "vault.20200101T000000000000.bak.kpsf").write_bytes(b"x")
        (backups_dir / "other.20200101T000000000000.bak.kpsf").write_bytes(b"x")
        (backups_dir / "unrelated.txt").write_bytes(b"x")
        (backups_dir / "subdir").mkdir()
        assert [i.path.name for i in store.backups()] == [
            "vault.20200101T000000000000.bak.kpsf"
        ]

    def test_backup_current_noop_when_vault_missing(self, tmp_path, use_fast_kdf):
        missing = tmp_path / "ghost.kpsf"
        assert backup_current(missing, 5) is None
        assert not (tmp_path / "backups").exists()

    def test_restore_missing_backup_file_raises_unavailable(self, store):
        stale = BackupInfo(path=store.vault_path.parent / "backups" / "gone.bak.kpsf",
                           timestamp="20200101T000000000000")
        with pytest.raises(errors.Unavailable):
            store.restore_backup(stale)


# ---------------------------------------------------------------------------
# Crash simulation: failures must never damage the existing vault
# ---------------------------------------------------------------------------

def assert_crash_guarantees(tmp_path, store, original_digest):
    """Original vault byte-identical; zero temp files left in the directory."""
    assert store.vault_path.is_file()
    assert digest(store.vault_path) == original_digest
    leftovers = list(store.vault_path.parent.glob(".keepsafe-tmp-*"))
    assert leftovers == []


class TestCrashSimulation:
    def test_os_replace_failure_mid_save(self, monkeypatch, store, tmp_path):
        key, salt, params = derived_key_for(PASSPHRASE, store)
        payload = payload_from_entries([make_entry("after/crash", "x")])

        def boom(src, dst):
            raise OSError(5, "Access is denied")

        monkeypatch.setattr(os, "replace", boom)
        original = digest(store.vault_path)
        with pytest.raises(errors.Unavailable) as excinfo:
            store.save(key, salt, params, payload)
        assert "Access is denied" in str(excinfo.value)
        assert_crash_guarantees(tmp_path, store, original)

    def test_partial_write_failure_mid_save(self, monkeypatch, store, tmp_path):
        key, salt, params = derived_key_for(PASSPHRASE, store)
        payload = payload_from_entries([make_entry("after/crash", "x")])

        real_ntf = tempfile.NamedTemporaryFile
        disk_full = OSError(28, "No space left on device")

        class HalfWriter:
            def __init__(self, *args, **kwargs):
                self._f = real_ntf(*args, **kwargs)

            def write(self, data):
                self._f.write(data[: max(1, len(data) // 2)])  # partial write
                raise disk_full

            def flush(self):
                return self._f.flush()

            def fileno(self):
                return self._f.fileno()

            def close(self):
                return self._f.close()

            @property
            def name(self):
                return self._f.name

        monkeypatch.setattr(tempfile, "NamedTemporaryFile", HalfWriter)
        original = digest(store.vault_path)
        with pytest.raises(errors.Unavailable):
            store.save(key, salt, params, payload)
        assert_crash_guarantees(tmp_path, store, original)

    def test_fsync_failure_mid_save(self, monkeypatch, store, tmp_path):
        key, salt, params = derived_key_for(PASSPHRASE, store)
        payload = payload_from_entries([make_entry("after/crash", "x")])

        real_fsync = os.fsync

        def boom(fd):
            real_fsync(fd)  # data really did hit the temp file...
            raise OSError(28, "No space left on device")  # ...but then "disk full"

        monkeypatch.setattr(os, "fsync", boom)
        original = digest(store.vault_path)
        with pytest.raises(errors.Unavailable):
            store.save(key, salt, params, payload)
        assert_crash_guarantees(tmp_path, store, original)


class TestAtomicWriteBytesUnit:
    def test_success_writes_exactly_and_leaves_no_temp(self, tmp_path):
        target = tmp_path / "out.bin"
        data = b"\x00\xffpayload " + "🔐".encode("utf-8")
        atomic_write_bytes(target, data)
        assert target.read_bytes() == data
        assert list(tmp_path.glob(".keepsafe-tmp-*")) == []

    def test_overwrites_existing_content_atomically(self, tmp_path):
        target = tmp_path / "out.bin"
        target.write_bytes(b"old content")
        atomic_write_bytes(target, b"new content")
        assert target.read_bytes() == b"new content"

    def test_failure_keeps_target_and_removes_temp(self, tmp_path, monkeypatch):
        target = tmp_path / "precious.bin"
        target.write_bytes(b"original bytes")
        original = digest(target)
        monkeypatch.setattr(os, "replace", lambda src, dst: (_ for _ in ()).throw(OSError(28, "No space left on device")))
        with pytest.raises(errors.Unavailable):
            atomic_write_bytes(target, b"replacement")
        assert digest(target) == original
        assert target.read_bytes() == b"original bytes"
        assert list(tmp_path.glob(".keepsafe-tmp-*")) == []

    def test_creates_missing_parent_directories(self, tmp_path):
        target = tmp_path / "deep" / "nest" / "file.txt"
        atomic_write_bytes(target, b"data")
        assert target.read_bytes() == b"data"


# ---------------------------------------------------------------------------
# Rekey
# ---------------------------------------------------------------------------

class TestRekey:
    def test_rekey_changes_passphrase_salt_and_keeps_entries(self, store):
        entries = [make_entry("keep/me", "kept-secret")]
        key, salt, params = derived_key_for(PASSPHRASE, store)
        store.save(key, salt, params, payload_from_entries(entries))

        old_salt = salt
        store.rekey(PASSPHRASE, PASSPHRASE_2)

        with pytest.raises(errors.UnlockFailed) as excinfo:
            store.unlock(PASSPHRASE)
        assert str(excinfo.value) == GENERIC_UNLOCK_MESSAGE

        header, payload = store.unlock(PASSPHRASE_2)
        assert entries_from(payload) == entries
        assert header.salt != old_salt          # fresh salt
        assert header.params == params          # parameters preserved by default

    def test_rekey_with_explicit_new_params(self, store):
        new_params = KdfParams(memory_kib=2048, iterations=2, parallelism=1)
        store.rekey(PASSPHRASE, PASSPHRASE_2, new_params=new_params)
        header, _payload = store.unlock(PASSPHRASE_2)
        assert header.params == new_params

    def test_rekey_creates_backup_and_wrong_old_passphrase_writes_nothing(self, store):
        before = digest(store.vault_path)
        n_backups = len(store.backups())
        with pytest.raises(errors.UnlockFailed):
            store.rekey("wrong-old-passphrase", PASSPHRASE_2)
        assert digest(store.vault_path) == before      # untouched on failure
        assert len(store.backups()) == n_backups       # no backup taken either

        info = store.rekey(PASSPHRASE, PASSPHRASE_2)
        assert isinstance(info, BackupInfo)
        assert len(store.backups()) == n_backups + 1


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@pytest.fixture
def khome(tmp_path, monkeypatch) -> Path:
    """Point KEEPSAFE_HOME at an empty temp dir for hermetic config tests."""
    monkeypatch.setenv("KEEPSAFE_HOME", str(tmp_path))
    return tmp_path


class TestConfig:
    def test_defaults_when_file_missing(self, khome):
        cfg, warnings = config.load()
        assert cfg == config.DEFAULTS
        assert warnings == []
        assert cfg is not config.DEFAULTS  # defensive copy
        config.DEFAULTS["backup_count"] = 999
        assert cfg["backup_count"] == 5
        config.DEFAULTS["backup_count"] = 5

    def test_config_path_layout(self, khome):
        assert config.config_dir() == khome
        assert config.config_path() == khome / "config.json"

    def test_save_load_round_trip(self, khome):
        custom = dict(config.DEFAULTS)
        custom.update(
            vault_path=r"D:\secrets\vault.kpsf",
            backup_count=9,
            clipboard_timeout=120,
            session_timeout=7200,
            audit_min_length=16,
            audit_stale_days=90,
            color_theme="light",
            output_mode="json",
        )
        config.save(custom)
        loaded, warnings = config.load()
        assert loaded == custom
        assert warnings == []
        text = (khome / "config.json").read_text(encoding="utf-8")
        assert json.loads(text) == custom

    def test_invalid_json_is_config_error(self, khome):
        (khome / "config.json").write_text('{"backup_count": 5,,}', encoding="utf-8")
        with pytest.raises(errors.ConfigError) as excinfo:
            config.load()
        assert "not valid JSON" in str(excinfo.value)
        assert "config.json" in str(excinfo.value)

    def test_non_object_json_is_config_error(self, khome):
        (khome / "config.json").write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(errors.ConfigError):
            config.load()

    def test_unknown_key_warned_and_ignored(self, khome):
        (khome / "config.json").write_text(
            json.dumps({"nope": 1, "also_bad": True}), encoding="utf-8"
        )
        cfg, warnings = config.load()
        assert cfg == config.DEFAULTS
        assert len(warnings) == 2
        assert any('"nope"' in w for w in warnings)
        assert any('"also_bad"' in w for w in warnings)

    @pytest.mark.parametrize(
        "key,value",
        [
            ("backup_count", -1),
            ("backup_count", 101),
            ("backup_count", "5"),
            ("backup_count", True),
            ("clipboard_timeout", 0),
            ("clipboard_timeout", 3601),
            ("session_timeout", 59),
            ("session_timeout", 86401),
            ("audit_min_length", 3),
            ("audit_min_length", 129),
            ("audit_stale_days", 0),
            ("audit_stale_days", 36501),
            ("color_theme", "blue"),
            ("color_theme", 1),
            ("output_mode", "yaml"),
            ("output_mode", None),
            ("vault_path", 5),
        ],
    )
    def test_out_of_range_or_wrong_type_values_are_config_errors(self, khome, key, value):
        (khome / "config.json").write_text(json.dumps({key: value}), encoding="utf-8")
        with pytest.raises(errors.ConfigError):
            config.load()

    @pytest.mark.parametrize(
        "key,value",
        [
            ("backup_count", 0),
            ("backup_count", 100),
            ("clipboard_timeout", 1),
            ("clipboard_timeout", 3600),
            ("session_timeout", 60),
            ("session_timeout", 86400),
            ("audit_min_length", 4),
            ("audit_min_length", 128),
            ("audit_stale_days", 1),
            ("audit_stale_days", 36500),
            ("color_theme", "dark"),
            ("color_theme", "light"),
            ("output_mode", "text"),
            ("output_mode", "json"),
            ("vault_path", ""),
            ("vault_path", "/tmp/anywhere/vault.kpsf"),
        ],
    )
    def test_boundary_values_accepted_and_round_trip(self, khome, key, value):
        cfg = dict(config.DEFAULTS)
        cfg[key] = value
        config.save(cfg)
        loaded, warnings = config.load()
        assert loaded[key] == value
        assert warnings == []

    def test_resolve_vault_path_both_branches(self, khome):
        configured = dict(config.DEFAULTS, vault_path="/custom/place/v.kpsf")
        assert config.resolve_vault_path(configured) == Path("/custom/place/v.kpsf")
        empty = dict(config.DEFAULTS, vault_path="")
        assert config.resolve_vault_path(empty) == khome / "vault.kpsf"
        assert config.resolve_vault_path({}) == khome / "vault.kpsf"

    def test_keepsafe_home_env_honored(self, khome, monkeypatch):
        nested = khome / "relocated"
        monkeypatch.setenv("KEEPSAFE_HOME", str(nested))
        assert config.config_dir() == nested
        config.save(dict(config.DEFAULTS, backup_count=42))
        assert (nested / "config.json").is_file()
        loaded, _warnings = config.load()
        assert loaded["backup_count"] == 42
        # nothing was written to the outer fake home
        assert not (khome / "config.json").exists()

    def test_empty_keepsafe_home_falls_back_to_real_home(self, khome, monkeypatch):
        monkeypatch.setenv("KEEPSAFE_HOME", "")
        assert config.config_dir() == Path.home() / ".keepsafe"
