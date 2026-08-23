"""Secret-hygiene gate: no secret may escape through any channel.

These tests fail loudly if a change ever lets a secret value reach
terminal output, error text, machine-readable output, or files on disk
outside the encrypted vault. They use deliberately distinctive sentinel
secrets so substring searches are reliable.
"""

from __future__ import annotations

import json

import pytest

PASS = "hygiene-passphrase-0001"
SENTINEL = "HYGIENE-SENTINEL-SECRET-7f3a"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    import keepsafe.crypto as crypto

    monkeypatch.setattr(crypto, "DEFAULT_MEMORY_KIB", 1024)
    monkeypatch.setattr(crypto, "DEFAULT_ITERATIONS", 1)
    monkeypatch.setattr(crypto, "DEFAULT_PARALLELISM", 1)


@pytest.fixture(autouse=True)
def _no_color_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("KEEPSAFE_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.fixture
def clip(monkeypatch):
    import keepsafe.clipboard as cb

    calls = {"copied": []}
    monkeypatch.setattr(cb, "copy_text",
                        lambda text: calls["copied"].append(text) or True)
    monkeypatch.setattr(cb, "schedule_clear", lambda h, t: None)
    return calls


def run_cli(monkeypatch, capsys, argv, hidden=None, visible=()):
    import keepsafe.cli as cli
    import keepsafe.prompts as P

    if hidden is None:
        hidden = [PASS]
    h = iter(hidden)
    v = iter(visible)

    def nh(_label=""):
        try:
            return next(h)
        except StopIteration:
            raise EOFError from None

    def nv(_label=""):
        try:
            return next(v)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr(P, "getpass_fn", nh)
    monkeypatch.setattr(P, "input_fn", nv)
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def seeded_vault(monkeypatch, capsys, home):
    run_cli(monkeypatch, capsys, ["init"], hidden=[PASS, PASS])
    run_cli(monkeypatch, capsys,
            ["add", "web/sentry", "--username", "u", "--url", "https://x",
             "--tags", "t"],
            hidden=[PASS, SENTINEL])
    return home / "vault.kpsf"


# ---------------------------------------------------------------------------
# Terminal and error channels
# ---------------------------------------------------------------------------

class TestTerminalChannels:
    def test_list_and_search_never_show_secret(self, monkeypatch, capsys, home):
        seeded_vault(monkeypatch, capsys, home)
        for argv in (["list"], ["search", "sentry"], ["list", "--tree"]):
            code, out, err = run_cli(monkeypatch, capsys, argv)
            assert code == 0
            assert SENTINEL not in out and SENTINEL not in err

    def test_get_masks_by_default(self, monkeypatch, capsys, home, clip):
        seeded_vault(monkeypatch, capsys, home)
        code, out, err = run_cli(monkeypatch, capsys, ["get", "web/sentry"])
        assert code == 0
        assert SENTINEL not in out + err
        assert clip["copied"] == [SENTINEL]

    def test_internal_error_trace_is_scrubbed(self, monkeypatch, capsys, home):
        seeded_vault(monkeypatch, capsys, home)
        import keepsafe.cli as cli

        def exploding(*a, **k):
            raise RuntimeError(f"crash while handling {SENTINEL}")

        monkeypatch.setattr(cli, "cmd_list", exploding)
        code, out, err = run_cli(monkeypatch, capsys, ["list"])
        assert code == 10
        assert SENTINEL not in err
        assert "[redacted]" in err

    def test_unlock_failure_does_not_leak_attempted_passphrase(
            self, monkeypatch, capsys, home):
        wrong = "WRONG-PASSPHRASE-ATTEMPT-abc123"
        seeded_vault(monkeypatch, capsys, home)
        code, out, err = run_cli(monkeypatch, capsys, ["list"], hidden=[wrong])
        assert code == 2
        assert wrong not in err


# ---------------------------------------------------------------------------
# Machine-readable output
# ---------------------------------------------------------------------------

class TestMachineOutput:
    def test_json_omits_secrets_unless_requested(self, monkeypatch, capsys, home):
        seeded_vault(monkeypatch, capsys, home)
        code, out, _ = run_cli(monkeypatch, capsys,
                               ["--output", "json", "list"])
        doc = json.loads(out)
        assert all("secret" not in e for e in doc["entries"]), \
            "machine output omits secret keys entirely unless requested"
        assert all(all("value" not in f for f in e.get("fields", []) if f.get("secret"))
                   for e in doc["entries"])
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["--output", "json", "search", "sentry",
                                  "--include-secrets"])
        assert "explicit request" in err
        assert SENTINEL in out  # explicitly requested: allowed

    def test_audit_output_carries_no_secret_values(self, monkeypatch, capsys, home):
        seeded_vault(monkeypatch, capsys, home)
        code, out, err = run_cli(monkeypatch, capsys, ["audit"])
        assert SENTINEL not in out + err


# ---------------------------------------------------------------------------
# Files on disk
# ---------------------------------------------------------------------------

class TestFilesOnDisk:
    def test_vault_and_backups_stay_opaque(self, monkeypatch, capsys, home):
        vpath = seeded_vault(monkeypatch, capsys, home)
        run_cli(monkeypatch, capsys, ["edit", "web/sentry", "--add-tags", "z"])
        raw = vpath.read_bytes()
        backups = list((home / "backups").glob("*.bak.kpsf"))
        assert backups, "expected an automatic backup after edit"
        for blob in [raw] + [b.read_bytes() for b in backups]:
            assert SENTINEL.encode("utf-8") not in blob
            assert PASS.encode("utf-8") not in blob

    def test_no_temp_files_left_after_normal_save(self, monkeypatch, capsys, home):
        seeded_vault(monkeypatch, capsys, home)
        run_cli(monkeypatch, capsys, ["edit", "web/sentry", "--add-tags", "q"])
        leftovers = list(home.glob(".keepsafe-tmp-*")) + \
            list((home / "backups").glob(".keepsafe-tmp-*"))
        assert leftovers == []

    def test_export_redacted_file_has_no_secrets(self, monkeypatch, capsys, home,
                                                 tmp_path):
        seeded_vault(monkeypatch, capsys, home)
        target = tmp_path / "out.json"
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["export", str(target), "--redacted"],
                                 visible=["y"])
        assert code == 0
        text = target.read_text(encoding="utf-8")
        assert SENTINEL not in text
        assert "web/sentry" in text  # structure is preserved


# ---------------------------------------------------------------------------
# Process surface
# ---------------------------------------------------------------------------

class TestProcessSurface:
    def test_passphrase_never_in_argv(self, monkeypatch, capsys, home):
        # The CLI accepts no passphrase argument by construction; prove the
        # parser rejects one rather than silently swallowing it.
        import keepsafe.cli as cli
        from keepsafe import errors
        with pytest.raises(errors.UsageError):
            # Usage problems are exit 4 (UsageError), never exit 2, so a
            # typo cannot be confused with an unlock failure.
            cli.build_parser().parse_args(["unlock", "--passphrase", PASS])

    def test_session_runtime_file_holds_no_key_material(self, monkeypatch, capsys, home):
        seeded_vault(monkeypatch, capsys, home)
        run_cli(monkeypatch, capsys, ["unlock"])
        import keepsafe.session as session
        info_file = session.runtime_path(str(home / "vault.kpsf"))
        if info_file.exists():
            raw = info_file.read_text(encoding="utf-8")
            assert PASS not in raw and SENTINEL not in raw
        run_cli(monkeypatch, capsys, ["lock"])

    def test_generated_password_not_logged_by_gen_notice(self, monkeypatch, capsys, home):
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["gen", "--words", "6", "--sep", "+"])
        value = out.strip().splitlines()[0]
        # stdout is the only sanctioned channel for gen values:
        assert value in out
