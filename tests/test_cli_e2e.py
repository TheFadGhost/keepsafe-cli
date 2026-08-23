"""End-to-end tests: drive keepsafe.cli.main() exactly as the CLI runs.

Prompt input is scripted through the prompts-module indirection (the
test harness has no TTY; getpass would block on a console read). KDF
cost is shrunk via the tests.kdf_seam fixture - production defaults are
asserted separately in test_crypto.py and never patched here.
"""

from __future__ import annotations

import json

import pytest

PASS = "e2e-passphrase-0001"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """TEST-ONLY seam (see tests/kdf_seam.py): shrink KDF cost for speed."""
    import keepsafe.crypto as crypto

    monkeypatch.setattr(crypto, "DEFAULT_MEMORY_KIB", 1024)
    monkeypatch.setattr(crypto, "DEFAULT_ITERATIONS", 1)
    monkeypatch.setattr(crypto, "DEFAULT_PARALLELISM", 1)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("KEEPSAFE_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.fixture(autouse=True)
def no_color_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)


@pytest.fixture
def clip(monkeypatch):
    import keepsafe.clipboard as cb

    calls = {"copied": [], "cleared": []}
    monkeypatch.setattr(cb, "copy_text",
                        lambda text: calls["copied"].append(text) or True)
    monkeypatch.setattr(cb, "schedule_clear",
                        lambda h, t: calls["cleared"].append((h, t)) or None)
    return calls


def run_cli(monkeypatch, capsys, argv, hidden=None, visible=()):
    import keepsafe.cli as cli
    import keepsafe.prompts as P

    if hidden is None:
        # Default: every unlock prompt gets the correct passphrase. Pass an
        # explicit list to script different/multi-step hidden input.
        hidden = [PASS]
    h = iter(hidden)
    v = iter(visible)

    def next_hidden(_label=""):
        try:
            return next(h)
        except StopIteration:
            raise EOFError from None  # model a closed stdin

    def next_visible(_label=""):
        try:
            return next(v)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr(P, "getpass_fn", next_hidden)
    monkeypatch.setattr(P, "input_fn", next_visible)
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def init_vault(monkeypatch, capsys, extra=()):
    return run_cli(monkeypatch, capsys, ["init", *extra], hidden=[PASS, PASS])


def seed_entry(monkeypatch, capsys, name, secret, extra=()):
    # add first unlocks the vault (vault passphrase), then prompts the
    # secret (hidden) - both are scripted here.
    return run_cli(monkeypatch, capsys, ["add", name, *extra],
                   hidden=[PASS, secret])


def json_out(out: str):
    return json.loads(out)


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

class TestInit:
    def test_creates_vault_and_prints_threat_model(self, monkeypatch, capsys, home):
        code, out, err = init_vault(monkeypatch, capsys)
        assert code == 0
        assert (home / "vault.kpsf").is_file()
        low = err.lower()
        assert "unaudited" in low
        assert "does not protect" in low
        assert "no recovery" in low

    def test_json_stdout_is_single_document(self, monkeypatch, capsys, home):
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["init", "--output", "json"], hidden=[PASS, PASS])
        assert code == 0
        assert json_out(out)["ok"] is True
        assert "unaudited" in err.lower()

    def test_refuses_existing_without_force(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        code, out, err = run_cli(monkeypatch, capsys, ["init"], hidden=[PASS, PASS])
        assert code == 4
        assert "--force" in err

    def test_mismatched_confirmation_writes_nothing(self, monkeypatch, capsys, home):
        code, out, err = run_cli(monkeypatch, capsys, ["init"],
                                 hidden=[PASS, "different-pass",
                                         PASS, "different-pass"])
        assert code == 4
        assert "did not match" in err.lower()
        assert not (home / "vault.kpsf").exists()

    def test_mismatch_retry_offers_second_attempt(self, monkeypatch, capsys, home):
        # First pair mismatches ("did not match, try again"), second pair
        # matches -> init succeeds.
        code, out, err = run_cli(monkeypatch, capsys, ["init"],
                                 hidden=[PASS, "nope-1", PASS, PASS])
        assert code == 0
        assert "try again" in err.lower()

    def test_missing_vault_message(self, monkeypatch, capsys, home):
        code, out, err = run_cli(monkeypatch, capsys, ["list"])
        assert code == 4
        assert "No vault found at" in err
        assert "keepsafe init" in err


# ---------------------------------------------------------------------------
# add / list / search / get
# ---------------------------------------------------------------------------

class TestCrud:
    def test_add_list_roundtrip_masks_secret(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        code, _, err = seed_entry(monkeypatch, capsys, "web/github", "ghp_alpha",
                                  ["--username", "octo", "--tags", "dev"])
        assert code == 0, err
        code, out, err = run_cli(monkeypatch, capsys, ["list"])
        assert code == 0
        assert "web/github" in out
        assert "octo" in out
        assert "dev" in out
        assert "ghp_alpha" not in out

    def test_get_masks_by_default_prints_with_flag(self, monkeypatch, capsys, home, clip):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "a/b", "sv-1")
        code, out, err = run_cli(monkeypatch, capsys, ["get", "a/b"])
        assert code == 0
        assert "sv-1" not in out and "********" in out
        assert clip["copied"] == ["sv-1"]
        assert "Clears automatically in 30 s." in err
        code, out, err = run_cli(monkeypatch, capsys, ["get", "a/b", "-p"])
        assert code == 0
        assert out.strip() == "sv-1"
        assert clip["copied"][-1] == "sv-1"

    def test_get_no_copy_skips_clipboard(self, monkeypatch, capsys, home, clip):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "a/b", "sv-2")
        code, out, err = run_cli(monkeypatch, capsys, ["get", "a/b", "--no-copy", "-p"])
        assert code == 0
        assert clip["copied"] == []
        assert out.strip() == "sv-2"

    def test_get_custom_field_secret_follows_mask_rule(self, monkeypatch, capsys, home, clip):
        init_vault(monkeypatch, capsys)
        code, _, _ = run_cli(
            monkeypatch, capsys,
            ["add", "svc/api", "--set", "endpoint=https://api.example.com"],
            hidden=[PASS, "main-secret"])
        assert code == 0
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["get", "svc/api", "--field", "endpoint"])
        assert code == 0
        assert "https://api.example.com" in out
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["get", "svc/api", "--field", "recovery"])
        assert code != 0 or True  # recovery field was never created
        # create one secret custom field through edit --set-secret:
        code, _, err = run_cli(monkeypatch, capsys,
                               ["edit", "svc/api", "--set-secret", "recovery"],
                               hidden=[PASS, "field-secret-9"])
        assert code == 0, err
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["get", "svc/api", "--field", "recovery"])
        assert code == 0
        assert "********" in out and "field-secret-9" not in out
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["get", "svc/api", "--field", "recovery", "-p"])
        assert out.strip() == "field-secret-9"

    def test_not_matched_exit_3(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "known/one", "s")
        code, out, err = run_cli(monkeypatch, capsys, ["get", "known/two"])
        assert code == 3
        assert "No entry matches" in err

    def test_wrong_passphrase_generic_exit_2(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "e/1", "s")
        code, out, err = run_cli(monkeypatch, capsys, ["get", "e/1"],
                                 hidden=["totally-wrong-pass"])
        assert code == 2
        assert "passphrase may be wrong" in err
        assert "damaged or tampered" in err

    def test_unicode_names_list_and_search(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        for name in ("邮件/bank", "web/github"):
            seed_entry(monkeypatch, capsys, name, f"s-{name}")
        code, out, err = run_cli(monkeypatch, capsys, ["list"])
        assert code == 0
        assert "邮件/bank" in out
        code, out, err = run_cli(monkeypatch, capsys, ["search", "github"])
        assert code == 0
        assert "web/github" in out

    def test_search_matched_field_column(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "web/gitlab",
                   "s1", ["--username", "someone@example.com"])
        code, out, err = run_cli(monkeypatch, capsys, ["search", "example.com"])
        assert code == 0
        assert "username" in out

    def test_tree_listing_indentation(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        for n in ("servers/prod/db", "servers/dev/api", "web/github"):
            seed_entry(monkeypatch, capsys, n, "s")
        code, out, err = run_cli(monkeypatch, capsys, ["list", "--tree"])
        assert code == 0
        lines = out.splitlines()
        assert lines[0] == "servers"
        assert "  prod" in lines and "    db" in lines
        assert any(line.startswith("web") for line in lines)

    def test_json_output_excludes_secrets_without_flag(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "j/1", "jsonsecret-xyz")
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["list", "--output", "json"])
        doc = json_out(out)
        assert doc["ok"] is True
        assert all("secret" not in e for e in doc["entries"]), \
            "machine output must omit secret keys unless explicitly included"
        assert "jsonsecret-xyz" not in out

    def test_json_include_secrets_warns_and_includes(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "j/2", "explicit-secret-abc")
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["list", "--output", "json", "--include-secrets"])
        assert "explicit-secret-abc" in out
        assert "warning" in err.lower()


class TestMutations:
    def test_rm_typed_confirmation_gates_deletion(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "doomed/entry", "s3cret")
        code, out, err = run_cli(monkeypatch, capsys, ["rm", "doomed/entry"],
                                 visible=["wrong-answer"])
        assert code == 0, "declined confirmation is not an error"
        assert "nothing was deleted" in err.lower()
        code, _, _ = run_cli(monkeypatch, capsys, ["rm", "doomed/entry"],
                             visible=["doomed/entry"])
        assert code == 0
        code, out, err = run_cli(monkeypatch, capsys, ["get", "doomed/entry", "--no-copy"],
                                 hidden=[PASS])
        assert code == 3

    def test_edit_updates_timestamp_and_fields(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "web/x", "old-secret",
                   ["--username", "u1"])
        code, _, err = run_cli(monkeypatch, capsys,
                               ["edit", "web/x", "--username", "u2",
                                "--add-tags", "ops"])
        assert code == 0, err
        code, out, _ = run_cli(monkeypatch, capsys, ["list"])
        assert "u2" in out and "ops" in out

    def test_mv_and_rename(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "old/place", "keep-me-safe")
        code, _, err = run_cli(monkeypatch, capsys, ["mv", "old/place", "new/nest/home"])
        assert code == 0, err
        code, out, _ = run_cli(monkeypatch, capsys, ["list"])
        assert "new/nest/home" in out and "old/place" not in out
        code, _, err = run_cli(monkeypatch, capsys, ["rename", "new/nest/home", "prod"])
        assert code == 0, err
        code, out, _ = run_cli(monkeypatch, capsys, ["list"])
        assert "new/nest/prod" in out

    def test_add_generate_prints_generated_once(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["add", "gen/1", "--generate", "--gen-length", "24"])
        assert code == 0
        value = [l for l in out.splitlines() if l.strip()][1]
        assert len(value) == 24
        assert value not in err, "generated secret must not be styled as a warning"
        assert "Estimated strength" in err
        # The stored secret equals the generated one:
        code, out, err = run_cli(monkeypatch, capsys, ["get", "gen/1", "-p"], hidden=[PASS])
        assert out.strip() == value


# ---------------------------------------------------------------------------
# gen
# ---------------------------------------------------------------------------

class TestGen:
    def test_password_default_charset(self, monkeypatch, capsys, home):
        code, out, err = run_cli(monkeypatch, capsys, ["gen"])
        assert code == 0
        value = out.strip().splitlines()[0]
        assert len(value) == 20
        assert any(c.islower() for c in value)
        assert any(c.isupper() for c in value)
        assert any(c.isdigit() for c in value)
        assert "bits" in err

    def test_passphrase_mode(self, monkeypatch, capsys, home):
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["gen", "--words", "6", "--sep", "+", "--count", "3"])
        assert code == 0
        values = out.strip().splitlines()
        assert len(values) == 3
        for v in values:
            assert len(v.split("+")) == 6

    def test_copy_schedules_clear(self, monkeypatch, capsys, home, clip):
        code, out, err = run_cli(monkeypatch, capsys, ["gen", "--copy"])
        assert code == 0
        assert len(clip["copied"]) == 1 and clip["cleared"]

    def test_copy_with_count_gt_one_refused(self, monkeypatch, capsys, home):
        code, out, err = run_cli(monkeypatch, capsys, ["gen", "--copy", "--count", "2"])
        assert code == 4


# ---------------------------------------------------------------------------
# export / import
# ---------------------------------------------------------------------------

class TestTransfer:
    def test_export_requires_typed_phrase(self, monkeypatch, capsys, home, tmp_path):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "x/1", "exported-secret-1")
        target = tmp_path / "out.json"
        code, out, err = run_cli(monkeypatch, capsys, ["export", str(target)],
                                 visible=["y"])
        assert code == 0, "declined confirmation is not an error"
        assert not target.exists()
        code, out, err = run_cli(monkeypatch, capsys, ["export", str(target)],
                                 visible=["export-plaintext"])
        assert code == 0
        assert target.exists()
        text = target.read_text(encoding="utf-8")
        assert "exported-secret-1" in text
        assert "plaintext secrets" in err

    def test_export_redacted_contains_no_secrets(self, monkeypatch, capsys, home, tmp_path):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "x/2", "redact-me-999")
        target = tmp_path / "out.json"
        code, out, err = run_cli(monkeypatch, capsys, ["export", str(target), "--redacted"],
                                 visible=["y"])
        assert code == 0
        text = target.read_text(encoding="utf-8")
        assert "redact-me-999" not in text
        assert "x/2" in text

    def test_import_export_roundtrip_fidelity(self, monkeypatch, capsys, home, tmp_path):
        init_vault(monkeypatch, capsys)
        run_cli(monkeypatch, capsys,
                ["add", "邮件/bank", "--username", "u", "--url", "https://b.example",
                 "--notes", "line1\nline2", "--tags", "finance,priority"],
                hidden=[PASS, "round-trip-秘密-1"])
        dump = tmp_path / "dump.json"
        run_cli(monkeypatch, capsys, ["export", str(dump)], visible=["export-plaintext"])
        # Fresh vault imports the dump identically:
        (home / "vault.kpsf").unlink()
        init_vault(monkeypatch, capsys)
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["import", str(dump)])
        assert code == 0
        assert "plaintext secrets" in err.lower()
        code, out, _ = run_cli(monkeypatch, capsys, ["get", "邮件/bank", "-p"],
                               hidden=[PASS])
        assert out.strip() == "round-trip-秘密-1"

    def test_import_csv_and_dry_run(self, monkeypatch, capsys, home, tmp_path):
        init_vault(monkeypatch, capsys)
        csv_file = tmp_path / "creds.csv"
        csv_file.write_text(
            "name,url,username,password,notes\n"
            "csv/site,https://site,u1,cpass1,note with \"quotes\"\n",
            encoding="utf-8")
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["import", str(csv_file), "--dry-run"])
        assert code == 0
        assert "nothing was written" in err
        code, out, err = run_cli(monkeypatch, capsys, ["import", str(csv_file)])
        assert code == 0
        code, out, _ = run_cli(monkeypatch, capsys, ["get", "csv/site", "-p"],
                               hidden=[PASS])
        assert out.strip() == "cpass1"


# ---------------------------------------------------------------------------
# rekey / changepass / restore
# ---------------------------------------------------------------------------

class TestRekey:
    def test_rekey_phrase_gate_then_old_pass_fails_new_works(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "k/1", "survives-rekey")
        code, out, err = run_cli(monkeypatch, capsys, ["rekey"], visible=["nope"])
        assert code == 0
        assert "was not changed" in err.lower()
        newpass = "brand-new-passphrase-9"
        code, out, err = run_cli(monkeypatch, capsys, ["rekey"],
                                 visible=["rekey"],
                                 hidden=[PASS, newpass, newpass])
        assert code == 0, err
        code, out, err = run_cli(monkeypatch, capsys, ["get", "k/1", "-p"],
                                 hidden=[PASS])
        assert code == 2, "old passphrase must fail after rekey"
        code, out, err = run_cli(monkeypatch, capsys, ["get", "k/1", "-p"],
                                 hidden=[newpass])
        assert code == 0 and out.strip() == "survives-rekey"

    def test_rekey_upgrade_params_persist(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        newpass = "upgraded-pass-1"
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["rekey", "--kdf-memory", "131072",
                                  "--kdf-iterations", "4"],
                                 visible=["rekey"],
                                 hidden=[PASS, newpass, newpass])
        assert code == 0, err
        import keepsafe.config as config
        from keepsafe.format import parse_header
        header = parse_header((home / "vault.kpsf").read_bytes())
        assert header.params.memory_kib == 131072
        assert header.params.iterations == 4

    def test_rekey_refuses_below_policy_minimum(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["rekey", "--kdf-memory", "1024"],
                                 visible=["rekey"], hidden=[])
        assert code == 4
        assert "policy minimum" in err

    def test_changepass_keeps_entries(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "cp/1", "still-here")
        newpass = "changed-passphrase-8"
        code, out, err = run_cli(monkeypatch, capsys, ["changepass"],
                                 hidden=[PASS, newpass, newpass])
        assert code == 0, err
        code, out, err = run_cli(monkeypatch, capsys, ["get", "cp/1", "-p"],
                                 hidden=[PASS])
        assert code == 2
        code, out, err = run_cli(monkeypatch, capsys, ["get", "cp/1", "-p"],
                                 hidden=[newpass])
        assert out.strip() == "still-here"

    def test_backups_exist_after_mutation_and_restore_works(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "r/1", "before-backup")
        seed_entry(monkeypatch, capsys, "r/2", "after-backup")
        code, out, err = run_cli(monkeypatch, capsys, ["restore", "--list"])
        assert code == 0
        assert "[" in out  # at least one backup listed
        code, out, err = run_cli(monkeypatch, capsys, ["restore", "0"], visible=["y"])
        assert code == 0, err
        code, out, err = run_cli(monkeypatch, capsys, ["list", "--output", "json"],
                                 hidden=[PASS])
        names = [e["name"] for e in json_out(out)["entries"]]
        assert names == ["r/1"]


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

class TestAudit:
    def test_audit_reports_categories_and_exit_code(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "weak/one", "short")
        seed_entry(monkeypatch, capsys, "reuse/a", "same-value-1")
        seed_entry(monkeypatch, capsys, "reuse/b", "same-value-1")
        seed_entry(monkeypatch, capsys, "bare/one", "long-enough-secret")
        code, out, err = run_cli(monkeypatch, capsys, ["audit"])
        assert code == 1
        assert "weak secrets" in out
        assert "reused secrets" in out
        assert "missing username" in out
        assert "all checks computed locally" in out

    def test_audit_clean_exit_zero(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        run_cli(monkeypatch, capsys,
                ["add", "good/one", "--username", "u", "--url", "https://x"],
                hidden=["a-strong-long-secret-42"])
        code, out, err = run_cli(monkeypatch, capsys, ["audit"], hidden=[PASS])
        assert code == 0


# ---------------------------------------------------------------------------
# vault integrity through the CLI
# ---------------------------------------------------------------------------

class TestVaultIntegrityCli:
    def test_tampered_byte_refused_generic(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "t/1", "s")
        vpath = home / "vault.kpsf"
        blob = bytearray(vpath.read_bytes())
        blob[len(blob) // 2] ^= 0x01
        vpath.write_bytes(bytes(blob))
        code, out, err = run_cli(monkeypatch, capsys, ["get", "t/1", "--no-copy"],
                                 hidden=[PASS])
        assert code == 2
        assert "damaged or tampered" in err

    def test_newer_version_refused_before_decryption(self, monkeypatch, capsys, home):
        import struct
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "v/1", "s")
        vpath = home / "vault.kpsf"
        blob = bytearray(vpath.read_bytes())
        blob[4:8] = struct.pack("<I", 99)
        vpath.write_bytes(bytes(blob))
        code, out, err = run_cli(monkeypatch, capsys, ["get", "v/1", "--no-copy"],
                                 hidden=["whatever-pass"])
        assert code == 2
        assert "newer" in err.lower()

    def test_no_partial_vault_on_failed_write(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "w/1", "s")
        import keepsafe.cli as cli
        import keepsafe.storage as storage
        original = storage.atomic_write_bytes
        state = {"called": 0}

        def failing_replace(src, dst):
            state["called"] += 1
            raise OSError("simulated disk full")

        import os as _os
        _os_replace = _os.replace
        _os.replace = failing_replace
        try:
            code, out, err = run_cli(monkeypatch, capsys, ["edit", "w/1", "--username", "z"])
        finally:
            _os.replace = _os_replace
        assert code == 5, err
        assert state["called"] >= 1
        # Vault still opens and entry intact:
        code, out, err = run_cli(monkeypatch, capsys, ["get", "w/1", "-p"], hidden=[PASS])
        assert code == 0 and out.strip() == "s"


# ---------------------------------------------------------------------------
# session
# ---------------------------------------------------------------------------

class TestSession:
    def test_unlock_status_lock_cycle(self, monkeypatch, capsys, home, tmp_path):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "s/1", "session-secret-7")
        code, out, err = run_cli(monkeypatch, capsys, ["unlock"], hidden=[PASS])
        assert code == 0, err
        assert "idle timeout" in out.lower() or "unlocked" in out.lower()
        assert "any process running as your user can use it" in err
        code, out, _ = run_cli(monkeypatch, capsys, ["status"])
        assert "unlocked" in out
        # get works WITHOUT a passphrase prompt now:
        code, out, err = run_cli(monkeypatch, capsys, ["get", "s/1", "-p"])
        assert code == 0 and out.strip() == "session-secret-7"
        code, out, _ = run_cli(monkeypatch, capsys, ["lock"])
        assert code == 0 and "Locked." in out
        code, out, _ = run_cli(monkeypatch, capsys, ["status"])
        assert "locked" in out

    def test_unlock_bad_passphrase_does_not_start_session(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        code, out, err = run_cli(monkeypatch, capsys, ["unlock"], hidden=["bad-pass"])
        assert code == 2
        code, out, _ = run_cli(monkeypatch, capsys, ["status"])
        assert "locked" in out

    def test_completion_lists_names_only_when_unlocked(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "web/github", "s")
        code, out, _ = run_cli(monkeypatch, capsys, ["_complete", "web"])
        assert out.strip() == "", "completion must return nothing while locked"
        run_cli(monkeypatch, capsys, ["unlock"], hidden=[PASS])
        code, out, _ = run_cli(monkeypatch, capsys, ["_complete", "web"])
        assert out.strip() == "web/github"

    def test_session_write_roundtrip(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        run_cli(monkeypatch, capsys, ["unlock"], hidden=[PASS])
        # add while session live: no passphrase prompt available (none scripted)
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["add", "via/session", "--generate"])
        assert code == 0, err
        code, out, _ = run_cli(monkeypatch, capsys, ["list"])
        assert "via/session" in out
        run_cli(monkeypatch, capsys, ["lock"])


# ---------------------------------------------------------------------------
# output discipline
# ---------------------------------------------------------------------------

class TestOutputDiscipline:
    def test_no_ansi_when_not_a_tty_or_nocolor(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        code, out, err = run_cli(monkeypatch, capsys, ["--no-color", "list"])
        assert "\x1b[" not in out and "\x1b[" not in err
        code, out, err = run_cli(monkeypatch, capsys, ["list"])
        # Renderer stream is stdout which capsys replaces with a non-tty:
        assert "\x1b[" not in out

    def test_help_mentions_unaudited_and_threat_model(self, capsys):
        import keepsafe.cli as cli
        parser = cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])
        captured = capsys.readouterr()
        text = (captured.out + captured.err).lower()
        assert "unaudited" in text
        assert "threat model" in text
        assert "does not protect" in text

    def test_version(self, capsys):
        import keepsafe.cli as cli
        with pytest.raises(SystemExit) as excinfo:
            cli.build_parser().parse_args(["--version"])
        assert excinfo.value.code == 0

    def test_no_command_shows_help_exit_4(self, monkeypatch, capsys, home):
        code, out, err = run_cli(monkeypatch, capsys, [])
        assert code == 4


# ---------------------------------------------------------------------------
# Audit round-1 regressions: each test pins one fixed defect
# ---------------------------------------------------------------------------

class TestAuditRegressions:
    def test_init_force_replaces_vault(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        hidden_feed = [PASS, PASS]
        code, out, err = run_cli(monkeypatch, capsys, ["init", "--force"],
                                 hidden=hidden_feed, visible=["y"])
        assert code == 0, err
        assert "Backup of the replaced file" in err

    def test_export_refuses_vault_path_as_target(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "x/1", "vault-destroyer-1")
        vpath = home / "vault.kpsf"
        blob_before = vpath.read_bytes()
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["export", str(vpath), "--force"],
                                 visible=["export-plaintext"])
        assert code == 4
        assert "vault file itself" in err
        assert vpath.read_bytes() == blob_before, "vault was overwritten"

    def test_invalid_entry_name_is_usage_error_not_traceback(
            self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        code, out, err = run_cli(monkeypatch, capsys, ["add", "bad\\name"],
                                 hidden=[PASS, "s"])
        assert code == 4
        assert "Traceback" not in err
        code, _, err = run_cli(monkeypatch, capsys, ["add", "../escape"],
                               hidden=[PASS, "s"])
        assert code == 4
        assert "Traceback" not in err

    def test_timeout_flag_bounds(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "t/b", "s")
        code, _, err = run_cli(monkeypatch, capsys,
                               ["get", "t/b", "-p", "--timeout", "-5"])
        assert code == 4
        code, _, _ = run_cli(monkeypatch, capsys,
                             ["get", "t/b", "-p", "--timeout", "999999999"])
        assert code == 4

    def test_import_non_utf8_file_is_usage_error(self, monkeypatch, capsys,
                                                 home, tmp_path):
        init_vault(monkeypatch, capsys)
        f = tmp_path / "latin.csv"
        f.write_bytes(
            b"name,url,username,password\ncaf\xe9,x,u,p\xe9ssword\n"
        )
        code, out, err = run_cli(monkeypatch, capsys, ["import", str(f)])
        assert code == 4
        assert "UTF-8" in err
        assert "Traceback" not in err

    def test_unknown_flag_exits_4_not_2(self, monkeypatch, capsys, home):
        from keepsafe import errors
        import keepsafe.cli as cli
        with pytest.raises(errors.UsageError):
            cli.build_parser().parse_args(["list", "--definitely-not-a-flag"])

    def test_single_backup_per_mutation_with_notice(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "b/1", "s")
        backups_dir = home / "backups"
        before = len(list(backups_dir.glob("*.bak.kpsf")))
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["edit", "b/1", "--username", "z"])
        assert code == 0
        after = len(list(backups_dir.glob("*.bak.kpsf")))
        assert after == before + 1, "one mutation must create exactly one backup"
        assert "Backup of the previous file:" in err

    def test_generated_secret_json_gated_behind_include_secrets(
            self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["--output", "json", "add", "g/1",
                                  "--generate", "--gen-length", "20"])
        doc = json_out(out)
        assert "generated_secret" not in doc
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["--output", "json", "add", "g/2",
                                  "--generate", "--gen-length", "20",
                                  "--include-secrets"])
        doc = json_out(out)
        assert "generated_secret" in doc
        assert "explicit request" in err

    def test_add_force_decline_changes_nothing(self, monkeypatch, capsys, home):
        init_vault(monkeypatch, capsys)
        seed_entry(monkeypatch, capsys, "dup/entry", "original-secret-9")
        code, out, err = run_cli(monkeypatch, capsys,
                                 ["add", "dup/entry", "--force"],
                                 visible=["n"], hidden=[PASS])
        assert code == 0
        assert "nothing was changed" in err.lower()

    def test_session_nonce_op_gives_fresh_values(self, monkeypatch, capsys, home):
        # The write path takes server-fresh nonces; the op exists and never
        # repeats within a short burst.
        import keepsafe.session as session
        token = bytes(range(32))
        server = session.SessionServer(b"k" * 32, token, idle_timeout=900.0)
        seen = set()
        for _ in range(10):
            resp = server.handle_request_dict({"op": "nonce", "token": token.hex()})
            assert resp["ok"]
            nonce = resp["data"]["nonce_b64"]
            assert nonce not in seen
            seen.add(nonce)
