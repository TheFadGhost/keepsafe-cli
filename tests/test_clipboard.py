"""Tests for keepsafe.clipboard: hashing, guard logic, dispatch, live win32.

Dispatch tests monkeypatch shutil.which / subprocess.run / sys.platform to
pin the exact argv shapes for macOS and Linux without those platforms.
The live Windows tests exercise the real clipboard on THIS machine and
always restore the previous clipboard content in finally blocks.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import time

import pytest

from keepsafe import errors
import keepsafe.clipboard as clipboard


class TestHashingAndGuard:
    def test_sha256_hex_known_vectors(self):
        assert (
            clipboard.sha256_hex("")
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert (
            clipboard.sha256_hex("abc")
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        assert clipboard.sha256_hex("héllo") == hashlib.sha256(
            "héllo".encode("utf-8")
        ).hexdigest()

    def test_should_clear_when_unchanged(self):
        payload = "keepsafe-secret"
        assert clipboard.should_clear(payload, clipboard.sha256_hex(payload)) is True

    def test_should_clear_false_when_user_copied_something_else(self):
        copied_hash = clipboard.sha256_hex("keepsafe-secret")
        assert clipboard.should_clear("user's own link", copied_hash) is False

    def test_should_clear_false_when_clipboard_emptied_by_user(self):
        copied_hash = clipboard.sha256_hex("keepsafe-secret")
        assert clipboard.should_clear("", copied_hash) is False


def _install_fake_run(monkeypatch, returncode=0, stdout=b""):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append({"argv": list(argv), "kwargs": kwargs})
        return subprocess.CompletedProcess(argv, returncode, stdout, b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


class TestPlatformDispatch:
    def test_linux_copy_prefers_first_available_tool(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(
            clipboard.shutil,
            "which",
            lambda name: {
                "wl-copy": "/usr/bin/wl-copy",
                "xclip": "/usr/bin/xclip",
                "xsel": "/usr/bin/xsel",
            }.get(name),
        )
        calls = _install_fake_run(monkeypatch)
        assert clipboard.copy_text("secret") is True
        assert len(calls) == 1
        assert calls[0]["argv"] == ["/usr/bin/wl-copy"]
        assert calls[0]["kwargs"]["input"] == b"secret"

    def test_linux_copy_falls_back_to_xclip_then_xsel(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")

        def which(name):
            return {"xclip": "/usr/bin/xclip", "xsel": "/usr/bin/xsel"}.get(name)

        monkeypatch.setattr(clipboard.shutil, "which", which)
        seen = []

        def fake_run(argv, **kwargs):
            seen.append(list(argv))
            code = 1 if argv[0] == "/usr/bin/xclip" else 0
            return subprocess.CompletedProcess(argv, code, b"", b"")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert clipboard.copy_text("secret") is True
        assert seen == [
            ["/usr/bin/xclip", "-selection", "clipboard"],
            ["/usr/bin/xsel", "--clipboard", "--input"],
        ]

    def test_linux_copy_survives_tool_crash_and_still_succeeds(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")

        def which(name):
            return {"wl-copy": "/usr/bin/wl-copy", "xsel": "/usr/bin/xsel"}.get(name)

        monkeypatch.setattr(clipboard.shutil, "which", which)
        seen = []

        def fake_run(argv, **kwargs):
            seen.append(list(argv))
            if argv[0] == "/usr/bin/wl-copy":
                raise OSError("boom")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        monkeypatch.setattr(subprocess, "run", fake_run)
        assert clipboard.copy_text("secret") is True
        assert [argv[0] for argv in seen] == ["/usr/bin/wl-copy", "/usr/bin/xsel"]

    def test_mac_copy_uses_pbcopy_with_stdin(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(clipboard.shutil, "which", lambda name: "/bin/pbcopy")
        calls = _install_fake_run(monkeypatch)
        assert clipboard.copy_text("mac secret") is True
        assert calls[0]["argv"] == ["/bin/pbcopy"]
        assert calls[0]["kwargs"]["input"] == b"mac secret"

    def test_unavailable_everywhere_raises(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(clipboard.shutil, "which", lambda name: None)
        with pytest.raises(errors.Unavailable):
            clipboard.copy_text("secret")
        with pytest.raises(errors.Unavailable):
            clipboard.copy_text("retry")

    def test_linux_read_chain_and_empty_when_nothing(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(
            clipboard.shutil,
            "which",
            lambda name: {"xclip": "/usr/bin/xclip"}.get(name),
        )
        calls = _install_fake_run(monkeypatch, returncode=0, stdout=b"from xclip\n")
        assert clipboard.read_text() == "from xclip\n"
        assert calls[0]["argv"] == [
            "/usr/bin/xclip",
            "-selection",
            "clipboard",
            "-o",
        ]

        monkeypatch.setattr(clipboard.shutil, "which", lambda name: None)
        assert clipboard.read_text() == ""

    def test_mac_read_uses_pbpaste(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(clipboard.shutil, "which", lambda name: "/bin/pbpaste")
        calls = _install_fake_run(monkeypatch, returncode=0, stdout=b"pasted")
        assert clipboard.read_text() == "pasted"
        assert calls[0]["argv"] == ["/bin/pbpaste"]

    def test_windows_powershell_fallback_copy_argv(self, monkeypatch):
        monkeypatch.setattr(clipboard, "_win_copy", lambda text: False)
        monkeypatch.setattr(
            clipboard.shutil, "which", lambda name: "C:/Windows/powershell.exe"
        )
        calls = _install_fake_run(monkeypatch)
        assert clipboard.copy_text("fallback") is True
        argv = calls[0]["argv"]
        assert argv[:3] == ["C:/Windows/powershell.exe", "-NoProfile", "-NonInteractive"]
        assert argv[-2:] == ["-Command", "$input | Set-Clipboard"]
        assert calls[0]["kwargs"]["input"] == b"fallback"


class TestClearScriptSource:
    def test_source_compiles_and_is_silent(self):
        code = compile(clipboard.CLEAR_SCRIPT_SOURCE, "<keepsafe-clear>", "exec")
        assert code is not None
        assert "print(" not in clipboard.CLEAR_SCRIPT_SOURCE
        assert "sys.exit" in clipboard.CLEAR_SCRIPT_SOURCE


@pytest.mark.skipif(sys.platform != "win32", reason="live Windows clipboard test")
class TestLiveWindowsClipboard:
    def _restore(self, original: str) -> None:
        try:
            if original:
                clipboard.copy_text(original)
            else:
                clipboard.clear_now()
        except errors.Unavailable:
            pass

    def test_copy_read_clear_roundtrip(self):
        original = clipboard.read_text()
        payload = f"keepsafe-test-{clipboard.sha256_hex(str(time.time()))[:16]}"
        try:
            assert clipboard.copy_text(payload) is True
            assert clipboard.read_text() == payload
            assert clipboard.clear_now() is True
            assert clipboard.read_text() != payload
        finally:
            self._restore(original)

    def test_schedule_clear_removes_only_our_payload(self):
        original = clipboard.read_text()
        payload = "keepsafe-schedule-payload-9f3a"
        copied_hash = clipboard.sha256_hex(payload)
        try:
            assert clipboard.copy_text(payload) is True
            proc = clipboard.schedule_clear(copied_hash, 1)
            if proc is None:
                pytest.skip("detached clearer process could not spawn")
            time.sleep(2.5)
            current = clipboard.read_text()
            assert current != payload
        finally:
            self._restore(original)

    def test_schedule_clear_spares_user_replacement(self):
        import time as _time

        original = clipboard.read_text()
        replacement = "user-copied-this-instead"
        try:
            assert clipboard.copy_text("doomed-payload") is True
            copied_hash = clipboard.sha256_hex("doomed-payload")
            proc = clipboard.schedule_clear(copied_hash, 1)
            if proc is None:
                pytest.skip("detached clearer process could not spawn")
            time.sleep(0.6)
            assert clipboard.copy_text(replacement) is True
            time.sleep(2.2)
            assert clipboard.read_text() == replacement
        finally:
            self._restore(original)


def test_force_clear_is_safe_to_call_off_windows_branch(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(clipboard.shutil, "which", lambda name: None)
    calls = []
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kwargs: calls.append(list(argv))
        or subprocess.CompletedProcess(argv, 1, b"", b""),
    )
    assert clipboard._force_clear() is False
    assert calls == []
