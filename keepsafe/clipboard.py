"""Clipboard copy/read/auto-clear for secrets delivery.

Per DESIGN.md "Clipboard": ``get`` copies and reports "Clears
automatically in N s"; the clear job runs DETACHED, re-checks after the
timeout that the clipboard still contains what WE copied (hash
comparison), and clears only then -- so we never destroy something the
user copied afterwards. Platforms: Windows ctypes (user32/kernel32)
with a PowerShell fallback, macOS pbcopy/pbpaste, Linux wl-copy/xclip/
xsel. No mechanism available -> ``errors.Unavailable`` (exit code 5).

Honest limits: anything running as the same user can read the clipboard
while the secret sits there, and the detached clearer is best-effort --
if the machine powers off before it fires, the secret stays until the
next copy. The window is bounded by the configured timeout, default 30 s.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import time

from . import errors

DEFAULT_TIMEOUT_SECONDS = 30

_CF_UNICODETEXT = 13
_GMEM_MOVEABLE = 0x0002
_WIN_OPEN_RETRIES = 10
_WIN_OPEN_RETRY_DELAY = 0.05
_PROC_TIMEOUT = 10.0
_WIN_DETACHED_PROCESS = 0x00000008
_WIN_CREATE_NO_WINDOW = 0x08000000

_LINUX_COPY_TOOLS = (
    ("wl-copy", ("wl-copy",)),
    ("xclip", ("xclip", "-selection", "clipboard")),
    ("xsel", ("xsel", "--clipboard", "--input")),
)
_LINUX_PASTE_TOOLS = (
    ("wl-paste", ("wl-paste",)),
    ("xclip", ("xclip", "-selection", "clipboard", "-o")),
    ("xsel", ("xsel", "--clipboard", "--output")),
)


def sha256_hex(text: str) -> str:
    """UTF-8 SHA-256 hex digest of *text*."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def should_clear(current_text: str, copied_hash_hex: str) -> bool:
    """True only when the clipboard still hashes to what we copied.

    If the user copied something else since, the hash differs and we
    must NOT clear.
    """
    return sha256_hex(current_text) == copied_hash_hex


def copy_text(text: str) -> bool:
    """Copy *text* to the system clipboard; True on success.

    Raises ``errors.Unavailable`` when no mechanism exists or every
    mechanism fails.
    """
    if sys.platform == "win32":
        if _win_copy(text):
            return True
        if _powershell_copy(text):
            return True
        raise errors.Unavailable(
            "No clipboard mechanism available: Windows clipboard API and "
            "PowerShell Set-Clipboard both failed."
        )
    if sys.platform == "darwin":
        pbcopy = shutil.which("pbcopy")
        if pbcopy:
            try:
                proc = subprocess.run(
                    [pbcopy],
                    input=text.encode("utf-8"),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=_PROC_TIMEOUT,
                )
                if proc.returncode == 0:
                    return True
            except (OSError, subprocess.SubprocessError):
                pass
        raise errors.Unavailable(
            "No clipboard mechanism available: pbcopy was not found."
        )
    for name, argv in _LINUX_COPY_TOOLS:
        tool = shutil.which(name)
        if tool:
            try:
                proc = subprocess.run(
                    [tool, *argv[1:]],
                    input=text.encode("utf-8"),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=_PROC_TIMEOUT,
                )
                if proc.returncode == 0:
                    return True
            except (OSError, subprocess.SubprocessError):
                continue
    raise errors.Unavailable(
        "No clipboard mechanism available: install wl-copy, xclip, or xsel "
        "(or use --print)."
    )


def read_text() -> str:
    """Current clipboard text; "" when no mechanism or nothing readable.

    Never raises: reading the clipboard is a check, not a promise.
    """
    try:
        if sys.platform == "win32":
            text = _win_read()
            if text is not None:
                return text
            return _powershell_read()
        if sys.platform == "darwin":
            pbpaste = shutil.which("pbpaste")
            if pbpaste is None:
                return ""
            proc = subprocess.run(
                [pbpaste],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=_PROC_TIMEOUT,
            )
            if proc.returncode != 0:
                return ""
            return proc.stdout.decode("utf-8", errors="replace")
        for name, argv in _LINUX_PASTE_TOOLS:
            tool = shutil.which(name)
            if tool:
                try:
                    proc = subprocess.run(
                        [tool, *argv[1:]],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        timeout=_PROC_TIMEOUT,
                    )
                except (OSError, subprocess.SubprocessError):
                    continue
                if proc.returncode == 0:
                    return proc.stdout.decode("utf-8", errors="replace")
        return ""
    except (OSError, subprocess.SubprocessError):
        return ""


def clear_now() -> bool:
    """Immediate best-effort clipboard clear; never raises."""
    try:
        return _force_clear()
    except Exception:
        return False


CLEAR_SCRIPT_SOURCE = r'''
import sys, time


def _main():
    # Handshake arrives on stdin: one line "<hash-hex> <timeout-seconds>".
    try:
        line = sys.stdin.readline()
    except Exception:
        return 0
    parts = line.split()
    if len(parts) != 2:
        return 0
    copied_hash_hex = parts[0]
    try:
        timeout = float(parts[1])
    except ValueError:
        return 0
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.25, remaining))
    try:
        from keepsafe.clipboard import read_text, should_clear, _force_clear

        current = read_text()
        if should_clear(current, copied_hash_hex):
            _force_clear()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(_main())
'''


def schedule_clear(copied_hash_hex: str, timeout_seconds: int):
    """Spawn the detached auto-clear helper; Popen or None (never raises).

    The child sleeps *timeout_seconds* in small increments, then clears
    only if the clipboard still hashes to *copied_hash_hex*. The hash and
    timeout are passed over the child's stdin, NOT argv: command lines are
    readable by other processes on the machine, pipes are not (by any
    process that was not given the handle). Parent-side stdout/stderr are
    DEVNULL; stdin is the pipe the child reads once.
    """
    try:
        popen_kwargs = {}
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = _WIN_DETACHED_PROCESS | _WIN_CREATE_NO_WINDOW
        else:
            popen_kwargs["start_new_session"] = True
        package_parent = _package_parent()
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                CLEAR_SCRIPT_SOURCE,
            ],
            cwd=str(package_parent),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **popen_kwargs,
        )
    except Exception:
        return None
    try:
        proc.stdin.write(f"{copied_hash_hex} {int(timeout_seconds)}\n".encode("ascii"))
        proc.stdin.close()
    except Exception:
        pass
    return proc


def _package_parent():
    from pathlib import Path

    return Path(__file__).resolve().parent.parent


def _run_powershell(command_args: list, input_bytes: bytes | None = None):
    exe = shutil.which("powershell")
    if exe is None:
        return None
    return subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", *command_args],
        input=input_bytes,
        capture_output=True,
        timeout=_PROC_TIMEOUT,
    )


def _powershell_copy(text: str) -> bool:
    try:
        proc = _run_powershell(["-Command", "$input | Set-Clipboard"], text.encode("utf-8"))
    except (OSError, subprocess.SubprocessError):
        return False
    return proc is not None and proc.returncode == 0


def _powershell_read() -> str:
    try:
        proc = _run_powershell(["-Command", "Get-Clipboard"])
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc is None or proc.returncode != 0:
        return ""
    return proc.stdout.decode("utf-8", errors="replace").rstrip("\r\n")


def _win_dlls():
    import ctypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_int
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = ctypes.c_int
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = ctypes.c_int
    user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    user32.SetClipboardData.restype = ctypes.c_void_p
    user32.GetClipboardData.argtypes = [ctypes.c_uint]
    user32.GetClipboardData.restype = ctypes.c_void_p
    user32.IsClipboardFormatAvailable.argtypes = [ctypes.c_uint]
    user32.IsClipboardFormatAvailable.restype = ctypes.c_int
    kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.restype = ctypes.c_int
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.restype = ctypes.c_void_p
    return user32, kernel32


def _win_open_clipboard(user32) -> bool:
    # Other apps hold the clipboard sometimes; retry politely before
    # giving up and falling back.
    for attempt in range(_WIN_OPEN_RETRIES):
        if user32.OpenClipboard(None):
            return True
        time.sleep(_WIN_OPEN_RETRY_DELAY)
    return False


def _win_copy(text: str) -> bool:
    import ctypes

    payload = text.encode("utf-16-le") + b"\x00\x00"
    try:
        user32, kernel32 = _win_dlls()
    except OSError:
        return False
    if not _win_open_clipboard(user32):
        return False
    try:
        if not user32.EmptyClipboard():
            return False
        handle = kernel32.GlobalAlloc(_GMEM_MOVEABLE, len(payload))
        if not handle:
            return False
        locked = kernel32.GlobalLock(handle)
        if not locked:
            kernel32.GlobalFree(handle)
            return False
        try:
            ctypes.memmove(locked, payload, len(payload))
        finally:
            kernel32.GlobalUnlock(handle)
        if not user32.SetClipboardData(_CF_UNICODETEXT, handle):
            kernel32.GlobalFree(handle)
            return False
        return True
    except Exception:
        return False
    finally:
        user32.CloseClipboard()


def _win_read() -> str | None:
    import ctypes

    try:
        user32, kernel32 = _win_dlls()
    except OSError:
        return None
    if not _win_open_clipboard(user32):
        return None
    try:
        if not user32.IsClipboardFormatAvailable(_CF_UNICODETEXT):
            return ""
        handle = user32.GetClipboardData(_CF_UNICODETEXT)
        if not handle:
            return ""
        locked = kernel32.GlobalLock(handle)
        if not locked:
            return ""
        try:
            return ctypes.wstring_at(locked)
        finally:
            kernel32.GlobalUnlock(handle)
    except Exception:
        return None
    finally:
        user32.CloseClipboard()


def _force_clear() -> bool:
    """Clear via the raw platform mechanism (EmptyClipboard / empty stdin)."""
    if sys.platform == "win32":
        user32, _kernel32 = _win_dlls()
        if not _win_open_clipboard(user32):
            return False
        try:
            return bool(user32.EmptyClipboard())
        finally:
            user32.CloseClipboard()
    candidates = (("pbcopy", ("pbcopy",)),) if sys.platform == "darwin" else _LINUX_COPY_TOOLS
    for name, argv in candidates:
        tool = shutil.which(name)
        if tool:
            try:
                proc = subprocess.run(
                    [tool, *argv[1:]],
                    input=b"",
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=_PROC_TIMEOUT,
                )
                if proc.returncode == 0:
                    return True
            except (OSError, subprocess.SubprocessError):
                continue
    return False
