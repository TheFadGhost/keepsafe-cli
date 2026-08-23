"""Feature-verification driver: exercises every Keepsafe feature through
the real CLI dispatch with real clipboard and a real session daemon.
Only the terminal-prompt functions are scripted (no TTY in automation).

Run:  python tools/demo_session.py
Writes nothing outside KEEPSAFE_HOME; prints a transcript to stdout and
demo-transcript.txt.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

HOME = Path(os.environ.get("KEEPSAFE_DEMO_HOME", ROOT / ".demo-home"))
PASS = "demo-passphrase-with-real-entropy-1"

import keepsafe.cli as cli          # noqa: E402
import keepsafe.prompts as prompts  # noqa: E402


class Transcript:
    def __init__(self):
        self.lines = []

    def header(self, text):
        self.lines.append("")
        self.lines.append("=" * 72)
        self.lines.append(text)
        self.lines.append("=" * 72)

    def note(self, text):
        self.lines.append(f"--- {text}")


T = Transcript()
_hidden = iter([])
_visible = iter([])


def hidden_feed(*values):
    global _hidden
    _hidden = iter(list(values))


def visible_feed(*values):
    global _visible
    _visible = iter(list(values))


prompts.getpass_fn = lambda label="": next(_hidden)
prompts.input_fn = lambda label="": next(_visible)


def run(argv, label=None):
    if label:
        T.note(f"$ keepsafe {' '.join(argv)}   [{label}]")
    else:
        T.note(f"$ keepsafe {' '.join(argv)}")
    buf_out, buf_err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(buf_out), redirect_stderr(buf_err):
            code = cli.main(argv)
    except SystemExit as exc:  # argparse errors
        code = exc.code or 0
    out_lines = buf_out.getvalue().splitlines()
    err_lines = buf_err.getvalue().splitlines()
    for line in out_lines[:14]:
        T.lines.append("  out| " + line)
    if len(out_lines) > 14:
        T.lines.append(f"  ... ({len(out_lines) - 14} more stdout lines)")
    for line in err_lines[:20]:
        T.lines.append("  err| " + line)
    if len(err_lines) > 20:
        T.lines.append(f"  ... ({len(err_lines) - 20} more stderr lines)")
    T.lines.append(f"  => exit {code}")
    return code


def unlocked(argv, label=None, extra=()):
    """A command that opens the vault: passphrase first, then extras
    (e.g. a prompted secret)."""
    hidden_feed(PASS, *extra)
    return run(argv, label)


def main() -> int:
    shutil.rmtree(HOME, ignore_errors=True)
    os.environ["KEEPSAFE_HOME"] = str(HOME)

    T.header("1. init: threat model onboarding")
    hidden_feed(PASS, PASS)
    run(["init"], "passphrase typed twice, input hidden")

    T.header("2. add entries (unicode names, fields, tags)")
    unlocked(["add", "web/github", "--username", "demo-user",
              "--url", "https://github.com", "--tags", "dev,web"],
             "secret prompted hidden after the vault passphrase",
             extra=["gh-demo-secret-123"])
    unlocked(["add", "邮件/bank", "--username", "用户", "--tags", "finance"],
             extra=["bank-demo-secret-456"])
    visible_feed("", "")  # template field answers (endpoint, quota)
    unlocked(["add", "servers/prod/api", "--template", "api-key"],
             "template fields prompted visibly; empty answers kept",
             extra=["api-key-demo-value-000111"])

    T.header("3. list / tree / search (secrets never shown)")
    unlocked(["list"])
    unlocked(["list", "--tree"])
    unlocked(["search", "github"])

    T.header("4. get: clipboard by default, --print to display")
    unlocked(["get", "web/github"], "copies to real clipboard, auto-clears")
    unlocked(["get", "web/github", "--print"])
    unlocked(["get", "邮件/bank", "-p", "--raw"])

    T.header("5. gen passwords and passphrases")
    run(["gen", "--length", "24"])
    run(["gen", "--words", "6", "--sep", "+", "--count", "2"])

    T.header("6. edit / mv / rename")
    unlocked(["edit", "web/github", "--add-tags", "important"])
    unlocked(["mv", "servers/prod/api", "servers/staging/api"])
    unlocked(["rename", "servers/staging/api", "edge"])

    T.header("7. export gates: declined, redacted, then plaintext phrase")
    target = HOME.parent / "demo-export.json"
    if target.exists():
        target.unlink()
    visible_feed("no")
    unlocked(["export", str(target)], "declined: no file written")
    assert not target.exists()
    visible_feed("y")
    unlocked(["export", str(target), "--redacted"])
    visible_feed("export-plaintext")
    unlocked(["export", str(target), "--force"], "typed phrase accepted")

    T.header("8. import round-trip into a fresh vault")
    vpath = HOME / "vault.kpsf"
    vpath.rename(HOME / "old-vault.kpsf")
    hidden_feed(PASS, PASS)
    run(["init"], "fresh vault for import")
    unlocked(["import", str(target)])
    unlocked(["list"])

    T.header("9. audit (local only)")
    run(["audit"])

    T.header("10. session: unlock, status, passphrase-free get, lock")
    run(["unlock"], "one passphrase now unlocks a session")
    run(["status"])
    run(["get", "web/github", "--output", "json"],
        "no passphrase scripted here; session served this request")
    run(["lock"])
    run(["status"])

    T.header("11. rekey gate + parameter upgrade, changepass")
    visible_feed("rekey")
    hidden_feed(PASS, "upgraded-passphrase-9", "upgraded-passphrase-9")
    run(["rekey", "--kdf-memory", "131072"])
    run(["restore", "--list"])
    visible_feed("y")
    run(["restore", "0"], "restores pre-rekey backup (old passphrase era)")

    T.header("12. refusals: wrong passphrase, rm phrase gate")
    hidden_feed("definitely-not-the-passphrase")
    run(["list"], "wrong passphrase -> generic unlock failure")
    run(["rm", "web/github"], "declined typed confirmation (EOF aborts)")

    T.header("13. tampered vault refused")
    # restore used backup 0 (pre-rekey); its passphrase is PASS again.
    blob = bytearray((HOME / "vault.kpsf").read_bytes())
    blob[len(blob) // 2] ^= 0x01
    (HOME / "vault.kpsf").write_bytes(bytes(blob))
    hidden_feed(PASS)
    run(["list"], "tamper detected, generic refusal")

    T.header("14. completions and help surface")
    run(["completions", "--shell", "bash"])
    T.note("--help epilog excerpt below")
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        try:
            cli.build_parser().parse_args(["--help"])
        except SystemExit:
            pass
    for line in buf_out.getvalue().splitlines()[-8:]:
        T.lines.append("  " + line)

    T.header("15. NO_COLOR honoured")
    os.environ["NO_COLOR"] = "1"
    hidden_feed(PASS)
    run(["list"])
    del os.environ["NO_COLOR"]

    out_path = Path(os.environ.get("KEEPSAFE_DEMO_OUT", ROOT / "demo-transcript.txt"))
    out_path.write_text("\n".join(T.lines), encoding="utf-8")
    print("Transcript written to", out_path)
    print("Demo vault home kept at:", HOME)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
