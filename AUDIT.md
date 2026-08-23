# AUDIT.md - pre-release audit log

Three independent audits were run by reviewers who wrote none of the code:
crypto/format, whole-codebase quality, and design/output conformance.
Findings below were reproduced where possible, then fixed; the re-audit
section at the bottom records the follow-up verdicts.

## Round 1 findings and dispositions

| # | Severity | Area | Finding | Disposition |
|---|----------|------|---------|-------------|
| 1 | BLOCKER | cli | `init --force` refused its own confirmed operation (`store.create` defaulted to force=False) | FIXED: force propagated |
| 2 | BLOCKER | cli | argparse usage errors exited 2, colliding with unlock failure | FIXED: parser.error raises UsageError (exit 4) |
| 3 | BLOCKER | cli | `add --generate` put the generated secret into JSON output ungated | FIXED: gated behind --include-secrets + banner; text mode prints to stdout like gen |
| 4 | MAJOR | cli/storage | `export` could target the live vault path, overwriting it with plaintext, no backup | FIXED: refuses targets resolving to the vault file |
| 5 | MAJOR | cli | model.ValueError surfaced as raw traceback exit 10 | FIXED: mapped to UsageError at command boundary |
| 6 | MAJOR | cli | non-UTF-8 import file -> UnicodeDecodeError traceback | FIXED: UsageError with remedy |
| 7 | MAJOR | cli | clipboard-unavailable on `get` exited 0, contradicting DESIGN (exit 5) | FIXED: Unavailable propagates unless --print/--no-copy |
| 8 | MAJOR | render | colour mode carried hue but dropped the literal word; warning/danger shared weight | FIXED: words always present in colour mode too; warning un-bolded so weight separates |
| 9 | MAJOR | prompts | passphrase-mismatch aborted immediately instead of retry-once with stated wording | FIXED: retry loop with exact wording |
| 10 | MAJOR | cli | generated secret printed to stderr styled as a warning | FIXED: stdout in text mode |
| 11 | MAJOR | output | doubled `warning:` prefixes at export/import/include-secrets | FIXED: prefixes removed from message bodies |
| 12 | MAJOR | cli | backup location announced only for rekey/changepass | FIXED: every mutating command reports its backup path |
| 13 | MINOR | format | pack_header packed out-of-range KDF params as raw struct.error | FIXED: validated, clean InternalError |
| 14 | MINOR | crypto | per-parameter caps did not bound the product memory x iterations | FIXED: combined-cost cap added |
| 15 | MINOR | cli | numeric flags (--timeout/--count/--gen-length) unbounded or negative | FIXED: bounded validators |
| 16 | MINOR | storage/cli | double backup per mutation halved retention | FIXED: caller-side backups removed where save backs up |
| 17 | MINOR | transfer | duplicated width helpers diverged from render's (combining marks) | FIXED: auditcmd uses render helpers |
| 18 | MINOR | cli | machine JSON schema inconsistent (reused names string vs arrays) | FIXED: arrays everywhere |
| 19 | MINOR | cli | stale runtime token file survived helper death | FIXED: cleared on failed connect |
| 20 | MINOR | clipboard | secret hash passed in clearer-process argv | FIXED: piped via stdin |
| 21 | MINOR | cli | ALL-CAPS shouting in notices/help (EVERY, PLAINTEXT, OLD, THREAT MODEL) | FIXED: sentence case |
| 22 | MINOR | cli | user declines styled as `error:` despite exit 0 | FIXED: plain abort notice, no danger word |
| 23 | MINOR | cli | audit exit code 1 undocumented | DOCUMENTED in DESIGN.md taxonomy |
| 24 | MINOR | cli | JSON mode kept masked keys instead of omitting | FIXED: omitted unless --include-secrets |
| 25 | MINOR | cli | --help subcommand descriptions blank (help kwarg popped) | FIXED |
| 26 | MINOR | cli | internal-error output lacked an `internal error:` heading | FIXED |
| 27 | MINOR | cli | sanitizer floor let short secrets escape scrubbing | DOCUMENTED threshold in DESIGN.md (substrings under 3 chars are ambiguous) and lowered floor to match |
| 28 | NOTE | session | seal op accepted arbitrary caller nonces | MITIGATED: added server-fresh `nonce` op used by the write path; explicit nonces remain necessary for header-AAD binding and are documented |
| 29 | NOTE | cli | unlock derived the key twice | FIXED: open_vault_file_with_key |
| 30 | NOTE | cli | zeroization zeroed a copy, not the key | FIXED: ctx.key held as bytearray, zeroized in place |
| 31 | NOTE | transfer | sniff_format could raise on NUL bytes on POSIX | FIXED: guarded |
| 32 | NOTE | docs | concurrent writers are last-writer-wins | DOCUMENTED in README/DESIGN |
| 33 | NOTE | session | Windows runtime-file chmod is a no-op | DOCUMENTED honestly in module docstring |

## Verified conformant (highlights)

- AEAD binds the entire 85-byte header on every writer and reader; layout
  byte-exact vs FORMAT.md; tampered headers refused everywhere.
- Fresh CSPRNG nonce on every write path; backups are ciphertext copies;
  crash simulations leave no partial files.
- Wrong-passphrase/tampered/corrupt produce byte-identical messages and
  exit 2; newer-version distinct; NotMatched reveals nothing.
- Masking rule holds across list/search/get/gen/audit/export-redacted/
  JSON mode; stdout carries exactly one JSON document in machine mode.
- Session: loopback-only, token compared constant-time, server-side idle
  expiry, key never in argv/env/files, lock cleans up.
- Threat model and unaudited notice present in README, --help epilog, and
  first-run init output.

## Round 2

Recorded after fixes land and the suite plus feature demonstration are
re-run; see the bottom of this file.
