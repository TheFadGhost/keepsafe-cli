# Keepsafe CLI

> **built with ox alpha**
>
> most of this was written in august 2026 during the free preview window of
> [ox alpha](https://openrouter.ai/stealth/ox-alpha), an anonymous stealth model
> that turned up on openrouter for about a week. i set the direction and reviewed
> what came back. the tests are real and they pass — clone it and run them.

A command-line encrypted secrets vault for personal use and learning: your
credentials and notes live in a single passphrase-encrypted file on your own
machine.

## Threat model - read this first

Keepsafe is **unaudited software**. It has not received professional
cryptographic review. Do not rely on it for high-risk situations.

What it protects: the confidentiality of the vault file at rest, against
someone who obtains the file but not your passphrase.

What it does not protect against:

- malware or any other compromise of this machine;
- keyloggers recording your passphrase as you type it;
- memory inspection of a running Keepsafe process;
- other applications reading your clipboard after you copy a secret;
- anyone using this terminal while a session is unlocked.

If you lose the passphrase, the data is gone. There is no recovery, no
reset, and no back door.

Keepsafe has no network capability of any kind. It never contacts a server,
never syncs, never looks up breach databases. All checks are computed
locally.

## Install

Requires Python 3.9+.

```
git clone https://github.com/TheFadGhost/keepsafe-cli
cd keepsafe-cli
python -m venv .venv
.venv\Scripts\pip install -e .        # Windows
# .venv/bin/pip install -e .          # macOS/Linux
keepsafe --help
```

Dependencies: `pynacl` (libsodium) and `argon2-cffi`. Both are vetted,
actively maintained libraries; Keepsafe implements no cryptographic
primitives itself.

## Quick start

```
keepsafe init                       create a vault (prints the threat model)
keepsafe add web/github             add an entry; secret input is hidden
keepsafe get web/github             copy the secret to the clipboard,
                                    auto-clears in 30 s; never prints
keepsafe get web/github --print     display the secret instead
keepsafe list --tree                show entries as a folder tree
keepsafe search github              search names, usernames, urls, notes, tags
keepsafe gen --words 6              generate a passphrase from the EFF short list
keepsafe gen --length 24            generate a password
keepsafe audit                      report weak, reused, stale, incomplete entries
keepsafe lock                       end an unlocked session immediately
```

Every command also accepts `--output json` for machine-readable output that
omits secret values unless `--include-secrets` is passed explicitly, and
`--no-color` / honours `NO_COLOR`.

Key derivation is intentionally slow (about a second on modest hardware).
That is the design working, not a defect; see the parameters below.

## Dangerous operations require more than y/n

Irreversible actions ask you to type a phrase, because one keystroke of
habit must not be able to trigger them:

| action                    | confirmation                        |
|---------------------------|-------------------------------------|
| `export` (plaintext)      | type `export-plaintext`             |
| `rm NAME`                 | type the entry path                 |
| `rekey`                   | type `rekey`                        |

## Cryptographic construction

For reviewers evaluating the tool:

- Key derivation: Argon2id (`argon2-cffi`, low-level raw API), 32-byte key.
  Shipped defaults: 64 MiB memory (65536 KiB), t=3 iterations, p=4 lanes,
  32-byte random salt. Parameters are stored in the vault header and can be
  raised later via `keepsafe rekey`. Readers enforce hard maximums on header
  parameters (2 GiB / 32 / 64) before derivation so a hostile or corrupt
  file cannot demand unbounded resources. Passphrases are NFKC-normalized
  then UTF-8 encoded.
- Encryption: libsodium's XChaCha20-Poly1305-IETF through PyNaCl's high-level
  `nacl.secret.Aead` API. A fresh 192-bit CSPRNG nonce per encryption;
  collision probability across n writes is below n^2 / 2^193. The entire
  85-byte header (magic, version, KDF type, salt, KDF parameters, nonce,
  payload length) is passed as associated data, so the authentication tag
  covers header plus payload together: a tampered header is detected and
  refused, never obeyed.
- File layout ("KPSF" v1), all integers little-endian:

```
offset  size  field
0       4     magic "KPSF"
4       4     format version (= 1)
8       1     KDF type (= 1, Argon2id)
9       32    salt
41      4     memory KiB
45      4     iterations
49      4     parallelism
53      24    nonce
77      8     payload length
85      ...   ciphertext + 16-byte Poly1305 tag
```

The payload is UTF-8 JSON (sorted keys): entry name, username, secret, url,
notes, tags, created/updated timestamps (ISO 8601 UTC), and arbitrary custom
fields each flagged secret or not. Entries live at slash-separated paths
(`servers/prod/db`); folders are implied by paths. See `FORMAT.md` for the
normative contract.

Unlock failures are deliberately indistinguishable: wrong passphrase,
tampered header, and corrupt file all produce the same message. Only three
pre-decryption conditions are reported specifically: missing file, bad
magic, newer format version.

## Backups and recovery

- Every mutating command first copies the current vault into
  `<vault folder>/backups/<name>.<timestamp>.bak.kpsf`. The newest
  `backup_count` backups (default 5, configurable) are kept; older ones are
  pruned. Backups are encrypted exactly like the vault.
- `keepsafe restore --list` enumerates backups; `keepsafe restore 0` (or
  `--latest`) restores one after backing up the current file again.
- Writes are atomic (temporary file plus rename). A crash mid-write leaves
  either the old or the new vault, never a truncated one. Two simultaneous
  writers are last-writer-wins and undetected; each writer backs up the
  pre-write file first, so the other result stays recoverable from backups.
  Run one mutating command at a time.
- Exports are plaintext by definition. `keepsafe export` requires typing
  `export-plaintext`; use `--redacted` to omit secret values. Imports warn
  that the source file still contains plaintext secrets.
- Lost passphrase: the data is unrecoverable. Keep the passphrase and at
  least one backup in different places if the data matters to you.

## Sessions

`keepsafe unlock` derives the key once and keeps it only in a helper
process's memory, reachable over a loopback endpoint guarded by a random
per-session token. The default idle timeout is 15 minutes (configurable);
`keepsafe lock` ends it now; `keepsafe status` shows remaining time. The
honest trade-off: while unlocked, any process running as your user can read
the token file and use the session, and memory inspection could reveal the
key.

## Configuration

`~/.keepsafe/config.json` (override the folder with `KEEPSAFE_HOME`):
`vault_path`, `backup_count`, `clipboard_timeout` seconds,
`session_timeout` seconds, `audit_min_length`, `audit_stale_days`,
`color_theme` (dark/light), `output_mode`. Shell completion scripts:
`keepsafe completions --shell bash|zsh|fish` (entry-name completion works
while a session is unlocked; names only, never values).

## Architecture note

Single Python package, no network code:

```
crypto.py     only module touching primitives (Argon2id, XChaCha20-Poly1305-IETF)
format.py     header pack/parse, whole-file encrypt/decrypt (FORMAT.md contract)
storage.py    atomic writes, automatic backups, restore
model.py      entry model, path semantics, payload round-trip
query.py      filter/search/tree        render.py  colour tokens, tables, masking
session.py    loopback unlock daemon    clipboard.py copy + timed auto-clear
transfer.py   import/export (JSON, CSV) auditcmd.py local-only audit analysis
generate.py   passwords/passphrases     cli.py     argument surface, dispatch
errors.py     exception taxonomy -> exit codes
```

Only `render.py` emits ANSI codes; colour vocabulary is five semantic
tokens, two themes, plus a plain mode paired with literal words
(`warning:`, `error:`) so meaning survives without colour and under
colour-vision deficiency.

## Test fixtures

Vault files under `tests/fixtures/` were generated by
`tools/make_fixtures.py` from invented data using the published test
passphrase `fixture-passphrase-0001`. They are marked as fake and must
never be replaced with real secrets. The regression suite proves current
releases still open every released format version.

## License

MIT (see LICENSE). The bundled EFF short wordlist is (c) Electronic Frontier
Foundation, redistributed under CC BY 4.0.