# Keepsafe CLI design

## Point of view

Keepsafe is a careful, sober tool for storing a small number of personal
secrets in one encrypted file. It never rushes the user and never makes a
destructive action easy by accident. For a security tool, clarity is the
design: an ambiguous prompt is a security defect, so every prompt states
what will happen in plain words, every warning carries its meaning in text
and not only in colour, and the destructive path always costs more
keystrokes than the safe one. The tool explains slowness instead of hiding
it (key derivation is intentionally slow), admits what it cannot protect
against, and treats silence about secrets as the default rather than the
exception.

## Command surface

Verb-first subcommands, predictable names:

```
keepsafe init                     create a new vault
keepsafe add NAME                 add an entry (interactive prompts)
keepsafe get NAME                 copy secret to clipboard (never prints)
keepsafe list [FOLDER]            list entries / show tree
keepsafe search QUERY             filter by name, username, url, notes, tags
keepsafe edit NAME                change fields of an entry
keepsafe rm NAME                  delete an entry (typed confirmation)
keepsafe mv SRC DST               move/repath an entry
keepsafe rename NAME NEW          rename last path segment only
keepsafe gen                      generate password or passphrase
keepsafe import FILE              import JSON or CSV into vault
keepsafe export FILE              export plaintext (typed confirmation)
keepsafe rekey                    new KDF parameters and/or passphrase
keepsafe changepass               new passphrase, keep KDF parameters
keepsafe audit                    report weak/reused/stale/incomplete entries
keepsafe unlock                   start an unlocked session
keepsafe lock                     end session immediately
keepsafe status                   show vault and session state (no secrets)
keepsafe restore                  restore a backup (--list to enumerate)
```

Flags are long-form kebab-case; short aliases only where obvious
(`-p` = `--print`). Global flags: `--vault PATH`, `--no-color`,
`--output text|json`. Every command honours `--output json`.

## Passphrase prompt

```
Passphrase for C:\Users\me\vault.kpsf (input hidden):
```

Input uses getpass: nothing echoes - no asterisks, no dots, nothing. The
literal "(input hidden)" explains why the screen stays blank. The prompt
asks once more on mismatch for init/rekey ("did not match, try again"),
then aborts without writing anything. The passphrase never appears in argv,
environment variables, shell history, logs, or error messages. Unlocking is
intentionally slow; when derivation runs longer than about a second the CLI
prints once:

```
Deriving key from passphrase (Argon2id, 64 MiB x3). This takes a moment by design.
```

No spinner and no progress bar: the wait is the security working, and a
spinner would imply something is wrong.

## Warnings before dangerous actions

A warning has four parts, in order:

1. STATE - what is true right now ("this entry holds 1 secret").
2. EFFECT - what the action does, including irreversibility.
3. SCOPE - exactly what is affected (full entry path, output file path).
4. COST - what the user must type to proceed.

A bare y/n is insufficient for irreversible actions because y is one
keystroke of habit. Those require typing an exact phrase:

| action   | required phrase       |
|----------|-----------------------|
| export   | export-plaintext      |
| rm       | the entry path itself |
| rekey    | rekey                 |

Reversible-but-risky actions (import over existing paths, restore) use y/n,
and every mutating action takes an automatic backup first; the notice says
where that backup went.

## Error taxonomy

Exit codes: 0 success (a declined confirmation is also 0); 1 audit found
issues; 2 unlock failure or unusable vault file; 3 nothing matched;
4 usage/config; 5 feature unavailable on this platform; 10 internal error;
130 interrupted.

- VaultMissing: "No vault found at PATH. Run: keepsafe init"
- UnlockFailed: "Unable to unlock the vault. The passphrase may be wrong,
  or the file may be damaged or tampered with." Wrong passphrase and
  corrupted/tampered file are never distinguished: authentication cannot
  tell them apart and neither should we.
- VersionNewer: "This vault was written by a newer version of Keepsafe
  (format vN). Upgrade Keepsafe to open it."
- NotMatched: "No entry matches NAME." Identical whether or not other
  entries exist; suggests list/search without hinting at contents.
- UsageError: what was wrong plus the exact correct form.
- Unavailable: missing clipboard tool, read-only directory, disk full;
  states cause and remedy.
- InternalError: prints "internal error" plus a sanitized trace; exception
  text is scrubbed of any loaded secret values before printing.

No-leak rule: error text must help the user without revealing whether a
given entry exists, whether a passphrase was partially correct (it is all
or nothing by construction), or any part of any secret. The crash-path
scrubber replaces loaded secret substrings with [redacted]; substrings
shorter than 8 characters are exempt because they cannot be placed
unambiguously in prose (a 1-2 character "secret" would mangle ordinary
words while adding no protection). Short values are still never echoed,
copied to logs, or included in any output channel.

## List and search layout

Text mode, aligned columns, unicode-safe width (East Asian wide characters
counted as 2 terminal cells):

```
NAME                       USERNAME       UPDATED     TAGS
web/github                 octocat        2026-08-01  dev
servers/prod/db            root           2026-07-12  prod,db
mail/bank                  -              2026-06-30  finance
```

Columns: NAME (left, min width 24), USERNAME (min 14, "-" if empty),
UPDATED (date only), TAGS (comma-joined). No SECRET column exists in list
or search output. "list --tree" shows the folder hierarchy indented two
spaces per level. Search uses the same table plus a MATCH column naming the
field that matched (name, username, url, notes, tag).

## Secret masking rule

A secret value may appear in full in exactly these places:

1. get NAME --print (explicit flag).
2. Custom fields with secret: false when printed explicitly.
3. gen stdout (generation is pointless otherwise); clipboard copy via --copy.
4. Export files written by export after typed confirmation.
5. Hidden typed input during add/edit.

Everywhere else secrets are masked as ******** (fixed 8 glyphs, revealing
nothing about length). get without --print shows the mask plus the copy
notice. Machine-readable output omits secret fields unless --include-secrets
is passed, which prints a warning banner to stderr first. There are no logs;
if a traceback escapes, a sanitizer replaces any loaded secret substring
with [redacted] before it reaches the terminal.

## Colour

One semantic token set, two themes, plain mode. No ANSI codes outside
render.py.

| token   | dark terminal    | light terminal    | plain form                  |
|---------|------------------|-------------------|-----------------------------|
| accent  | cyan (36)        | blue (34)         | none (structure only)       |
| dim     | bright black(90) | bright black(90)  | parentheses around metadata |
| success | green (32)       | green (32)        | word ok:                    |
| warning | yellow (33)      | yellow (33)       | word warning:               |
| danger  | red (31) bold    | magenta (35) bold | word error:                 |

Rules:

- Colour is decoration-free: this table is the entire vocabulary.
- The literal word travels with the colour in EVERY mode, colour mode
  included, so hue is never the only carrier of meaning. Warning is not
  bold while danger is: the two states differ in weight as well as hue,
  which keeps them distinguishable under deuteranopia even on a
  full-colour terminal. Light-theme danger uses magenta against yellow
  warnings for hue-independent separation.
- NO_COLOR env var, --no-color, and non-TTY stdout all disable colour
  completely. Only 16-colour SGR codes exist anywhere; no 256-colour or
  truecolour codes.
- A security CLI does not need more colour than this. Nothing else gets a
  token.

## Machine-readable output

--output json: exactly one JSON document on stdout; all human notices go to
stderr so scripts capture clean data. Secret-valued keys are omitted unless
--include-secrets is also given (warning banner on stderr first). Exit
codes unchanged. Lists are arrays; single results are objects.

## Audit report layout

```
Audit of C:\Users\me\vault.kpsf - 42 entries

weak secrets (length under 12 characters)
  servers/prod/db                        8 chars, changed 2025-01-04

reused secrets (same value in multiple entries)
  [sha256 prefix 3f9a] used by 3 entries
    web/github, web/gitlab, web/gitea

not rotated in 365 days (--stale-days)
  old/misc/dialup                        changed 2024-02-11

missing username
  web/forum

missing url
  servers/prod/db

summary: 3 weak, 1 reused group (3 entries), 2 stale, 1 missing username, 1 missing url
all checks computed locally; no external lookups of any kind
```

Sections appear only when non-empty. Each finding names an entry path and a
reason in words. Reused secrets group by 6-hex-char sha256 prefix; full
hashes never print. Weakness checks: length under threshold (default 12,
configurable), fewer than 2 character classes at length 16+, presence in a
small embedded common-password list. Everything local.

## Session

unlock derives the key once and keeps it only in a helper process memory,
behind a loopback-only endpoint guarded by a random per-session token
stored with user-only permissions. Default idle timeout 15 minutes
(configurable); lock ends it immediately; status reports remaining time
without exposing the key. Honest trade-off, stated in help and README:
while unlocked, any process running as your user can read the token file
and ask the session to decrypt, and memory inspection of the helper could
reveal the key. The default timeout is deliberately short.

## Clipboard

get copies and reports: Copied to clipboard. Clears automatically in 30 s.
The clear job runs detached, compares current clipboard content against
what we copied, and clears only if unchanged, so we never destroy something
the user copied afterwards. Per platform: Windows PowerShell Set-Clipboard
with a ctypes-based clear check, macOS pbcopy/pbpaste, Linux xclip/xsel/
wl-copy. With no mechanism available: exit code 5, message names the gap
and suggests --print.

## Terminal integrity

SIGINT and any exit path restore the terminal state; vault writes are
atomic (temp file + rename) so a crash leaves either the old or the new
file, never a truncated one, with the pre-write copy preserved as a backup.

Concurrent writers: two simultaneous mutating commands are last-writer-
wins and are not detected. Each writer backs up the file as it existed
BEFORE its own write, so the other writer's result remains recoverable
from the backup directory; this is stated in the README rather than
hidden.
