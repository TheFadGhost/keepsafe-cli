# PLAN.md - feature ideation decisions

Each idea was judged against three tests: (1) does it serve storing and
retrieving secrets safely, (2) can it be finished to the same quality bar as
the core, (3) does it avoid expanding scope into a second product. Evidence
came from what users of pass, rbw, gopass, and bitwarden-cli actually
request. Accepted items are first-class features: same build loop, same
tests, same audit.

## Accepted

| feature | one-line reason |
|---------|-----------------|
| Shell completion for entry names (bash/zsh/fish) | Accelerates retrieval; names only, never values; bounded scripts plus one hidden completion command. |
| Config file (vault path, clipboard timeout, session timeout, audit thresholds, theme) | Every knob needs a home; static JSON, docs-and-tests work only. |
| Error taxonomy: wrong passphrase vs corrupt vault vs newer version | The version check is pre-decryption plaintext; auth failures stay deliberately indistinguishable from each other - this is core safety, not a feature bolt-on. |
| Machine-readable output (`--output json`, stable exit codes, `--raw` newline suppression on get --print) | Scripting is half the use case; secret fields omitted unless explicitly requested. |
| Per-platform clipboard with stated auto-clear timeout and graceful degrade | Safest default delivery channel for secrets; bounded platform matrix. |
| Disambiguation picker when a name matches multiple entries (numbered list, TTY-only) | Narrow form of passmenu's value without building a second interface; full TUI rejected separately. |
| `--dry-run` for import/export/rekey/restore | These have effects beyond routine edits (external files, parameter migration); preview costs little and shares the real code path. |
| Entry templates for add (`--template login/server/api-key`) | Consistent custom-field shapes improve search and audit; convention over schema. |
| Onboarding: threat model and unaudited notice printed on first init | Sets honest expectations at the moment they matter; pure text. |
| Session idle auto-lock with `status` showing remaining time | Completes the session model; small and testable. |

## Rejected

| idea | one-line reason |
|------|-----------------|
| Interactive TUI browser | Duplicates the entire command surface in a second interface; cannot meet the quality bar (focus, state, resize, accessibility) alongside the core. |
| Team sharing / multi-key recipients | Demands key distribution and revocation semantics - a threat model this tool cannot honestly claim. |
| Cloud sync | Requires network capability the tool must never have. |
| Browser extension / autofill | An entire product line (native messaging, per-browser ports). |
| Breach-database lookup | Requires network; also leaks a hash of your secret to a third party, against the local-only promise. Audit stays fully offline. |
| TOTP generation | A crypto subsystem with clock/window/seed edge cases - a second product by test 3. |
| SSH-agent mode | Second product; different consumers, different threat model. |
| Soft-delete trash + per-entry history inside the vault | Automatic whole-file backups plus restore already cover accidental deletion; a second mechanism doubles recovery paths that must each be audited. |
| Binary attachments | Turns the vault into an encrypted-archive product; export/import of entries is the boundary. |
| Git integration for vault history | Foot-gun for plaintext leakage and out-of-scope VCS semantics; backups cover rollback. |

## Consequences carried into the build

- F-completion, F-config, F-picker, F-dryrun, F-templates, F-onboarding are
  tracked like any other feature: implemented, tested, verified by running
  the software, covered by the final audit.
