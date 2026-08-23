"""Shell completion support.

Completion exposes ENTRY NAMES ONLY - never usernames, URLs, notes, tags
values, or secrets - because names are exactly what list/search already
show an unlocked user. Completion works only while a session is unlocked:
without it, listing names would require the passphrase on every Tab press,
which would be unusable rather than unsafe. With no session it silently
returns nothing.

The scripts below are deliberately small: they complete subcommand names
statically and delegate entry-name completion to `keepsafe _complete`,
which reads the vault through the unlocked session.
"""

from __future__ import annotations

from pathlib import Path

from . import errors

COMMANDS = [
    "init", "add", "get", "list", "search", "edit", "rm", "mv", "rename",
    "gen", "import", "export", "rekey", "changepass", "audit", "unlock",
    "lock", "status", "restore", "completions",
]

BASH_SCRIPT = """\
# Keepsafe bash completion - entry NAMES only, never secret values.
_keepsafe() {
  local cur prev words cword
  cur="${COMP_WORDS[COMP_CWORD]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "init add get list search edit rm mv rename gen import export rekey changepass audit unlock lock status restore completions" -- "$cur") )
    return 0
  fi
  case "${COMP_WORDS[1]}" in
    get|edit|rm|rename)
      COMPREPLY=( $(compgen -W "$(keepsafe _complete "$cur" 2>/dev/null)" -- "$cur") ) ;;
    mv)
      COMPREPLY=( $(compgen -W "$(keepsafe _complete "$cur" 2>/dev/null)" -- "$cur") ) ;;
    *)
      COMPREPLY=() ;;
  esac
  return 0
}
complete -F _keepsafe keepsafe
"""

ZSH_SCRIPT = """\
#compdef keepsafe
# Keepsafe zsh completion - entry NAMES only, never secret values.
_keepsafe() {
  local -a commands
  commands=(
    'init:create a new vault'
    'add:add an entry'
    'get:retrieve an entry secret'
    'list:list entries'
    'search:search entries'
    'edit:edit an entry'
    'rm:delete an entry'
    'mv:move an entry'
    'rename:rename an entry'
    'gen:generate a password or passphrase'
    'import:import entries from JSON or CSV'
    'export:export entries to plaintext'
    'rekey:change KDF parameters and/or passphrase'
    'changepass:change the passphrase'
    'audit:report weak, reused, stale, incomplete entries'
    'unlock:start an unlocked session'
    'lock:end the session'
    'status:show vault and session state'
    'restore:restore a backup'
    'completions:emit shell completion scripts'
  )
  if (( CURRENT == 2 )); then
    _describe 'command' commands
  else
    local -a names
    names=(${(f)"$(keepsafe _complete "$words[CURRENT]" 2>/dev/null)"})
    compadd -a names
  fi
}
_keepsafe "$@"
"""

FISH_SCRIPT = """\
# Keepsafe fish completion - entry NAMES only, never secret values.
complete -c keepsafe -n '__fish_use_subcommand' -a init -d 'create a new vault'
complete -c keepsafe -n '__fish_use_subcommand' -a add -d 'add an entry'
complete -c keepsafe -n '__fish_use_subcommand' -a get -d 'retrieve an entry secret'
complete -c keepsafe -n '__fish_use_subcommand' -a list -d 'list entries'
complete -c keepsafe -n '__fish_use_subcommand' -a search -d 'search entries'
complete -c keepsafe -n '__fish_use_subcommand' -a edit -d 'edit an entry'
complete -c keepsafe -n '__fish_use_subcommand' -a rm -d 'delete an entry'
complete -c keepsafe -n '__fish_use_subcommand' -a mv -d 'move an entry'
complete -c keepsafe -n '__fish_use_subcommand' -a rename -d 'rename an entry'
complete -c keepsafe -n '__fish_use_subcommand' -a gen -d 'generate a password or passphrase'
complete -c keepsafe -n '__fish_use_subcommand' -a import -d 'import entries'
complete -c keepsafe -n '__fish_use_subcommand' -a export -d 'export entries'
complete -c keepsafe -n '__fish_use_subcommand' -a rekey -d 'change KDF parameters'
complete -c keepsafe -n '__fish_use_subcommand' -a changepass -d 'change the passphrase'
complete -c keepsafe -n '__fish_use_subcommand' -a audit -d 'audit entries'
complete -c keepsafe -n '__fish_use_subcommand' -a unlock -d 'start a session'
complete -c keepsafe -n '__fish_use_subcommand' -a lock -d 'end the session'
complete -c keepsafe -n '__fish_use_subcommand' -a status -d 'show state'
complete -c keepsafe -n '__fish_use_subcommand' -a restore -d 'restore a backup'
complete -c keepsafe -n '__fish_contains_op get edit rm mv rename' \
  -a '(keepsafe _complete (commandline -ot) 2>/dev/null)' -d 'entry name'
"""

SCRIPTS = {"bash": BASH_SCRIPT, "zsh": ZSH_SCRIPT, "fish": FISH_SCRIPT}


def shell_script(shell: str, prog: str = "keepsafe") -> str:
    if shell not in SCRIPTS:
        raise errors.UsageError(f"unknown shell '{shell}'; known: {', '.join(sorted(SCRIPTS))}")
    return SCRIPTS[shell]


def entry_names_for_completion(vault_path: Path, prefix: str) -> list[str]:
    """Entry names matching prefix via the live session; [] when locked."""
    import base64
    import json as _json

    from . import format as fmt, model
    from . import session as session_mod

    try:
        info = session_mod.read_runtime(vault_path)
        if info is None:
            return []
        client = session_mod.SessionClient(info.host, info.port, info.token)
        blob = Path(vault_path).read_bytes()
        header = fmt.parse_header(blob)
        resp = client.request(
            "open",
            nonce_b64=base64.b64encode(header.nonce).decode(),
            ct_b64=base64.b64encode(blob[fmt.HEADER_SIZE:]).decode(),
            aad_b64=base64.b64encode(blob[:fmt.HEADER_SIZE]).decode(),
        )
        if not resp.get("ok"):
            return []
        payload = base64.b64decode(resp["data"]["plaintext_b64"]).decode("utf-8")
        parsed = _json.loads(payload)
        entries = model.entries_from_payload(parsed)
        names = [e.name for e in entries]
        return [n for n in names if n.startswith(prefix)]
    except Exception:
        # Completion must never surface errors, secrets, or stack traces.
        return []
