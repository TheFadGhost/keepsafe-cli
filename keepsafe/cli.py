"""Keepsafe command surface.

Discipline enforced here:
- stdout carries DATA ONLY. Every human notice goes to stderr, so
  `--output json` yields exactly one clean document on stdout.
- Secrets reach stdout only through explicitly requested paths
  (`get --print`, `gen`, export files, `--include-secrets`).
- Passphrases and secrets are never accepted as command-line arguments
  (they would land in shell history); they arrive via hidden prompts.
- Only keepsafe.crypto touches primitives; this module may call its
  functions but never imports argon2 or nacl.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import traceback
from pathlib import Path

from . import auditcmd, clipboard, completion, config, crypto, errors
from . import format as fmt
from . import generate, model, notices, prompts, query, render, session, storage, transfer

PROG = "keepsafe"

# Loaded secret values (entry secrets, secret custom fields, passphrases)
# registered so the crash-path sanitizer can scrub them from any output.
_SECRET_REGISTRY: set[str] = set()


def _register_secrets(entries: list) -> None:
    for e in entries:
        if e.secret:
            _SECRET_REGISTRY.add(e.secret)
        for f in e.fields:
            if f.secret and f.value:
                _SECRET_REGISTRY.add(f.value)


def _register_secret(value: str) -> None:
    if value:
        _SECRET_REGISTRY.add(value)


_MIN_SCRUB_LEN = 8


def _sanitized(text: str) -> str:
    # Only substrings long enough to be unambiguous are scrubbed; shorter
    # values would mangle ordinary words without adding safety.
    long_secrets = [s for s in _SECRET_REGISTRY if len(s) >= _MIN_SCRUB_LEN]
    return render.sanitize(text, long_secrets)


class _Ctx:
    """An unlocked vault context: either local (holds key) or via session."""

    def __init__(self, store, path: Path, header=None, key: bytes | None = None,
                 payload: dict | None = None, client=None):
        self.store = store
        self.path = path
        self.header = header
        self.key = key
        self.payload = payload
        self.client = client

    @property
    def entries(self) -> list:
        return model.entries_from_payload(self.payload)

    def entries_sorted(self) -> list:
        return query.sort_entries(model.entries_from_payload(self.payload))


def _resolve_vault_path(args, cfg) -> Path:
    if getattr(args, "vault", None):
        return Path(args.vault)
    return config.resolve_vault_path(cfg)


def _try_session(path: Path):
    """Return a live SessionClient or None (silent on stale sessions)."""
    client = session.connect_session(path)
    if client is None:
        return None
    try:
        resp = client.request("status")
        if resp.get("ok"):
            return client
    except errors.KeepsafeError:
        pass
    return None


def _decrypt_via_session(client, blob: bytes) -> dict:
    header = fmt.parse_header(blob)
    resp = client.request(
        "open",
        nonce_b64=base64.b64encode(header.nonce).decode(),
        ct_b64=base64.b64encode(blob[fmt.HEADER_SIZE:]).decode(),
        aad_b64=base64.b64encode(blob[:fmt.HEADER_SIZE]).decode(),
    )
    if not resp.get("ok"):
        raise errors.UnlockFailed(fmt.GENERIC_UNLOCK_MESSAGE)
    plaintext = base64.b64decode(resp["data"]["plaintext_b64"])
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise errors.InternalError("authenticated vault payload is not valid JSON") from exc


def _write_via_session(ctx: _Ctx, payload: dict):
    """Encrypt through the session and atomically replace the vault file."""
    import dataclasses

    plaintext = fmt.serialize_payload(payload)
    # The nonce lives inside the header and the header is the AAD, so it
    # must exist before those bytes are assembled. We take a server-fresh
    # value rather than choosing one ourselves.
    resp = ctx.client.request("nonce")
    if not resp.get("ok"):
        raise errors.Unavailable("the session refused the write; run 'keepsafe unlock' again")
    nonce = base64.b64decode(resp["data"]["nonce_b64"])
    new_header = dataclasses.replace(ctx.header, nonce=nonce)
    header_bytes = fmt.pack_header(new_header, payload_len=len(plaintext) + crypto.TAG_SIZE)
    resp = ctx.client.request(
        "seal",
        plaintext_b64=base64.b64encode(plaintext).decode(),
        aad_b64=base64.b64encode(bytes(header_bytes)).decode(),
        nonce_b64=base64.b64encode(nonce).decode(),
    )
    if not resp.get("ok"):
        raise errors.Unavailable("the session refused the write; run 'keepsafe unlock' again")
    ct = base64.b64decode(resp["data"]["ct_b64"])
    backup = storage.backup_current(ctx.path, ctx.store.backup_count)
    storage.atomic_write_bytes(ctx.path, bytes(header_bytes) + ct)
    return backup


def open_unlocked(args, cfg, r, need_write: bool = False) -> _Ctx:
    """Open the vault: prefer a live session, else prompt for passphrase."""
    path = _resolve_vault_path(args, cfg)
    store = storage.VaultStore(path, backup_count=cfg["backup_count"])
    if not store.exists():
        raise errors.VaultMissing(f"No vault found at {path}. Run: {PROG} init")

    client = _try_session(path)
    blob = store.read_bytes()

    if client is not None:
        header = fmt.parse_header(blob)
        payload = _decrypt_via_session(client, blob)
        return _Ctx(store, path, header=header, payload=payload, client=client)

    passphrase = prompts.ask_passphrase(str(path))
    _register_secret(passphrase)
    params = fmt.parse_header(blob).params
    if params.memory_kib >= 8192:
        r.warn(notices.derivation_notice(params.memory_kib, params.iterations))
    header, key, payload = fmt.open_vault_file_with_key(blob, passphrase)
    entries = model.entries_from_payload(payload)
    _register_secrets(entries)
    # bytearray so the finally-block zeroization reaches the actual buffer
    # (CPython cannot promise copies never existed; see crypto.zeroize).
    return _Ctx(store, path, header=header, key=bytearray(key), payload=payload)


def save_ctx(ctx: _Ctx, entries: list):
    """Persist entries with an automatic encrypted backup first.

    Returns the BackupInfo for the pre-write copy (None when the vault did
    not exist yet), so commands can tell the user where the backup went.
    """
    payload = model.payload_from_entries(entries)
    if ctx.client is not None:
        return _write_via_session(ctx, payload)
    try:
        info = ctx.store.save(ctx.key, ctx.header.salt, ctx.header.params, payload)
        return info
    finally:
        key = getattr(ctx, "key", None)
        if key is not None:
            try:
                crypto.zeroize(key)
            except Exception:
                pass


def _warn_include_secrets(r, args) -> None:
    if getattr(args, "include_secrets", False) and args.output_mode == "json":
        r.warn("secret values are included in this output at explicit request.")


def _json_entry(entry, include_secrets: bool) -> dict:
    """Machine-readable form. Secret keys are OMITTED (not masked) unless
    explicitly included - the fixed mask is for human output."""
    if include_secrets:
        return entry.to_dict()
    doc = entry.redacted_dict()
    doc.pop("secret", None)
    cleaned_fields = []
    for f in doc.get("fields", []):
        if f.get("secret"):
            cleaned_fields.append({"key": f["key"], "secret": True})
        else:
            cleaned_fields.append(f)
    doc["fields"] = cleaned_fields
    return doc


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args, r, cfg) -> int:
    path = _resolve_vault_path(args, cfg)
    store = storage.VaultStore(path, backup_count=cfg["backup_count"])
    if store.exists():
        if args.force:
            r.warn(f"A vault already exists at {path}. A backup of the current "
                   f"file will be written before it is replaced.")
            if not prompts.ask_yes_no(f"Replace the vault at {path}?", default=False):
                raise errors.AbortedByUser("Aborted; nothing was written.")
            storage.backup_current(path, store.backup_count)
        else:
            raise errors.UsageError(
                f"A vault already exists at {path}. Use --force to replace it "
                "(a backup is kept automatically)."
            )
    passphrase = prompts.ask_new_passphrase(confirm=True)
    _register_secret(passphrase)
    store.create(passphrase, force=args.force)
    r.warn_block(notices.THREAT_MODEL_LINES + [notices.UNAUDITED_LINE])
    backup_note = ""
    if args.force:
        backups = store.backups()
        if backups:
            backup_note = f" Backup of the replaced file: {backups[0].path}."
    r.warn(f"Vault created at {path}. Backups will be written to {path.parent / 'backups'}.{backup_note}")
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "vault": str(path)}))
    else:
        r.say(f"Vault created at {path}")
    return 0


TEMPLATES = {
    "login": [("url", False)],
    "server": [("host", False), ("port", False)],
    "api-key": [("endpoint", False), ("quota", False)],
}


def cmd_add(args, r, cfg) -> int:
    ctx = open_unlocked(args, cfg, r)
    entries = ctx.entries_sorted()
    existing = {e.name for e in entries}
    name = model.validate_path(args.name)
    old = next((e for e in entries if e.name == name), None)
    replaced = old is not None
    if replaced and not args.force:
        raise errors.UsageError(f"an entry named '{name}' already exists; use edit, or add --force to replace")
    if replaced:
        r.warn(f"'{name}' already exists and will be replaced. A backup of the "
               "current vault is written first; the existing secret is kept unless --new-secret is given.")
        if not prompts.ask_yes_no("Replace it?", default=False):
            raise errors.AbortedByUser("Aborted; nothing was changed.")

    username = args.username if args.username is not None else ""
    url = args.url if args.url is not None else ""
    notes = args.notes if args.notes is not None else ""
    tags = [t.strip() for t in (args.tags or "").split(",") if t.strip()]
    fields = []
    for kv in (args.field or []):
        if "=" not in kv:
            raise errors.UsageError("--field expects KEY=VALUE")
        k, v = kv.split("=", 1)
        fields.append(model.Field(key=k.strip(), value=v, secret=False))

    if args.template:
        if args.template not in TEMPLATES:
            raise errors.UsageError(f"unknown template '{args.template}'; known: {', '.join(sorted(TEMPLATES))}")
        have = {f.key for f in fields}
        for key, secret_flag in TEMPLATES[args.template]:
            if key not in have:
                if secret_flag:
                    val = prompts.ask_secret_value(key)
                else:
                    val = prompts.ask_optional_visible(f"{key} (optional)")
                fields.append(model.Field(key=key, value=val, secret=secret_flag))

    if args.generate:
        secret = generate.gen_password(
            length=args.gen_length, symbols=args.symbols, exclude_similar=args.exclude_similar)
        generated = secret
    elif replaced and not args.new_secret:
        secret = old.secret
        generated = None
    else:
        secret = prompts.ask_secret_value("Secret for " + name)
        generated = None
    _register_secret(secret)

    if replaced:
        entry = model.Entry(name=name, username=username or old.username,
                            url=url or old.url, notes=notes or old.notes,
                            tags=tags or old.tags, created=old.created,
                            updated=model.utc_now_iso(), fields=fields or old.fields)
        entry.secret = secret
    else:
        entry = model.Entry(name=name, username=username, secret=secret, url=url,
                            notes=notes, tags=tags, fields=fields)
    entries = [e for e in entries if e.name != name]
    entries.append(entry)
    entries.sort(key=lambda e: e.name)
    info = save_ctx(ctx, entries)

    if args.output_mode == "json":
        out = {"ok": True, "name": name, "replaced": replaced}
        if generated is not None and getattr(args, "include_secrets", False):
            _warn_include_secrets(r, args)
            out["generated_secret"] = generated
        print(render.machine_json(out))
    else:
        verb = "Replaced" if replaced else "Added"
        r.say(f"{verb} entry '{name}'")
        if info is not None:
            r.warn(f"Backup of the previous file: {info.path}")
        if generated is not None:
            bits = generate.entropy_bits_password(
                len(generated), generate.pool_size(symbols=args.symbols,
                                                   exclude_similar=args.exclude_similar))
            # stdout: generation results are sanctioned output (DESIGN.md);
            # the strength estimate goes to stderr and names no value.
            r.say(generated)
            r.warn(f"Estimated strength: {bits:.0f} bits - "
                   f"{generate.describe_strength(bits)} (estimate, not a guarantee)")
    return 0


def cmd_get(args, r, cfg) -> int:
    ctx = open_unlocked(args, cfg, r)
    entry = _find(ctx, args.name)
    include_secrets = bool(args.include_secrets)

    if args.field is not None:
        matches = [f for f in entry.fields if f.key == args.field]
        if not matches:
            raise errors.NotMatched(f"No entry matches {args.name} with field '{args.field}'.")
        field = matches[0]
        if field.secret and not args.print:
            return _copy_flow(r, cfg, field.value, label=f"{args.name} field {args.field}",
                              args=args, json_value_name="value")
        if args.print:
            _emit_secret(r, args, field.value)
            return 0
        if args.output_mode == "json":
            print(render.machine_json({"ok": True, "name": entry.name, "field": args.field, "value": field.value}))
        else:
            r.say(field.value)
        return 0

    if args.print:
        _emit_secret(r, args, entry.secret)
        return 0
    return _copy_flow(r, cfg, entry.secret, label=args.name, args=args,
                      json_value_name="secret")


def _emit_secret(r, args, value: str) -> None:
    if args.raw:
        sys.stdout.write(value)
        sys.stdout.flush()
    elif args.output_mode == "json":
        doc = {"ok": True, "value": value}
        print(render.machine_json(doc))
    else:
        r.say(value)


def _copy_flow(r, cfg, value: str, label: str, args, json_value_name: str) -> int:
    timeout = args.timeout if args.timeout is not None else cfg["clipboard_timeout"]
    copied = False
    if not args.no_copy:
        try:
            copied = bool(clipboard.copy_text(value))
        except errors.Unavailable:
            # DESIGN.md: no clipboard mechanism -> exit code 5 with the
            # remedy named. --print is the documented alternative.
            if args.print or getattr(args, "raw", False):
                raise
            raise errors.Unavailable(
                "no clipboard mechanism is available on this platform; "
                "use --print to display the value instead"
            ) from None
        if copied:
            clipboard.schedule_clear(clipboard.sha256_hex(value), timeout)
    if copied:
        r.warn(f"Copied to clipboard. Clears automatically in {timeout} s.")
    if args.output_mode == "json":
        doc = {"ok": True, "name": label, "copied_to_clipboard": copied,
               "clipboard_clear_seconds": timeout if copied else None}
        print(render.machine_json(doc))
    else:
        r.say(f"{label}: {render.MASK}")
    return 0


def _find(ctx: _Ctx, name: str):
    for e in ctx.entries:
        if e.name == name:
            return e
    raise errors.NotMatched(f"No entry matches '{name}'.")


def cmd_list(args, r, cfg) -> int:
    ctx = open_unlocked(args, cfg, r)
    entries = ctx.entries_sorted()
    if args.folder:
        entries = query.filter_folder(entries, args.folder)
    if args.tags:
        wanted = {t.strip() for t in args.tags.split(",") if t.strip()}
        entries = query.filter_tags(entries, wanted)
    include_secrets = bool(args.include_secrets)
    _warn_include_secrets(r, args)
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "entries": [_json_entry(e, include_secrets) for e in entries]}))
        return 0
    if not entries:
        r.say("No entries." if not args.folder else f"No entries under '{args.folder}'.")
        return 0
    if args.tree:
        tree = query.build_tree(entries)
        r.say("\n".join(query.render_tree(tree)))
        return 0
    rows = [[e.name, e.username or "-", e.updated[:10], ",".join(e.tags)] for e in entries]
    r.say(render.table(["NAME", "USERNAME", "UPDATED", "TAGS"], rows,
                       min_widths=[24, 14, 10, 4]))
    return 0


def cmd_search(args, r, cfg) -> int:
    ctx = open_unlocked(args, cfg, r)
    entries = ctx.entries_sorted()
    results = query.search(entries, args.query)
    if args.tags:
        wanted = {t.strip() for t in args.tags.split(",") if t.strip()}
        names = {e.name for e in query.filter_tags(entries, wanted)}
        results = [(e, f) for (e, f) in results if e.name in names]
    include_secrets = bool(args.include_secrets)
    _warn_include_secrets(r, args)
    if args.output_mode == "json":
        docs = []
        for e, matched_field in results:
            d = _json_entry(e, include_secrets)
            d["matched_field"] = matched_field
            docs.append(d)
        print(render.machine_json({"ok": True, "results": docs}))
        return 0
    if not results:
        raise errors.NotMatched(f"No entry matches '{args.query}'.")
    rows = [[e.name, e.username or "-", e.updated[:10], ",".join(e.tags), mf]
            for e, mf in results]
    r.say(render.table(["NAME", "USERNAME", "UPDATED", "TAGS", "MATCH"], rows,
                       min_widths=[24, 14, 10, 4, 8]))
    return 0


def cmd_edit(args, r, cfg) -> int:
    ctx = open_unlocked(args, cfg, r)
    entries = ctx.entries_sorted()
    entry = _find(ctx, args.name)
    changed = []

    if args.username is not None:
        entry.username = args.username; changed.append("username")
    if args.url is not None:
        entry.url = args.url; changed.append("url")
    if args.notes is not None:
        entry.notes = args.notes; changed.append("notes")
    if args.tags is not None:
        entry.tags = [t.strip() for t in args.tags.split(",") if t.strip()]; changed.append("tags")
    if args.add_tags:
        for t in args.add_tags.split(","):
            t = t.strip()
            if t and t not in entry.tags:
                entry.tags.append(t)
        changed.append("tags")
    if args.new_secret:
        entry.secret = prompts.ask_secret_value("New secret"); changed.append("secret")
        _register_secret(entry.secret)
    for kv in (args.set or []):
        if "=" not in kv:
            raise errors.UsageError("--set expects KEY=VALUE")
        k, v = kv.split("=", 1)
        _upsert_field(entry, k.strip(), v, secret=False); changed.append(k.strip())
    for k in (args.set_secret or []):
        _upsert_field(entry, k, prompts.ask_secret_value(k), secret=True); changed.append(k)
        _register_secret(next(f.value for f in entry.fields if f.key == k))
    for k in (args.clear or []):
        entry.fields = [f for f in entry.fields if f.key != k]; changed.append(k)

    if not changed:
        current = entry.username or "-"
        new_user = prompts.ask_visible_default(f"Username [{current}]") or entry.username
        entry.username = new_user; changed.append("username")
        new_url = prompts.ask_visible_default(f"URL [{entry.url or '-'}]")
        if new_url:
            entry.url = new_url; changed.append("url")
        if prompts.ask_yes_no("Change the secret?", default=False):
            entry.secret = prompts.ask_secret_value(); changed.append("secret")
            _register_secret(entry.secret)
    entry.touch()
    _register_secrets([entry])
    entries = [e for e in entries if e.name != entry.name]
    entries.append(entry)
    entries.sort(key=lambda e: e.name)
    info = save_ctx(ctx, entries)
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "name": entry.name,
                                   "changed": sorted(set(changed))}))
    else:
        if info is not None:
            r.warn(f"Backup of the previous file: {info.path}")
        r.say(f"Updated '{entry.name}' ({', '.join(sorted(set(changed)))})")
    return 0


def _upsert_field(entry, key: str, value: str, secret: bool) -> None:
    for f in entry.fields:
        if f.key == key:
            f.value = value
            f.secret = secret
            return
    entry.fields.append(model.Field(key=key, value=value, secret=secret))


def cmd_rm(args, r, cfg) -> int:
    ctx = open_unlocked(args, cfg, r)
    entry = _find(ctx, args.name)
    secret_count = 1 + sum(1 for f in entry.fields if f.secret)
    lines = [
        f"'{entry.name}' holds {secret_count} secret value(s).",
        "Deleting removes the only copy inside this vault. This cannot be undone"
        " by Keepsafe (automatic backups aside).",
        f"To confirm, type the entry path exactly: {entry.name}",
    ]
    if not prompts.confirm_phrase(lines, entry.name):
        raise errors.AbortedByUser("Aborted; nothing was deleted.")
    remaining = [e for e in ctx.entries if e.name != entry.name]
    info = save_ctx(ctx, remaining)
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "deleted": entry.name}))
    else:
        if info is not None:
            r.warn(f"Backup of the previous file: {info.path}")
        r.say(f"Deleted '{entry.name}'")
    return 0


def cmd_mv(args, r, cfg) -> int:
    return _move(args, r, cfg, rename_only=False)


def cmd_rename(args, r, cfg) -> int:
    return _move(args, r, cfg, rename_only=True)


def _move(args, r, cfg, rename_only: bool) -> int:
    ctx = open_unlocked(args, cfg, r)
    entries = ctx.entries_sorted()
    # rename parses its positional as `name`; mv as `source`.
    src_name = args.name if rename_only else args.source
    src = next((e for e in entries if e.name == src_name), None)
    if src is None:
        raise errors.NotMatched(f"No entry matches '{src_name}'.")
    if rename_only:
        dst = model.join_path(model.parent_path(src.name), args.destination)
    else:
        dst = model.validate_path(args.destination)
    clash = next((e for e in entries if e.name == dst), None)
    if clash is not None and not args.force:
        raise errors.UsageError(f"an entry named '{dst}' already exists; use --force to replace it")
    remaining = [e for e in entries if e.name not in (src.name,)]
    moved = model.Entry(name=dst, username=src.username, secret=src.secret,
                        url=src.url, notes=src.notes, tags=list(src.tags),
                        created=src.created, updated=src.updated,
                        fields=[model.Field(key=f.key, value=f.value, secret=f.secret) for f in src.fields])
    _register_secrets([moved])
    if clash is not None:
        remaining = [e for e in remaining if e.name != dst]
        r.warn(f"Replacing existing entry '{dst}'.")
    remaining.append(moved)
    remaining.sort(key=lambda e: e.name)
    info = save_ctx(ctx, remaining)
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "from": src.name, "to": dst}))
    else:
        if info is not None:
            r.warn(f"Backup of the previous file: {info.path}")
        r.say(f"Moved '{src.name}' to '{dst}'" if not rename_only else f"Renamed '{src.name}' to '{dst}'")
    return 0


def cmd_gen(args, r, cfg) -> int:
    values = []
    bits = 0.0
    if args.words is not None:
        for _ in range(args.count):
            v = generate.gen_passphrase(words=args.words, sep=args.sep, capitalize=args.capitalize)
            values.append(v)
        bits = generate.entropy_bits_passphrase(args.words)
    else:
        pool = generate.pool_size(args.upper, args.lower, args.digits, args.symbols, args.exclude_similar)
        for _ in range(args.count):
            values.append(generate.gen_password(
                length=args.length, upper=args.upper, lower=args.lower,
                digits=args.digits, symbols=args.symbols,
                exclude_similar=args.exclude_similar))
        bits = generate.entropy_bits_password(args.length, pool)
    for v in values:
        _register_secret(v)
    if args.copy:
        if args.count != 1:
            raise errors.UsageError("--copy works only with --count 1")
        if not clipboard.copy_text(values[0]):
            raise errors.Unavailable("clipboard is not available on this platform")
        clipboard.schedule_clear(clipboard.sha256_hex(values[0]), cfg["clipboard_timeout"])
        r.warn(f"Copied to clipboard. Clears automatically in {cfg['clipboard_timeout']} s.")
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "values": values,
                                   "entropy_bits": round(bits, 1)}))
    else:
        for v in values:
            r.say(v)
        r.warn(f"Estimated strength: {bits:.0f} bits - {generate.describe_strength(bits)}"
               " (estimate, not a guarantee)")
    return 0


def cmd_import_file(args, r, cfg) -> int:
    # Read and validate the source BEFORE asking for a passphrase: a bad
    # path or undecodable file should not cost an Argon2 run first.
    source = Path(args.file)
    if not source.is_file():
        raise errors.UsageError(f"no such file: {source}")
    try:
        text = source.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise errors.UsageError(
            f"{source} is not valid UTF-8; re-export or re-save it as UTF-8 "
            f"and try again ({exc.reason} at byte {exc.start})"
        ) from None
    ctx = open_unlocked(args, cfg, r)
    fmt_name = args.format or transfer.sniff_format(text)
    incoming = transfer.parse_import(text, fmt_name)
    entries = ctx.entries_sorted()
    plan = transfer.plan_import(incoming, {e.name for e in entries}, overwrite=args.overwrite)
    report = transfer.import_report_lines(plan, str(source))
    if args.dry_run:
        for line in report:
            r.warn(line)
        r.warn("(dry run: nothing was written)")
        if args.output_mode == "json":
            print(render.machine_json({"ok": True, "dry_run": True, "plan": {
                "add": len(plan.add), "overwrite": len(plan.overwrite), "skip": len(plan.skip)}}))
        return 0
    if plan.overwrite and not args.overwrite:
        raise errors.InternalError("overwrite plan without --overwrite; this is a bug")
    if plan.overwrite:
        r.warn(f"This import would replace {len(plan.overwrite)} existing "
               f"{'entry' if len(plan.overwrite) == 1 else 'entries'}. A backup of the current vault is written first.")
        if not prompts.ask_yes_no("Proceed with the import?", default=False):
            raise errors.AbortedByUser("Aborted; nothing was imported.")
    by_name = {e.name: e for e in entries}
    for e in plan.add + plan.overwrite:
        by_name[e.name] = e
    merged = sorted(by_name.values(), key=lambda e: e.name)
    _register_secrets(merged)
    info = save_ctx(ctx, merged)
    for line in report:
        r.warn(line)
    if info is not None and args.output_mode != "json":
        r.warn(f"Backup of the previous file: {info.path}")
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "added": len(plan.add),
                                   "overwritten": len(plan.overwrite),
                                   "skipped": len(plan.skip)}))
    return 0


def cmd_export(args, r, cfg) -> int:
    path = _resolve_vault_path(args, cfg)
    target = Path(args.file)
    # Never write plaintext over (or onto the same file as) the encrypted
    # vault. Resolve both sides so tricks like "..", different case on
    # Windows, or relative paths cannot sneak past.
    def _norm(p: Path) -> str:
        return str(Path(os.path.abspath(str(p)))).lower() if os.name == "nt" else str(Path(os.path.abspath(str(p))))
    if _norm(target) == _norm(path):
        raise errors.UsageError(
            "the export target is the vault file itself; choose a different path - exporting would overwrite the encrypted vault with plaintext"
        )
    if target.exists() and not args.force:
        raise errors.UsageError(f"{target} already exists; choose another file or use --force to overwrite")
    ctx = open_unlocked(args, cfg, r)
    fmt_name = args.format
    if fmt_name is None:
        ext = target.suffix.lower()
        if ext == ".json":
            fmt_name = "json"
        elif ext == ".csv":
            fmt_name = "csv"
        else:
            raise errors.UsageError(
                f"cannot infer an export format from '{target.name}'; pass --format json or --format csv"
            )
    if fmt_name not in transfer.EXPORT_FORMATS:
        raise errors.UsageError(f"--format must be one of: {', '.join(transfer.EXPORT_FORMATS)}")
    include_secrets = not args.redacted
    if include_secrets:
        if not prompts.confirm_phrase(notices.plaintext_export_lines(str(target)), "export-plaintext"):
            raise errors.AbortedByUser("Aborted; no file was written.")
    else:
        if not prompts.ask_yes_no(
                f"Write a redacted export (no secret values) to {target}?", default=False):
            raise errors.AbortedByUser("Aborted; no file was written.")
    entries = ctx.entries_sorted()
    text = transfer.export_entries(entries, fmt_name, include_secrets=include_secrets)
    storage.atomic_write_bytes(target, text.encode("utf-8"))
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "file": str(target), "format": fmt_name,
                                   "redacted": not include_secrets, "entries": len(entries)}))
    else:
        r.say(f"Wrote {len(entries)} entries to {target} ({fmt_name}"
              f"{', redacted' if not include_secrets else ''})")
        if include_secrets:
            r.warn("that file contains plaintext secrets; delete it securely when done.")
    return 0


def _bounded_int(flag: str, minimum: int, maximum: int):
    """argparse type= callback producing a bounded, validated int."""

    def convert(value: str) -> int:
        try:
            n = int(value)
        except ValueError:
            raise errors.UsageError(f"{flag} expects an integer") from None
        if n < minimum or n > maximum:
            raise errors.UsageError(f"{flag} must be between {minimum} and {maximum}")
        return n

    return convert


def _parse_positive_int(value: str, flag: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise errors.UsageError(f"{flag} expects an integer") from None
    if n < 1:
        raise errors.UsageError(f"{flag} must be at least 1")
    return n


def cmd_rekey(args, r, cfg) -> int:
    path = _resolve_vault_path(args, cfg)
    store = storage.VaultStore(path, backup_count=cfg["backup_count"])
    if not store.exists():
        raise errors.VaultMissing(f"No vault found at {path}. Run: {PROG} init")
    session.lock(path)  # a live session holds the old derivation; end it
    blob = store.read_bytes()
    old_header = fmt.parse_header(blob)
    old_params = old_header.params
    new_mem = _kdf_arg(args.kdf_memory, "memory", old_params.memory_kib,
                       crypto.DEFAULT_MEMORY_KIB, crypto.MIN_MEMORY_KIB)
    new_it = _kdf_arg(args.kdf_iterations, "iterations", old_params.iterations,
                      crypto.DEFAULT_ITERATIONS, crypto.MIN_ITERATIONS)
    new_par = _kdf_arg(args.kdf_parallelism, "parallelism", old_params.parallelism,
                       crypto.DEFAULT_PARALLELISM, crypto.MIN_PARALLELISM)
    r.warn(f"Current KDF parameters: {old_params.memory_kib} KiB x{old_params.iterations} x{old_params.parallelism}")
    r.warn(f"New KDF parameters:     {new_mem} KiB x{new_it} x{new_par}")
    if new_mem * new_it > crypto.MAX_COMBINED_KIB_ITERATIONS:
        raise errors.UsageError(
            "--kdf-memory x --kdf-iterations exceeds the combined cost cap "
            f"({crypto.MAX_COMBINED_KIB_ITERATIONS}); lower one of them"
        )
    if not prompts.confirm_phrase(notices.rekey_lines(), "rekey"):
        raise errors.AbortedByUser("Aborted; the vault was not changed.")
    old_pass = prompts.ask_passphrase(str(path))
    _register_secret(old_pass)
    new_pass = prompts.ask_new_passphrase(confirm=True)
    _register_secret(new_pass)
    info = store.rekey(old_pass, new_pass,
                       fmt.KdfParams(memory_kib=new_mem, iterations=new_it, parallelism=new_par))
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "backup": str(info.path),
                                   "kdf": {"memory_kib": new_mem, "iterations": new_it,
                                           "parallelism": new_par}}))
    else:
        r.say(f"Re-keyed vault at {path}")
        r.warn(f"Backup of the previous file: {info.path}")
        r.warn("That backup opens only with the old passphrase.")
    return 0


def _kdf_arg(flag_value, name, current, shipped_default, minimum):
    if flag_value is not None:
        n = _parse_positive_int(flag_value, f"--kdf-{name}")
        maximum = {"memory": crypto.MAX_MEMORY_KIB,
                   "iterations": crypto.MAX_ITERATIONS,
                   "parallelism": crypto.MAX_PARALLELISM}[name]
        if n < minimum:
            raise errors.UsageError(f"--kdf-{name} below the policy minimum of {minimum} would weaken the vault; refused")
        if n > maximum:
            raise errors.UsageError(f"--kdf-{name} above the hard maximum of {maximum}; refused")
        return n
    return max(current, shipped_default)


def cmd_changepass(args, r, cfg) -> int:
    path = _resolve_vault_path(args, cfg)
    store = storage.VaultStore(path, backup_count=cfg["backup_count"])
    if not store.exists():
        raise errors.VaultMissing(f"No vault found at {path}. Run: {PROG} init")
    session.lock(path)
    old_pass = prompts.ask_passphrase(str(path))
    _register_secret(old_pass)
    new_pass = prompts.ask_new_passphrase(confirm=True)
    _register_secret(new_pass)
    info = store.rekey(old_pass, new_pass, None)
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "backup": str(info.path)}))
    else:
        r.say(f"Passphrase changed for {path}")
        r.warn(f"Backup of the previous file: {info.path} (opens with the old passphrase)")
    return 0


def cmd_audit(args, r, cfg) -> int:
    ctx = open_unlocked(args, cfg, r)
    min_length = args.min_length if args.min_length is not None else cfg["audit_min_length"]
    stale_days = args.stale_days if args.stale_days is not None else cfg["audit_stale_days"]
    entries = ctx.entries_sorted()
    report = auditcmd.analyze(entries, min_length=min_length, stale_days=stale_days)
    if args.output_mode == "json":
        print(render.machine_json({
            "ok": True,
            "counts": report.counts,
            # exit code is 1 when any finding exists (see --help)
            "weak": [{"name": f.name, "detail": f.detail} for f in report.weak],
            "reused": [{"names": [n.strip() for n in f.name.split(",") if n.strip() and n.strip() != "..."],
                        "detail": f.detail} for f in report.reused],
            "stale": [{"name": f.name, "detail": f.detail} for f in report.stale],
            "missing_username": [f.name for f in report.missing_username],
            "missing_url": [f.name for f in report.missing_url],
        }))
    else:
        r.say(auditcmd.render_report(report, str(ctx.path), min_length, stale_days))
    total = report.counts.get("weak", 0) + report.counts.get("reused_groups", 0) + \
        report.counts.get("stale", 0) + report.counts.get("missing_username", 0) + \
        report.counts.get("missing_url", 0)
    return 1 if total else 0


def cmd_unlock(args, r, cfg) -> int:
    path = _resolve_vault_path(args, cfg)
    store = storage.VaultStore(path, backup_count=cfg["backup_count"])
    if not store.exists():
        raise errors.VaultMissing(f"No vault found at {path}. Run: {PROG} init")
    existing = _try_session(path)
    if existing is not None:
        st = session.session_status(path)
        remaining = st.get("remaining_seconds") if st else None
        if args.output_mode == "json":
            print(render.machine_json({"ok": True, "already_unlocked": True,
                                       "remaining_seconds": remaining}))
        else:
            r.say(f"A session is already unlocked ({remaining} s of idle time left).")
        return 0
    passphrase = prompts.ask_passphrase(str(path))
    _register_secret(passphrase)
    blob = store.read_bytes()
    # One derivation proves the passphrase AND yields the key for the session.
    header, key, _payload = fmt.open_vault_file_with_key(blob, passphrase)
    timeout = cfg["session_timeout"]
    info = session.unlock_session(path, bytes(key), timeout)
    try:
        crypto.zeroize(key)
    except Exception:
        pass
    r.warn(notices.session_tradeoff_line())
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "already_unlocked": False,
                                   "idle_timeout_seconds": timeout}))
    else:
        r.say(f"Session unlocked for {path}; idle timeout {timeout // 60} min. 'keepsafe lock' ends it now.")
    return 0


def cmd_lock(args, r, cfg) -> int:
    path = _resolve_vault_path(args, cfg)
    locked = session.lock(path)
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "was_unlocked": bool(locked)}))
    else:
        r.say("Locked." if locked else "No unlocked session found.")
    return 0


def cmd_status(args, r, cfg) -> int:
    path = _resolve_vault_path(args, cfg)
    store = storage.VaultStore(path, backup_count=cfg["backup_count"])
    exists = store.exists()
    st = session.session_status(path) if exists else None
    doc = {"ok": True, "vault": str(path), "exists": exists,
           "session": {"unlocked": bool(st),
                       "remaining_seconds": st.get("remaining_seconds") if st else None}}
    if args.output_mode == "json":
        print(render.machine_json(doc))
        return 0
    r.say(f"Vault: {path} ({'present' if exists else 'missing'})")
    if st:
        r.say(f"Session: unlocked, {st['remaining_seconds']} s of idle time left")
    else:
        r.say("Session: locked")
    return 0


def cmd_restore(args, r, cfg) -> int:
    path = _resolve_vault_path(args, cfg)
    store = storage.VaultStore(path, backup_count=cfg["backup_count"])
    backups = store.backups()
    if args.list:
        if args.output_mode == "json":
            print(render.machine_json({"ok": True, "backups": [
                {"index": i, "path": str(b.path), "timestamp": b.timestamp}
                for i, b in enumerate(backups)]}))
        elif not backups:
            r.say("No backups found.")
        else:
            for i, b in enumerate(backups):
                size = b.path.stat().st_size if b.path.exists() else 0
                r.say(f"[{i}] {b.timestamp}  {size} bytes  {b.path}")
        return 0
    if not backups:
        raise errors.NotMatched("No backups found to restore.")
    if args.latest:
        idx = 0
    elif args.index is not None:
        raw = args.index.strip()
        if not raw.isdigit():
            raise errors.UsageError("the restore index must be a non-negative integer (see restore --list)")
        idx = int(raw)
        if idx >= len(backups):
            raise errors.UsageError(f"index must be between 0 and {len(backups) - 1} (see restore --list)")
    else:
        raise errors.UsageError("specify an index (see restore --list) or --latest")
    chosen = backups[idx]
    r.warn(f"The current vault will be backed up first, then replaced with the backup from {chosen.timestamp}.")
    if not prompts.ask_yes_no(f"Restore backup [{idx}] over {path}?", default=False):
        raise errors.AbortedByUser("Aborted; nothing was restored.")
    store.restore_backup(chosen)
    if args.output_mode == "json":
        print(render.machine_json({"ok": True, "restored": str(chosen.path)}))
    else:
        r.say(f"Restored backup [{idx}] from {chosen.timestamp}")
    return 0


def cmd_completions(args, r, cfg) -> int:
    script = completion.shell_script(args.shell, prog=PROG)
    r.say(script)
    return 0


def cmd_complete(args, r, cfg) -> int:
    names = completion.entry_names_for_completion(_resolve_vault_path(args, cfg), args.prefix)
    for n in names:
        r.say(n)
    return 0


# ---------------------------------------------------------------------------
# Argument parsing and entry point
# ---------------------------------------------------------------------------

def _add_output_flags(sp: argparse.ArgumentParser) -> None:
    # --output/--no-color/--vault arrive from the shared parent parser;
    # this adds only the secret-inclusion opt-in.
    sp.add_argument("--include-secrets", action="store_true",
                    help="include secret values in machine-readable output (explicitly requested only)")


class _Parser(argparse.ArgumentParser):
    """argparse whose usage errors follow the Keepsafe taxonomy.

    Default argparse exits 2 on bad usage - the same code as an unlock
    failure - which would make a typo'd flag script-indistinguishable
    from a wrong passphrase. Usage problems are exit 4 here.
    """

    def error(self, message):  # noqa: D401 - argparse API
        raise errors.UsageError(message)

    def exit(self, status=0, message=None):
        # --help/--version raise SystemExit(0); anything non-zero from
        # argparse is a usage problem and maps to exit 4.
        if status:
            raise errors.UsageError((message or "usage error").strip())
        raise SystemExit(status)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog=PROG,
        description="Unaudited local encrypted secrets vault: one passphrase-protected file.",
        epilog=(
            "Threat model (short form; see README for the full statement):\n"
            "Protects the vault file at rest against someone who obtains the file\n"
            "but not your passphrase. Does not protect against a compromised\n"
            "machine, keyloggers, memory inspection, clipboard snooping by other\n"
            "applications, or an unlocked session.\n\n"
            + notices.UNAUDITED_LINE + "\n"
            "Losing the passphrase means losing the data. There is no recovery."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    from . import __version__
    p.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    p.add_argument("--vault", metavar="PATH", help="path to the vault file (default: per config)")
    p.add_argument("--no-color", action="store_true", help="disable colour output")
    p.add_argument("--output", choices=("text", "json"), dest="output_mode", default=None,
                   help="output mode (default: text, or config output_mode)")
    # Shared parent so global flags also work AFTER the subcommand.
    # SUPPRESS defaults keep an absent subcommand flag from clobbering a
    # value the top-level parser already set.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--vault", metavar="PATH", default=argparse.SUPPRESS,
                        help=argparse.SUPPRESS)
    common.add_argument("--no-color", action="store_true",
                        default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    common.add_argument("--output", choices=("text", "json"), dest="output_mode",
                        default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    def add_sub(name, help_text=None, **kwargs):
        if help_text is not None:
            kwargs["help"] = help_text
        sp = sub.add_parser(name, parents=[common], **kwargs)
        return sp

    sp = add_sub("init", "create a new vault")
    sp.add_argument("--force", action="store_true", help="replace an existing vault (backup kept)")
    sp.set_defaults(fn=cmd_init)

    sp = add_sub("add", help="add an entry")
    sp.add_argument("name", metavar="NAME")
    sp.add_argument("--username", default=None)
    sp.add_argument("--url", default=None)
    sp.add_argument("--notes", default=None)
    sp.add_argument("--tags", default=None, help="comma-separated tags")
    sp.add_argument("--field", "--set", action="append", metavar="KEY=VALUE",
                    help="non-secret custom field (value visible in shell history; use --template or edit for secret fields)")
    sp.add_argument("--template", choices=tuple(sorted(TEMPLATES)), help="prefill suggested fields via prompts")
    sp.add_argument("--generate", action="store_true", help="generate the main secret instead of prompting")
    sp.add_argument("--gen-length", type=_bounded_int("--gen-length", 4, 256), default=20)
    sp.add_argument("--symbols", action="store_true", help="with --generate: include symbols")
    sp.add_argument("--exclude-similar", action="store_true", help="with --generate: avoid look-alike characters")
    sp.add_argument("--new-secret", action="store_true", help="with add --force: prompt for a fresh secret instead of keeping the old")
    sp.add_argument("--force", action="store_true", help="replace an existing entry of the same name")
    _add_output_flags(sp)
    sp.set_defaults(fn=cmd_add)

    sp = add_sub("get", help="copy an entry's secret to the clipboard (never prints without --print)")
    sp.add_argument("name", metavar="NAME")
    sp.add_argument("-p", "--print", dest="print", action="store_true", help="print the value to stdout instead of copying")
    sp.add_argument("--raw", action="store_true", help="with --print: no trailing newline")
    sp.add_argument("--field", metavar="KEY", help="operate on a custom field instead of the main secret")
    sp.add_argument("--timeout", type=_bounded_int("--timeout", 1, 86400), default=None, metavar="SECONDS", help="clipboard auto-clear timeout override (1-86400)")
    sp.add_argument("--no-copy", action="store_true", help="skip the clipboard entirely")
    _add_output_flags(sp)
    sp.set_defaults(fn=cmd_get)

    sp = add_sub("list", help="list entries")
    sp.add_argument("folder", nargs="?", default="", metavar="FOLDER")
    sp.add_argument("--tree", action="store_true", help="show the folder hierarchy")
    sp.add_argument("--tags", metavar="TAGS", help="comma-separated tags; entries must have all")
    _add_output_flags(sp)
    sp.set_defaults(fn=cmd_list)

    sp = add_sub("search", help="search name, username, url, notes, tags")
    sp.add_argument("query", metavar="QUERY")
    sp.add_argument("--tags", metavar="TAGS", help="further restrict to entries carrying all tags")
    _add_output_flags(sp)
    sp.set_defaults(fn=cmd_search)

    sp = add_sub("edit", help="edit an entry")
    sp.add_argument("name", metavar="NAME")
    sp.add_argument("--username", default=None)
    sp.add_argument("--url", default=None)
    sp.add_argument("--notes", default=None)
    sp.add_argument("--tags", default=None, help="replace all tags")
    sp.add_argument("--add-tags", dest="add_tags", default=None, help="append comma-separated tags")
    sp.add_argument("--new-secret", action="store_true", help="prompt for a replacement main secret (hidden input)")
    sp.add_argument("--set", action="append", metavar="KEY=VALUE", help="set a non-secret custom field")
    sp.add_argument("--set-secret", action="append", metavar="KEY", help="prompt hidden input for a secret custom field")
    sp.add_argument("--clear", action="append", metavar="KEY", help="remove a custom field")
    sp.set_defaults(fn=cmd_edit)

    sp = add_sub("rm", help="delete an entry (typed confirmation)")
    sp.add_argument("name", metavar="NAME")
    sp.set_defaults(fn=cmd_rm)

    sp = add_sub("mv", help="move/repath an entry")
    sp.add_argument("source", metavar="SOURCE")
    sp.add_argument("destination", metavar="DESTINATION")
    sp.add_argument("--force", action="store_true", help="replace an existing destination entry")
    sp.set_defaults(fn=cmd_mv)

    sp = add_sub("rename", help="rename the last path segment of an entry")
    sp.add_argument("name", metavar="NAME")
    sp.add_argument("destination", metavar="NEW_NAME")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(fn=cmd_rename)

    sp = add_sub("gen", help="generate a password or passphrase")
    sp.add_argument("--length", type=int, default=20, help="password length (default 20)")
    sp.add_argument("--upper", action=argparse.BooleanOptionalAction, default=True)
    sp.add_argument("--lower", action=argparse.BooleanOptionalAction, default=True)
    sp.add_argument("--digits", action=argparse.BooleanOptionalAction, default=True)
    sp.add_argument("--symbols", action="store_true")
    sp.add_argument("--exclude-similar", action="store_true", help="avoid look-alike characters (Il1O0)")
    sp.add_argument("--words", type=int, default=None, metavar="N", help="passphrase mode: N words from the EFF short list")
    sp.add_argument("--sep", default="-", help="passphrase separator (1-3 printable characters)")
    sp.add_argument("--capitalize", action="store_true", help="capitalize passphrase words")
    sp.add_argument("--count", type=_bounded_int("--count", 1, 100), default=1)
    sp.add_argument("--copy", action="store_true", help="copy the single result to the clipboard (auto-clears)")
    sp.set_defaults(fn=cmd_gen)

    sp = add_sub("import", help="import entries from a JSON or CSV file")
    sp.add_argument("file", metavar="FILE")
    sp.add_argument("--format", choices=("json", "csv"), default=None, help="default: sniffed from content")
    sp.add_argument("--overwrite", action="store_true", help="replace same-path entries (confirmed interactively)")
    sp.add_argument("--dry-run", dest="dry_run", action="store_true", help="show what would happen; write nothing")
    sp.set_defaults(fn=cmd_import_file)

    sp = add_sub("export", help="export entries to plaintext JSON or CSV (typed confirmation)")
    sp.add_argument("file", metavar="FILE")
    sp.add_argument("--format", choices=("json", "csv"), default=None, help="default: from file extension")
    sp.add_argument("--redacted", action="store_true", help="omit secret values from the export")
    sp.add_argument("--force", action="store_true", help="overwrite an existing output file")
    sp.set_defaults(fn=cmd_export)

    sp = add_sub("rekey", help="migrate the vault to new KDF parameters and/or passphrase")
    sp.add_argument("--kdf-memory", dest="kdf_memory", metavar="KIB", default=None)
    sp.add_argument("--kdf-iterations", dest="kdf_iterations", metavar="N", default=None)
    sp.add_argument("--kdf-parallelism", dest="kdf_parallelism", metavar="N", default=None)
    sp.set_defaults(fn=cmd_rekey)

    sp = add_sub("changepass", help="change the passphrase (KDF parameters unchanged)")
    sp.set_defaults(fn=cmd_changepass)

    sp = add_sub("audit", help="report weak, reused, stale, incomplete entries (all local)",
                        description="Exit code 1 when any finding exists, 0 when the vault is clean.")
    sp.add_argument("--stale-days", dest="stale_days", default=None, metavar="DAYS")
    sp.add_argument("--min-length", dest="min_length", default=None, metavar="N")
    sp.set_defaults(fn=cmd_audit)

    sp = add_sub("unlock", help="start an unlocked session (key held in helper process memory)")
    sp.set_defaults(fn=cmd_unlock)
    sp = add_sub("lock", help="end any unlocked session now")
    sp.set_defaults(fn=cmd_lock)
    sp = add_sub("status", help="show vault and session state (no secrets)")
    sp.set_defaults(fn=cmd_status)

    sp = add_sub("restore", help="restore an automatic backup")
    sp.add_argument("index", nargs="?", default=None, metavar="INDEX")
    sp.add_argument("--list", dest="list", action="store_true", help="enumerate backups")
    sp.add_argument("--latest", action="store_true", help="restore the most recent backup")
    sp.set_defaults(fn=cmd_restore)

    sp = add_sub("completions", help="emit shell completion scripts")
    sp.add_argument("--shell", required=True, choices=("bash", "zsh", "fish"))
    sp.set_defaults(fn=cmd_completions)

    return p


def _handler_for(args):
    return getattr(args, "fn", None)


def _parse_hidden_complete(argv: list[str]):
    """The hidden entry-name completion command must not appear in --help,
    so argparse never registers it; it is parsed here instead."""
    sp = argparse.ArgumentParser(prog=f"{PROG} _complete", add_help=False)
    sp.add_argument("prefix", nargs="?", default="")
    ns = sp.parse_args(argv[1:])
    ns.fn = cmd_complete
    ns.vault = None
    ns.output_mode = "text"
    ns.no_color = False
    return ns


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    if argv and argv[0] == "_complete":
        args = _parse_hidden_complete(argv)
        try:
            cfg, warnings = config.load()
            r = render.Renderer(no_color_flag=bool(args.no_color), stream=sys.stdout)
            return args.fn(args, r, cfg)
        except errors.KeepsafeError as exc:
            return exc.exit_code
        except Exception:
            # Completion must fail silent and clean.
            return 0
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except errors.UsageError as exc:
        fallback = render.Renderer(no_color_flag=True)
        fallback.fail(_sanitized(str(exc)))
        return errors.UsageError.exit_code
    if _handler_for(args) is None:
        parser.print_help(sys.stderr)
        return 4
    try:
        cfg, warnings = config.load()
        if args.output_mode is None:
            args.output_mode = cfg["output_mode"]
        r = render.Renderer(theme_name=cfg["color_theme"],
                            no_color_flag=bool(args.no_color), stream=sys.stdout)
        for w in warnings:
            r.warn(w)
        return args.fn(args, r, cfg)
    except errors.AbortedByUser as exc:
        # A decline is not an error: plain dim notice on stderr, exit 0.
        try:
            sys.stderr.flush()
        except Exception:
            pass
        fallback = render.Renderer(no_color_flag=True)
        text = str(exc) or "Aborted; nothing was changed."
        print(fallback.paint("dim", text), file=sys.stderr)
        return 0
    except errors.KeepsafeError as exc:
        try:
            sys.stderr.flush()
        except Exception:
            pass
        fallback = render.Renderer(no_color_flag=True)
        fallback.fail(_sanitized(str(exc)))
        return exc.exit_code
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except ValueError as exc:
        # Validation helpers (entry paths, field shapes) raise ValueError;
        # they are user-input problems, not internal ones.
        fallback = render.Renderer(no_color_flag=True)
        fallback.fail(_sanitized(str(exc)))
        return errors.UsageError.exit_code
    except Exception:
        trace = traceback.format_exc()
        print("internal error:", file=sys.stderr)
        print(_sanitized(trace), file=sys.stderr)
        return errors.InternalError.exit_code
