"""Short-lived unlocked session: a helper process holds the derived key.

After ``unlock`` derives the vault key once, the key lives ONLY in the
RAM of a detached helper process (``python -m keepsafe.session``). The
helper serves a loopback TCP endpoint (127.0.0.1 only) guarded by a
random per-session token; clients speak one JSON document per line
(utf-8, "\\n" terminated), request then response. The key is transferred
to the helper exactly once, over the child's stdin pipe -- never via
argv, environment variables, or files.

Honest trade-off, stated rather than pretended away: while a session
lives, ANY process running as the same user can read the token file and
ask the session to encrypt or decrypt, and memory inspection of the
helper could reveal the key. Loopback + token raises the bar from "any
code on the machine" to "any code running as your user", nothing more.
The default idle timeout is therefore deliberately short (900 s); lock
ends the session immediately.

Idle timeout semantics: the server records ``time.monotonic()`` of the
last valid authenticated request; a daemon thread wakes every
``min(idle_timeout, 1.0)`` seconds and on expiry stops serving and exits,
so later requests are refused (the client surfaces this as an
``errors.Unavailable`` mentioning the expired session).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import queue as _queue
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import crypto, errors

_MAX_LINE_BYTES = 8 * 1024 * 1024
_CONN_TIMEOUT = 5.0
_HANDSHAKE_TIMEOUT = 15.0
_WIN_DETACHED_PROCESS = 0x00000008
_WIN_CREATE_NO_WINDOW = 0x08000000


@dataclass
class SessionInfo:
    host: str
    port: int
    token: str
    pid: int
    started_epoch: float
    timeout_seconds: int
    vault_path: str


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: object) -> bytes:
    if not isinstance(text, str):
        raise ValueError("expected base64 string")
    return base64.b64decode(text.encode("ascii"), validate=True)


class SessionServer:
    """Loopback JSON-line server holding the derived key in RAM."""

    def __init__(self, key: bytes, token: bytes, idle_timeout: float, vault_path: str = ""):
        self._key = bytes(key)
        self._token = bytes(token)
        # Requests carry the token as a hex string; compare hex to hex.
        self._token_hex_ascii = self._token.hex().encode("ascii")
        self._idle_timeout = float(idle_timeout)
        self._vault_path = str(vault_path)
        self._listener: socket.socket | None = None
        self._stop_requested = False
        self._expired_flag = False
        self._last_activity = time.monotonic()

    def bind(self) -> int:
        """Bind 127.0.0.1:0, listen, return the chosen port."""
        if self._listener is not None:
            raise errors.InternalError("session server is already bound")
        self._listener = _bind_listener()
        return int(self._listener.getsockname()[1])

    def serve_forever(self) -> None:
        """Serve until shutdown/expiry; cleans up sockets; KeyboardInterrupt-safe."""
        listener = self._listener
        if listener is None:
            raise errors.InternalError("session server is not bound")
        watcher = threading.Thread(
            target=self._watch_idle, name="keepsafe-idle-watch", daemon=True
        )
        watcher.start()
        try:
            listener.settimeout(0.2)
            while not self._stop_requested and not self._expired_flag:
                try:
                    conn, addr = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                if addr[0] != "127.0.0.1":
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
                self._serve_connection(conn)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def handle_request_dict(self, req: dict, peer_last_activity: list | None = None) -> dict:
        """Pure request handler: dict in, response dict out, no sockets.

        The token is checked with ``crypto.constant_time_equals`` BEFORE
        anything else; any mismatch yields {"ok": false, "error":
        "unauthorized"}. A valid token refreshes the idle timer. When
        *peer_last_activity* (a caller-owned list) is given, it is
        replaced with ``[time.monotonic()]`` on every authenticated
        request so callers can observe the refresh without sharing state.
        """
        token = req.get("token")
        if not isinstance(token, str):
            return {"ok": False, "error": "unauthorized"}
        if not crypto.constant_time_equals(token.encode("utf-8"), self._token_hex_ascii):
            return {"ok": False, "error": "unauthorized"}

        now = time.monotonic()
        previous_activity = self._last_activity
        self._last_activity = now
        if peer_last_activity is not None:
            peer_last_activity[:] = [now]

        op = req.get("op")
        if op == "ping":
            return {"ok": True, "data": {"pong": True}}
        if op == "status":
            if self._idle_timeout > 0:
                remaining = max(0, int(round(self._idle_timeout - (now - previous_activity))))
                return {"ok": True, "data": {"remaining_seconds": remaining, "expires": True}}
            return {"ok": True, "data": {"remaining_seconds": -1, "expires": False}}
        if op == "seal":
            return self._op_seal(req)
        if op == "open":
            return self._op_open(req)
        if op == "shutdown":
            self._stop_requested = True
            return {"ok": True}
        return {"ok": False, "error": "bad_request"}

    def shutdown(self) -> None:
        """Stop serving and release the listening socket; idempotent."""
        self._stop_requested = True
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

    @property
    def expired(self) -> bool:
        return self._expired_flag

    def _watch_idle(self) -> None:
        interval = min(self._idle_timeout, 1.0) if self._idle_timeout > 0 else 1.0
        while not self._stop_requested and not self._expired_flag:
            time.sleep(max(interval, 0.05))
            if self._idle_timeout <= 0:
                continue
            if time.monotonic() - self._last_activity >= self._idle_timeout:
                self._expired_flag = True
                self.shutdown()
                break

    def _serve_connection(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(_CONN_TIMEOUT)
            buf = bytearray()
            while b"\n" not in buf and len(buf) <= _MAX_LINE_BYTES:
                try:
                    chunk = conn.recv(65536)
                except (socket.timeout, OSError):
                    return
                if not chunk:
                    break
                buf.extend(chunk)
            newline = buf.find(b"\n")
            if newline == -1 or newline > _MAX_LINE_BYTES:
                return
            resp = self._dispatch_raw(bytes(buf[:newline]))
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _dispatch_raw(self, raw_line: bytes) -> dict:
        raw_line = raw_line.strip()
        if not raw_line:
            return {"ok": False, "error": "bad_request"}
        try:
            req = json.loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return {"ok": False, "error": "bad_request"}
        if not isinstance(req, dict):
            return {"ok": False, "error": "bad_request"}
        return self.handle_request_dict(req)

    def _op_seal(self, req: dict) -> dict:
        try:
            plaintext = _b64decode(req.get("plaintext_b64"))
            aad = _b64decode(req.get("aad_b64"))
        except (ValueError, TypeError, binascii.Error):
            return {"ok": False, "error": "bad_request"}
        # The caller MAY supply the nonce: when writing a vault file, the
        # nonce sits inside the header and the header is the AAD, so the
        # nonce must be chosen before the AAD bytes are assembled. When
        # omitted, a fresh CSPRNG nonce is generated here.
        if req.get("nonce_b64") is not None:
            try:
                nonce = _b64decode(req.get("nonce_b64"))
            except (ValueError, TypeError, binascii.Error):
                return {"ok": False, "error": "bad_request"}
            if not isinstance(nonce, bytes) or len(nonce) != crypto.NONCE_SIZE:
                return {"ok": False, "error": "bad_request"}
        else:
            nonce = crypto.generate_nonce()
        try:
            ct = crypto.encrypt(self._key, nonce, plaintext, aad)
        except crypto.CryptoError:
            return {"ok": False, "error": "bad_request"}
        return {
            "ok": True,
            "data": {"nonce_b64": _b64encode(nonce), "ct_b64": _b64encode(ct)},
        }

    def _op_open(self, req: dict) -> dict:
        try:
            nonce = _b64decode(req.get("nonce_b64"))
            ct = _b64decode(req.get("ct_b64"))
            aad = _b64decode(req.get("aad_b64"))
        except (ValueError, TypeError, binascii.Error):
            return {"ok": False, "error": "bad_request"}
        try:
            plaintext = crypto.decrypt(self._key, nonce, ct, aad)
        except crypto.CryptoError:
            return {"ok": False, "error": "unlock_failed"}
        return {"ok": True, "data": {"plaintext_b64": _b64encode(plaintext)}}


def _bind_listener() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    return sock


class SessionClient:
    """One-connection-per-request client for the session endpoint."""

    def __init__(self, host: str, port: int, token: str, connect_timeout: float = 2.0):
        self.host = host
        self.port = int(port)
        self.token = token
        self.connect_timeout = float(connect_timeout)

    def request(self, op: str, **fields) -> dict:
        payload = {"op": op, "token": self.token}
        payload.update(fields)
        line = (json.dumps(payload) + "\n").encode("utf-8")
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self.connect_timeout
            ) as sock:
                sock.settimeout(self.connect_timeout)
                sock.sendall(line)
                return self._read_response(sock)
        except errors.KeepsafeError:
            raise
        except OSError as exc:
            raise errors.Unavailable(
                f"no unlocked session: could not reach the session helper "
                f"({exc}). It may have expired; unlock again."
            ) from exc

    def _read_response(self, sock: socket.socket) -> dict:
        buf = bytearray()
        while b"\n" not in buf:
            if len(buf) > _MAX_LINE_BYTES:
                raise errors.Unavailable(
                    "no unlocked session: the session helper returned an "
                    "unreadable response."
                )
            try:
                chunk = sock.recv(65536)
            except OSError as exc:
                raise errors.Unavailable(
                    f"no unlocked session: connection to the session helper "
                    f"failed ({exc}). It may have expired; unlock again."
                ) from exc
            if not chunk:
                break
            buf.extend(chunk)
        newline = buf.find(b"\n")
        if newline == -1:
            raise errors.Unavailable(
                "no unlocked session: the session helper closed the "
                "connection without responding."
            )
        try:
            resp = json.loads(bytes(buf[:newline]).decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise errors.Unavailable(
                "no unlocked session: the session helper returned an "
                "unreadable response."
            ) from exc
        if not isinstance(resp, dict):
            raise errors.Unavailable(
                "no unlocked session: the session helper returned an "
                "unreadable response."
            )
        if resp.get("ok") is False and resp.get("error") == "unauthorized":
            raise errors.Unavailable("session rejected the request")
        return resp


def runtime_path(vault_path) -> Path:
    digest = hashlib.sha256(str(vault_path).encode("utf-8")).hexdigest()[:16]
    from .config import config_dir

    return config_dir() / "run" / f"{digest}.json"


def write_runtime(info: SessionInfo) -> None:
    path = runtime_path(info.vault_path)
    data = json.dumps(
        {
            "host": info.host,
            "port": info.port,
            "token": info.token,
            "pid": info.pid,
            "started_epoch": info.started_epoch,
            "timeout_seconds": info.timeout_seconds,
            "vault_path": info.vault_path,
        },
        sort_keys=True,
    ).encode("utf-8")
    from .storage import atomic_write_bytes

    atomic_write_bytes(path, data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_runtime(vault_path) -> SessionInfo | None:
    path = runtime_path(vault_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        return SessionInfo(
            host=str(data["host"]),
            port=int(data["port"]),
            token=str(data["token"]),
            pid=int(data["pid"]),
            started_epoch=float(data["started_epoch"]),
            timeout_seconds=int(data["timeout_seconds"]),
            vault_path=str(data["vault_path"]),
        )
    except (OSError, KeyError, TypeError, ValueError):
        return None


def clear_runtime(vault_path) -> bool:
    try:
        runtime_path(vault_path).unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def spawn_session(vault_path, key: bytes, timeout_seconds: int) -> SessionInfo:
    """Launch a detached helper, hand it the key over stdin, register it."""
    vault_str = str(vault_path)
    token_bytes = crypto.random_bytes(32)
    token_hex = token_bytes.hex()
    package_parent = Path(__file__).resolve().parent.parent
    popen_kwargs = {}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = _WIN_DETACHED_PROCESS | _WIN_CREATE_NO_WINDOW
    else:
        popen_kwargs["start_new_session"] = True
    child = None
    try:
        child = subprocess.Popen(
            [sys.executable, "-m", "keepsafe.session"],
            cwd=str(package_parent),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            **popen_kwargs,
        )
        port = _read_port_line(child)
        handshake = json.dumps(
            {
                "token": token_hex,
                "key_b64": _b64encode(bytes(key)),
                "timeout": int(timeout_seconds),
                "vault_path": vault_str,
            }
        )
        assert child.stdin is not None
        child.stdin.write(handshake + "\n")
        child.stdin.flush()
        child.stdin.close()
        if child.poll() is not None:
            raise errors.Unavailable("could not start session helper")
        info = SessionInfo(
            host="127.0.0.1",
            port=port,
            token=token_hex,
            pid=child.pid,
            started_epoch=time.time(),
            timeout_seconds=int(timeout_seconds),
            vault_path=vault_str,
        )
        write_runtime(info)
        return info
    except errors.KeepsafeError:
        _kill_quietly(child)
        clear_runtime(vault_str)
        raise errors.Unavailable("could not start session helper")
    except (OSError, ValueError, AssertionError) as exc:
        _kill_quietly(child)
        clear_runtime(vault_str)
        raise errors.Unavailable("could not start session helper") from exc


def _read_port_line(child: subprocess.Popen) -> int:
    lines: "_queue.Queue[str | None]" = _queue.Queue()
    assert child.stdout is not None

    def _reader() -> None:
        try:
            line = child.stdout.readline()
        except OSError:
            line = ""
        lines.put(line)

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()
    try:
        line = lines.get(timeout=_HANDSHAKE_TIMEOUT)
    except _queue.Empty as exc:
        raise errors.Unavailable("could not start session helper") from exc
    line = line.strip()
    prefix = "KEEPSAFE_PORT "
    if not line.startswith(prefix):
        raise errors.Unavailable("could not start session helper")
    try:
        port = int(line[len(prefix):])
    except ValueError as exc:
        raise errors.Unavailable("could not start session helper") from exc
    if not 0 < port < 65536:
        raise errors.Unavailable("could not start session helper")
    return port


def _kill_quietly(child: subprocess.Popen | None) -> None:
    if child is None:
        return
    for stream in (child.stdin, child.stdout):
        try:
            if stream is not None:
                stream.close()
        except OSError:
            pass
    try:
        child.kill()
    except OSError:
        pass
    try:
        child.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def unlock_session(vault_path, key: bytes, timeout_seconds: int) -> SessionInfo:
    """Spawn a session for *vault_path*; alias used by the CLI unlock path."""
    return spawn_session(vault_path, key, timeout_seconds)


def connect_session(vault_path) -> SessionClient | None:
    info = read_runtime(vault_path)
    if info is None:
        return None
    client = SessionClient(info.host, info.port, info.token)
    try:
        client.request("ping")
    except (errors.KeepsafeError, OSError):
        return None
    return client


def lock(vault_path) -> bool:
    vault_str = str(vault_path)
    info = read_runtime(vault_str)
    live = False
    if info is not None:
        client = SessionClient(info.host, info.port, info.token)
        try:
            client.request("shutdown")
            live = True
        except (errors.KeepsafeError, OSError):
            live = False
    clear_runtime(vault_str)
    return live


def session_status(vault_path) -> dict | None:
    client = connect_session(vault_path)
    if client is None:
        return None
    try:
        resp = client.request("status")
    except (errors.KeepsafeError, OSError):
        return None
    if not isinstance(resp, dict) or resp.get("ok") is not True:
        return None
    data = resp.get("data")
    if not isinstance(data, dict) or "remaining_seconds" not in data:
        return None
    return {"remaining_seconds": data["remaining_seconds"]}


def _child_main() -> None:
    """Child side: bind, announce port, receive the key on stdin, serve."""
    listener = None
    try:
        listener = _bind_listener()
        sys.stdout.write(f"KEEPSAFE_PORT {listener.getsockname()[1]}\n")
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line.strip():
            return
        handshake = json.loads(line)
        key = base64.b64decode(str(handshake["key_b64"]))
        token = bytes.fromhex(str(handshake["token"]))
        idle_timeout = float(handshake["timeout"])
        vault_path = str(handshake.get("vault_path", ""))
        server = SessionServer(key, token, idle_timeout, vault_path)
        server._listener = listener
        listener = None
        server.serve_forever()
    except Exception:
        try:
            if listener is not None:
                listener.close()
        except OSError:
            pass
        sys.exit(1)


if __name__ == "__main__":
    _child_main()
