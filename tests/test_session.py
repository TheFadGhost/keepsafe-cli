"""Tests for keepsafe.session: handler, socket loop, expiry, real spawn.

The end-to-end test launches a REAL detached subprocess on this machine
(Windows) through the production handshake: key transferred once over
the child's stdin pipe, never argv/env/files. Runtime files live under
KEEPSAFE_HOME, which config.config_dir() reads at CALL time, so
monkeypatch.setenv keeps everything hermetic.
"""

from __future__ import annotations

import base64
import threading
import time

import pytest

from keepsafe import crypto, errors
import keepsafe.session as session


def make_key() -> bytes:
    return crypto.random_bytes(32)


@pytest.fixture()
def key() -> bytes:
    return make_key()


@pytest.fixture()
def token() -> bytes:
    return crypto.random_bytes(32)


@pytest.fixture()
def server(key: bytes, token: bytes) -> session.SessionServer:
    return session.SessionServer(key, token, idle_timeout=900.0, vault_path="v.kpsf")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class TestPureHandler:
    def test_ping(self, server, token):
        resp = server.handle_request_dict({"op": "ping", "token": token.hex()})
        assert resp == {"ok": True, "data": {"pong": True}}

    def test_status_reports_remaining_and_expires(self, server, token):
        time.sleep(0.05)
        resp = server.handle_request_dict({"op": "status", "token": token.hex()})
        assert resp["ok"] is True
        assert resp["data"]["expires"] is True
        assert 0 < resp["data"]["remaining_seconds"] <= 900

    def test_seal_output_decryptable_with_same_key(self, server, token, key):
        plaintext = b"attack at dawn"
        aad = b"entry:email"
        resp = server.handle_request_dict(
            {
                "op": "seal",
                "token": token.hex(),
                "plaintext_b64": b64(plaintext),
                "aad_b64": b64(aad),
            }
        )
        assert resp["ok"] is True
        nonce = base64.b64decode(resp["data"]["nonce_b64"])
        ct = base64.b64decode(resp["data"]["ct_b64"])
        assert crypto.decrypt(key, nonce, ct, aad) == plaintext

    def test_open_roundtrip(self, server, token, key):
        plaintext = "pässwörd-日本語".encode("utf-8")
        aad = b"aad"
        nonce, ct = crypto.seal(key, plaintext, aad)
        resp = server.handle_request_dict(
            {
                "op": "open",
                "token": token.hex(),
                "nonce_b64": b64(nonce),
                "ct_b64": b64(ct),
                "aad_b64": b64(aad),
            }
        )
        assert resp["ok"] is True
        assert base64.b64decode(resp["data"]["plaintext_b64"]) == plaintext

    def test_open_tampered_ciphertext_unlock_failed(self, server, token, key):
        nonce, ct = crypto.seal(key, b"secret", b"aad")
        tampered = bytearray(ct)
        tampered[0] ^= 0x01
        resp = server.handle_request_dict(
            {
                "op": "open",
                "token": token.hex(),
                "nonce_b64": b64(nonce),
                "ct_b64": b64(bytes(tampered)),
                "aad_b64": b64(b"aad"),
            }
        )
        assert resp == {"ok": False, "error": "unlock_failed"}

    def test_open_wrong_aad_unlock_failed(self, server, token, key):
        nonce, ct = crypto.seal(key, b"secret", b"aad-one")
        resp = server.handle_request_dict(
            {
                "op": "open",
                "token": token.hex(),
                "nonce_b64": b64(nonce),
                "ct_b64": b64(ct),
                "aad_b64": b64(b"aad-two"),
            }
        )
        assert resp == {"ok": False, "error": "unlock_failed"}

    def test_shutdown(self, server, token):
        resp = server.handle_request_dict({"op": "shutdown", "token": token.hex()})
        assert resp == {"ok": True}
        assert server._stop_requested is True

    @pytest.mark.parametrize("op", ["ping", "status", "seal", "open", "shutdown"])
    def test_wrong_token_unauthorized_before_anything_else(self, server, token, op):
        wrong = crypto.random_bytes(32).hex()
        req = {"op": op, "token": wrong}
        if op == "seal":
            req.update(plaintext_b64="AAAA", aad_b64="AAAA")
        elif op == "open":
            req.update(nonce_b64="AAAA", ct_b64="AAAA", aad_b64="AAAA")
        activity: list = []
        resp = server.handle_request_dict(req, peer_last_activity=activity)
        assert resp == {"ok": False, "error": "unauthorized"}
        assert activity == []

    def test_missing_token_unauthorized(self, server):
        assert server.handle_request_dict({"op": "ping"}) == {
            "ok": False,
            "error": "unauthorized",
        }

    def test_authenticated_request_refreshes_activity_list(self, server, token):
        activity: list = []
        resp = server.handle_request_dict(
            {"op": "ping", "token": token.hex()}, peer_last_activity=activity
        )
        assert resp["ok"] is True
        assert len(activity) == 1
        assert abs(activity[0] - time.monotonic()) < 5.0

    def test_malformed_fields_bad_request(self, server, token):
        for req in (
            {"op": "seal", "token": token.hex()},
            {"op": "seal", "token": token.hex(), "plaintext_b64": "!!!", "aad_b64": ""},
            {"op": "open", "token": token.hex()},
            {"op": "nope", "token": token.hex()},
        ):
            assert server.handle_request_dict(req) == {
                "ok": False,
                "error": "bad_request",
            }


def _start_server(idle_timeout: float):
    key = make_key()
    token = crypto.random_bytes(32)
    srv = session.SessionServer(key, token, idle_timeout=idle_timeout)
    port = srv.bind()
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    client = session.SessionClient("127.0.0.1", port, token.hex())
    return srv, thread, client, key, port


class TestSocketLoop:
    def test_client_roundtrips_then_shutdown(self):
        srv, thread, client, _key, _port = _start_server(idle_timeout=60.0)
        try:
            assert client.request("ping") == {"ok": True, "data": {"pong": True}}
            status = client.request("status")
            assert status["ok"] is True
            assert status["data"]["remaining_seconds"] > 0
            sealed = client.request(
                "seal", plaintext_b64=b64(b"roundtrip"), aad_b64=b64(b"aad")
            )
            opened = client.request(
                "open",
                nonce_b64=sealed["data"]["nonce_b64"],
                ct_b64=sealed["data"]["ct_b64"],
                aad_b64=b64(b"aad"),
            )
            assert base64.b64decode(opened["data"]["plaintext_b64"]) == b"roundtrip"
            assert client.request("shutdown") == {"ok": True}
        finally:
            thread.join(timeout=5)
        assert not thread.is_alive()
        with pytest.raises(errors.Unavailable) as excinfo:
            client.request("ping")
        assert "no unlocked session" in str(excinfo.value)

    def test_wrong_token_over_socket_rejected(self):
        srv, thread, good_client, _key, port = _start_server(idle_timeout=60.0)
        bad_client = session.SessionClient("127.0.0.1", port, "00" * 32)
        with pytest.raises(errors.Unavailable) as excinfo:
            bad_client.request("ping")
        assert str(excinfo.value) == "session rejected the request"
        good_client.request("shutdown")
        thread.join(timeout=5)
        assert not thread.is_alive()

    def test_listener_is_loopback_only(self):
        srv = session.SessionServer(make_key(), crypto.random_bytes(32), 60.0)
        port = srv.bind()
        try:
            host, bound_port = srv._listener.getsockname()
            assert host == "127.0.0.1"
            assert bound_port == port
            assert 0 < port < 65536
        finally:
            srv.shutdown()


def test_idle_expiry_invalidates_session():
    srv, thread, client, _key, _port = _start_server(idle_timeout=0.4)
    assert client.request("ping")["ok"] is True
    time.sleep(0.9)
    with pytest.raises(errors.Unavailable) as excinfo:
        client.request("ping")
    assert "expired" in str(excinfo.value)
    assert srv.expired is True
    thread.join(timeout=5)
    assert not thread.is_alive()


def test_activity_prevents_expiry():
    srv, thread, client, _key, _port = _start_server(idle_timeout=0.8)
    try:
        deadline = time.monotonic() + 1.7
        while time.monotonic() < deadline:
            assert client.request("ping")["ok"] is True
            time.sleep(0.2)
        assert srv.expired is False
    finally:
        client.request("shutdown")
        thread.join(timeout=5)


class TestRuntimeFile:
    def _info(self, tmp_path, **overrides) -> session.SessionInfo:
        fields = dict(
            host="127.0.0.1",
            port=45678,
            token="ab" * 32,
            pid=1234,
            started_epoch=1700000000.5,
            timeout_seconds=900,
            vault_path=str(tmp_path / "v.kpsf"),
        )
        fields.update(overrides)
        return session.SessionInfo(**fields)

    def test_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KEEPSAFE_HOME", str(tmp_path / "home"))
        info = self._info(tmp_path)
        session.write_runtime(info)
        loaded = session.read_runtime(info.vault_path)
        assert loaded == info
        expected = tmp_path / "home" / "run" / (
            __import__("hashlib").sha256(
                info.vault_path.encode("utf-8")
            ).hexdigest()[:16]
            + ".json"
        )
        assert expected.is_file()

    def test_clear_runtime_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KEEPSAFE_HOME", str(tmp_path / "home"))
        info = self._info(tmp_path)
        assert session.clear_runtime(info.vault_path) is False
        session.write_runtime(info)
        assert session.clear_runtime(info.vault_path) is True
        assert session.clear_runtime(info.vault_path) is False
        assert session.read_runtime(info.vault_path) is None

    def test_read_runtime_garbage_json_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KEEPSAFE_HOME", str(tmp_path / "home"))
        vault = tmp_path / "v.kpsf"
        path = session.runtime_path(vault)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json at all", encoding="utf-8")
        assert session.read_runtime(vault) is None

    def test_read_runtime_missing_file_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KEEPSAFE_HOME", str(tmp_path / "home"))
        assert session.read_runtime(tmp_path / "v.kpsf") is None


class TestSpawnEndToEnd:
    def test_unlock_status_seal_open_lock(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KEEPSAFE_HOME", str(tmp_path))
        vault = tmp_path / "v.kpsf"
        key = make_key()

        info = session.unlock_session(vault, key, timeout_seconds=120)
        try:
            assert isinstance(info, session.SessionInfo)
            assert info.host == "127.0.0.1"
            assert 0 < info.port < 65536
            assert info.timeout_seconds == 120
            assert info.vault_path == str(vault)
            assert session.read_runtime(vault) == info

            status = session.session_status(vault)
            assert status is not None
            assert isinstance(status["remaining_seconds"], int)
            assert 0 < status["remaining_seconds"] <= 120

            client = session.connect_session(vault)
            assert client is not None
            plaintext = "s3cret-值".encode("utf-8")
            sealed = client.request(
                "seal",
                plaintext_b64=b64(plaintext),
                aad_b64=b64(b"keepsafe-session-aad"),
            )
            opened = client.request(
                "open",
                nonce_b64=sealed["data"]["nonce_b64"],
                ct_b64=sealed["data"]["ct_b64"],
                aad_b64=b64(b"keepsafe-session-aad"),
            )
            assert base64.b64decode(opened["data"]["plaintext_b64"]) == plaintext
        finally:
            locked = session.lock(vault)

        assert locked is True
        assert session.lock(vault) is False
        assert session.connect_session(vault) is None
        assert session.session_status(vault) is None
        with pytest.raises(errors.Unavailable) as excinfo:
            client.request("ping")
        assert "no unlocked session" in str(excinfo.value)

    def test_connect_session_without_runtime_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KEEPSAFE_HOME", str(tmp_path))
        assert session.connect_session(tmp_path / "none.kpsf") is None
        assert session.session_status(tmp_path / "none.kpsf") is None



def test_seal_accepts_caller_nonce_for_header_aad_binding(server, token):
    import base64
    import keepsafe.crypto as crypto

    nonce = crypto.generate_nonce()
    # AAD stands in for the full vault header (which embeds this nonce).
    aad = b"HEADER-BYTES-" + nonce
    resp = server.handle_request_dict(
        {
            "op": "seal",
            "token": token.hex(),
            "plaintext_b64": base64.b64encode(b"payload").decode(),
            "aad_b64": base64.b64encode(aad).decode(),
            "nonce_b64": base64.b64encode(nonce).decode(),
        }
    )
    assert resp["ok"] is True
    returned_nonce = base64.b64decode(resp["data"]["nonce_b64"])
    assert returned_nonce == nonce, "seal must honour the caller-supplied nonce"
    ct = base64.b64decode(resp["data"]["ct_b64"])
    assert crypto.decrypt(server._key, nonce, ct, aad) == b"payload"
    # Wrong-nonce-in-AAD tampering is still caught:
    try:
        crypto.decrypt(server._key, nonce, ct, aad[:-1] + bytes([aad[-1] ^ 1]))
        raised = False
    except crypto.AuthenticationFailure:
        raised = True
    assert raised
