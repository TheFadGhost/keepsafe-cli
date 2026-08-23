"""Tests for keepsafe.format: header layout, encrypt/decrypt, tamper refusal.

The tamper sweep is the centerpiece: EVERY byte offset of a real vault
file is flipped and the outcome is asserted -- specific pre-decryption
refusals where FORMAT.md permits them (magic, version, KDF type), and the
one generic UnlockFailed everywhere else, with plaintext never returned.
"""

from __future__ import annotations

import json
import struct

import pytest

import keepsafe.crypto as crypto
import keepsafe.errors as errors
from keepsafe import format as fmt
from keepsafe.model import Entry, Field, new_payload, payload_from_entries

from tests.kdf_seam import use_fast_kdf  # noqa: F401  (fixture)

FAST = {"memory_kib": 1024, "iterations": 1, "parallelism": 1}
FAST_PARAMS = fmt.KdfParams(**FAST)
OTHER_FAST_PARAMS = fmt.KdfParams(memory_kib=2048, iterations=1, parallelism=1)
PASSPHRASE = "correct horse battery staple 郵件🔐"

GENERIC = (
    "Unable to unlock the vault. The passphrase may be wrong, "
    "or the file may be damaged or tampered with."
)


def sample_payload() -> dict:
    entry = Entry(
        name="web/github",
        username="octocat",
        secret="tr0ub4dor&3",
        url="https://github.com",
        notes="primary account",
        tags=["dev"],
        created="2026-08-22T12:00:00+00:00",
        updated="2026-08-22T12:00:00+00:00",
        fields=[Field(key="recovery", value="1111-2222", secret=True)],
    )
    return payload_from_entries([entry])


# Deterministic content -> deterministic JSON length -> fixed blob length,
# so the tamper sweep can parametrize over every byte offset at collection.
SAMPLE_PAYLOAD = sample_payload()
PLAINTEXT_LEN = len(fmt.serialize_payload(SAMPLE_PAYLOAD))
BLOB_LEN = fmt.HEADER_SIZE + PLAINTEXT_LEN + crypto.TAG_SIZE


@pytest.fixture
def vault_blob(use_fast_kdf) -> bytes:
    blob, _header = fmt.build_vault_file(PASSPHRASE, SAMPLE_PAYLOAD, FAST_PARAMS)
    return blob


# ---------------------------------------------------------------------------
# Header pack/parse
# ---------------------------------------------------------------------------

def _arbitrary_header() -> fmt.VaultHeader:
    return fmt.VaultHeader(
        version=crypto.FORMAT_VERSION,
        kdf_type=crypto.KDF_TYPE_ARGON2ID,
        salt=bytes(range(32)),
        params=fmt.KdfParams(memory_kib=262144, iterations=7, parallelism=3),
        nonce=bytes(range(32, 56)),
    )


class TestPackParseRoundTrip:
    def test_round_trip_preserves_every_field(self):
        header = _arbitrary_header()
        packed = fmt.pack_header(header)
        assert len(packed) == fmt.HEADER_SIZE == 85
        parsed = fmt.parse_header(packed)
        assert parsed.version == header.version
        assert parsed.kdf_type == header.kdf_type
        assert parsed.salt == header.salt
        assert parsed.params.memory_kib == header.params.memory_kib
        assert parsed.params.iterations == header.params.iterations
        assert parsed.params.parallelism == header.params.parallelism
        assert parsed.nonce == header.nonce

    def test_exact_layout_bytes(self):
        """Byte-for-byte lock on the FORMAT.md v1 layout, little-endian."""
        header = _arbitrary_header()
        expected = (
            b"KPSF"
            + struct.pack("<I", crypto.FORMAT_VERSION)
            + bytes([crypto.KDF_TYPE_ARGON2ID])
            + bytes(range(32))
            + struct.pack("<III", 262144, 7, 3)
            + bytes(range(32, 56))
            + struct.pack("<Q", 4242)
        )
        assert len(expected) == 85
        assert fmt.pack_header(header, payload_len=4242) == expected

    def test_payload_len_defaults_to_zero_field(self):
        packed = fmt.pack_header(_arbitrary_header())
        assert struct.unpack_from("<Q", packed, 77)[0] == 0


class TestParseRefusals:
    @pytest.mark.parametrize("blob", [b"", b"K", b"KPSF", b"x" * 84])
    def test_short_blob_not_a_vault(self, blob):
        with pytest.raises(errors.NotAKeepsafeVault):
            fmt.parse_header(blob)

    def test_bad_magic_not_a_vault(self):
        blob = b"NOPE" + b"\x00" * 81
        with pytest.raises(errors.NotAKeepsafeVault):
            fmt.parse_header(blob)

    def test_unknown_version_message_names_version_and_says_newer(self):
        data = bytearray(fmt.pack_header(_arbitrary_header()))
        struct.pack_into("<I", data, 4, 999)
        with pytest.raises(errors.VaultTooNew) as excinfo:
            fmt.parse_header(bytes(data))
        message = str(excinfo.value)
        assert "newer" in message
        assert "999" in message

    def test_unknown_kdf_type_is_vault_too_new(self):
        data = bytearray(fmt.pack_header(_arbitrary_header()))
        data[8] = 42
        with pytest.raises(errors.VaultTooNew) as excinfo:
            fmt.parse_header(bytes(data))
        assert "written by different software" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Payload serialization and whole-file round trip
# ---------------------------------------------------------------------------

class TestSerializePayload:
    def test_deterministic_sorted_compact_utf8(self):
        payload = {"b": 1, "a": {"ż": "邮件🔐"}, "c": [3, 2]}
        first = fmt.serialize_payload(payload)
        second = fmt.serialize_payload({"c": [3, 2], "a": {"ż": "邮件🔐"}, "b": 1})
        assert first == second
        assert json.loads(first.decode("utf-8")) == payload
        # sorted keys, no whitespace padding
        assert first.startswith(b'{"a":')
        assert b": " not in first and b', ' not in first


class TestBuildOpenRoundTrip:
    def test_unicode_rich_payload_preserved_exactly(self, use_fast_kdf):
        entries = [
            Entry(
                name="邮件/bank",
                username="用户@example.com",
                secret="p@sswörd🔑日本語🦄",
                url="https://例え.jp/ログイン",
                notes="emoji 🔐 and unicode ✓ ñ",
                tags=["金融", "dev"],
                created="2026-01-02T03:04:05+00:00",
                updated="2026-06-07T08:09:10+00:00",
                fields=[
                    Field(key="recovery", value="码字🔑", secret=True),
                    Field(key="note", value="plain", secret=False),
                ],
            ),
            Entry(name="web/github", username="octocat", secret="s3cret"),
        ]
        blob, header = fmt.build_vault_file(
            PASSPHRASE, payload_from_entries(entries), FAST_PARAMS
        )
        out_header, out_payload = fmt.open_vault_file(blob, PASSPHRASE)
        assert out_header == header
        assert out_header.params == FAST_PARAMS
        assert len(out_header.salt) == crypto.SALT_SIZE
        assert len(out_header.nonce) == crypto.NONCE_SIZE
        assert out_payload == payload_from_entries(entries)

    def test_explicit_tiny_params_honored_end_to_end(self, use_fast_kdf):
        params = fmt.KdfParams(memory_kib=1024, iterations=2, parallelism=1)
        blob, header = fmt.build_vault_file(PASSPHRASE, new_payload(), params)
        assert header.params == params
        opened_header, payload = fmt.open_vault_file(blob, PASSPHRASE)
        assert opened_header.params == params
        assert payload == new_payload()

    def test_default_params_read_at_call_time(self, use_fast_kdf):
        blob, header = fmt.build_vault_file(PASSPHRASE, new_payload())
        assert header.params == FAST_PARAMS  # patched defaults, not shipped
        _, payload = fmt.open_vault_file(blob, PASSPHRASE)
        assert payload == new_payload()

    def test_fresh_salt_nonce_and_ciphertext_per_build(self, use_fast_kdf):
        blob_a, header_a = fmt.build_vault_file(PASSPHRASE, SAMPLE_PAYLOAD, FAST_PARAMS)
        blob_b, header_b = fmt.build_vault_file(PASSPHRASE, SAMPLE_PAYLOAD, FAST_PARAMS)
        assert header_a.salt != header_b.salt
        assert header_a.nonce != header_b.nonce
        assert blob_a[fmt.HEADER_SIZE:] != blob_b[fmt.HEADER_SIZE:]

    def test_wrong_passphrase_generic_message_only(self, use_fast_kdf):
        blob, _header = fmt.build_vault_file(PASSPHRASE, SAMPLE_PAYLOAD, FAST_PARAMS)
        with pytest.raises(errors.UnlockFailed) as excinfo:
            fmt.open_vault_file(blob, "totally different passphrase")
        assert str(excinfo.value) == GENERIC

    def test_garbage_json_after_successful_auth_is_internal_error(
        self, use_fast_kdf, monkeypatch
    ):
        blob, _header = fmt.build_vault_file(PASSPHRASE, SAMPLE_PAYLOAD, FAST_PARAMS)
        monkeypatch.setattr(crypto, "decrypt", lambda *a, **k: b"{not json at all")
        with pytest.raises(errors.InternalError):
            fmt.open_vault_file(blob, PASSPHRASE)


class TestParamsComeFromHeader:
    def _manual_blob(self, real_params, claimed_params):
        """File whose payload is encrypted under real_params but whose
        header claims claimed_params."""
        salt = crypto.generate_salt()
        nonce = crypto.generate_nonce()
        payload_bytes = fmt.serialize_payload(new_payload())
        key = crypto.derive_key(
            PASSPHRASE,
            salt,
            memory_kib=real_params.memory_kib,
            iterations=real_params.iterations,
            parallelism=real_params.parallelism,
        )
        header = fmt.VaultHeader(
            version=crypto.FORMAT_VERSION,
            kdf_type=crypto.KDF_TYPE_ARGON2ID,
            salt=salt,
            params=claimed_params,
            nonce=nonce,
        )
        header_bytes = fmt.pack_header(header, len(payload_bytes) + crypto.TAG_SIZE)
        ciphertext = crypto.encrypt(key, nonce, payload_bytes, aad=header_bytes)
        return header_bytes + ciphertext

    def test_claimed_params_override_defaults_on_open(self, use_fast_kdf):
        # use_fast_kdf patched the module defaults to FAST; the header here
        # claims OTHER params while the payload was encrypted under FAST.
        # If open_vault_file wrongly used module defaults it would succeed;
        # using the header's (claimed) parameters it must fail auth.
        blob = self._manual_blob(FAST_PARAMS, OTHER_FAST_PARAMS)
        with pytest.raises(errors.UnlockFailed) as excinfo:
            fmt.open_vault_file(blob, PASSPHRASE)
        assert str(excinfo.value) == GENERIC

    def test_matching_manual_construction_opens(self, use_fast_kdf):
        # Control for the test above: identical construction with honest
        # header opens fine, proving the failure is param mismatch alone.
        blob = self._manual_blob(OTHER_FAST_PARAMS, OTHER_FAST_PARAMS)
        header, payload = fmt.open_vault_file(blob, PASSPHRASE)
        assert header.params == OTHER_FAST_PARAMS
        assert payload == new_payload()

    def test_built_vault_ignores_later_default_changes(self, use_fast_kdf, monkeypatch):
        blob, header = fmt.build_vault_file(PASSPHRASE, SAMPLE_PAYLOAD, FAST_PARAMS)
        monkeypatch.setattr(crypto, "DEFAULT_MEMORY_KIB", 2048)
        monkeypatch.setattr(crypto, "DEFAULT_ITERATIONS", 4)
        monkeypatch.setattr(crypto, "DEFAULT_PARALLELISM", 2)
        opened, payload = fmt.open_vault_file(blob, PASSPHRASE)
        assert opened.params == header.params
        assert payload["entries"]["web/github"]["secret"] == "tr0ub4dor&3"


class TestVersionRefusalBeforeDecryption:
    def test_version_check_runs_before_any_key_derivation(
        self, use_fast_kdf, vault_blob, monkeypatch
    ):
        tampered = bytearray(vault_blob)
        struct.pack_into("<I", tampered, 4, 999)
        monkeypatch.setattr(
            crypto,
            "derive_key",
            lambda *a, **k: pytest.fail("derive_key must not run for bad version"),
        )
        with pytest.raises(errors.VaultTooNew) as excinfo:
            fmt.open_vault_file(bytes(tampered), PASSPHRASE)
        assert "newer" in str(excinfo.value)
        assert "999" in str(excinfo.value)


class TestTamperSweep:
    """Flip every single byte of the file; assert the exact refusal.

    Offsets 0-3 (magic) -> NotAKeepsafeVault; offsets 4-7 (version) and
    offset 8 (KDF type) -> VaultTooNew, the pre-decryption refusals
    FORMAT.md permits; EVERY other offset -- salt, KDF parameters, nonce,
    declared payload length, ciphertext, tag -> generic UnlockFailed with
    the exact canonical message, because the AAD covers the entire header.
    Decryption must never yield partial or wrong-but-decoded plaintext.
    """

    EXPECTED_MAGIC = errors.NotAKeepsafeVault
    EXPECTED_VERSION_OR_KDF = errors.VaultTooNew
    EXPECTED_GENERIC = errors.UnlockFailed

    @staticmethod
    def expected_for(offset: int) -> type:
        if offset < 4:
            return TestTamperSweep.EXPECTED_MAGIC
        if offset < 8:
            return TestTamperSweep.EXPECTED_VERSION_OR_KDF
        if offset == 8:  # kdf_type 1 ^ 1 -> 0, unknown -> refused pre-decrypt
            return TestTamperSweep.EXPECTED_VERSION_OR_KDF
        return TestTamperSweep.EXPECTED_GENERIC

    @pytest.mark.parametrize("offset", range(BLOB_LEN))
    def test_single_byte_flip_is_refused(self, use_fast_kdf, vault_blob, offset):
        assert len(vault_blob) == BLOB_LEN
        tampered = bytearray(vault_blob)
        tampered[offset] ^= 0x01
        expected = self.expected_for(offset)
        with pytest.raises(expected) as excinfo:
            fmt.open_vault_file(bytes(tampered), PASSPHRASE)
        if expected is errors.UnlockFailed:
            assert str(excinfo.value) == GENERIC

    def test_truncated_payload_is_generic_failure(self, use_fast_kdf, vault_blob):
        with pytest.raises(errors.UnlockFailed) as excinfo:
            fmt.open_vault_file(vault_blob[:-20], PASSPHRASE)
        assert str(excinfo.value) == GENERIC

    def test_truncated_below_tag_is_generic_failure(self, use_fast_kdf, vault_blob):
        with pytest.raises(errors.UnlockFailed) as excinfo:
            fmt.open_vault_file(vault_blob[: fmt.HEADER_SIZE + 5], PASSPHRASE)
        assert str(excinfo.value) == GENERIC

    def test_header_only_file_is_generic_failure(self, use_fast_kdf, vault_blob):
        with pytest.raises(errors.UnlockFailed):
            fmt.open_vault_file(vault_blob[: fmt.HEADER_SIZE], PASSPHRASE)
