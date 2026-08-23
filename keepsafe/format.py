"""Vault file pack/parse and whole-file encryption (FORMAT.md contract).

Layout, version 1 (all integers little-endian), see FORMAT.md:

    offset  size  field
    0       4     magic            b"KPSF"
    4       4     format_version   u32
    8       1     kdf_type         u8 (1 = Argon2id)
    9       32    salt
    41      4     kdf_memory_kib   u32
    45      4     kdf_iterations   u32
    49      4     kdf_parallelism  u32
    53      24    nonce
    77      8     payload_len      u64, length of ciphertext+tag that follows
    85      ...   payload          XChaCha20-Poly1305 ciphertext (+16B tag)

The AEAD associated data is the ENTIRE 85-byte header. Per FORMAT.md rule 1
every byte of the file, header included, is authenticated: a tampered header
is detected and refused, never obeyed, because the tag covers header plus
payload together. Consequence: any flip in magic, version, KDF type, salt,
parameters, nonce, declared payload length, ciphertext, or tag surfaces as
one generic unlock failure (or, for magic/version/KDF-type, as the specific
pre-decryption refusals FORMAT.md permits). Callers must never distinguish
wrong passphrase from corruption; see DESIGN.md error taxonomy.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass

from . import crypto, errors

HEADER_SIZE = 85

_MAGIC_OFFSET = 0
_VERSION_OFFSET = 4
_KDF_TYPE_OFFSET = 8
_SALT_OFFSET = 9
_PARAMS_OFFSET = 41
_NONCE_OFFSET = 53
_PAYLOAD_LEN_OFFSET = 77

GENERIC_UNLOCK_MESSAGE = (
    "Unable to unlock the vault. The passphrase may be wrong, "
    "or the file may be damaged or tampered with."
)


@dataclass(frozen=True)
class KdfParams:
    """Argon2id cost parameters as stored in the vault header."""

    memory_kib: int
    iterations: int
    parallelism: int


@dataclass(frozen=True)
class VaultHeader:
    """The parsed fixed-size header of a KPSF vault file."""

    version: int
    kdf_type: int
    salt: bytes
    params: KdfParams
    nonce: bytes


def pack_header(h: VaultHeader, payload_len: int = 0) -> bytes:
    """Serialize *h* to exactly HEADER_SIZE bytes per the FORMAT.md layout.

    ``payload_len`` is the u64 at offset 77: the length of the ciphertext
    (plaintext + 16-byte tag) that follows the header in a complete file.
    It defaults to 0 for header-only packing; ``build_vault_file`` always
    passes the true length so the value is bound into the authentication
    tag via the AAD. Raises InternalError on malformed field sizes rather
    than emitting a corrupt header silently.
    """
    if len(h.salt) != crypto.SALT_SIZE:
        raise errors.InternalError(
            f"header salt must be exactly {crypto.SALT_SIZE} bytes"
        )
    if len(h.nonce) != crypto.NONCE_SIZE:
        raise errors.InternalError(
            f"header nonce must be exactly {crypto.NONCE_SIZE} bytes"
        )
    if isinstance(payload_len, bool) or not isinstance(payload_len, int):
        raise errors.InternalError("payload_len must be an int")
    if payload_len < 0 or payload_len >= 2**64:
        raise errors.InternalError("payload_len does not fit in u64")

    out = bytearray(HEADER_SIZE)
    out[_MAGIC_OFFSET:_MAGIC_OFFSET + 4] = crypto.MAGIC
    struct.pack_into("<I", out, _VERSION_OFFSET, h.version)
    out[_KDF_TYPE_OFFSET] = h.kdf_type
    out[_SALT_OFFSET:_SALT_OFFSET + crypto.SALT_SIZE] = h.salt
    struct.pack_into(
        "<III",
        out,
        _PARAMS_OFFSET,
        h.params.memory_kib,
        h.params.iterations,
        h.params.parallelism,
    )
    out[_NONCE_OFFSET:_NONCE_OFFSET + crypto.NONCE_SIZE] = h.nonce
    struct.pack_into("<Q", out, _PAYLOAD_LEN_OFFSET, payload_len)
    return bytes(out)


def parse_header(blob: bytes) -> VaultHeader:
    """Parse the fixed-size header from a whole vault file blob.

    Applies exactly the pre-decryption refusals FORMAT.md permits:
    shorter than HEADER_SIZE or wrong magic -> NotAKeepsafeVault;
    unknown format version -> VaultTooNew (message names the format
    version and says the file is newer); unknown KDF type ->
    VaultTooNew (written by different software). Everything else is
    left to authentication, which refuses tampered headers wholesale.
    """
    data = bytes(blob)
    if len(data) < HEADER_SIZE or data[_MAGIC_OFFSET:_MAGIC_OFFSET + 4] != crypto.MAGIC:
        raise errors.NotAKeepsafeVault(
            "This file is not a Keepsafe vault (missing KPSF magic or truncated header)."
        )

    version = struct.unpack_from("<I", data, _VERSION_OFFSET)[0]
    if version != crypto.FORMAT_VERSION:
        raise errors.VaultTooNew(
            f"This vault was written by a newer version of Keepsafe "
            f"(format v{version}; this software reads format v{crypto.FORMAT_VERSION}). "
            f"Upgrade Keepsafe to open it."
        )

    kdf_type = data[_KDF_TYPE_OFFSET]
    if kdf_type != crypto.KDF_TYPE_ARGON2ID:
        raise errors.VaultTooNew(
            f"Unknown KDF type {kdf_type} in vault header: "
            f"this vault was written by different software."
        )

    salt = data[_SALT_OFFSET:_SALT_OFFSET + crypto.SALT_SIZE]
    memory_kib, iterations, parallelism = struct.unpack_from("<III", data, _PARAMS_OFFSET)
    nonce = data[_NONCE_OFFSET:_NONCE_OFFSET + crypto.NONCE_SIZE]
    return VaultHeader(
        version=version,
        kdf_type=kdf_type,
        salt=salt,
        params=KdfParams(memory_kib, iterations, parallelism),
        nonce=nonce,
    )


def serialize_payload(payload: dict) -> bytes:
    """Canonical plaintext serialization: sorted keys, compact, UTF-8.

    Identical content therefore yields identical bytes before encryption,
    as FORMAT.md requires of writers.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _params_from_defaults() -> KdfParams:
    # Read at CALL time so test seams (and future config-driven policies)
    # that patch crypto.DEFAULT_* take effect immediately.
    d = crypto.get_default_kdf_params()
    return KdfParams(d["memory_kib"], d["iterations"], d["parallelism"])


def build_vault_file(
    passphrase: str,
    payload: dict,
    kdf_params: KdfParams | None = None,
) -> tuple[bytes, VaultHeader]:
    """Encrypt *payload* into a complete vault file blob.

    Generates a fresh CSPRNG salt and nonce; when *kdf_params* is None the
    crypto module's defaults are read at call time. Returns
    ``(header || ciphertext, header)``. The AEAD associated data is the
    entire serialized header (including the true payload length), so per
    FORMAT.md the authentication tag covers header plus payload together
    and any tampered header is refused at decrypt time.
    """
    params = kdf_params if kdf_params is not None else _params_from_defaults()
    payload_bytes = serialize_payload(payload)
    header = VaultHeader(
        version=crypto.FORMAT_VERSION,
        kdf_type=crypto.KDF_TYPE_ARGON2ID,
        salt=crypto.generate_salt(),
        params=params,
        nonce=crypto.generate_nonce(),
    )
    header_bytes = pack_header(header, payload_len=len(payload_bytes) + crypto.TAG_SIZE)
    key = crypto.derive_key(
        passphrase,
        header.salt,
        memory_kib=params.memory_kib,
        iterations=params.iterations,
        parallelism=params.parallelism,
    )
    ciphertext = crypto.encrypt(key, header.nonce, payload_bytes, aad=header_bytes)
    return header_bytes + ciphertext, header


def open_vault_file(blob: bytes, passphrase: str) -> tuple[VaultHeader, dict]:
    """Parse, authenticate, and decrypt a whole vault file blob.

    Header-level refusals (bad magic, unknown version or KDF type) happen
    before any decryption work, per FORMAT.md. The key is derived using the
    parameters FROM THE HEADER -- never module defaults -- then decrypted
    with the full header as AAD, so a tampered header cannot survive
    authentication. Wrong passphrase, corrupted or tampered header, truncated
    payload, and short ciphertext all collapse into ONE generic UnlockFailed;
    they are indistinguishable by design (see DESIGN.md). Plaintext that
    authenticates but fails to parse as JSON is an internal condition: the
    data was authenticated, so it should always be valid.
    """
    data = bytes(blob)
    header = parse_header(data)
    header_bytes = data[:HEADER_SIZE]
    ciphertext = data[HEADER_SIZE:]
    try:
        key = crypto.derive_key(
            passphrase,
            header.salt,
            memory_kib=header.params.memory_kib,
            iterations=header.params.iterations,
            parallelism=header.params.parallelism,
        )
        plaintext = crypto.decrypt(key, header.nonce, ciphertext, aad=header_bytes)
    except (crypto.AuthenticationFailure, crypto.InvalidParameters) as exc:
        raise errors.UnlockFailed(GENERIC_UNLOCK_MESSAGE) from exc
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise errors.InternalError(
            "authenticated vault payload is not valid JSON; this is a bug, not corruption"
        ) from exc
    return header, payload


def open_vault_file_with_key(blob: bytes, passphrase: str) -> tuple[VaultHeader, bytes, dict]:
    """Like open_vault_file, but also returns the derived key.

    Mutating commands need the same key to re-encrypt the payload under
    the existing salt and KDF parameters with a fresh nonce per save.
    Using this avoids a second Argon2 run per mutation. Callers should
    treat the key as short-lived and zeroize it when practical.
    """
    data = bytes(blob)
    header = parse_header(data)
    header_bytes = data[:HEADER_SIZE]
    ciphertext = data[HEADER_SIZE:]
    try:
        key = crypto.derive_key(
            passphrase,
            header.salt,
            memory_kib=header.params.memory_kib,
            iterations=header.params.iterations,
            parallelism=header.params.parallelism,
        )
        plaintext = crypto.decrypt(key, header.nonce, ciphertext, aad=header_bytes)
    except (crypto.AuthenticationFailure, crypto.InvalidParameters) as exc:
        raise errors.UnlockFailed(GENERIC_UNLOCK_MESSAGE) from exc
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise errors.InternalError(
            "authenticated vault payload is not valid JSON; this is a bug, not corruption"
        ) from exc
    return header, key, payload
