"""Cryptographic core for Keepsafe.

This is the ONLY module in Keepsafe permitted to touch cryptographic
primitives. Every other module -- vault I/O, session handling, CLI --
must call the functions defined here and must never import argon2 or
PyNaCl itself. Keeping every primitive call behind this seam is what
makes the format testable, auditable, and swappable in one place.

Honest limits, stated rather than pretended away: CPython offers no way
to guarantee that key material becomes unrecoverable from process
memory. ``zeroize()`` overwrites the buffer we control, but copies made
by the interpreter, the standard library, or the OS (swap, core dumps,
idle memory reuse) are outside our reach. We ship anyway, and we say so,
because a vault that claims perfect forward secrecy of RAM would be lying.

Construction (see FORMAT.md for the on-disk layout):

- Key derivation: Argon2id via argon2-cffi's low-level raw-hash API,
  32-byte output, parameters stored in the vault header.
- Encryption: libsodium AEAD through PyNaCl's ``nacl.secret.Aead``
  (XChaCha20-Poly1305-IETF). The library generates and validates
  24-byte nonces and authenticates caller-supplied associated data;
  ciphertext is returned with the 16-byte Poly1305 tag appended.
- Randomness: exclusively the CSPRNG behind ``nacl.utils.random``.
"""

from __future__ import annotations

import hmac
import unicodedata

from argon2.exceptions import Argon2Error
from argon2.low_level import Type, hash_secret_raw
from nacl.exceptions import CryptoError as NaclCryptoError
from nacl.secret import Aead
from nacl.utils import random as _csprng

MAGIC = b"KPSF"
FORMAT_VERSION = 1
KDF_TYPE_ARGON2ID = 1

SALT_SIZE = 32
KEY_SIZE = 32
NONCE_SIZE = 24
TAG_SIZE = 16

DEFAULT_MEMORY_KIB = 65536  # 64 MiB
DEFAULT_ITERATIONS = 3
DEFAULT_PARALLELISM = 4

MIN_MEMORY_KIB = 65536  # policy floor for shipped defaults, not for tests
MIN_ITERATIONS = 3
MIN_PARALLELISM = 1

# Upper bounds applied to parameters read from an UNTRUSTED vault header,
# before authentication succeeds. A hostile or corrupt header must not be
# able to demand gigabytes of RAM or hours of CPU from every unlock
# attempt. Generous relative to any sane configuration (the defaults sit
# far below), but hard enough to turn a crafted header into a clean error.
MAX_MEMORY_KIB = 2_097_152  # 2 GiB
MAX_ITERATIONS = 32
MAX_PARALLELISM = 64

# Joint bound: individually legal parameters could still multiply out to an
# enormous total cost (max memory x max iterations). The product is capped
# as well; the shipped defaults (65536 x 3) sit far below it.
MAX_COMBINED_KIB_ITERATIONS = 4_194_304


class CryptoError(Exception):
    """Base class for every error raised by this module."""


class AuthenticationFailure(CryptoError):
    """Decryption failed: wrong key, tampered data, or wrong AAD.

    These causes are deliberately indistinguishable from here upward;
    authentication cannot tell them apart and neither should callers.
    """


class InvalidParameters(CryptoError):
    """A caller passed structurally invalid input to this module."""


def random_bytes(n: int) -> bytes:
    """Return *n* bytes from the operating system CSPRNG."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise InvalidParameters("byte count must be a non-negative int")
    return _csprng(n)


def generate_salt() -> bytes:
    """Return SALT_SIZE fresh random bytes for a new KDF salt."""
    return _csprng(SALT_SIZE)


def generate_nonce() -> bytes:
    """Return NONCE_SIZE fresh random bytes; one nonce per encryption."""
    return _csprng(NONCE_SIZE)


def get_default_kdf_params() -> dict:
    """Return the module's current default KDF parameters as a dict.

    Values are read from module attributes at CALL time, so patching
    e.g. ``crypto.DEFAULT_MEMORY_KIB`` (as tests/kdf_seam.py does) is
    reflected immediately. Production paths use these defaults only
    when creating a vault; afterwards the header values are authoritative.
    """
    return {
        "memory_kib": DEFAULT_MEMORY_KIB,
        "iterations": DEFAULT_ITERATIONS,
        "parallelism": DEFAULT_PARALLELISM,
    }


def _require_int(name: str, value: object, minimum: int, maximum: int) -> int:
    # bool is an int subclass; treating True as iterations=1 would hide a
    # bug, so it is rejected explicitly.
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidParameters(f"{name} must be an int")
    if value < minimum or value > maximum:
        raise InvalidParameters(
            f"{name} must be between {minimum} and {maximum}"
        )
    return value


def _require_exact_length(name: str, value: object, size: int) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
    else:
        raise InvalidParameters(f"{name} must be bytes-like")
    if len(data) != size:
        raise InvalidParameters(f"{name} must be exactly {size} bytes")
    return data


def derive_key(
    passphrase: str | bytes,
    salt: bytes,
    memory_kib: int,
    iterations: int,
    parallelism: int,
) -> bytes:
    """Derive a KEY_SIZE-byte key from a passphrase using Argon2id.

    str passphrases are Unicode-normalized (NFKC) and then UTF-8 encoded
    before hashing, so the same logical passphrase entered under NFC or
    NFD input methods derives the same key. bytes passphrases are hashed
    exactly as given. salt must be exactly SALT_SIZE bytes;
    memory_kib/iterations/parallelism must be ints within the MIN_/MAX_
    bounds - these arrive from an untrusted file header on unlock, so
    absurd values are rejected before the KDF runs. An empty passphrase
    is rejected: it can only indicate an upstream prompt bug. Any failure
    of the underlying library is re-raised as InvalidParameters so
    callers handle exactly two error types: InvalidParameters for bad
    input, AuthenticationFailure for decryption.
    """
    if isinstance(passphrase, str):
        if passphrase == "":
            raise InvalidParameters("passphrase must not be empty")
        secret = unicodedata.normalize("NFKC", passphrase).encode("utf-8")
    elif isinstance(passphrase, (bytes, bytearray, memoryview)):
        secret = bytes(passphrase)
        if secret == b"":
            raise InvalidParameters("passphrase must not be empty")
    else:
        raise InvalidParameters("passphrase must be str or bytes")

    _require_exact_length("salt", salt, SALT_SIZE)
    _require_int("memory_kib", memory_kib, 1, MAX_MEMORY_KIB)
    _require_int("iterations", iterations, 1, MAX_ITERATIONS)
    _require_int("parallelism", parallelism, 1, MAX_PARALLELISM)
    if memory_kib * iterations > MAX_COMBINED_KIB_ITERATIONS:
        raise InvalidParameters(
            "memory x iterations exceeds the combined cost cap "
            f"({MAX_COMBINED_KIB_ITERATIONS})"
        )

    try:
        return hash_secret_raw(
            secret=secret,
            salt=salt,
            time_cost=iterations,
            memory_cost=memory_kib,
            parallelism=parallelism,
            hash_len=KEY_SIZE,
            type=Type.ID,
        )
    except Argon2Error as exc:
        raise InvalidParameters(f"key derivation rejected: {exc}") from exc


def seal(key: bytes, plaintext: bytes, aad: bytes) -> tuple:
    """Generate a fresh nonce and encrypt in one call.

    Returns ``(nonce, ciphertext_with_tag)``. This is the safe default
    path for callers that do not already hold a nonce: freshness is
    handled here and cannot be forgotten. The raw ``encrypt`` remains
    for the format layer, which stores the nonce at a fixed header
    offset rather than prefixing it.
    """
    nonce = generate_nonce()
    return nonce, encrypt(key, nonce, plaintext, aad)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt *plaintext* under *key*/*nonce*, binding *aad* into the tag.

    Returns ciphertext with the TAG_SIZE-byte authentication tag
    appended and NO nonce prefix; the caller stores/transmits the nonce
    separately. key must be exactly KEY_SIZE bytes, nonce exactly
    NONCE_SIZE bytes. The same plaintext encrypted twice under distinct
    nonces yields distinct output (probabilistic encryption).
    """
    key_data = _require_exact_length("key", key, KEY_SIZE)
    nonce_data = _require_exact_length("nonce", nonce, NONCE_SIZE)
    pt = _plaintext_to_bytes(plaintext)
    ad = _aad_to_bytes(aad)

    box = Aead(key_data)
    return bytes(box.encrypt(pt, aad=ad, nonce=nonce_data).ciphertext)


def decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes) -> bytes:
    """Decrypt and authenticate; return the exact original plaintext.

    Raises AuthenticationFailure on any authentication failure (bad tag,
    wrong key, wrong nonce, wrong AAD) and never returns partial
    plaintext. A buffer shorter than the tag alone is structural damage,
    not an authentication event, and raises InvalidParameters.
    """
    key_data = _require_exact_length("key", key, KEY_SIZE)
    nonce_data = _require_exact_length("nonce", nonce, NONCE_SIZE)
    ct = _ciphertext_to_bytes(ciphertext_with_tag)
    ad = _aad_to_bytes(aad)

    if len(ct) < TAG_SIZE:
        raise InvalidParameters(
            f"ciphertext shorter than the {TAG_SIZE}-byte tag"
        )

    box = Aead(key_data)
    try:
        return box.decrypt(ct, aad=ad, nonce=nonce_data)
    except NaclCryptoError as exc:
        raise AuthenticationFailure(
            "decryption failed: wrong passphrase/key, or damaged or "
            "tampered data"
        ) from exc


def constant_time_equals(a: bytes, b: bytes) -> bool:
    """Compare two byte strings without leaking where they differ."""
    return hmac.compare_digest(a, b)


def zeroize(buf: bytearray) -> None:
    """Overwrite *buf* with zeros, best effort.

    Honest caveat: CPython cannot guarantee key material is unrecoverable
    from memory. This clears the buffer object we hold; it cannot reach
    interpreter-internal copies, bytes created earlier from this buffer,
    swap, or core dumps. Call it anyway -- it shrinks the window -- but
    do not claim more than it delivers.
    """
    if not isinstance(buf, bytearray):
        raise InvalidParameters("zeroize requires a bytearray")
    buf[:] = bytes(len(buf))


def _plaintext_to_bytes(plaintext: object) -> bytes:
    if isinstance(plaintext, (bytes, bytearray, memoryview)):
        return bytes(plaintext)
    raise InvalidParameters("plaintext must be bytes-like")


def _ciphertext_to_bytes(ciphertext: object) -> bytes:
    if isinstance(ciphertext, (bytes, bytearray, memoryview)):
        return bytes(ciphertext)
    raise InvalidParameters("ciphertext must be bytes-like")


def _aad_to_bytes(aad: object) -> bytes:
    if isinstance(aad, (bytes, bytearray, memoryview)):
        return bytes(aad)
    raise InvalidParameters("aad must be bytes-like")
