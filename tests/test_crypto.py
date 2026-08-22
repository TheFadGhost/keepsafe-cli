"""Tests for keepsafe.crypto -- the only module allowed near primitives.

Runtime discipline: exactly ONE test derives with the real shipped
defaults (test_default_parameters_derive_end_to_end). Everything else
passes tiny explicit parameters. The shipped-default policy is asserted
against constants only in test_shipped_defaults_meet_policy, which is
never monkeypatched and must never be weakened.
"""

from __future__ import annotations

import pytest

import keepsafe.crypto as crypto

FAST = {"memory_kib": 1024, "iterations": 1, "parallelism": 1}
PASSPHRASE = "correct horse battery staple"
PLAINTEXT = b"attack at dawn"
AAD = b"KPSFHDR1"


def fast_key(passphrase: str = PASSPHRASE) -> bytes:
    return crypto.derive_key(
        passphrase, crypto.generate_salt(), memory_kib=1024,
        iterations=1, parallelism=1,
    )


@pytest.fixture(scope="module")
def key() -> bytes:
    return fast_key()


@pytest.fixture(scope="module")
def nonce() -> bytes:
    return crypto.generate_nonce()


@pytest.fixture(scope="module")
def sealed(key: bytes, nonce: bytes):
    """One valid encryption reused by the tamper-hunting tests."""
    ciphertext = crypto.encrypt(key, nonce, PLAINTEXT, AAD)
    return {"key": key, "nonce": nonce, "aad": AAD, "ciphertext": ciphertext}


# ---------------------------------------------------------------------------
# 1. Round-trips
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00",
        b"a",
        PLAINTEXT,
        "pässwörd-日本語-🔑".encode("utf-8"),
        bytes(range(256)) * 4,
        crypto.random_bytes(4096),
    ],
    ids=[
        "empty", "one-zero-byte", "one-byte", "sentence",
        "utf8-multibyte", "all-byte-values-x4", "4k-random",
    ],
)
def test_roundtrip_preserves_bytes_exactly(payload):
    k, n = fast_key(), crypto.generate_nonce()
    ciphertext = crypto.encrypt(k, n, payload, AAD)
    assert len(ciphertext) == len(payload) + crypto.TAG_SIZE
    assert crypto.decrypt(k, n, ciphertext, AAD) == payload


def test_roundtrip_with_bytearray_and_memoryview_inputs(key, nonce):
    ciphertext = crypto.encrypt(
        bytearray(key), bytearray(nonce), bytearray(PLAINTEXT), bytearray(AAD)
    )
    assert crypto.decrypt(
        memoryview(key), memoryview(nonce), ciphertext, AAD
    ) == PLAINTEXT


# ---------------------------------------------------------------------------
# 2. Wrong key
# ---------------------------------------------------------------------------

def test_wrong_key_raises_authentication_failure_and_returns_nothing(sealed):
    intruder = fast_key("a completely different passphrase")

    returned = "<sentinel: decrypt must not return>"
    with pytest.raises(crypto.AuthenticationFailure):
        returned = crypto.decrypt(
            intruder, sealed["nonce"], sealed["ciphertext"], sealed["aad"]
        )
    assert returned == "<sentinel: decrypt must not return>"


# ---------------------------------------------------------------------------
# 3/4. Tampering: every single byte of ciphertext+tag, of the AAD, plus wrong AAD
# ---------------------------------------------------------------------------

def test_wrong_aad_fails(sealed):
    with pytest.raises(crypto.AuthenticationFailure):
        crypto.decrypt(
            sealed["key"], sealed["nonce"], sealed["ciphertext"], b"KPSFHDR2"
        )
    with pytest.raises(crypto.AuthenticationFailure):
        crypto.decrypt(sealed["key"], sealed["nonce"], sealed["ciphertext"], b"")


def test_tamper_every_ciphertext_byte_fails(sealed):
    ct = sealed["ciphertext"]
    assert len(ct) == len(PLAINTEXT) + crypto.TAG_SIZE  # tag included below

    failures = []
    for position in range(len(ct)):
        corrupted = bytearray(ct)
        corrupted[position] ^= 0x01  # flip lowest bit of one byte
        try:
            crypto.decrypt(
                sealed["key"], sealed["nonce"], bytes(corrupted), sealed["aad"]
            )
        except crypto.AuthenticationFailure:
            continue
        except crypto.InvalidParameters as exc:
            failures.append((position, f"InvalidParameters: {exc}"))
            continue
        failures.append((position, "tampered ciphertext decrypted cleanly"))
    assert failures == [], f"undetected tampering at positions: {failures}"


def test_tamper_high_bit_of_each_tag_byte_fails(sealed):
    ct = sealed["ciphertext"]
    tag_start = len(ct) - crypto.TAG_SIZE
    for offset in range(crypto.TAG_SIZE):
        corrupted = bytearray(ct)
        corrupted[tag_start + offset] ^= 0x80
        with pytest.raises(crypto.AuthenticationFailure):
            crypto.decrypt(
                sealed["key"], sealed["nonce"], bytes(corrupted), sealed["aad"]
            )


def test_tamper_every_aad_byte_fails(sealed):
    aad = sealed["aad"]
    failures = []
    for position in range(len(aad)):
        corrupted = bytearray(aad)
        corrupted[position] ^= 0x01
        try:
            crypto.decrypt(
                sealed["key"], sealed["nonce"], sealed["ciphertext"], bytes(corrupted)
            )
        except crypto.AuthenticationFailure:
            continue
        failures.append((position, "tampered AAD accepted"))
    assert failures == [], f"undetected AAD tampering at positions: {failures}"


def test_swapped_ciphertext_buffers_fail(sealed, key, nonce):
    other = crypto.encrypt(key, nonce, b"different message entirely", AAD)
    with pytest.raises(crypto.AuthenticationFailure):
        # right sizes everywhere, but tag from one payload against another
        crypto.decrypt(
            key, nonce,
            sealed["ciphertext"][:-crypto.TAG_SIZE] + other[-crypto.TAG_SIZE:],
            AAD,
        )


# ---------------------------------------------------------------------------
# 5. Nonce uniqueness / probabilistic encryption
# ---------------------------------------------------------------------------

def test_nonces_unique_across_500_encryptions():
    k = fast_key()
    nonces = []
    ciphertexts = []
    for _ in range(500):
        n = crypto.generate_nonce()
        nonces.append(n)
        ciphertexts.append(crypto.encrypt(k, n, PLAINTEXT, AAD))
    assert len(set(nonces)) == len(nonces), "nonce collision within 500 draws"
    assert len(ciphertexts) == 500
    assert all(len(n) == crypto.NONCE_SIZE for n in nonces)


def test_identical_plaintext_distinct_nonces_gives_distinct_ciphertexts():
    k = fast_key()
    seen = set()
    for i in range(50):
        n = crypto.generate_nonce()
        ct = crypto.encrypt(k, n, PLAINTEXT, AAD)
        assert ct not in seen, f"ciphertext repeated at iteration {i}"
        seen.add(ct)


# ---------------------------------------------------------------------------
# 6. KDF parameters are honoured
# ---------------------------------------------------------------------------

def test_different_kdf_parameters_yield_distinct_keys():
    salt = crypto.generate_salt()

    def derive(memory_kib, iterations, parallelism):
        return crypto.derive_key(PASSPHRASE, salt, memory_kib, iterations, parallelism)

    variants = {
        "baseline": derive(1024, 1, 1),
        "more-memory": derive(2048, 1, 1),
        "more-iters": derive(1024, 2, 1),
        "more-lanes": derive(1024, 1, 2),
    }
    distinct = {bytes(v) for v in variants.values()}
    assert len(distinct) == 4, f"expected 4 distinct keys, got {len(distinct)}"
    baseline = variants["baseline"]
    for name, variant in variants.items():
        if name != "baseline":
            assert variant != baseline, f"{name} did not change the key"


def test_same_parameters_deterministic():
    salt = crypto.generate_salt()
    first = crypto.derive_key(PASSPHRASE, salt, **FAST)
    second = crypto.derive_key(PASSPHRASE, salt, **FAST)
    assert first == second
    third = crypto.derive_key("other passphrase", salt, **FAST)
    assert third != first


def test_different_salt_or_passphrase_changes_key():
    salt = crypto.generate_salt()
    base = crypto.derive_key(PASSPHRASE, salt, **FAST)
    assert crypto.derive_key(PASSPHRASE, crypto.generate_salt(), **FAST) != base
    assert crypto.derive_key(PASSPHRASE.upper(), salt, **FAST) != base


# ---------------------------------------------------------------------------
# 7. Shipped defaults meet policy (REAL constants; never patched here)
# ---------------------------------------------------------------------------

def test_shipped_defaults_meet_policy():
    # Literals are pinned so a simultaneous lowering of default and floor
    # cannot pass silently; the >= forms guard the relationship as well.
    assert crypto.DEFAULT_MEMORY_KIB == 65536
    assert crypto.DEFAULT_ITERATIONS == 3
    assert crypto.DEFAULT_PARALLELISM == 4
    assert crypto.MIN_MEMORY_KIB == 65536
    assert crypto.MIN_ITERATIONS == 3
    assert crypto.DEFAULT_MEMORY_KIB >= crypto.MIN_MEMORY_KIB
    assert crypto.DEFAULT_ITERATIONS >= crypto.MIN_ITERATIONS
    assert crypto.DEFAULT_PARALLELISM >= crypto.MIN_PARALLELISM
    assert crypto.SALT_SIZE >= 16
    assert crypto.KEY_SIZE == 32
    assert crypto.NONCE_SIZE == 24
    assert crypto.TAG_SIZE == 16
    assert crypto.MAGIC == b"KPSF"
    assert crypto.FORMAT_VERSION == 1
    assert crypto.KDF_TYPE_ARGON2ID == 1
    assert issubclass(crypto.AuthenticationFailure, crypto.CryptoError)
    assert issubclass(crypto.InvalidParameters, crypto.CryptoError)


def test_default_parameters_derive_end_to_end():
    """The single full-cost derivation in this suite (~64 MiB x3)."""
    params = crypto.get_default_kdf_params()
    assert params == {
        "memory_kib": crypto.DEFAULT_MEMORY_KIB,
        "iterations": crypto.DEFAULT_ITERATIONS,
        "parallelism": crypto.DEFAULT_PARALLELISM,
    }
    salt = crypto.generate_salt()
    k = crypto.derive_key(PASSPHRASE, salt, **params)
    assert len(k) == crypto.KEY_SIZE
    n = crypto.generate_nonce()
    ct = crypto.encrypt(k, n, PLAINTEXT, AAD)
    assert crypto.decrypt(k, n, ct, AAD) == PLAINTEXT


# ---------------------------------------------------------------------------
# 8. derive_key validation
# ---------------------------------------------------------------------------

GOOD_SALT = crypto.SALT_SIZE * b"\xa5"


def _derive(**overrides):
    kwargs = {
        "passphrase": PASSPHRASE,
        "salt": GOOD_SALT,
        "memory_kib": 1024,
        "iterations": 1,
        "parallelism": 1,
    }
    kwargs.update(overrides)
    return crypto.derive_key(**kwargs)


@pytest.mark.parametrize(
    "overrides",
    [
        {"salt": b""},
        {"salt": b"\x01" * 15},
        {"salt": b"\x01" * 16},
        {"salt": b"\x01" * 31},
        {"salt": b"\x01" * 33},
        {"salt": "not-bytes"},
        {"salt": None},
        {"iterations": 0},
        {"iterations": -1},
        {"iterations": -100000},
        {"iterations": "3"},
        {"iterations": 1.0},
        {"iterations": None},
        {"memory_kib": 0},
        {"memory_kib": -65536},
        {"memory_kib": "65536"},
        {"memory_kib": 1024.5},
        {"memory_kib": None},
        {"parallelism": 0},
        {"parallelism": -1},
        {"parallelism": "4"},
        {"parallelism": 2.0},
        {"passphrase": None},
        {"passphrase": 123456789},
        {"passphrase": ["list", "of", "words"]},
    ],
)
def test_derive_key_rejects_invalid_parameters(overrides):
    with pytest.raises(crypto.InvalidParameters):
        _derive(**overrides)


# ---------------------------------------------------------------------------
# 9. Re-key semantics at the crypto level
# ---------------------------------------------------------------------------

def test_rekey_new_salt_new_passphrase_yields_new_key():
    old_key = crypto.derive_key(
        "old passphrase", crypto.generate_salt(), **FAST
    )
    new_key = crypto.derive_key(
        "new passphrase", crypto.generate_salt(), **FAST
    )
    assert old_key != new_key

    new_nonce = crypto.generate_nonce()
    reencrypted = crypto.encrypt(new_key, new_nonce, PLAINTEXT, AAD)

    returned = "<sentinel>"
    with pytest.raises(crypto.AuthenticationFailure):
        returned = crypto.decrypt(old_key, new_nonce, reencrypted, AAD)
    assert returned == "<sentinel>"

    # sanity: the new key still opens it
    assert crypto.decrypt(new_key, new_nonce, reencrypted, AAD) == PLAINTEXT


# ---------------------------------------------------------------------------
# 10/11. Helpers
# ---------------------------------------------------------------------------

def test_zeroize_clears_buffer_entirely():
    buf = bytearray(b"hunter2 hunter2 hunter2")
    crypto.zeroize(buf)
    assert buf == bytearray(len(buf))


def test_zeroize_on_empty_buffer_is_noop():
    buf = bytearray()
    crypto.zeroize(buf)
    assert buf == bytearray()


def test_zeroize_rejects_immutable_input():
    with pytest.raises(crypto.InvalidParameters):
        crypto.zeroize(b"immutable")


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (b"", b"", True),
        (b"x", b"x", True),
        (b"\x00\xff\x10", b"\x00\xff\x10", True),
        (b"abc", b"abd", False),
        (b"abc", b"xbc", False),
        (b"abc", b"ab", False),
        (b"ab", b"abc", False),
        (b"", b"a", False),
        (b"A" * 64, b"A" * 63 + b"B", False),
    ],
)
def test_constant_time_equals(a, b, expected):
    assert crypto.constant_time_equals(a, b) is expected


# ---------------------------------------------------------------------------
# 12. get_default_kdf_params reads module attributes AT CALL TIME
# ---------------------------------------------------------------------------

def test_get_default_kdf_params_matches_module_attrs_now():
    params = crypto.get_default_kdf_params()
    assert params == {
        "memory_kib": crypto.DEFAULT_MEMORY_KIB,
        "iterations": crypto.DEFAULT_ITERATIONS,
        "parallelism": crypto.DEFAULT_PARALLELISM,
    }


def test_get_default_kdf_params_reflects_patched_attr(monkeypatch):
    original = crypto.DEFAULT_MEMORY_KIB
    monkeypatch.setattr(crypto, "DEFAULT_MEMORY_KIB", 123456)
    params = crypto.get_default_kdf_params()
    assert params["memory_kib"] == 123456
    assert params["iterations"] == crypto.DEFAULT_ITERATIONS
    assert params["parallelism"] == crypto.DEFAULT_PARALLELISM
    assert crypto.DEFAULT_MEMORY_KIB == 123456 != original


def test_kdf_seam_fixture_pattern_works(monkeypatch):
    """The exact patching pattern tests/kdf_seam.py relies on."""
    monkeypatch.setattr(crypto, "DEFAULT_MEMORY_KIB", 1024)
    monkeypatch.setattr(crypto, "DEFAULT_ITERATIONS", 1)
    monkeypatch.setattr(crypto, "DEFAULT_PARALLELISM", 1)
    assert crypto.get_default_kdf_params() == {
        "memory_kib": 1024,
        "iterations": 1,
        "parallelism": 1,
    }


# ---------------------------------------------------------------------------
# Extra: size/type validation on encrypt/decrypt, CSPRNG sanity
# ---------------------------------------------------------------------------

def test_encrypt_rejects_wrong_key_and_nonce_sizes():
    good_key, good_nonce = fast_key(), crypto.generate_nonce()
    with pytest.raises(crypto.InvalidParameters):
        crypto.encrypt(good_key[:-1], good_nonce, PLAINTEXT, AAD)
    with pytest.raises(crypto.InvalidParameters):
        crypto.encrypt(good_key + b"x", good_nonce, PLAINTEXT, AAD)
    with pytest.raises(crypto.InvalidParameters):
        crypto.encrypt(good_key, good_nonce[:-1], PLAINTEXT, AAD)
    with pytest.raises(crypto.InvalidParameters):
        crypto.encrypt(good_key, good_nonce + b"x", PLAINTEXT, AAD)
    with pytest.raises(crypto.InvalidParameters):
        crypto.encrypt(good_key, "not-bytes", PLAINTEXT, AAD)
    with pytest.raises(crypto.InvalidParameters):
        crypto.encrypt(good_key, good_nonce, "str-not-bytes", AAD)


def test_decrypt_rejects_shorter_than_tag_and_bad_sizes(sealed):
    ct = sealed["ciphertext"]
    for short_len in range(crypto.TAG_SIZE):
        with pytest.raises(crypto.InvalidParameters):
            crypto.decrypt(sealed["key"], sealed["nonce"], ct[:short_len], AAD)
    assert len(ct) >= crypto.TAG_SIZE
    with pytest.raises(crypto.InvalidParameters):
        crypto.decrypt(sealed["key"], sealed["nonce"], b"", AAD)
    with pytest.raises(crypto.InvalidParameters):
        crypto.decrypt(sealed["key"], sealed["nonce"], "not-bytes", AAD)


def test_random_bytes_length_and_novelty():
    first = crypto.random_bytes(32)
    second = crypto.random_bytes(32)
    assert len(first) == 32 and len(second) == 32
    assert first != second
    assert crypto.random_bytes(0) == b""
    with pytest.raises(crypto.InvalidParameters):
        crypto.random_bytes(-1)
    with pytest.raises(crypto.InvalidParameters):
        crypto.random_bytes(1.0)


def test_generate_salt_and_nonce_sizes():
    assert len(crypto.generate_salt()) == crypto.SALT_SIZE
    assert len(crypto.generate_nonce()) == crypto.NONCE_SIZE
    salts = {crypto.generate_salt() for _ in range(20)}
    nonces = {crypto.generate_nonce() for _ in range(20)}
    assert len(salts) == 20
    assert len(nonces) == 20


# ---------------------------------------------------------------------------
# 8. Review hardening: untrusted-header bounds, normalization, seal()
# ---------------------------------------------------------------------------

def test_kdf_parameters_above_hard_maximum_rejected():
    salt = crypto.generate_salt()
    with pytest.raises(crypto.InvalidParameters):
        crypto.derive_key(PASSPHRASE, salt, memory_kib=crypto.MAX_MEMORY_KIB + 1,
                          iterations=1, parallelism=1)
    with pytest.raises(crypto.InvalidParameters):
        crypto.derive_key(PASSPHRASE, salt, memory_kib=1024,
                          iterations=crypto.MAX_ITERATIONS + 1, parallelism=1)
    with pytest.raises(crypto.InvalidParameters):
        crypto.derive_key(PASSPHRASE, salt, memory_kib=1024,
                          iterations=1, parallelism=crypto.MAX_PARALLELISM + 1)
    # Boundary values inside the caps are accepted (tiny derivation).
    crypto.derive_key(PASSPHRASE, salt, memory_kib=1024,
                      iterations=crypto.MAX_ITERATIONS - 1, parallelism=1)


def test_passphrase_unicode_normalization_nfc_equals_nfd():
    salt = crypto.generate_salt()
    nfc = "cafe\u0301"          # decomposed: e + combining acute
    nfd = "\u00e9"              # precomposed: e-acute is NFC; swap roles
    # Build a string that genuinely differs between NFC and NFD:
    decomposed = "e\u0301"      # NFD form of e-acute
    precomposed = "\u00e9"      # NFC form
    assert decomposed != precomposed
    k1 = crypto.derive_key(decomposed, salt, **FAST)
    k2 = crypto.derive_key(precomposed, salt, **FAST)
    assert k1 == k2, "NFC and NFD spellings must derive the same key"
    # And the unrelated strings still differ:
    assert crypto.derive_key(nfc, salt, **FAST) != crypto.derive_key(nfd, salt, **FAST)


def test_empty_passphrase_rejected():
    salt = crypto.generate_salt()
    with pytest.raises(crypto.InvalidParameters):
        crypto.derive_key("", salt, **FAST)
    with pytest.raises(crypto.InvalidParameters):
        crypto.derive_key(b"", salt, **FAST)


def test_seal_generates_fresh_nonce_and_round_trips():
    k = fast_key()
    seen_nonces = set()
    for _ in range(20):
        n, ct = crypto.seal(k, PLAINTEXT, AAD)
        assert len(n) == crypto.NONCE_SIZE
        assert n not in seen_nonces, "seal reused a nonce"
        seen_nonces.add(n)
        assert crypto.decrypt(k, n, ct, AAD) == PLAINTEXT


def test_decrypt_rejects_wrong_nonce_size():
    k = fast_key()
    n, ct = crypto.seal(k, PLAINTEXT, AAD)
    with pytest.raises(crypto.InvalidParameters):
        crypto.decrypt(k, n[:-1], ct, AAD)
    with pytest.raises(crypto.InvalidParameters):
        crypto.decrypt(k, n + b"\x00", ct, AAD)
