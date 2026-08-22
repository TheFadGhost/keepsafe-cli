# Shared test seam for fast key derivation.
#
# PRODUCTION CODE NEVER SETS THESE. This module exists so the test suite can
# run hundreds of unlock operations without paying full Argon2id cost each
# time. The shipped production defaults are asserted separately in
# test_crypto.py::test_shipped_defaults_meet_policy and are never patched by
# that test.
#
# Usage in a test:
#     from tests.kdf_seam import use_fast_kdf
#     def test_something(use_fast_kdf):
#         ...  # vault creation inside this test derives keys in microseconds

import pytest


@pytest.fixture
def use_fast_kdf(monkeypatch):
    """TEST-ONLY: shrink KDF defaults for vault creation in this test."""
    import keepsafe.crypto as crypto

    monkeypatch.setattr(crypto, "DEFAULT_MEMORY_KIB", 1024)
    monkeypatch.setattr(crypto, "DEFAULT_ITERATIONS", 1)
    monkeypatch.setattr(crypto, "DEFAULT_PARALLELISM", 1)
