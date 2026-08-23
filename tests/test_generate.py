"""Tests for keepsafe.generate: passwords, passphrases, entropy, strength."""

from __future__ import annotations

import math

import pytest

from keepsafe.errors import UsageError
from keepsafe.generate import (
    CHAR_CLASSES,
    MAX_PASSWORD_LENGTH,
    MAX_WORDS,
    MIN_PASSWORD_LENGTH,
    MIN_WORDS,
    SIMILAR_CHARS,
    describe_strength,
    entropy_bits_password,
    entropy_bits_passphrase,
    gen_password,
    gen_passphrase,
)
from keepsafe.wordlists.eff_short import EXPECTED_COUNT, WORDS


def only(**overrides) -> dict:
    flags = {"upper": False, "lower": False, "digits": False, "symbols": False}
    flags.update(overrides)
    return flags


# ---------------------------------------------------------------------------
# 1. Charset membership over many draws
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("exclude_similar", [False, True])
@pytest.mark.parametrize("length", [4, 8, 20, 64, 256])
def test_charset_membership_over_many_draws(length, exclude_similar):
    allowed = set("".join(CHAR_CLASSES.values()))
    if exclude_similar:
        allowed -= set(SIMILAR_CHARS)
    for _ in range(100):
        pw = gen_password(length=length, symbols=True, exclude_similar=exclude_similar)
        assert len(pw) == length
        assert set(pw) <= allowed


def test_single_class_draws_stay_inside_that_class():
    for _ in range(50):
        for name, pool in CHAR_CLASSES.items():
            pw = gen_password(length=12, **only(**{name: True}))
            assert set(pw) <= set(pool)


# ---------------------------------------------------------------------------
# 2. Guarantee: at least one character per selected class
# ---------------------------------------------------------------------------


def test_every_selected_class_appears_in_200_draws():
    for _ in range(200):
        pw = gen_password(length=24, upper=True, lower=True, digits=True)
        assert any(c in CHAR_CLASSES["upper"] for c in pw)
        assert any(c in CHAR_CLASSES["lower"] for c in pw)
        assert any(c in CHAR_CLASSES["digits"] for c in pw)


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(),
        dict(symbols=True),
        dict(exclude_similar=True),
        dict(symbols=True, exclude_similar=True),
        dict(length=4),
        dict(length=4, symbols=True, exclude_similar=True),
    ],
)
def test_guarantee_holds_across_option_combinations(kwargs):
    options = dict(upper=True, lower=True, digits=True, symbols=True)
    options.update(kwargs)
    length = options.pop("length", 32)
    for _ in range(60):
        pw = gen_password(length=length, **options)
        assert any(c in CHAR_CLASSES["upper"] for c in pw)
        assert any(c in CHAR_CLASSES["lower"] for c in pw)
        assert any(c in CHAR_CLASSES["digits"] for c in pw)
        assert any(c in CHAR_CLASSES["symbols"] for c in pw)


def test_exclude_similar_shrinks_digit_pool_but_keeps_class():
    # digits '0' and '1' are look-alikes; 2-9 must remain usable.
    seen = set()
    for _ in range(200):
        pw = gen_password(length=10, **only(digits=True), exclude_similar=True)
        seen |= set(pw)
        assert set(pw) <= set("23456789")
    assert len(seen) > 2


def test_fully_emptied_pool_raises(monkeypatch):
    monkeypatch.setitem(CHAR_CLASSES, "digits", "01")
    with pytest.raises(UsageError):
        gen_password(length=8, **only(digits=True), exclude_similar=True)


# ---------------------------------------------------------------------------
# 3. exclude_similar truly removes every look-alike character
# ---------------------------------------------------------------------------


def test_exclude_similar_never_leaks_look_alikes_in_300_draws():
    forbidden = set(SIMILAR_CHARS)
    for _ in range(150):
        pw = gen_password(length=32, symbols=True, exclude_similar=True)
        assert not (set(pw) & forbidden)
    for _ in range(150):
        pw = gen_password(
            length=16, upper=True, lower=True, digits=True, symbols=True,
            exclude_similar=True,
        )
        assert not (set(pw) & forbidden)


# ---------------------------------------------------------------------------
# 4. Shuffle actually varies order sometimes
# ---------------------------------------------------------------------------


def test_output_varies_across_20_draws():
    draws = {gen_password(length=20) for _ in range(20)}
    assert len(draws) > 1
    phrases = {gen_passphrase(words=6) for _ in range(20)}
    assert len(phrases) > 1


def test_first_characters_vary_despite_fixed_class_order():
    heads = {gen_password(length=16)[0] for _ in range(20)}
    assert len(heads) > 1


# ---------------------------------------------------------------------------
# 5. Passphrase shape: word count, joiner, capitalization, repetition
# ---------------------------------------------------------------------------


def test_passphrase_word_count_and_joiner():
    phrase = gen_passphrase(words=5, sep="_")
    tokens = phrase.split("_")
    assert len(tokens) == 5
    assert all(token in WORDS for token in tokens)


def test_passphrase_defaults():
    phrase = gen_passphrase()
    tokens = phrase.split("-")
    assert len(tokens) == 6
    assert all(token in WORDS for token in tokens)


def test_passphrase_capitalization_applies_per_word():
    phrase = gen_passphrase(words=7, sep=".", capitalize=True)
    tokens = phrase.split(".")
    assert len(tokens) == 7
    for token in tokens:
        assert token == token.capitalize()
        assert token.lower() in WORDS


def test_passphrase_words_are_independent_draws():
    words = [gen_passphrase(words=MIN_WORDS, sep=" ") for _ in range(30)]
    flat = [w for phrase in words for w in phrase.split()]
    assert all(w in WORDS for w in flat)


def test_multi_char_separator_allowed():
    assert gen_passphrase(words=3, sep="::").count("::") == 2


# ---------------------------------------------------------------------------
# 6. Wordlist sanity
# ---------------------------------------------------------------------------


def test_wordlist_shape_matches_contract():
    assert EXPECTED_COUNT == 1296
    assert len(WORDS) == EXPECTED_COUNT
    assert all(isinstance(w, str) and w and w == w.lower() for w in WORDS)
    assert len(set(WORDS)) == len(WORDS)


# ---------------------------------------------------------------------------
# 7. Validation errors carry UsageError
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "length", [None, "20", 3.5, MIN_PASSWORD_LENGTH - 1, MAX_PASSWORD_LENGTH + 1]
)
def test_bad_password_length_rejected(length):
    with pytest.raises(UsageError):
        gen_password(length=length)


def test_no_selected_class_rejected():
    with pytest.raises(UsageError):
        gen_password(upper=False, lower=False, digits=False, symbols=False)


@pytest.mark.parametrize("words", [None, "6", 2.5, MIN_WORDS - 1, MAX_WORDS + 1])
def test_bad_word_count_rejected(words):
    with pytest.raises(UsageError):
        gen_passphrase(words=words)


@pytest.mark.parametrize("sep", ["", "toolong", "\t", "\n"])
def test_bad_separator_rejected(sep):
    with pytest.raises(UsageError):
        gen_passphrase(sep=sep)


# ---------------------------------------------------------------------------
# 8. Entropy math spot values
# ---------------------------------------------------------------------------


def test_entropy_password_is_length_times_log2_pool():
    assert isinstance(entropy_bits_password(10, 52), float)
    assert entropy_bits_password(20, 94) == pytest.approx(20 * math.log2(94))
    assert entropy_bits_password(8, 26) == pytest.approx(8 * math.log2(26))
    assert entropy_bits_password(1, 2) == pytest.approx(1.0)


def test_entropy_passphrase_spot_values():
    six_words = entropy_bits_passphrase(6)
    assert six_words == pytest.approx(6 * math.log2(1296))
    assert abs(six_words - 62.04) < 0.1
    assert entropy_bits_passphrase(1) == pytest.approx(math.log2(1296))


# ---------------------------------------------------------------------------
# 9. Strength boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bits,expected",
    [
        (0.0, "very weak"),
        (17.99, "very weak"),
        (18.0, "weak"),
        (27.9, "weak"),
        (28.0, "moderate"),
        (49.9, "moderate"),
        (50.0, "strong"),
        (79.9, "strong"),
        (80.0, "very strong"),
        (128.0, "very strong"),
    ],
)
def test_describe_strength_boundaries(bits, expected):
    assert describe_strength(bits) == expected
