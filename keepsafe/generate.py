"""Secret generation: passwords and diceware-style passphrases.

All randomness comes from ``secrets`` (SystemRandom) only. The module is
pure: no I/O, no terminal output, no clipboard. Errors raise
UsageError with what was wrong and the exact correct form, per DESIGN.md.
"""

from __future__ import annotations

import math
import secrets
import string

from keepsafe.errors import UsageError
from keepsafe.wordlists.eff_short import WORDS

CHAR_CLASSES = {
    "upper": string.ascii_uppercase,
    "lower": string.ascii_lowercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{};:,.<>?/~",
}
SIMILAR_CHARS = "Il1O0|`'\""
MIN_PASSWORD_LENGTH = 4
MAX_PASSWORD_LENGTH = 256
MIN_WORDS = 3
MAX_WORDS = 40
PASSPHRASE_POOL_SIZE = len(WORDS)

_RNG = secrets.SystemRandom()


def gen_password(
    length: int = 20,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = False,
    exclude_similar: bool = False,
) -> str:
    """Generate a password with at least one character per selected class.

    Look-alike characters (SIMILAR_CHARS) are removed from every pool
    before any draw when exclude_similar is set. The remaining budget is
    filled from the union of the filtered pools and the result shuffled.
    """
    _validate_length(length)
    selected = [
        key
        for key, enabled in (
            ("upper", upper),
            ("lower", lower),
            ("digits", digits),
            ("symbols", symbols),
        )
        if enabled
    ]
    if not selected:
        raise UsageError(
            "no character class selected; enable at least one of "
            "upper, lower, digits, symbols (e.g. --upper --lower --digits)"
        )
    pools = {
        key: _filtered(CHAR_CLASSES[key], exclude_similar) for key in selected
    }
    empty = [key for key in selected if not pools[key]]
    if empty:
        raise UsageError(
            f"character class(es) {', '.join(empty)} have no characters left "
            "after removing look-alikes; disable look-alike exclusion or "
            "drop that class"
        )
    union = sorted(set().union(*(set(pools[key]) for key in selected)))
    if len(union) < len(selected) or length < len(selected):
        raise UsageError(
            "character pool is smaller than the number of selected classes; "
            "select fewer classes or a longer length"
        )
    chars = [_RNG.choice(pools[key]) for key in selected]
    chars.extend(_RNG.choice(union) for _ in range(length - len(chars)))
    _RNG.shuffle(chars)
    return "".join(chars)


def gen_passphrase(words: int = 6, sep: str = "-", capitalize: bool = False) -> str:
    """Generate a passphrase from the EFF short wordlist (1296 words).

    Words are drawn independently with repetition allowed. capitalize
    applies per word after the joining logic picks its tokens.
    """
    if (
        not isinstance(words, int)
        or isinstance(words, bool)
        or not MIN_WORDS <= words <= MAX_WORDS
    ):
        raise UsageError(
            f"passphrase word count must be between {MIN_WORDS} and "
            f"{MAX_WORDS}, got {words!r} (e.g. --words 6)"
        )
    if not isinstance(sep, str) or not 1 <= len(sep) <= 3 or not sep.isprintable():
        raise UsageError(
            f"separator must be 1 to 3 printable characters, got {sep!r} "
            "(e.g. --sep '-')"
        )
    chosen = [secrets.choice(WORDS) for _ in range(words)]
    if capitalize:
        chosen = [word.capitalize() for word in chosen]
    return sep.join(chosen)


def entropy_bits_password(length: int, pool_size: int) -> float:
    """Honest Shannon entropy estimate: length * log2(pool_size)."""
    return length * math.log2(pool_size)


def entropy_bits_passphrase(words: int) -> float:
    """Entropy estimate for words drawn uniformly from the 1296-word list."""
    return words * math.log2(PASSPHRASE_POOL_SIZE)


def describe_strength(bits: float) -> str:
    """Word-only strength label; callers add the estimate disclaimer."""
    if bits < 18:
        return "very weak"
    if bits < 28:
        return "weak"
    if bits < 50:
        return "moderate"
    if bits < 80:
        return "strong"
    return "very strong"


def _validate_length(length: object) -> None:
    if not isinstance(length, int) or isinstance(length, bool):
        raise UsageError(
            f"password length must be a whole number between "
            f"{MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}, got {length!r} "
            "(e.g. --length 20)"
        )
    if not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
        raise UsageError(
            f"password length must be between {MIN_PASSWORD_LENGTH} and "
            f"{MAX_PASSWORD_LENGTH}, got {length} (e.g. --length 20)"
        )


def _filtered(pool: str, exclude_similar: bool) -> list[str]:
    if not exclude_similar:
        return list(pool)
    return [char for char in pool if char not in SIMILAR_CHARS]


def pool_size(upper: bool = True, lower: bool = True, digits: bool = True,
              symbols: bool = False, exclude_similar: bool = False) -> int:
    """Size of the union pool gen_password draws from (for entropy math).

    Mirrors CHAR_CLASSES/SIMILAR_CHARS filtering without generating
    anything. Raises the same UsageError as gen_password when no class
    is selected.
    """
    from . import errors

    selected = []
    if upper:
        selected.append(CHAR_CLASSES["upper"])
    if lower:
        selected.append(CHAR_CLASSES["lower"])
    if digits:
        selected.append(CHAR_CLASSES["digits"])
    if symbols:
        selected.append(CHAR_CLASSES["symbols"])
    if not selected:
        raise errors.UsageError("select at least one character class")
    union: set[str] = set()
    for pool in selected:
        for ch in pool:
            if exclude_similar and ch in SIMILAR_CHARS:
                continue
            union.add(ch)
    return len(union)
