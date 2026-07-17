"""
generator.py — Cryptographically secure password generation.

Uses `secrets` (CSPRNG) exclusively — never `random`. Guarantees at least
one character from each selected class by construction, then shuffles with
secrets-driven Fisher-Yates so the guaranteed characters are not in
predictable positions.
"""

from __future__ import annotations

import math
import secrets
import string

MIN_LENGTH = 8
DEFAULT_LENGTH = 20

# Symbols chosen to avoid characters that commonly break shells/sites.
SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?/"


def generate(length: int = DEFAULT_LENGTH, *, lower: bool = True,
             upper: bool = True, digits: bool = True,
             symbols: bool = True) -> str:
    if length < MIN_LENGTH:
        raise ValueError(f"Minimum length is {MIN_LENGTH}.")

    pools: list[str] = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        raise ValueError("At least one character class must be enabled.")
    if length < len(pools):
        raise ValueError("Length too short for the selected classes.")

    alphabet = "".join(pools)
    # One guaranteed char per class, remainder from the full alphabet.
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(pools))]

    # Secure Fisher-Yates shuffle.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def entropy_bits(length: int, *, lower=True, upper=True, digits=True,
                 symbols=True) -> float:
    n = (26 * lower) + (26 * upper) + (10 * digits) + (len(SYMBOLS) * symbols)
    return length * math.log2(n) if n else 0.0
