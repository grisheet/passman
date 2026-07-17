"""
crypto.py — Key derivation and authenticated encryption.

Design (secure defaults only):
  * Cipher:  AES-256-GCM (AEAD — confidentiality + integrity in one primitive)
  * KDF:     Argon2id if `argon2-cffi` is installed, else PBKDF2-HMAC-SHA256
             with 600,000 iterations (OWASP 2023+ recommendation).
  * Salt:    16 random bytes, generated once per vault (stored in header).
  * Nonce:   12 random bytes, freshly generated on EVERY encryption/save.
  * AAD:     The vault header (version + KDF params) is bound to the
             ciphertext as GCM "associated data", so an attacker cannot
             silently downgrade the KDF parameters in the file header.

No mode weaker than GCM is offered. There are no configuration knobs that
allow weak crypto.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- constants (fixed, not user-tunable downward) --------------------------

KEY_LEN = 32            # 256-bit key  -> AES-256
SALT_LEN = 16           # 128-bit salt
NONCE_LEN = 12          # 96-bit nonce (GCM recommended size)
PBKDF2_ITERATIONS = 600_000

# Argon2id parameters (used only if argon2-cffi is available)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024   # 64 MiB
ARGON2_PARALLELISM = 4

try:
    from argon2.low_level import Type as _Argon2Type, hash_secret_raw as _argon2_raw
    _HAS_ARGON2 = True
except ImportError:  # pragma: no cover
    _HAS_ARGON2 = False


class WrongPasswordOrCorrupt(Exception):
    """Raised when decryption fails: wrong master password OR tampered file."""


@dataclass(frozen=True)
class KdfParams:
    name: str
    salt: bytes
    iterations: int = 0          # PBKDF2 only
    time_cost: int = 0           # Argon2 only
    memory_kib: int = 0
    parallelism: int = 0

    @staticmethod
    def new() -> "KdfParams":
        salt = os.urandom(SALT_LEN)
        if _HAS_ARGON2:
            return KdfParams(
                name="argon2id",
                salt=salt,
                time_cost=ARGON2_TIME_COST,
                memory_kib=ARGON2_MEMORY_KIB,
                parallelism=ARGON2_PARALLELISM,
            )
        return KdfParams(name="pbkdf2-sha256", salt=salt,
                         iterations=PBKDF2_ITERATIONS)


def derive_key(master_password: bytes, params: KdfParams) -> bytearray:
    """
    Derive a 256-bit key. Returns a mutable `bytearray` so the caller can
    zero it (`wipe`) when done. `master_password` should also be a
    bytearray the caller wipes afterwards.
    """
    pw = bytes(master_password)  # KDF APIs require immutable bytes
    try:
        if params.name == "argon2id":
            if not _HAS_ARGON2:
                raise RuntimeError(
                    "Vault was created with Argon2id but argon2-cffi is not "
                    "installed. Run: pip install argon2-cffi"
                )
            raw = _argon2_raw(
                secret=pw,
                salt=params.salt,
                time_cost=params.time_cost,
                memory_cost=params.memory_kib,
                parallelism=params.parallelism,
                hash_len=KEY_LEN,
                type=_Argon2Type.ID,
            )
        elif params.name == "pbkdf2-sha256":
            if params.iterations < PBKDF2_ITERATIONS:
                # Refuse downgraded parameters even if the file header says so.
                raise WrongPasswordOrCorrupt(
                    "Refusing weak KDF parameters in vault header."
                )
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=KEY_LEN,
                salt=params.salt,
                iterations=params.iterations,
            )
            raw = kdf.derive(pw)
        else:
            raise WrongPasswordOrCorrupt(f"Unknown KDF: {params.name!r}")
        return bytearray(raw)
    finally:
        del pw  # drop our extra immutable copy reference promptly


def encrypt(key: bytearray, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Return (nonce, ciphertext_with_tag). Fresh random nonce every call."""
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)
    return nonce, ct


def decrypt(key: bytearray, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise WrongPasswordOrCorrupt(
            "Decryption failed: wrong master password, or the vault file "
            "has been modified/corrupted."
        ) from exc


def wipe(buf: bytearray | None) -> None:
    """Best-effort zeroization of a mutable buffer (see threat model notes)."""
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0
