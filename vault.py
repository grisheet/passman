"""
vault.py — Encrypted vault file format + entry CRUD.

On-disk format (JSON, but the payload is opaque ciphertext):

  {
    "magic": "PASSMAN",
    "version": 1,
    "kdf": { "name": "...", "salt": "<b64>", ...params },
    "nonce": "<b64>",              # fresh per save
    "ciphertext": "<b64>"          # AES-256-GCM(entries JSON), tag appended
  }

Nothing sensitive is ever written in plaintext. The header (magic/version/
kdf) is authenticated as GCM associated data, so tampering with KDF params
or version is detected at decrypt time.

Writes are atomic (tempfile + os.replace) and the file is chmod 0600.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
import time
import uuid
from pathlib import Path

from . import crypto

MAGIC = "PASSMAN"
VERSION = 1


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _canonical_aad(header: dict) -> bytes:
    """Deterministic serialization of the header for use as GCM AAD."""
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


class VaultError(Exception):
    pass


class Vault:
    """
    Holds decrypted entries in memory only while the process runs.
    Entries: {id: {"site", "username", "password", "notes",
                   "created_at", "updated_at"}}
    """

    def __init__(self, path: Path, key: bytearray, kdf: crypto.KdfParams,
                 entries: dict[str, dict]):
        self.path = path
        self._key = key
        self._kdf = kdf
        self.entries = entries

    # ---------------- lifecycle ----------------

    @classmethod
    def create(cls, path: Path, master_password: bytearray) -> "Vault":
        if path.exists():
            raise VaultError(f"Refusing to overwrite existing vault: {path}")
        kdf = crypto.KdfParams.new()
        key = crypto.derive_key(master_password, kdf)
        vault = cls(path, key, kdf, entries={})
        vault.save()
        return vault

    @classmethod
    def open(cls, path: Path, master_password: bytearray) -> "Vault":
        if not path.exists():
            raise VaultError(f"No vault found at {path}. Run 'init' first.")
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError(f"Cannot read vault file: {exc}") from exc

        if doc.get("magic") != MAGIC:
            raise VaultError("Not a passman vault file.")

        k = doc["kdf"]
        kdf = crypto.KdfParams(
            name=k["name"],
            salt=_b64d(k["salt"]),
            iterations=k.get("iterations", 0),
            time_cost=k.get("time_cost", 0),
            memory_kib=k.get("memory_kib", 0),
            parallelism=k.get("parallelism", 0),
        )
        key = crypto.derive_key(master_password, kdf)

        header = {"magic": doc["magic"], "version": doc["version"], "kdf": k}
        plaintext = crypto.decrypt(
            key,
            _b64d(doc["nonce"]),
            _b64d(doc["ciphertext"]),
            _canonical_aad(header),
        )
        try:
            entries = json.loads(plaintext.decode("utf-8"))
        finally:
            # Drop the plaintext blob reference immediately.
            del plaintext
        return cls(path, key, kdf, entries)

    def save(self) -> None:
        k = self._kdf
        kdf_doc: dict = {"name": k.name, "salt": _b64e(k.salt)}
        if k.name == "pbkdf2-sha256":
            kdf_doc["iterations"] = k.iterations
        else:
            kdf_doc.update(time_cost=k.time_cost, memory_kib=k.memory_kib,
                           parallelism=k.parallelism)

        header = {"magic": MAGIC, "version": VERSION, "kdf": kdf_doc}
        plaintext = json.dumps(self.entries).encode("utf-8")
        nonce, ct = crypto.encrypt(self._key, plaintext, _canonical_aad(header))
        doc = {**header, "nonce": _b64e(nonce), "ciphertext": _b64e(ct)}

        # Atomic write with restrictive permissions.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent),
                                   prefix=".passman-", suffix=".tmp")
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0600
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def close(self) -> None:
        """Zero the key and drop entries from this object."""
        crypto.wipe(self._key)
        self._key = bytearray()
        self.entries = {}

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------------- CRUD ----------------

    def add(self, site: str, username: str, password: str,
            notes: str = "") -> str:
        entry_id = uuid.uuid4().hex[:8]
        now = int(time.time())
        self.entries[entry_id] = {
            "site": site, "username": username, "password": password,
            "notes": notes, "created_at": now, "updated_at": now,
        }
        self.save()
        return entry_id

    def get(self, entry_id: str) -> dict:
        try:
            return self.entries[entry_id]
        except KeyError:
            raise VaultError(f"No entry with id {entry_id!r}.") from None

    def find(self, query: str) -> list[tuple[str, dict]]:
        q = query.lower()
        return [(eid, e) for eid, e in self.entries.items()
                if q in e["site"].lower() or q in e["username"].lower()]

    def update(self, entry_id: str, **fields) -> None:
        entry = self.get(entry_id)
        allowed = {"site", "username", "password", "notes"}
        for k, v in fields.items():
            if k in allowed and v is not None:
                entry[k] = v
        entry["updated_at"] = int(time.time())
        self.save()

    def delete(self, entry_id: str) -> None:
        self.get(entry_id)  # raises if missing
        del self.entries[entry_id]
        self.save()
