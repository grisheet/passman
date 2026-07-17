"""
clipboard.py — Optional clipboard copy with auto-clear.

Uses pyperclip if installed. The clear runs in a detached daemon-less
foreground countdown by default (explicit and predictable for a CLI), and
only clears the clipboard if it still contains the secret we placed there —
so we never clobber something the user copied afterwards.
"""

from __future__ import annotations

import sys
import time

try:
    import pyperclip
    _HAS_CLIPBOARD = True
except ImportError:  # pragma: no cover
    _HAS_CLIPBOARD = False

AUTO_CLEAR_SECONDS = 25


def available() -> bool:
    return _HAS_CLIPBOARD


def copy_with_autoclear(secret: str, seconds: int = AUTO_CLEAR_SECONDS) -> None:
    """Copy `secret`, count down visibly, then clear (if unchanged)."""
    if not _HAS_CLIPBOARD:
        raise RuntimeError("pyperclip not installed (pip install pyperclip).")
    pyperclip.copy(secret)
    try:
        for remaining in range(seconds, 0, -1):
            sys.stderr.write(
                f"\r  Copied to clipboard — clearing in {remaining:2d}s "
                f"(Ctrl+C to clear now) "
            )
            sys.stderr.flush()
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        # Only clear if the clipboard still holds our secret.
        try:
            if pyperclip.paste() == secret:
                pyperclip.copy("")
        except Exception:
            pyperclip.copy("")
        sys.stderr.write("\r  Clipboard cleared." + " " * 40 + "\n")
