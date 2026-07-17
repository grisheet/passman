"""
cli.py — Command-line interface.

Design rules for handling secrets in the UI layer:
  * Master password and stored passwords are read with getpass (no echo).
  * Passwords are NEVER printed unless the user passes --show explicitly;
    the default retrieval path is clipboard copy with auto-clear (or a
    one-time reveal prompt if pyperclip is missing).
  * Secrets never appear in argv (visible in `ps`/shell history), so there
    is deliberately no --password flag.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import datetime
from pathlib import Path

from . import clipboard, generator
from .crypto import WrongPasswordOrCorrupt, wipe
from .vault import Vault, VaultError

DEFAULT_VAULT = Path(os.environ.get(
    "PASSMAN_VAULT", str(Path.home() / ".passman" / "vault.enc")))


# ---------------- helpers ----------------

def _read_master(confirm: bool = False) -> bytearray:
    pw = getpass.getpass("Master password: ")
    if confirm:
        again = getpass.getpass("Confirm master password: ")
        if pw != again:
            _die("Passwords do not match.")
        if len(pw) < 10:
            _die("Master password must be at least 10 characters.")
    buf = bytearray(pw.encode("utf-8"))
    del pw  # drop the immutable str reference (see threat-model caveats)
    return buf


def _open_vault(path: Path) -> Vault:
    master = _read_master()
    try:
        return Vault.open(path, master)
    except (WrongPasswordOrCorrupt, VaultError) as exc:
        _die(str(exc))
    finally:
        wipe(master)


def _die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def _fmt_time(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def _print_entry(eid: str, e: dict, show_password: bool) -> None:
    print(f"  id:       {eid}")
    print(f"  site:     {e['site']}")
    print(f"  username: {e['username']}")
    print(f"  password: {e['password'] if show_password else '••••••••'}")
    if e.get("notes"):
        print(f"  notes:    {e['notes']}")
    print(f"  updated:  {_fmt_time(e['updated_at'])}")


def _deliver_password(password: str, show: bool) -> None:
    """Default: clipboard with auto-clear. --show prints instead."""
    if show:
        print(f"  password: {password}")
    elif clipboard.available():
        clipboard.copy_with_autoclear(password)
    else:
        print("  (pyperclip not installed — printing once; clear your "
              "terminal afterwards)")
        print(f"  password: {password}")


# ---------------- commands ----------------

def cmd_init(args) -> None:
    master = _read_master(confirm=True)
    try:
        with Vault.create(args.vault, master):
            pass
        print(f"Vault created at {args.vault}")
    except VaultError as exc:
        _die(str(exc))
    finally:
        wipe(master)


def cmd_add(args) -> None:
    with _open_vault(args.vault) as v:
        site = args.site or input("Site: ").strip()
        username = args.username or input("Username: ").strip()
        if args.generate:
            password = generator.generate(args.length)
            print(f"  Generated a {args.length}-character password "
                  f"(~{generator.entropy_bits(args.length):.0f} bits).")
        else:
            password = getpass.getpass("Password (blank to auto-generate): ")
            if not password:
                password = generator.generate()
                print("  Generated a strong password for you.")
        notes = args.notes if args.notes is not None else input("Notes (optional): ").strip()
        eid = v.add(site, username, password, notes)
        print(f"Saved entry {eid} for {site}.")


def cmd_get(args) -> None:
    with _open_vault(args.vault) as v:
        matches = ([(args.query, v.get(args.query))]
                   if args.query in v.entries else v.find(args.query))
        if not matches:
            _die(f"No entries matching {args.query!r}.")
        if len(matches) > 1:
            print(f"{len(matches)} matches — showing metadata only. "
                  f"Use `get <id>` for the password.\n")
            for eid, e in matches:
                print(f"  [{eid}] {e['site']}  ({e['username']})")
            return
        eid, e = matches[0]
        _print_entry(eid, e, show_password=False)
        _deliver_password(e["password"], show=args.show)


def cmd_list(args) -> None:
    with _open_vault(args.vault) as v:
        if not v.entries:
            print("Vault is empty.")
            return
        print(f"{len(v.entries)} entries:\n")
        for eid, e in sorted(v.entries.items(), key=lambda kv: kv[1]["site"].lower()):
            print(f"  [{eid}] {e['site']:<30} {e['username']}")


def cmd_update(args) -> None:
    with _open_vault(args.vault) as v:
        v.get(args.id)  # validate early
        new_password = None
        if args.rotate:
            new_password = generator.generate(args.length)
            print(f"  Rotated to a new {args.length}-character password.")
        elif args.prompt_password:
            new_password = getpass.getpass("New password: ")
        v.update(args.id, site=args.site, username=args.username,
                 password=new_password, notes=args.notes)
        print(f"Updated entry {args.id}.")


def cmd_delete(args) -> None:
    with _open_vault(args.vault) as v:
        e = v.get(args.id)
        if not args.yes:
            answer = input(f"Delete entry for {e['site']!r}? [y/N] ").strip().lower()
            if answer != "y":
                print("Aborted.")
                return
        v.delete(args.id)
        print(f"Deleted entry {args.id}.")


def cmd_gen(args) -> None:
    pw = generator.generate(args.length, lower=not args.no_lower,
                            upper=not args.no_upper,
                            digits=not args.no_digits,
                            symbols=not args.no_symbols)
    bits = generator.entropy_bits(args.length, lower=not args.no_lower,
                                  upper=not args.no_upper,
                                  digits=not args.no_digits,
                                  symbols=not args.no_symbols)
    print(f"(~{bits:.0f} bits of entropy)")
    if args.copy and clipboard.available():
        clipboard.copy_with_autoclear(pw)
    else:
        print(pw)


# ---------------- parser ----------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="passman",
        description="Local encrypted password manager (AES-256-GCM).")
    p.add_argument("--vault", type=Path, default=DEFAULT_VAULT,
                   help=f"vault file (default: {DEFAULT_VAULT})")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(fn=cmd_init)

    a = sub.add_parser("add", help="add an entry")
    a.add_argument("--site")
    a.add_argument("--username")
    a.add_argument("--notes")
    a.add_argument("--generate", action="store_true",
                   help="auto-generate the password")
    a.add_argument("--length", type=int, default=generator.DEFAULT_LENGTH)
    a.set_defaults(fn=cmd_add)

    g = sub.add_parser("get", help="retrieve an entry (copies password)")
    g.add_argument("query", help="entry id or search text")
    g.add_argument("--show", action="store_true",
                   help="print the password instead of copying it")
    g.set_defaults(fn=cmd_get)

    sub.add_parser("list", help="list entries (no secrets)").set_defaults(fn=cmd_list)

    u = sub.add_parser("update", help="update an entry")
    u.add_argument("id")
    u.add_argument("--site")
    u.add_argument("--username")
    u.add_argument("--notes")
    u.add_argument("--rotate", action="store_true",
                   help="replace password with a newly generated one")
    u.add_argument("--prompt-password", action="store_true",
                   help="prompt for a new password (hidden input)")
    u.add_argument("--length", type=int, default=generator.DEFAULT_LENGTH)
    u.set_defaults(fn=cmd_update)

    d = sub.add_parser("delete", help="delete an entry")
    d.add_argument("id")
    d.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    d.set_defaults(fn=cmd_delete)

    ge = sub.add_parser("gen", help="generate a password")
    ge.add_argument("--length", type=int, default=generator.DEFAULT_LENGTH)
    ge.add_argument("--no-lower", action="store_true")
    ge.add_argument("--no-upper", action="store_true")
    ge.add_argument("--no-digits", action="store_true")
    ge.add_argument("--no-symbols", action="store_true")
    ge.add_argument("--copy", action="store_true",
                    help="copy to clipboard instead of printing")
    ge.set_defaults(fn=cmd_gen)

    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except ValueError as exc:
        _die(str(exc))


if __name__ == "__main__":
    main()
