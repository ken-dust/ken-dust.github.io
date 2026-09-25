#!/usr/bin/env python3
"""
Encrypt all HTML files in to-encrypt/ using StatiCrypt,
output the protected files to docs/ (the GitHub Pages release folder).

Password strategy: derived passwords
  Each client's password = HMAC-SHA256(master_secret, client_folder), base64-encoded,
  where client_folder is the first folder under to-encrypt/ (to-encrypt/acme/march.html -> acme).
  - One master secret to rule them all (in ~/.env, backed up in your password manager)
  - Each client gets one password for all its reports — one client's password opens nothing of another's
  - A file directly in to-encrypt/, outside a client folder, is refused
  - Deterministic: you can always regenerate any password from secret + client folder name
  - The secret never touches the repo, and this script never prints it

Usage:
    python3 scripts/encrypt/encrypt_public.py                    # encrypt all files → docs/
    python3 scripts/encrypt/encrypt_public.py --show             # show passwords without encrypting
    python3 scripts/encrypt/encrypt_public.py --skip-unchanged    # skip files whose encrypted output is newer than source
    python3 scripts/encrypt/encrypt_public.py --file reports/q1.html # one file only
    python3 scripts/encrypt/encrypt_public.py --check-secret     # exit 0 if the secret is set, 1 if not; prints nothing

Requirements:
    npx (Node.js) — StatiCrypt is run via npx, no global install needed.
"""

import argparse
import base64
import hashlib
import hmac
import os
import subprocess
import sys
from pathlib import Path

WORKSPACE = Path(__file__).parent.parent.parent

# Load the home key file if present (pure stdlib, no dependencies). AgentC-OS
# keeps every key in ~/.env, never in a repository folder; values already in
# the environment win.
_env_file = Path.home() / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

SOURCE_DIR = WORKSPACE / "to-encrypt"
OUTPUT_DIR = WORKSPACE / "docs"
TEMPLATE   = Path(__file__).parent / "template.html"


def derive_password(master_secret: str, relative_path: str) -> str:
    key = master_secret.encode("utf-8")
    msg = relative_path.encode("utf-8")
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest)[:24].decode("ascii")


def encrypt_file(src: Path, output_dir: Path, password: str) -> bool:
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "npx", "--yes", "staticrypt",
        str(src),
        "--password", password,
        "-d", str(output_dir),
        "--short",
    ]
    if TEMPLATE.exists():
        cmd += ["--template", str(TEMPLATE)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"    staticrypt error: {result.stderr.strip()}", file=sys.stderr)
        return False
    return True


def print_password_table(passwords: dict, results: dict = None):
    print()
    print(f"  {'File':<45} Password")
    print(f"  {'-'*45} {'-'*24}")
    for name, pwd in passwords.items():
        status = f"  [{results[name]}]" if results else ""
        print(f"  {name:<45} {pwd}{status}")
    print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--skip-unchanged", action="store_true")
    parser.add_argument("--file", metavar="FILENAME")
    parser.add_argument("--check-secret", action="store_true")
    args = parser.parse_args()

    master_secret = os.environ.get("ENCRYPT_SECRET", "")
    if args.check_secret:
        sys.exit(0 if master_secret else 1)
    if not master_secret:
        print("ERROR: ENCRYPT_SECRET is not set in ~/.env.", file=sys.stderr)
        print("  Add a line ENCRYPT_SECRET=<value> to ~/.env in a text editor (see Step 4).", file=sys.stderr)
        sys.exit(1)

    if not SOURCE_DIR.exists():
        print(f"ERROR: Source directory '{SOURCE_DIR}' does not exist.", file=sys.stderr)
        sys.exit(1)

    html_files = sorted(SOURCE_DIR.rglob("*.html"))
    rel_paths = {f: str(f.relative_to(SOURCE_DIR)) for f in html_files}

    if args.file:
        html_files = [f for f in html_files if rel_paths[f] == args.file or f.name == args.file]
        if not html_files:
            print(f"ERROR: '{args.file}' not found in {SOURCE_DIR}", file=sys.stderr)
            sys.exit(1)

    if args.skip_unchanged:
        def _is_up_to_date(src: Path, rel: str) -> bool:
            out = OUTPUT_DIR / rel
            return out.exists() and out.stat().st_mtime >= src.stat().st_mtime

        skipped = [f for f in html_files if _is_up_to_date(f, rel_paths[f])]
        html_files = [f for f in html_files if not _is_up_to_date(f, rel_paths[f])]
        if skipped:
            print(f"Skipping {len(skipped)} up-to-date file(s): {', '.join(rel_paths[f] for f in skipped)}")

    if not html_files:
        print(f"No HTML files to process in {SOURCE_DIR}")
        sys.exit(0)

    loose = [rel_paths[f] for f in html_files if len(Path(rel_paths[f]).parts) < 2]
    if loose:
        print(f"ERROR: file(s) outside a client folder: {', '.join(loose)}. Move each into to-encrypt/<client>/.", file=sys.stderr)
        sys.exit(1)

    passwords = {rel_paths[f]: derive_password(master_secret, Path(rel_paths[f]).parts[0]) for f in html_files}

    if args.show:
        print(f"\nDerived passwords for files in {SOURCE_DIR.relative_to(WORKSPACE)}/")
        print("(Master secret not shown — store it in your password manager)")
        print_password_table(passwords)
        return

    template_note = f" (template: {TEMPLATE.name})" if TEMPLATE.exists() else " (default template)"
    print(f"\nEncrypting {len(html_files)} file(s){template_note}")
    print(f"  {SOURCE_DIR.relative_to(WORKSPACE)}/ → {OUTPUT_DIR.relative_to(WORKSPACE)}/\n")

    results = {}
    for src in html_files:
        rel = rel_paths[src]
        out_dir = OUTPUT_DIR / Path(rel).parent
        print(f"  {rel} ...", end=" ", flush=True)
        ok = encrypt_file(src, out_dir, passwords[rel])
        results[rel] = "OK" if ok else "FAILED"
        print(results[rel])

    print("\nPasswords (one per client, the same for every report of that client):")
    print_password_table(passwords, results)

    failed = [rel for rel, status in results.items() if status != "OK"]
    if failed:
        print(f"WARNING: {len(failed)} file(s) failed: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
