#!/usr/bin/env python3
"""Add a new ENCRYPT_SECRET to the home key file, once, without showing it."""
import os, secrets, stat
from pathlib import Path

f = Path.home() / ".env"
text = f.read_text() if f.exists() else ""
if any(l.strip().startswith("ENCRYPT_SECRET=") for l in text.splitlines()):
    print("Already there. Nothing changed.")
else:
    with f.open("a") as fh:
        fh.write(("" if text.endswith("\n") or not text else "\n")
                 + "\n# Master secret for password-protected client pages (ken-dust.github.io)\n"
                 + f"ENCRYPT_SECRET={secrets.token_urlsafe(32)}\n")
    os.chmod(f, stat.S_IRUSR | stat.S_IWUSR)
    print("Done. The secret is saved, and it was not shown.")
