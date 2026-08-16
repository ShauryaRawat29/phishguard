"""
sync_docs.py
============
Keep the `docs/` GitHub Pages mirror in sync with `frontend/`.

The `docs/` directory is a byte-for-byte copy of `frontend/` and is deployed
to GitHub Pages. CI enforces parity with `--check`.

Usage:
    python scripts/sync_docs.py            # copy frontend -> docs
    python scripts/sync_docs.py --check    # exit 1 if docs/ differs
"""

from __future__ import annotations

import filecmp
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
DOCS = ROOT / "docs"

FILES = ["index.html", "style.css", "app.js"]


def sync() -> None:
    """Copy every file from frontend/ into docs/, overwriting."""
    DOCS.mkdir(exist_ok=True)
    for name in FILES:
        src = FRONTEND / name
        dst = DOCS / name
        shutil.copyfile(src, dst)
    print(f"Synced {len(FILES)} files: frontend/ -> docs/")


def check() -> int:
    """Return 0 if docs/ matches frontend/, 1 otherwise."""
    missing = [n for n in FILES if not (FRONTEND / n).exists()]
    if missing:
        print(f"Missing in frontend/: {', '.join(missing)}")
        return 1

    out_of_sync = []
    for name in FILES:
        src = FRONTEND / name
        dst = DOCS / name
        if not dst.exists():
            out_of_sync.append(f"{name} (missing in docs/)")
        elif not filecmp.cmp(src, dst, shallow=False):
            out_of_sync.append(name)

    if out_of_sync:
        print("docs/ is OUT OF SYNC with frontend/")
        for name in out_of_sync:
            print(f"  - {name}")
        print("Run `python scripts/sync_docs.py` and commit the mirror.")
        return 1

    print("docs/ is in sync with frontend/.")
    return 0


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(check())
    sync()
