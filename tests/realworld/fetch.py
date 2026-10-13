"""Download the public OT/ICS sample files listed in manifest.json into
tests/realworld/.cache (not committed). Files are pinned by commit and checked
against their SHA-256, so the real-world tests are reproducible.

    python tests/realworld/fetch.py            # download missing files
    python -m pytest tests/test_realworld.py   # run the checks
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, ".cache")


def local_path(entry: dict) -> str:
    return os.path.join(CACHE, entry["repo"].replace("/", "__"), os.path.basename(entry["path"]))


def url(entry: dict) -> str:
    host = "https://media.githubusercontent.com/media" if entry.get("lfs") else "https://raw.githubusercontent.com"
    return f"{host}/{entry['repo']}/{entry['commit']}/{urllib.parse.quote(entry['path'])}"


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main() -> int:
    with open(os.path.join(HERE, "manifest.json"), encoding="utf-8") as fh:
        files = json.load(fh)["files"]
    bad = 0
    for e in files:
        dest = local_path(e)
        if os.path.exists(dest) and sha256(dest) == e["sha256"]:
            continue
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            with urllib.request.urlopen(url(e), timeout=60) as r, open(dest + ".part", "wb") as out:
                out.write(r.read())
        except OSError as ex:
            print(f"FAIL {e['path']}: {ex}", file=sys.stderr)
            bad += 1
            continue
        if sha256(dest + ".part") != e["sha256"]:
            print(f"FAIL {e['path']}: SHA-256 mismatch", file=sys.stderr)
            os.unlink(dest + ".part")
            bad += 1
            continue
        os.replace(dest + ".part", dest)
        print(f"ok   {e['path']}")
    print(f"{len(files) - bad}/{len(files)} files ready in {CACHE}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
