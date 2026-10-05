#!/usr/bin/env python3
"""Keep unchanged inputs older than restored Theos objects; changed content keeps its new mtime."""
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "out/kit-cache/source-times.json"


def inputs():
    for directory in ("tweak/Sources", "vendor/audio", "extension", "icons", "plist", "scripts"):
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and not any(part in ("build", "__pycache__") for part in path.parts):
                yield path
    for name in ("tweak/Makefile", "vendor/audio/Makefile", "version.txt"):
        yield ROOT / name


def main():
    previous = json.loads(STATE.read_text()) if STATE.exists() else {}
    current = {}
    for path in inputs():
        key = path.relative_to(ROOT).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        old = previous.get(key)
        if sys.argv[1] == "restore" and old and old["sha256"] == digest:
            os.utime(path, ns=(path.stat().st_atime_ns, old["mtime_ns"]))
        current[key] = {"sha256": digest, "mtime_ns": path.stat().st_mtime_ns}
    if sys.argv[1] == "save":
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(current))


if __name__ == "__main__":
    main()
