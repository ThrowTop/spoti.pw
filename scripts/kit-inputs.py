#!/usr/bin/env python3
"""Prepare small reusable build inputs, or validate/restore them. Never stores the app executable."""
import argparse
import hashlib
import json
import plistlib
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--ipa", type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    directory = args.directory
    extractor = sha(ROOT / "scripts/extract-flags.py")
    if args.ipa:
        if sha(args.ipa) != args.sha256:
            raise SystemExit("Base IPA SHA-256 mismatch")
        directory.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(args.ipa) as archive:
            infos = [n for n in archive.namelist() if n.count("/") == 2 and n.endswith(".app/Info.plist")]
            if len(infos) != 1:
                raise SystemExit("Expected exactly one host app")
            name = infos[0]
            raw = archive.read(name)
            info = plistlib.loads(raw)
            if info.get("CFBundleExecutable") != "Spotify" or info.get("CFBundleShortVersionString") != "9.1.78":
                raise SystemExit("This workflow expects decrypted Spotify 9.1.78")
            with archive.open(name.replace("Info.plist", "Spotify")) as stream:
                header = stream.read(65536)
            if struct.unpack_from("<I", header)[0] != 0xFEEDFACF:
                raise SystemExit("Expected a thin 64-bit Mach-O")
            offset = 32
            for _ in range(struct.unpack_from("<I", header, 16)[0]):
                command, size = struct.unpack_from("<II", header, offset)
                if command == 0x2C and struct.unpack_from("<I", header, offset + 16)[0]:
                    raise SystemExit("The IPA is encrypted")
                offset += size
            (directory / "host.plist").write_bytes(raw)
            # app-icons.sh needs only these two files, not a runnable Spotify app.
            with zipfile.ZipFile(directory / "icons-base.zip", "w", zipfile.ZIP_DEFLATED) as sparse:
                for member in (name, name.replace("Info.plist", "Assets.car")):
                    sparse.writestr(member, archive.read(member))
        (directory / "SGFlagList.m").write_bytes((ROOT / "tweak/Sources/Shared/Flags/SGFlagList.m").read_bytes())
        files = {p.name: sha(p) for p in directory.iterdir() if p.name != "inputs.json" and p.is_file()}
        (directory / "inputs.json").write_text(json.dumps({
            "baseSHA256": args.sha256, "extractorSHA256": extractor, "spotify": "9.1.78", "files": files,
        }, indent=2))
    metadata = json.loads((directory / "inputs.json").read_text())
    if metadata["baseSHA256"] != args.sha256 or metadata["extractorSHA256"] != extractor:
        raise SystemExit("Build inputs do not match this base IPA / flag extractor")
    for name, expected in metadata["files"].items():
        if sha(directory / name) != expected:
            raise SystemExit(f"Build input checksum mismatch: {name}")
    (ROOT / "tweak/Sources/Shared/Flags/SGFlagList.m").write_bytes((directory / "SGFlagList.m").read_bytes())
    print("Build inputs verified; no app executable is stored in them")


if __name__ == "__main__":
    main()
