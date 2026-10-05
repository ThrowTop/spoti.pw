#!/usr/bin/env python3
"""Verify kit integrity, privacy machine code, and (optionally) the locally patched IPA."""
import argparse
import hashlib
import json
import plistlib
import struct
import zipfile


def macho(data):
    if struct.unpack_from("<I", data)[0] != 0xFEEDFACF:
        raise ValueError("Expected thin arm64 Mach-O")
    if struct.unpack_from("<I", data, 4)[0] != 0x100000C:
        raise ValueError("Expected arm64")
    offset, segments, symbols, dylibs = 32, [], None, []
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, size = struct.unpack_from("<II", data, offset)
        if command == 0x19:
            address, length, fileoff, filesize = struct.unpack_from("<QQQQ", data, offset + 24)
            segments.append((address, length, fileoff, filesize))
        elif command == 2:
            symbols = struct.unpack_from("<IIII", data, offset + 8)
        elif command in (0xC, 0x80000018):
            start = offset + struct.unpack_from("<I", data, offset + 8)[0]
            dylibs.append(data[start:data.index(b"\0", start)].decode())
        elif command == 0x2C and struct.unpack_from("<I", data, offset + 16)[0]:
            raise ValueError("Encrypted binary")
        if size < 8:
            raise ValueError("Invalid load command")
        offset += size
    return segments, symbols, dylibs


def privacy_code(data):
    segments, table, _ = macho(data)
    if table is None:
        raise ValueError("No symbol table to verify privacy functions")
    symoff, count, stroff, _ = table
    found = {}
    for index in range(count):
        string, kind, section, desc, address = struct.unpack_from("<IBBHQ", data, symoff + index * 16)
        if not string or (kind & 0x0E) != 0x0E:
            continue
        start = stroff + string
        name = data[start:data.index(b"\0", start)].decode()
        for vm, _, fileoff, filesize in segments:
            if vm <= address < vm + filesize:
                found[name] = fileoff + address - vm
                break
    zeros = {0xD2800000, 0x52800000, 0xAA1F03E0, 0x2A1F03E0}
    checks = {
        "_SGUsageBody": True, "_SGUsageOwed": True, "_SGUsageNoteAsked": False,
        "_SGCheckForUpdate": False, "_SGWatchForUpdates": False,
        "_SGWatchForCertificate": False, "_SGCertificateRow": True,
        "_SGCertificateOfferShown": True, "_SGUpdateVersion": True,
    }
    for name, returns_zero in checks.items():
        if name not in found:
            raise ValueError(f"Missing privacy symbol: {name}")
        offset = found[name]
        first, second = struct.unpack_from("<II", data, offset)
        # Compiler-proven stubs: MOV X0/W0, zero; RET, or RET for a void function.
        good = first in zeros and second == 0xD65F03C0 if returns_zero else first == 0xD65F03C0
        if not good:
            raise ValueError(f"Privacy function is not the expected stub: {name}, {first:08x} {second:08x}")
    for endpoint in (b"/api/update", b"/api/certificate", b"spotipw.install", b"spotipw.asked"):
        if endpoint in data:
            raise ValueError(f"Unexpected reporting endpoint/key in compiled tweak: {endpoint!r}")
    print(f"Verified {len(checks)} compiled arm64 privacy stubs and absence of reporting endpoints")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kit")
    parser.add_argument("--ipa")
    args = parser.parse_args()
    with zipfile.ZipFile(args.kit) as archive:
        manifest = json.loads(archive.read("kit.json"))
        payload = {n for n in archive.namelist() if n != "kit.json"}
        if payload != set(manifest["integrity"]):
            raise ValueError("Incomplete kit integrity manifest")
        for name, expected in manifest["integrity"].items():
            if hashlib.sha256(archive.read(name)).hexdigest() != expected:
                raise ValueError(f"Checksum mismatch: {name}")
        privacy_code(archive.read("files/Frameworks/spotifyglass.dylib"))
        if args.ipa:
            with zipfile.ZipFile(args.ipa) as ipa:
                bad = ipa.testzip()
                if bad:
                    raise ValueError(f"IPA ZIP CRC failure: {bad}")
                name = next(n for n in ipa.namelist() if n.count("/") == 2 and n.endswith(".app/Info.plist"))
                app = name.removesuffix("Info.plist")
                info = plistlib.loads(ipa.read(name))
                for entry, expected in manifest["integrity"].items():
                    if entry.startswith("files/") and entry[6:] not in manifest["templates"]:
                        actual = hashlib.sha256(ipa.read(app + entry[6:])).hexdigest()
                        if actual != expected:
                            raise ValueError(f"Injected kit file differs: {entry}")
                for load in manifest["load"]:
                    binary = app + (info["CFBundleExecutable"] if load["binary"] == "@main" else load["binary"])
                    if binary not in ipa.namelist() and load.get("optional"):
                        continue
                    linked = macho(ipa.read(binary))[2]
                    if not set(load["dylibs"]).issubset(linked):
                        raise ValueError(f"Missing injected load command in {binary}")
                widget_info = plistlib.loads(ipa.read(app + manifest["templates"][0]))
                if widget_info["CFBundleIdentifier"] != info["CFBundleIdentifier"] + ".liveactivity":
                    raise ValueError("Live Activity template was not filled correctly")
                ours = json.loads(archive.read("appintents/extract.actionsdata"))["actions"]
                merged = json.loads(ipa.read(app + "Metadata.appintents/extract.actionsdata"))["actions"]
                if not set(ours).issubset(merged):
                    raise ValueError("Live Activity intents are missing")
                if not info.get("CFBundleIcons", {}).get("CFBundleAlternateIcons"):
                    raise ValueError("Alternate icons are missing")
                if any(n.startswith(app + removed + "/") for n in ipa.namelist() for removed in manifest["remove"]):
                    raise ValueError("Watch bundle removal failed")
                print("IPA CRCs, kit files, host/widget injection, Live Activity, intents and alternate icons verified")
        print(f"Kit source commit: {manifest['sourceCommit']}")


if __name__ == "__main__":
    main()
