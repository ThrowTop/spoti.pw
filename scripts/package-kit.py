#!/usr/bin/env python3
"""Package locally compiled files for the pinned offline Node patcher, including icons and intents."""
import hashlib
import json
import plistlib
import stat
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    support = ROOT / "out/kit-support"
    inputs = json.loads((ROOT / "out/kit-inputs/inputs.json").read_text())
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    version = (ROOT / "version.txt").read_text().strip() + "+" + commit[:7]
    dylibs = list((ROOT / "tweak/.theos/obj").rglob("spotifyglass.dylib"))
    if not dylibs:
        raise SystemExit("The compiled tweak is missing")
    dylib = min(dylibs, key=lambda p: len(p.parts))
    files = {"files/Frameworks/spotifyglass.dylib": (dylib.read_bytes(), 0o755),
             "files/Frameworks/SpotifyGlassAppGroups.dylib": ((support / "SpotifyGlassAppGroups.dylib").read_bytes(), 0o755)}
    extension = support / "extension/SpotifyGlassLiveActivity.appex"
    for path in extension.rglob("*"):
        if path.is_file():
            relative = path.relative_to(extension).as_posix()
            data = (ROOT / "extension/LiveActivity/Info.plist").read_bytes() if relative == "Info.plist" else path.read_bytes()
            files["files/PlugIns/SpotifyGlassLiveActivity.appex/" + relative] = (data, stat.S_IMODE(path.stat().st_mode))
    for path in (support / "extension/app/Metadata.appintents").iterdir():
        if path.is_file():
            files["appintents/" + path.name] = (path.read_bytes(), 0o644)
    with (ROOT / "plist/liquid-glass.plist").open("rb") as stream:
        overlay = plistlib.load(stream)
    union = {"NSBonjourServices": overlay.pop("NSBonjourServices")}
    # Preserve alternate icons without requiring Apple's CoreUI on the local Windows machine.
    with zipfile.ZipFile(support / "icons.zip") as icons:
        info_name = next(n for n in icons.namelist() if n.endswith(".app/Info.plist"))
        info = plistlib.loads(icons.read(info_name))
        app = info_name.removesuffix("Info.plist")
        if not info.get("CFBundleIcons", {}).get("CFBundleAlternateIcons"):
            raise SystemExit("Alternate icon compilation failed; refusing to silently drop the feature")
        for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
            if key in info:
                overlay[key] = info[key]
        for name in icons.namelist():
            relative = name[len(app):]
            if name.startswith(app) and (relative == "Assets.car" or relative.startswith("SGAppIconPreviews/")) and not name.endswith("/"):
                files["files/" + relative] = (icons.read(name), 0o644)
    manifest = {
        "format": 1, "version": version, "spotify": inputs["spotify"], "sourceCommit": commit,
        "baseSHA256": inputs["baseSHA256"],
        "infoPlist": {"set": overlay, "union": union, "default": {
            "NSLocalNetworkUsageDescription": "Find nearby speakers and devices for Spotify Connect and Cast."}},
        "load": [{"binary": "@main", "dylibs": ["@rpath/SpotifyGlassAppGroups.dylib", "@rpath/spotifyglass.dylib"]},
                 {"binary": "PlugIns/WidgetExtension.appex/WidgetExtension", "dylibs": ["@rpath/SpotifyGlassAppGroups.dylib"], "optional": True}],
        "rpath": "@executable_path/Frameworks",
        "templates": ["PlugIns/SpotifyGlassLiveActivity.appex/Info.plist"], "appIntents": "appintents",
        "remove": ["Watch", "WatchKit", "com.apple.WatchPlaceholder"],
        "integrity": {name: hashlib.sha256(data).hexdigest() for name, (data, _) in files.items()},
    }
    output = ROOT / "out" / f"spoti.pw-{version}-kit.zip"
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
        archive.writestr("kit.json", json.dumps(manifest, indent=2))
        for name, (data, mode) in sorted(files.items()):
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | mode) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data, compresslevel=1)
    print(f"{output.name}: {output.stat().st_size / 1e6:.1f} MB, commit {commit[:7]}")


if __name__ == "__main__":
    main()
