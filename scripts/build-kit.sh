#!/usr/bin/env bash
# Compile custom source, never the upstream release binary. No full IPA injection/upload here.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
: "${THEOS:?Set THEOS to the pinned checkout}"
mkdir -p out/kit-support out/kit-cache
python3 scripts/source-mtimes.py restore

SUPPORT_KEY="$(python3 - <<'PY'
import hashlib, pathlib, subprocess
h = hashlib.sha256()
for root in ('extension', 'icons'):
    for p in sorted(pathlib.Path(root).rglob('*')):
        if p.is_file(): h.update(str(p).encode()); h.update(p.read_bytes())
for name in ('scripts/build-extension.sh', 'scripts/app-icons.sh', 'scripts/car-tool.m',
             'tweak/Sources/Shared/LiveActivity/LiveActivityShared.swift', 'out/kit-inputs/inputs.json'):
    h.update(pathlib.Path(name).read_bytes())
h.update(subprocess.check_output(['xcodebuild', '-version']))
print(h.hexdigest())
PY
)"

build_support() {
  if [ "$(cat out/kit-support/key 2>/dev/null || true)" = "$SUPPORT_KEY" ]; then
    echo "==> reusing widget, App Group shim and alternate icons"
    return
  fi
  scripts/build-extension.sh out/kit-inputs/host.plist out/kit-support/extension
  xcrun --sdk iphoneos clang -target arm64-apple-ios16.0 -dynamiclib -fobjc-arc -Os \
    -framework Foundation -framework Security -install_name @rpath/SpotifyGlassAppGroups.dylib \
    -o out/kit-support/SpotifyGlassAppGroups.dylib extension/AppGroups/AppGroups.m
  cp out/kit-inputs/icons-base.zip out/kit-support/icons.zip
  scripts/app-icons.sh out/kit-support/icons.zip
  printf '%s\n' "$SUPPORT_KEY" > out/kit-support/key
}

build_support &
SUPPORT_PID=$!
trap 'kill "$SUPPORT_PID" 2>/dev/null || true' EXIT
echo "==> compiling tweak incrementally"
if [ "${KIT_CLEAN:-false}" = true ]; then
  env -u MAKELEVEL gmake -C tweak clean
fi
env -u MAKELEVEL gmake -C tweak -j"$(sysctl -n hw.ncpu)" all
wait "$SUPPORT_PID"
trap - EXIT
python3 scripts/package-kit.py
python3 scripts/verify-kit.py out/*-kit.zip
python3 scripts/source-mtimes.py save
