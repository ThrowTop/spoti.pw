# Custom kit builds

Branch: `codex/fast-kit-builds`, based on upstream `0.23.0-beta`. Usage collection, all update
checks/notices, and certificate promotions are disabled in this source. Links you explicitly open
and normal Spotify/lyrics/artwork providers still work.

## Windows: edit to IPA

Needs Git, authenticated GitHub CLI (`gh auth login`) and Node **24 or newer**. No local Xcode,
Theos, Python or Mac is required for the usual build-and-patch command.

```powershell
git switch codex/fast-kit-builds
# Edit source, then commit it:
git add <the-files-you-edited>
git commit -m "fix: describe your change"
.\scripts\dev-build.ps1
```

This pushes the branch, uses the Actions run for that exact commit, downloads its custom kit,
and patches the local base IPA into `out/spoti.pw-0.23.0-beta+<commit>.ipa`. It never downloads
the upstream Chroma release kit. Pass `-Ipa 'C:\path\base.ipa'`, or set `SPOTI_IPA`, to use a
different path. The default is `~/Downloads/com.spotify.client-9.1.78.ipa`.

To repatch offline without running Actions:

```powershell
.\scripts\dev-build.ps1 -Kit .\out\kits\<run-id>\spoti.pw-<version>-kit.zip
# Or, on Windows / Linux / macOS:
node scripts/patcher.mjs BASE.ipa CUSTOM-KIT.zip out
```

`-Clean` requests a complete tweak recompile; `-NoWait` starts the build and prints its URL.
The output still needs your normal signing/install step. This patcher does not decrypt or sign.
It preserves Spotify's widget, adds its App Group shim and the Live Activity extension/intents,
and carries the compiled alternate icons. Its manifest/checksums identify the exact source
commit and base IPA. Other IPA fingerprints are rejected because the icon catalog is base-specific.

## Bootstrap / changing the base IPA

Only the first build needs the full decrypted IPA on the Mac runner:

```powershell
.\scripts\dev-build.ps1 -Bootstrap
```

This uploads the supplied IPA to a random Filebin URL, stores that URL as a GitHub secret, and
sets `KIT_BASE_SHA256`. Actions deletes the remote file after saving the derived input artifact;
the local helper removes the URL secret after a successful patch. Actions extracts the flag table,
app metadata and icon catalog. **The executable
and full IPA are not cached or uploaded as Actions artifacts.** Small input bundles and custom
kits are accessible through this public repository's Actions artifacts; they contain no accounts
or signing credentials. `-Bootstrap` must wait; it cannot be combined with `-NoWait`. Interrupted
bootstraps retain an ignored cleanup record locally; the next successful patch retries cleanup.

Inputs are cached and retained as a recovery artifact for 90 days, renewed on each build. Keep
a local copy (`gh run download RUN_ID --pattern 'kit-inputs-*' --dir out/input-backup`). After
90 days without a successful run, bootstrap again or restore that backup as an artifact. Changes
to the flag extractor require a new bootstrap, too.

## What makes this faster

- No full IPA injection, compression or upload on the runner, and no `cyan` installation.
- Pinned Theos checkout and its generated compiler support tools are cached.
- Theos objects and the audio library are restored; content hashes restore original mtimes for
  unchanged source files, so checkout timestamps do not force a full recompile.
- Xcode build, runner architecture, Theos revision, base IPA, build flags and mod version partition
  the object cache. Changed source still recompiles; a changed header invalidates dependents.
- Widget, App Group shim and icon compilation are cached separately by their actual inputs.
- The tweak uses all available compiler jobs. Auxiliary compilation overlaps on cold builds.
- New pushes cancel older pending/running builds on this branch.

The Node patcher is a pinned snapshot of `https://chroma.pw/patcher.mjs`, retrieved 2026-10-05,
with a local base-fingerprint check and custom-build labels. Its archive/Mach-O implementation
is retained. It performs no HTTP requests; no code is fetched from Chroma at patch time.
Original snapshot SHA-256: `de20ab1e2407479c0b6e711a46fc7c7b76d9d834270a03e16e7000af50fd61db`.

The workflow verifies the actual arm64 instructions of the reporting/update/promotion stubs.
To also verify a finished IPA locally (requires Python 3.11+):

```powershell
python scripts/verify-kit.py CUSTOM-KIT.zip --ipa out/FINISHED.ipa
```
