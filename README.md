# scarlet-bundle-android

AOSP userspace bundle producer for Scarlet.

This repository is the distribution boundary for Android images and Android's
userspace launcher/adapters. The Scarlet kernel, Linux and Android ABI modules,
system-call integration, native protection mechanisms and compositor stay
in [`petitstrawberry/Scarlet`](https://github.com/petitstrawberry/Scarlet).
Scarlet consumes a verified release archive through a normal `bundle.toml`
`archive` layer.

The current producer exports the AOSP Android 13 ARM64 emulator image with tag
`default`. Google APIs and Play Store images are rejected. The native display,
input and network adapters are under `runtime/`; the native session manager is
under `manager/`, and the graphics HAL and stock adapters are under `graphics/`.
The boot profile and its Shield policy translator are under `profiles/` and
`producer/policy/`. Prepared init/APEX files and source-policy exports still come
from the Scarlet development inputs.
[`v0.1.16`](https://github.com/petitstrawberry/scarlet-bundle-android/releases/tag/v0.1.16)
is public and contains the complete prepared Android runtime plus a separately
built native manager/frontend archive. The
release workflow requires the exact corresponding-source archive, SHA-256 and
source revision for SDK build 10940250 before it creates a draft release, pins
the bundle and makes the release public.

## Build

The release build uses the pinned prepared runtime in
`producer/runtime-input.json` and builds the native manager/frontend from this
repository. Run the same two steps as CI:

```sh
python3 producer/tools/import_session_runtime.py \
  --version v0.1.0 --output producer/artifacts
nix develop --command python3 producer/tools/build_native.py \
  --version v0.1.0 --output producer/artifacts
```

The importer verifies the archive and assembly-lock SHA-256 values, retains the
complete Android tree and its inode metadata, and rejects inputs missing the
flattened ART APEX, graphics HAL/adapters, Shield policy or input bridge. It
keeps the upstream provenance and assembly lock inside the runtime archive.
The native build uses the pinned Scarlet toolchain and SDK.

Together these steps write:

- `android-aarch64-v0.1.0.tar.gz`
- `android-native-aarch64-v0.1.0.tar.gz`
- `SHA256SUMS`
- `bundle.toml`, containing both hash-pinned archive layers

Validate the runtime with
`python3 producer/tests/check_archive.py producer/artifacts/android-aarch64-v0.1.0.tar.gz`.
The native archive is validated during packaging and again before publication.
Run the producer tests with `python3 -m unittest discover -s producer/tests`;
the inode-export cases also require `mke2fs` and `debugfs`.

`producer/tools/build_rootfs.py` remains the stock SDK partition exporter used
when preparing a new runtime input. It preserves ownership, modes, timestamps,
hardlinks, xattrs and guest symlinks, and merges the checked-in `overlay/`.
That export alone does not assemble flattened APEX or the graphics adapters.
Use the complete-session assembly below to prepare and record a replacement
input; release CI does not reconstruct those components from the SDK ZIP.

## Release

Main-branch producer changes build and publish `v0.1.<run-number>` automatically
when the source repository variables are configured. A `v*` tag or
`workflow_dispatch` with a `vX.Y.Z` version can be used for an explicit release;
both require the URL, SHA-256 and exact source revision of the corresponding
AOSP source archive. Tag and main-branch releases use the repository variables
`ANDROID_SOURCE_ARCHIVE_URL`, `ANDROID_SOURCE_ARCHIVE_SHA256` and
`ANDROID_SOURCE_REVISION`.

CI imports the checksum-pinned complete runtime archive, builds the native app
and frontend with the pinned Scarlet Rust toolchain, validates both archive
layouts and source digests, creates a draft prerelease, checks every uploaded
asset, commits the two-layer manifest to `bundles/android/bundle.toml`, and only
then publishes the release. The release contains both binary archives, an exact
AOSP source manifest and retrieval record, producer sources, `corresponding-source.json`, checksums and the
pinned bundle manifest.

## Native userspace

`runtime/` contains the existing native window frontend, Android InputManager
bridge and network adapters. Its dependencies on Scarlet's shared libraries and
ScarletUI are pinned Git revisions. Build the AArch64 frontend with the Scarlet
Rust toolchain from the crate directory:

```sh
cd runtime
cargo build --locked --release --target aarch64-unknown-scarlet
```

`manager/` builds the native `android` application with the same command. Its
normal launch is `--view-handle 3 --policy-factory-handle 4`: the host transfers
an administrator View and a policy-factory capability with distinct descriptors.
The manager constructs its Shield policy during setup, then closes the policy
factory before starting Android children. It constructs Android's
Environment and device/input views, starts stock Android init in a child
PID/mount namespace, and owns that process scope. The display frontend connects
to the desktop's existing SWS. Closing its window ends the Android session.

`manager/app.toml` is the normal Scarlet app recipe. CI builds it through
`cargo-scarlet app build`, so `/applications/android.app` contains the generated
descriptor as well as `bin/android`. The frontend is installed at
`/bin/android-runtime`, and the explicit administrator grant remains under
`/etc/stemd.d/capabilities`. These portions form
`android-native-aarch64-vX.Y.Z.tar.gz`, installed at `/` after the complete
Android runtime archive. No init import, autostart entry or generated init file
belongs to this native layer. `bundles/native/bundle.toml` remains the local
source-build recipe; release consumers use the two archive layers in
`bundles/android/bundle.toml`.

The grant pairs `target = 3` with `shield_policy_factory = 4`. This requires
Scarlet's explicit factory grants from commit
[`7c96ed773`](https://github.com/petitstrawberry/Scarlet/commit/7c96ed773), which
includes the whole-View mount preservation fix and the native factory API.
The earlier normal launch path reached Android home. The release consumes a
checksum-pinned complete runtime artifact that includes the flattened APEX,
graphics HAL/adapters and prepared boot adjustments; CI does not rebuild those
components. Archive import and native compilation passed release CI, while final
release-runtime boot and graphics validation remain pending. This does not claim
that every Android service or display path has completed.

## Complete session archive

Generate the native Shield records from the checked-in profile and the verified
stock policy exports:

```sh
python3 producer/tools/build_policy.py \
  --android-root /path/to/assembled-android-root \
  --service-policy /path/to/service-policy.txt \
  --service-manifest /path/to/service-policy.json \
  --generic-manifest /path/to/generic-service-policy.json \
  --output producer/artifacts/policy
```

The Android root supplies the pinned compiled policy, property contexts and
declared init files. The producer verifies the compiled-policy and init-file
hashes and the relationship between both exports, then records all input digests
in `build.json` alongside `shield.policy`. The output
retains the profile's isolated-process transitions and stable file-label
persistence domain. Install it as `scarlet/boot/shield.policy` in the prepared
boot inputs and record its digest in `boot-profile.json` before packaging.
Include the empty `data/dalvik-cache` and `data/dalvik-cache/arm64` directories
in that prepared inventory: the manager binds their labels before stock init
starts. The stock profile does not depend on the old development sample APK.

`producer/tools/build_session.py` combines an AOSP archive with a prepared boot
profile, the native app, frontend and graphics outputs. It verifies the
input manifests and file hashes, preserves stock metadata and symlink aliases,
and records each explicit stock-file replacement in the session lock. Prepared
inputs must include the assembled stock-init configuration. Autostart hooks are
rejected.

Build the app with `cargo-scarlet app build --source manager/app.toml`, build the
frontend above and the [graphics outputs](graphics/README.md), then run:

```sh
python3 producer/tools/build_session.py \
  --aosp-archive producer/artifacts/android-aarch64-v0.1.0.tar.gz \
  --boot-inputs /path/to/prepared-boot-inputs \
  --android-app /path/to/android.app \
  --android-runtime /path/to/android-runtime \
  --graphics-hal /path/to/hal \
  --graphics-adapters /path/to/adapters \
  --version v0.1.0 --output producer/artifacts/session
```

That manual session command is separate from release CI. Release CI imports the
preserved, checksum-pinned runtime with
`producer/tools/import_session_runtime.py`, then adds the independently built
native archive. A release `bundle.toml` has two hash-pinned archive layers: the
complete runtime at `/systems/android-aarch64` and the native app/frontend at
`/`. Existing outputs are never overwritten, and the imported archive retains
its input lock and upstream provenance.

## Licensing

The producer and native Scarlet sources use MIT; copied Scarlet sources retain
their original license. AOSP-derived adapter interfaces retain Apache 2.0 notices
and the license in `runtime/network/LICENSE-APACHE-2.0`.
The Android images remain under their upstream licenses. The SDK `NOTICE.txt`,
image identity, build fingerprint, and exact input digest are retained in every
archive. See [ATTRIBUTION.md](ATTRIBUTION.md).

The `v*` tag or manual workflow requires a corresponding-source archive URL,
SHA-256 and exact source revision. CI imports the pinned complete runtime and
builds the native overlay, validates both binary archives and the source digest,
creates a draft prerelease with both archives and provenance, then commits the
verified manifest to `bundles/android/bundle.toml` before the release is made
public. The `default` tag and retained NOTICE are input identity, not a
substitute for the source record. See `producer/release-notes.md`.
