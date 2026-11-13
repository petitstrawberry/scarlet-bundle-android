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
No binary release has been published:
the exact corresponding-source record for SDK build 10940250 is still missing.

## Build

Requirements: Python 3.11+, `debugfs`, and the pinned SDK archive.

```sh
curl -LO https://dl.google.com/android/repository/sys-img/android/arm64-v8a-33_r02.zip
python3 producer/tools/build_rootfs.py \
  --sdk-image arm64-v8a-33_r02.zip \
  --version v0.1.0 \
  --output producer/artifacts
```

The producer verifies the input SHA-256 and AOSP tag, exports all four userspace
partitions (including the complete system-as-root tree), and preserves numeric
ownership, modes, modification times, hardlinks and extended attributes in the
PAX archive. Symlink targets retain their original absolute or relative form;
absolute targets are validated as guest paths without following host files.
This also preserves references from APEX payloads after stock apexd mounts
them at `/apex`. No files or services are selected out. It writes:

- `android-aarch64-v0.1.0.tar.gz`
- `SHA256SUMS`
- `bundle.toml` as the candidate hash-pinned consumer manifest
- `provenance.json` inside the artifact

Validate the archive with
`python3 producer/tests/check_archive.py producer/artifacts/android-aarch64-v0.1.0.tar.gz`.
Run the image-export regression with
`python3 -m unittest discover -s producer/tests` (requires `mke2fs` and `debugfs`).
It checks real ext4 inodes, binary xattrs, hardlinks, system-as-root contents and
reproducible archive bytes without root privileges.

Once a release is ready, a normal Scarlet bundle can consume the generated
manifest. The metadata-preserving SDK importer is available in
[`scarlet-sdk` commit 743bf61](https://github.com/petitstrawberry/scarlet-sdk/commit/743bf61),
on `fix/archive-inode-metadata`. The complete archive was imported into ext2 and
sampled for ownership and label retention. Scarlet's default SDK pin and image
have not been switched. This stock archive alone is not a configured or
boot-validated Scarlet Android environment.

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

`manager/app.toml` is the normal Scarlet app recipe. `bundles/native/bundle.toml`
installs it at `/applications/android.app`, the frontend at `/bin/android-runtime`,
and the explicit administrator grant under `/etc/stemd.d/capabilities`. The
generated app descriptor provides its catalog entry with the same exact argv.
The grant pairs `target = 3` with `shield_policy_factory = 4`. This requires
Scarlet's explicit factory grants from commit
[`7c96ed773`](https://github.com/petitstrawberry/Scarlet/commit/7c96ed773), which
includes the whole-View mount preservation fix and the native factory API.
The complete session archive has imported through the SDK and booted the normal
four-core HVF desktop. A manual catalog launch received both capabilities,
created the Shield policy, registered 81 boot file labels and started stock init
in its own PID/mount namespace. The native Android window, SurfaceFlinger and
graphics HAL processes were observed. Home and app display remain unverified.
The last boot stopped at i18n APEX library resolution; the producer now preserves
the absolute symlink targets needed after APEX mount relocation. Stock logd
also did not remain running. Configured launches require the exact
command and capture startup errors in the native logd. The stock init lifecycle
begins after an explicit catalog launch.
The full producer archive above contains stock AOSP only.

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

`producer/tools/build_session.py` combines the full stock archive with a prepared
boot profile, the native app, frontend and graphics outputs. It verifies the
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

The generated `bundle.toml` has one hash-pinned archive layer containing
`/applications/android.app`, `/bin/android-runtime`, the stemd grant and the
complete `/systems/android-aarch64` tree. Add that manifest as a normal `bundle`
layer in the Scarlet root image. Local builds use an absolute `file://` URL;
`--archive-url` selects the eventual release URL without changing archive bytes.
Existing outputs are never overwritten. The session lock records all input
hashes and original/installed hashes for device-profile replacements.

## Licensing

The producer and native Scarlet sources use MIT; copied Scarlet sources retain
their original license. AOSP-derived adapter interfaces retain Apache 2.0 notices
and the license in `runtime/network/LICENSE-APACHE-2.0`.
The Android images remain under their upstream licenses. The SDK `NOTICE.txt`,
image identity, build fingerprint, and exact input digest are retained in every
archive. See [ATTRIBUTION.md](ATTRIBUTION.md).

Before publishing a binary, establish its exact matching source manifest and
provide the corresponding source materials required by included licenses. The
`default` tag and retained NOTICE are input identity, not proof of redistribution
compliance. See `producer/release-notes.md` for the unresolved source identity.
