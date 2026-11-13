# scarlet-bundle-android

AOSP userspace bundle producer for Scarlet.

This repository is the distribution boundary for Android images and Android's
userspace launcher/adapters. The Scarlet kernel, Linux and Android ABI modules,
system-call integration, native protection mechanisms and compositor stay
in [`petitstrawberry/Scarlet`](https://github.com/petitstrawberry/Scarlet).
Scarlet consumes a verified release archive through a normal `bundle.toml`
`archive` layer.

The current producer exports the AOSP Android 13 ARM64 emulator image with tag
`default`. Google APIs and Play Store images are rejected. The launcher and HALs
have not yet been migrated from Scarlet. No binary release has been published:
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
PAX archive. Absolute in-image symlinks become equivalent relative links inside
the archive. No files or services are selected out. It writes:

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

## Licensing

The repository's MIT license covers only the producer scripts and documentation.
The Android images remain under their upstream licenses. The SDK `NOTICE.txt`,
image identity, build fingerprint, and exact input digest are retained in every
archive. See [ATTRIBUTION.md](ATTRIBUTION.md).

Before publishing a binary, establish its exact matching source manifest and
provide the corresponding source materials required by included licenses. The
`default` tag and retained NOTICE are input identity, not proof of redistribution
compliance. See `producer/release-notes.md` for the unresolved source identity.
