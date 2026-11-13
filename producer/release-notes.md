# AOSP Android 13 ARM64 userspace image

Experimental stock AOSP Android 13 AArch64 userspace archive for Scarlet. The
binary contains no Scarlet kernel or ABI module.

The input fingerprint is
`Android/sdk_phone64_arm64/emulator64_arm64:13/TE1A.220922.034/10940250:userdebug/test-keys`.

This release includes the binary archive, the exact corresponding-source
archive, a producer-source archive, `corresponding-source.json`, both checksum
manifests, and the `bundle.toml` used by Scarlet. The release workflow validates
the binary archive, source SHA-256 and exact source revision, uploads every
asset to a draft prerelease, verifies the uploaded sizes, pins the manifest, and
only then makes the release public.

The binary archive retains `licenses/android-sdk/NOTICE.txt` and
`provenance.json`. Android images remain under their upstream licenses; the
repository's MIT license covers only its original producer code and
documentation.
