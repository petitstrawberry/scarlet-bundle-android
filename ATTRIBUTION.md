# Third-party contents

The MIT license in this repository covers its original producer and native
userspace code. The manager, app policy translator and display/input frontend
derive from `petitstrawberry/Scarlet` commit
`2d5308067367a2f697cfed45b90d8f3c324a7c81`; their original MIT license is retained
in each source directory. See `runtime/ATTRIBUTION.md` for AOSP-derived interfaces.
These licenses do not relicense Android or components in the system images.

The boot profile in `profiles/scarlet-arm64-flattened.json` is copied from
`tools/android-compat/profiles/scarlet-arm64-flattened.json` at Scarlet commit
`bad9815a662ae15f3822594b024326b70f3acaaa` (SHA-256
`0b6bd76df28e4ca025acffc256b60bee5364230e893e705913ec629096e0f0b6`).
The pure policy generation and selection-validation code in `producer/policy/`
is extracted from the same revision's `tools/android-compat/boot_profile.py`,
`service_policy.py`, `vintf_inputs.py`, `host_services.py` and `desktop_inputs.py`.
It retains the original MIT license; VM execution, staging and export tools are
outside this extraction.

## Input image

- Package: Android SDK System Image
- API: 33
- ABI: `arm64-v8a`
- Tag: `default` (AOSP, not Google APIs and not Play Store)
- Source: `https://dl.google.com/android/repository/sys-img/android/arm64-v8a-33_r02.zip`
- SHA-256: `55ba9a20d473dd5351c77342016956342c40375f3e073b65a43dc9db13ccc5c6`

The archive contains `NOTICE.txt` from the pinned SDK image at
`/licenses/android-sdk/NOTICE.txt` and records the original image URI, digest,
tag, ABI, source properties, and build properties in `/provenance.json`.

## Source distribution

A binary release must not be published unless its release notes identify the
corresponding AOSP source revision for the exact build fingerprint and the
corresponding-source material required by the licenses of every included
component. The producer preserves the SDK notices but does not claim that a
notice alone satisfies source-distribution obligations.

The current binary identifies itself as
`Android/sdk_phone64_arm64/emulator64_arm64:13/TE1A.220922.034/10940250:userdebug/test-keys`.
Its exact matching source manifest has not been established. Do not substitute
an arbitrary Android 13 release tag for that build's source identity.

The [Android SDK terms, sections 3.4–3.5](https://developer.android.com/studio/terms)
distinguish the SDK's distribution restrictions from components governed by
their own open source licenses. AOSP also documents its
[license policy and exceptions](https://source.android.com/docs/setup/contribute/licenses).
The producer's input tag is not a per-component license inventory.

Android is a trademark of Google LLC. This is an independent compatibility
artifact for Scarlet and is not an official Android or Google release.
