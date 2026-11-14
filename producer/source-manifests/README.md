# Android corresponding-source records

These archives pin the exact AOSP source manifest used for a released Android
image. Each archive contains the tagged `platform/manifest` checkout and a
`SOURCE-RECORD.json` identifying the image fingerprint, input digest, manifest
tag/commit and the command used to retrieve the component sources.

`android-13.0.0_r15-source.tar.zst` records AOSP tag
`android-13.0.0_r15` at manifest commit
`1013d985f70641b2cc05943f57fab5824d9e2ff3`. The release workflow copies this
archive into the GitHub Release and records its URL and SHA-256 in
`corresponding-source.json`.
