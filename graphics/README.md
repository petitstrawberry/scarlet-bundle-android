# Scarlet Android graphics

This directory contains the reusable CPU gralloc/framebuffer HAL and the stock
gralloc0-to-HIDL mapper, allocator, and composer adapters. The checked-in source
files are exact copies of the validated Scarlet Android 13 sources. Probes,
test runners, checkpoints, init code, kernel code, and Scarlet shared libraries
stay in their original projects.

The HAL has no ScarletUI or SWS header dependency. The adapters include the
dynamic framebuffer resize changes: synchronized mode, state, and callback
publication; fresh HWC configuration IDs; hotplug notifications; buffer
replacement; and failed presentation propagation.

## Build inputs

Both builders use the pinned Android 13 AOSP headers described by
headers.json and adapter-headers.json. input-lock.json fixes the graphics
source hashes and the 13 system libraries used by the adapters. A library root
passed as --android-root must contain those exact paths and hashes.

Use a validated header cache containing the named pin trees to avoid downloads:

    python3 graphics/build-graphics-hal.py \
      --ndk /path/to/ndk \
      --reuse-headers /path/to/hal-header-cache \
      --output /path/to/artifacts/hal \
      --jobs 2

    python3 graphics/build-graphics-adapters.py \
      --ndk /path/to/ndk \
      --android-root /path/to/flattened-android-system \
      --reuse-headers /path/to/adapter-header-cache \
      --output /path/to/artifacts/adapters \
      --jobs 2

Without --reuse-headers, the builders download bounded header archives and
verify every archive's file-content tree hash. Header caches are checked in
place; temporary download trees are removed after the build.

The NDK is expected to provide API 33 ARM64 compilers for the current host.
The adapter builder links directly against the hash-verified system libraries,
so no Android root is needed by the HAL builder.

Output directories must not already exist. Successful builds write
build.json beside the binary products and include exact commands, compiler
identity, source and input hashes, output hashes, and ELF NEEDED entries.
Execution, service registration, and composition readiness are not asserted.

## Install targets

Install the four build products and the composer interface companion at these
device paths:

| Source or build product | Device path |
| --- | --- |
| `gralloc.scarlet.so` | `/vendor/lib64/hw/gralloc.scarlet.so` |
| `android.hardware.graphics.mapper@2.0-impl.scarlet.so` | `/vendor/lib64/hw/android.hardware.graphics.mapper@2.0-impl.scarlet.so` |
| `android.hardware.graphics.allocator@2.0-service.scarlet` | `/vendor/bin/hw/android.hardware.graphics.allocator@2.0-service.scarlet` |
| `android.hardware.graphics.composer@2.1-service.scarlet` | `/vendor/bin/hw/android.hardware.graphics.composer@2.1-service.scarlet` |
| `/system/lib64/android.hardware.graphics.composer@2.1.so` | `/vendor/lib64/android.hardware.graphics.composer@2.1.so` |

The mapper is a HIDL implementation library loaded from `hw`; it has no
mapper service executable. The composer service's exact HIDL interface DSO
must also be available in the vendor namespace at the path above. The
consuming image provides its init registrations and SELinux policy.
