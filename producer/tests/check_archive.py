#!/usr/bin/env python3
"""Reject malformed, escaping, or incomplete Android bundle archives."""
from __future__ import annotations

import argparse
import json
import posixpath
import tarfile
from pathlib import Path

ROOT = "android-aarch64"
ALLOWED_GUEST_ALIAS_ROOTS = (
    "/apex/", "/config/", "/data/", "/data_mirror/", "/debug_ramdisk/",
    "/dev/", "/linkerconfig/", "/metadata/", "/mnt/", "/odm/", "/odm_dlkm/",
    "/proc/", "/product/", "/sdcard/", "/storage/", "/sys/", "/system/",
    "/system_dlkm/", "/system_ext/", "/vendor/", "/vendor_dlkm/",
)


def validate_symlink(name: str, target: str) -> None:
    if target.startswith("/"):
        resolved = posixpath.normpath(target)
        if not any(resolved == root.rstrip("/") or resolved.startswith(root)
                   for root in ALLOWED_GUEST_ALIAS_ROOTS):
            raise ValueError("absolute symlink escapes Android userspace: " + name)
        return
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
    if resolved != ROOT and not resolved.startswith(ROOT + "/"):
        raise ValueError("escaping symlink: " + name)


def check_archive(path: Path) -> int:
    required = {
        f"{ROOT}/provenance.json",
        f"{ROOT}/licenses/android-sdk/NOTICE.txt",
        f"{ROOT}/system/build.prop",
        f"{ROOT}/init",
        f"{ROOT}/init.environ.rc",
        f"{ROOT}/apex",
        f"{ROOT}/system/bin/init",
        f"{ROOT}/system/bin/app_process64",
        f"{ROOT}/system/bin/surfaceflinger",
        f"{ROOT}/vendor/etc/init/hw/init.ranchu.rc",
    }
    seen = set()
    symlinks = set()
    regular_files = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name.rstrip("/")
            if not name or name.startswith("/") or ".." in Path(name).parts:
                raise ValueError("unsafe archive path: " + name)
            if name != ROOT and not name.startswith(ROOT + "/"):
                raise ValueError("entry outside the bundle root: " + name)
            if any(parent.as_posix() in symlinks for parent in Path(name).parents):
                raise ValueError("entry below a symlink: " + name)
            if name in seen:
                raise ValueError("duplicate archive path: " + name)
            seen.add(name)
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError("unsupported archive node: " + name)
            if member.issym():
                symlinks.add(name)
                validate_symlink(name, member.linkname)
            if member.islnk() and member.linkname not in regular_files:
                raise ValueError("invalid hardlink target: " + name)
            if member.isfile() or member.islnk():
                regular_files.add(name)
        provenance = json.load(archive.extractfile(f"{ROOT}/provenance.json"))
        if provenance["source"]["tag"] != "default" or provenance["source"]["abi"] != "arm64-v8a":
            raise ValueError("unexpected image identity")
        # These values come from the pinned source inodes and catch an exporter
        # accidentally replacing Android's attributes with host ownership.
        run_as = archive.getmember(f"{ROOT}/system/bin/run-as")
        if (run_as.uid, run_as.gid, run_as.mode) != (0, 2000, 0o750):
            raise ValueError("run-as ownership or mode was lost")
        if run_as.pax_headers.get("SCHILY.xattr.security.selinux") != "u:object_r:runas_exec:s0\0":
            raise ValueError("run-as SELinux label was lost")
        capability = run_as.pax_headers.get("SCHILY.xattr.security.capability", "").encode("utf-8", "surrogateescape")
        if capability != bytes.fromhex("01000002c0000000000000000000000000000000"):
            raise ValueError("run-as capability xattr was lost")
    missing = required - seen
    if missing:
        raise ValueError("missing required entries: " + ", ".join(sorted(missing)))
    print(f"archive ok: {len(seen)} entries")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    return check_archive(args.archive)


if __name__ == "__main__":
    raise SystemExit(main())
