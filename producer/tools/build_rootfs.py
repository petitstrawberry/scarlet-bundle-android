#!/usr/bin/env python3
"""Extract a pinned AOSP image and produce Scarlet's archive bundle."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "producer/lock.json"
ARCHIVE_ROOT = "android-aarch64"
ALLOWED_GUEST_ALIAS_ROOTS = (
    "/apex/", "/config/", "/data/", "/data_mirror/", "/debug_ramdisk/",
    "/dev/", "/linkerconfig/", "/metadata/", "/mnt/", "/odm/", "/odm_dlkm/",
    "/proc/", "/product/", "/sdcard/", "/storage/", "/sys/", "/system/",
    "/system_dlkm/", "/system_ext/", "/vendor/", "/vendor_dlkm/",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_exact(source, target: Path, size: int) -> None:
    remaining = size
    with target.open("xb") as destination:
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("truncated ext4 extent")
            destination.write(chunk)
            remaining -= len(chunk)


def extract_partitions(archive: Path, lock: dict, output: Path) -> dict:
    records = {}
    with zipfile.ZipFile(archive) as sdk:
        source_properties = sdk.read(f"{lock['abi']}/source.properties").decode()
        build_properties = sdk.read(f"{lock['abi']}/build.prop").decode()
        properties = dict(line.split("=", 1) for line in source_properties.splitlines()
                          if "=" in line and not line.startswith("#"))
        if properties.get("SystemImage.TagId") != lock["tag"]:
            raise ValueError("input is not the pinned AOSP default tag")
        with sdk.open(f"{lock['abi']}/system.img") as source:
            for name, (sector, sectors) in lock["partitions"].items():
                target = output / f"{name}.ext4"
                offset, size = (4096 + sector) * 512, sectors * 512
                source.seek(offset)
                copy_exact(source, target, size)
                with target.open("rb") as check:
                    check.seek(1080)
                    if check.read(2) != b"\x53\xef":
                        raise ValueError(f"{name} is not ext4")
                records[name] = {"offset": offset, "size": size, "sha256": sha256(target)}
    return {
        "source_properties": source_properties,
        "build_properties": build_properties,
        "partitions": records,
    }


def quote_debugfs(value: str | Path) -> str:
    value = str(value)
    if any(char in value for char in ('\n', '\r', '\0')):
        raise ValueError("invalid debugfs argument")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def debugfs(image: Path, commands: list[str]) -> list[str]:
    result = subprocess.run(
        ["debugfs", "-f", "-", str(image)],
        input="\n".join(commands) + "\n", capture_output=True, text=True,
    )
    unexpected = [line for line in result.stderr.splitlines()
                  if line and not line.startswith("debugfs ")]
    if result.returncode or unexpected:
        raise ValueError("debugfs failed: " + "; ".join(unexpected[:3]))
    sections = re.split(r"^debugfs: [^\n]*\n", result.stdout, flags=re.MULTILINE)
    if sections[0] or len(sections) != len(commands) + 1:
        raise ValueError("unexpected debugfs batch output")
    return sections[1:]


def rdump(image: Path, target: Path) -> None:
    target.mkdir(parents=True)
    result = subprocess.run(
        ["debugfs", "-R", f"rdump / {quote_debugfs(target)}", str(image)],
        capture_output=True, text=True,
    )
    unexpected = [line for line in result.stderr.splitlines()
                  if line
                  and not line.startswith("debugfs ")
                  and "Operation not permitted while changing ownership" not in line]
    if result.returncode or unexpected:
        raise ValueError("debugfs extraction failed: " + "; ".join(unexpected[:3]))


def read_metadata(image: Path, tree: Path, scratch: Path) -> dict:
    """Read inode attributes from the image, not the unprivileged host dump."""
    nodes = [tree, *sorted(tree.rglob("*"))]
    paths = ["/" if node == tree else "/" + node.relative_to(tree).as_posix()
             for node in nodes]
    stats = debugfs(image, ["stat " + quote_debugfs(path) for path in paths])
    metadata = {}
    attributes = []
    scratch.mkdir()
    for node, path, output in zip(nodes, paths, stats, strict=True):
        inode = re.search(r"^Inode: (\d+)\s+Type: (\w+)\s+Mode:\s+([0-7]+)", output, re.M)
        owner = re.search(r"^User:\s+(\d+)\s+Group:\s+(\d+)", output, re.M)
        modified = re.search(r"^ mtime: 0x([0-9a-f]+)(?::([0-9a-f]+))?", output, re.M)
        if not inode or not owner or not modified:
            raise ValueError("missing inode attributes: " + path)
        seconds = int(modified[1], 16)
        if seconds & (1 << 31):
            seconds -= 1 << 32
        extra = int(modified[2] or "0", 16)
        seconds += (extra & 3) << 32
        entry = {"inode": int(inode[1]), "type": inode[2], "mode": int(inode[3], 8),
                 "uid": int(owner[1]), "gid": int(owner[2]), "mtime": seconds,
                 "mtime_ns": extra >> 2, "xattrs": {}}
        if entry["type"] not in ("regular", "directory", "symlink"):
            raise ValueError("unsupported inode type: " + path)
        metadata[node.relative_to(tree).as_posix()] = entry
        for name, length in re.findall(r"^  ([^\s]+) \((\d+)\) =", output, re.M):
            target = scratch / str(len(attributes))
            attributes.append((path, name, int(length), target, entry))
    if attributes:
        debugfs(image, [f"ea_get -f {quote_debugfs(target)} {quote_debugfs(path)} {quote_debugfs(name)}"
                        for path, name, _, target, _ in attributes])
    for path, name, length, target, entry in attributes:
        value = target.read_bytes()
        if len(value) != length:
            raise ValueError("incomplete extended attribute: " + path + ":" + name)
        entry["xattrs"][name] = value
    return metadata


def merge_tree(source: Path, destination: Path) -> None:
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError("partition mountpoint is not a directory: " + str(destination))
    destination.mkdir(parents=True, exist_ok=True)
    for node in sorted(source.iterdir(), key=lambda value: value.name):
        target = destination / node.name
        if node.is_dir() and not node.is_symlink() and target.is_dir() and not target.is_symlink():
            merge_tree(node, target)
        elif target.exists() or target.is_symlink():
            raise ValueError("partition tree collision: " + str(target))
        elif node.is_symlink():
            target.symlink_to(os.readlink(node))
        elif node.is_dir():
            shutil.copytree(node, target, symlinks=True)
        elif node.is_file():
            shutil.copy2(node, target)
        else:
            raise ValueError("unsupported partition node: " + str(node))


def guest_link_resolution(link_name: str, target: str) -> str:
    """Resolve a guest symlink target without touching the host filesystem."""
    if not target or "\\" in target or "\0" in target:
        raise ValueError("invalid guest symlink target: " + link_name)
    if target.startswith("/"):
        resolved = posixpath.normpath(target)
    else:
        resolved = posixpath.normpath(posixpath.join("/", posixpath.dirname(link_name), target))
    if not any(resolved == root.rstrip("/") or resolved.startswith(root)
               for root in ALLOWED_GUEST_ALIAS_ROOTS):
        raise ValueError("guest symlink escapes the Android userspace: " + link_name)
    return resolved


def normalize_link(link_name: str, target: str) -> str:
    """Preserve absolute guest targets after validating their destination."""
    if not target.startswith("/"):
        return target
    guest_link_resolution(link_name, target)
    return target


def assemble_root(partitions: Path, temporary: Path) -> tuple[Path, dict]:
    root = temporary / ARCHIVE_ROOT
    root.mkdir()
    metadata = {}
    for name in ("system", "system_ext", "product", "vendor"):
        dumped = temporary / (name + "-tree")
        image = partitions / (name + ".ext4")
        rdump(image, dumped)
        entries = read_metadata(image, dumped, temporary / (name + "-xattrs"))
        # system-as-root includes /init, init.environ.rc and Android's root
        # directories. Keep the entire tree, then populate its mountpoints.
        destination = root if name == "system" else root / name
        merge_tree(dumped, destination)
        for relative, entry in entries.items():
            key = relative if name == "system" else name if relative == "." else name + "/" + relative
            metadata[key] = {**entry, "partition": name}
    return root, metadata


def apply_boot_properties(root: Path, profile_path: Path) -> None:
    """Apply the explicit Android device profile to the stock product props."""
    profile = json.loads(profile_path.read_text())
    properties = profile.get("boot_properties")
    if not isinstance(properties, dict) or not properties:
        raise ValueError("profile boot_properties are missing")
    normalized = {}
    for key, value in properties.items():
        if (not isinstance(key, str) or not isinstance(value, str) or
                re.fullmatch(r"[A-Za-z0-9_.-]+", key) is None or
                any(character in value for character in "\0\r\n")):
            raise ValueError("invalid boot property")
        normalized[key] = value
    path = root / "product/etc/build.prop"
    if not path.is_file() or path.is_symlink():
        raise ValueError("product build.prop is missing")
    lines = [line for line in path.read_text().splitlines()
             if line.split("=", 1)[0] not in normalized]
    lines.extend(f"{key}={value}" for key, value in sorted(normalized.items()))
    path.write_text("\n".join(lines) + "\n")


def write_archive(root: Path, output: Path, metadata: dict) -> None:
    # Do not include a host filename or wall-clock gzip timestamp in the digest.
    with output.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        nodes = [root, *sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix())]
        hardlinks = {}
        for node in nodes:
            relative = node.relative_to(root).as_posix()
            name = ARCHIVE_ROOT if relative == "." else f"{ARCHIVE_ROOT}/{relative}"
            info = archive.gettarinfo(str(node), arcname=name)
            source = metadata.get(relative)
            if source:
                info.uid, info.gid, info.mode = source["uid"], source["gid"], source["mode"]
                info.pax_headers = {"SCHILY.xattr." + key: value.decode("utf-8", "surrogateescape")
                                    for key, value in source["xattrs"].items()}
                info.mtime = source["mtime"]
                if source["mtime_ns"]:
                    info.pax_headers["mtime"] = f"{source['mtime']}.{source['mtime_ns']:09d}"
                if info.isreg():
                    identity = (source["partition"], source["inode"])
                    if identity in hardlinks:
                        info.type, info.size, info.linkname = tarfile.LNKTYPE, 0, hardlinks[identity]
                    else:
                        hardlinks[identity] = name
            else:
                info.uid = info.gid = 0
                info.mode = 0o755 if info.isdir() else 0o644
                info.mtime = 0
            info.uname = info.gname = ""
            if info.issym():
                info.linkname = normalize_link(relative, info.linkname)
            if info.isreg():
                with node.open("rb") as stream:
                    archive.addfile(info, stream)
            elif info.isdir() or info.issym() or info.islnk():
                archive.addfile(info)
            else:
                raise ValueError("unsupported archive node: " + str(node))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-image", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--profile", type=Path,
                        default=ROOT / "profiles/scarlet-arm64-flattened.json",
                        help="device profile whose boot properties are applied to product build.prop")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.version):
        parser.error("--version must look like v0.1.0")
    lock_document = json.loads(LOCK_PATH.read_text())
    lock = lock_document["android"]
    lock["partitions"] = lock_document["partitions"]
    if sha256(args.sdk_image) != lock["sha256"]:
        raise ValueError("Android SDK image SHA-256 mismatch")
    args.output.mkdir(parents=True, exist_ok=True)
    archive_name = f"android-aarch64-{args.version}.tar.gz"
    archive_path = args.output / archive_name
    if archive_path.exists():
        raise ValueError("refusing to overwrite an existing artifact")
    with tempfile.TemporaryDirectory(prefix="android-bundle-", dir=args.output) as directory:
        temporary = Path(directory)
        partitions = temporary / "partitions"
        partitions.mkdir()
        provenance_input = extract_partitions(args.sdk_image, lock, partitions)
        root, metadata = assemble_root(partitions, temporary)
        if args.profile is not None:
            apply_boot_properties(root, args.profile)
        with zipfile.ZipFile(args.sdk_image) as sdk:
            notice = sdk.read(f"{lock['abi']}/NOTICE.txt")
        notice_path = root / "licenses/android-sdk/NOTICE.txt"
        notice_path.parent.mkdir(parents=True)
        notice_path.write_bytes(notice)
        provenance = {
            "schema": 1,
            "kind": "scarlet-android-aosp-userspace",
            "version": args.version,
            "source": {key: lock[key] for key in ("api", "abi", "tag", "url", "sha256")},
            "partitions": provenance_input["partitions"],
            "source_properties": provenance_input["source_properties"],
            "build_properties": provenance_input["build_properties"],
        }
        if args.profile is not None:
            provenance["device_profile"] = {
                "path": args.profile.name,
                "sha256": sha256(args.profile),
                "boot_properties": dict(sorted(
                    json.loads(args.profile.read_text())["boot_properties"].items())),
            }
        (root / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
        candidate = temporary / archive_name
        write_archive(root, candidate, metadata)
        # Publish only a completed local archive; never replace an existing version.
        os.link(candidate, archive_path)
    digest = sha256(archive_path)
    (args.output / "SHA256SUMS").write_text(f"{digest}  {archive_name}\n")
    manifest = (
        "# Generated by scarlet-bundle-android.\n\n[[layers]]\n"
        "kind = \"archive\"\n"
        f"url = \"https://github.com/petitstrawberry/scarlet-bundle-android/releases/download/{args.version}/{archive_name}\"\n"
        f"sha256 = {{ aarch64 = \"sha256:{digest}\" }}\n"
        "format = \"tar-gz\"\nstrip_components = 1\nto = \"/systems/android-aarch64\"\n"
    )
    (args.output / "bundle.toml").write_text(manifest)
    print(archive_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
