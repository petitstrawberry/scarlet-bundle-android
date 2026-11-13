#!/usr/bin/env python3
"""Package verified Android inputs as one ordinary Scarlet archive bundle.

The AOSP PAX archive is the authority for stock inode metadata.  Prepared boot
inputs are applied as a strict virtual overlay: files repeated from AOSP keep
the stock uid/gid/mode/xattrs, while new files receive deterministic root
ownership and conservative modes.  Host symlinks are never followed.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10 hosts use the packaged fallback.
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "producer"))
from policy.selections import DEVICE_PROVIDERS, KEYMINT_DEVICE, validate_vintf_selection

AOSP_ROOT = "android-aarch64"
OUTER_ROOT = "android-session-aarch64"
ANDROID_ROOT = "systems/android-aarch64"
ALLOWED_BOOT_ALIAS_ROOTS = (
    "/apex/", "/config/", "/data/", "/data_mirror/", "/debug_ramdisk/",
    "/dev/", "/linkerconfig/", "/metadata/", "/mnt/", "/odm/", "/odm_dlkm/",
    "/proc/", "/product/", "/sdcard/", "/storage/", "/sys/", "/system/",
    "/system_dlkm/", "/system_ext/", "/vendor/", "/vendor_dlkm/",
)
GRAPHICS_INSTALL_PATHS = {
    "hal/gralloc.scarlet.so": "vendor/lib64/hw/gralloc.scarlet.so",
    "adapters/android.hardware.graphics.mapper@2.0-impl.scarlet.so":
        "vendor/lib64/hw/android.hardware.graphics.mapper@2.0-impl.scarlet.so",
    "adapters/android.hardware.graphics.allocator@2.0-service.scarlet":
        "vendor/bin/hw/android.hardware.graphics.allocator@2.0-service.scarlet",
    "adapters/android.hardware.graphics.composer@2.1-service.scarlet":
        "vendor/bin/hw/android.hardware.graphics.composer@2.1-service.scarlet",
}
HASH = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
AUTOSTART = re.compile(r"(?:^|[_.-])autostart(?:$|[_.-])", re.IGNORECASE)
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_TREE_ENTRIES = 50_000
MAX_TREE_BYTES = 16 * 1024 * 1024 * 1024
MAX_POLICY_BYTES = 1024 * 1024
MAX_POLICY_LINE_CHARS = 8192
MAX_FILE_LABELS = 4096
COPY_CHUNK = 1024 * 1024
FILE_LABEL_POLICY = "scarlet/boot/shield.policy"
DEVICE_MANIFEST = "vendor/etc/vintf/manifest.xml"
DEVICE_FRAGMENT_ROOTS = ("vendor/etc/vintf/manifest", "odm/etc/vintf/manifest")
# Only the fragment roots themselves must be real directories. Android images
# commonly alias an entire partition prefix (for example ``odm/etc`` to
# ``/vendor/odm/etc``); requiring every lexical parent to be a directory would
# reject a stock tree without increasing the selection boundary.
DEVICE_VINTF_DIRECTORIES = set(DEVICE_FRAGMENT_ROOTS)
MAX_VINTF_BYTES = 256 * 1024
MAX_VINTF_FRAGMENTS = 256
EMPTY_DEVICE_MANIFEST = b'<manifest version="1.0" type="device" />\n'


class InputError(ValueError):
    """A local input is absent, changed, ambiguous, or unsafe."""


@dataclass(frozen=True)
class HostFile:
    source: Path
    sha256: str
    mode: int


@dataclass
class BootOverlay:
    root: Path
    manifest_path: Path
    manifest_sha256: str
    metadata: dict[str, Any]
    files: dict[str, HostFile]
    symlinks: dict[str, str]
    directories: set[str]


@dataclass
class ComponentTree:
    root: Path
    destination: str
    files: dict[str, HostFile] = field(default_factory=dict)
    directories: set[str] = field(default_factory=set)
    digest: str = ""
    pins: dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionPlan:
    aosp_archive: Path
    aosp_sha256: str
    stock_kinds: dict[str, str]
    stock_links: dict[str, str]
    stock_digests: dict[str, str]
    stock_provenance: dict[str, Any]
    boot: BootOverlay
    overlay_files: dict[str, HostFile]
    overlay_symlinks: dict[str, str]
    overlay_directories: set[str]
    components: dict[str, ComponentTree]
    runtime: HostFile
    manager_fs: ComponentTree
    native_entries: dict[str, HostFile]
    lock_inputs: dict[str, Any]
    generated_files: dict[str, bytes]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(COPY_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def require_regular(path: Path, label: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise InputError(f"{label} is missing: {path}") from error
    if not stat.S_ISREG(mode):
        raise InputError(f"{label} is not a regular file: {path}")
    return path


def require_directory(path: Path, label: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise InputError(f"{label} is missing: {path}") from error
    if not stat.S_ISDIR(mode):
        raise InputError(f"{label} is not a real directory: {path}")
    return path


def relative_path(value: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 4096 or
            value.startswith("/") or "\\" in value or
            any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise InputError("invalid input path")
    path = PurePosixPath(value)
    if str(path) != value or ".." in path.parts or path.parts == (".",):
        raise InputError(f"unsafe input path: {value}")
    return value


def reject_autostart_path(value: str) -> None:
    if any(AUTOSTART.search(part) for part in PurePosixPath(value).parts):
        raise InputError(f"autostart content is not allowed: {value}")


def read_json_limited(path: Path, label: str) -> tuple[dict[str, Any], str]:
    require_regular(path, label)
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise InputError(f"{label} exceeds its size bound")
    data = path.read_bytes()
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InputError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise InputError(f"{label} must contain an object")
    return value, hashlib.sha256(data).hexdigest()


def default_mode(path: str, source_mode: int) -> int:
    executable_path = path.startswith(("bin/", "systems/android-aarch64/bin/",
                                       "systems/android-aarch64/vendor/bin/"))
    return 0o755 if executable_path or source_mode & 0o111 else 0o644


def scan_tree(root: Path, destination: str, label: str) -> ComponentTree:
    """Index a host tree without following or retaining any host symlink."""
    require_directory(root, label)
    tree = ComponentTree(root=root, destination=destination)
    total = count = 0

    def visit(directory: Path, prefix: str) -> None:
        nonlocal total, count
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise InputError(f"cannot read {label}: {directory}") from error
        for entry in entries:
            name = entry.name
            if not name or name in (".", "..") or "/" in name or "\\" in name:
                raise InputError(f"invalid host path in {label}")
            relative = f"{prefix}/{name}" if prefix else name
            destination_path = f"{destination}/{relative}" if destination else relative
            reject_autostart_path(relative)
            count += 1
            if count > MAX_TREE_ENTRIES:
                raise InputError(f"{label} exceeds the entry bound")
            if entry.is_symlink():
                raise InputError(f"{label} contains a host symlink: {relative}")
            if entry.is_dir(follow_symlinks=False):
                tree.directories.add(destination_path)
                visit(Path(entry.path), relative)
            elif entry.is_file(follow_symlinks=False):
                path = Path(entry.path)
                size = path.stat().st_size
                total += size
                if total > MAX_TREE_BYTES:
                    raise InputError(f"{label} exceeds the byte bound")
                tree.files[destination_path] = HostFile(path, sha256_file(path), path.stat().st_mode)
            else:
                raise InputError(f"{label} contains an unsupported entry: {relative}")

    visit(root, "")
    tree.digest = canonical_digest({
        "files": {name: item.sha256 for name, item in sorted(tree.files.items())},
        "directories": sorted(tree.directories),
    })
    return tree


def validate_profile(profile: Any, metadata: dict[str, Any]) -> None:
    if not isinstance(profile, dict) or profile.get("version") not in (1, 2):
        raise InputError("boot profile version is unsupported")
    name = profile.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9-]+", name):
        raise InputError("boot profile name is invalid")
    for field_name in ("boot_properties", "bootconfig", "subjects", "init_imports"):
        if field_name not in profile:
            raise InputError(f"boot profile lacks {field_name}")
    properties = profile["boot_properties"]
    if not isinstance(properties, dict) or not properties:
        raise InputError("boot properties are missing")
    for key, value in properties.items():
        if AUTOSTART.search(str(key)):
            raise InputError(f"autostart property is not allowed: {key}")
        if not isinstance(key, str) or not isinstance(value, str):
            raise InputError("invalid boot property")
    imports = profile["init_imports"]
    if (not isinstance(imports, list) or not imports or len(set(imports)) != len(imports) or
            any(not isinstance(item, str) or not item.startswith("/") or
                ".." in PurePosixPath(item).parts for item in imports)):
        raise InputError("invalid boot init imports")
    for item in imports:
        reject_autostart_path(item)
    stock_init = metadata.get("stock_init")
    if (not isinstance(stock_init, dict) or stock_init.get("kind") != "scarlet-stock-init-assembly-v1" or
            stock_init.get("result") != "ASSEMBLED"):
        raise InputError("stock init must be explicitly ASSEMBLED")
    stock_files = stock_init.get("files")
    if not isinstance(stock_files, dict) or not stock_files:
        raise InputError("assembled stock init has no file hashes")
    declared = metadata.get("files")
    if not isinstance(declared, dict):
        raise InputError("boot input file manifest is missing")
    for path, digest in stock_files.items():
        relative_path(path)
        if HASH.fullmatch(str(digest)) is None or declared.get(path) != digest:
            raise InputError(f"stock init file is not pinned by the overlay: {path}")


def verify_boot_inputs(root: Path, manifest_path: Path | None) -> BootOverlay:
    root = require_directory(root, "boot inputs")
    manifest_path = root / "boot-profile.json" if manifest_path is None else manifest_path
    metadata, manifest_sha256 = read_json_limited(manifest_path, "boot profile")
    if metadata.get("kind") != "scarlet-android-boot-inputs-v1" or metadata.get("result") != "PREPARED":
        raise InputError("boot inputs are not verified and prepared")
    validate_profile(metadata.get("profile"), metadata)

    files = metadata.get("files")
    symlinks = metadata.get("symlinks")
    directories = metadata.get("directories")
    replacements = metadata.get("replacements", {})
    if not isinstance(files, dict) or not isinstance(symlinks, dict) or not isinstance(directories, list):
        raise InputError("boot input inventory is malformed")
    if not isinstance(replacements, dict):
        raise InputError("boot input replacements are malformed")
    if len(files) + len(symlinks) + len(directories) > MAX_TREE_ENTRIES:
        raise InputError("boot input inventory exceeds the entry bound")

    normalized_files: dict[str, HostFile] = {}
    normalized_links: dict[str, str] = {}
    for name, target in symlinks.items():
        relative_path(name)
        reject_autostart_path(name)
        normalized_links[name] = normalize_guest_link(name, target)
    normalized_directories = set()
    for name in directories:
        relative_path(name)
        reject_autostart_path(name)
        if name in normalized_directories:
            raise InputError(f"duplicate boot directory: {name}")
        normalized_directories.add(name)
    for name, digest in replacements.items():
        relative_path(name)
        if name not in files or HASH.fullmatch(str(digest)) is None:
            raise InputError(f"invalid boot replacement: {name}")
    if set(files) & (set(normalized_links) | normalized_directories):
        raise InputError("conflicting boot file entries")
    if set(normalized_links) & normalized_directories:
        raise InputError("conflicting boot symlink entries")
    for name in normalized_links:
        if any(parent.as_posix() in normalized_links for parent in PurePosixPath(name).parents):
            raise InputError(f"boot input is below a symlink: {name}")

    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    count = 0
    try:
        manifest_inside = manifest_path.relative_to(root).as_posix()
    except ValueError:
        manifest_inside = None

    def visit(directory: Path, prefix: str) -> None:
        nonlocal count
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            count += 1
            if count > MAX_TREE_ENTRIES:
                raise InputError("prepared boot tree exceeds its entry bound")
            if entry.is_symlink():
                raise InputError("prepared boot tree contains a host symlink")
            if entry.is_dir(follow_symlinks=False):
                actual_directories.add(relative)
                visit(Path(entry.path), relative)
            elif entry.is_file(follow_symlinks=False):
                if relative != manifest_inside:
                    actual_files.add(relative)
            else:
                raise InputError("prepared boot tree contains an unsupported entry")

    visit(root, "")
    if actual_files != set(files) or actual_directories != normalized_directories:
        missing = sorted(set(files) - actual_files)
        extra = sorted(actual_files - set(files))
        raise InputError(f"prepared boot tree inventory differs (missing={missing[:3]}, extra={extra[:3]})")

    # The tree scan above proves that no declared path can traverse a host
    # symlink.  Read and hash the files only after that check.
    for name, digest in files.items():
        relative_path(name)
        reject_autostart_path(name)
        if not isinstance(digest, str) or HASH.fullmatch(digest) is None:
            raise InputError(f"invalid boot input hash: {name}")
        source = root / name
        require_regular(source, f"boot input {name}")
        actual = sha256_file(source)
        if actual != digest:
            raise InputError(f"boot input hash mismatch: {name}")
        normalized_files[name] = HostFile(source, actual, source.stat().st_mode)
    return BootOverlay(root, manifest_path, manifest_sha256, metadata,
                       normalized_files, normalized_links, normalized_directories)


def normalize_guest_link(name: str, target: Any) -> str:
    """Validate a prepared-overlay link while retaining its target form."""
    guest_link_resolution(name, target)
    return target


def guest_link_resolution(name: str, target: Any) -> str:
    """Return the guest absolute path represented by a symlink target."""
    if not isinstance(target, str) or not target or len(target) > 4096 or "\\" in target or "\0" in target:
        raise InputError(f"invalid guest symlink target: {name}")
    if target.startswith("/"):
        resolved = posixpath.normpath(target)
    else:
        resolved = posixpath.normpath(posixpath.join("/", posixpath.dirname(name), target))
    if not any(resolved == root.rstrip("/") or resolved.startswith(root)
               for root in ALLOWED_BOOT_ALIAS_ROOTS):
        raise InputError(f"guest symlink escapes the Android userspace: {name}")
    return resolved


def is_device_fragment(path: str) -> bool:
    return any(path.startswith(root + "/") for root in DEVICE_FRAGMENT_ROOTS)


def is_other_device_aggregate(path: str) -> bool:
    return (path in {"vendor/manifest.xml", "odm/manifest.xml", "odm/etc/vintf/manifest.xml"} or
            any(path.startswith(f"{partition}/etc/vintf/manifest_") and path.endswith(".xml")
                for partition in ("vendor", "odm")))


def device_manifest_contracts(data: bytes, label: str) -> dict[str, dict[str, str]]:
    """Read the bounded AIDL/HIDL manifest subset used by the profile producer.

    Reject unrecognized constructs instead of claiming an exact selection after
    ignoring declarations, overrides, or alternate interface/version syntax.
    """
    def invalid() -> InputError:
        return InputError(f"malformed or ambiguous device VINTF manifest: {label}")

    if len(data) > MAX_VINTF_BYTES:
        raise InputError(f"device VINTF manifest exceeds its size bound: {label}")
    try:
        text = data.decode("utf-8")
        if "\0" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
            raise invalid()
        root = ET.fromstring(text)
    except (UnicodeDecodeError, ET.ParseError) as error:
        raise invalid() from error
    if (root.tag != "manifest" or root.get("type") != "device" or
            set(root.attrib) - {"version", "type", "target-level"} or
            re.fullmatch(r"[1-9][0-9]*\.[0-9]+", root.get("version", "")) is None or
            ("target-level" in root.attrib and
             re.fullmatch(r"[1-9][0-9]*", root.get("target-level", "")) is None) or
            sum(1 for _ in root.iter()) > 4096):
        raise invalid()

    def container(node: ET.Element, allowed: set[str]) -> None:
        if ((node.text or "").strip() or
                any(child.tag not in allowed or (child.tail or "").strip() for child in node)):
            raise invalid()

    def leaf(node: ET.Element, pattern: str, attributes: frozenset[str] | set[str] = frozenset()) -> str:
        value = (node.text or "").strip()
        if (len(node) or set(node.attrib) - attributes or len(value) > 256 or
                re.fullmatch(pattern, value) is None):
            raise invalid()
        return value

    def one(node: ET.Element, tag: str) -> ET.Element:
        matches = node.findall(tag)
        if len(matches) != 1:
            raise invalid()
        return matches[0]

    identifier = r"[A-Za-z_][A-Za-z0-9_]*"
    instance_name = r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*"
    instance = identifier + "/" + instance_name
    version_pattern = r"[0-9]+\.[0-9]+"
    container(root, {"hal", "sepolicy"})
    if len(root.findall("sepolicy")) > 1:
        raise invalid()
    for sepolicy in root.findall("sepolicy"):
        container(sepolicy, {"version"})
        if sepolicy.attrib:
            raise invalid()
        leaf(one(sepolicy, "version"), version_pattern)
    contracts: dict[str, dict[str, str]] = {}
    for hal in root.findall("hal"):
        container(hal, {"name", "transport", "version", "fqname", "interface"})
        kind = hal.get("format", "hidl")
        if kind not in ("aidl", "hidl") or set(hal.attrib) - {"format"}:
            raise invalid()
        package = leaf(one(hal, "name"), identifier + r"(?:\." + identifier + r")+")
        versions = [leaf(value, r"[1-9][0-9]*" if kind == "aidl" else version_pattern)
                    for value in hal.findall("version")]
        if len(versions) != len(set(versions)):
            raise invalid()
        arch = ""
        if kind == "aidl":
            if hal.findall("transport") or len(versions) > 1:
                raise invalid()
            versions = versions or ["1"]
            transport = "aidl"
        else:
            element = one(hal, "transport")
            transport = leaf(element, r"hwbinder|passthrough", {"arch"})
            arch = element.get("arch", "")
            if ((transport == "hwbinder" and arch) or
                    (transport == "passthrough" and arch not in ("32", "64", "32+64"))):
                raise invalid()
        declared = 0
        used_versions: set[str] = set()

        def add(version: str, qualified: str) -> None:
            nonlocal declared
            contract = (f"{package}.{qualified}" if kind == "aidl" else
                        f"{package}@{version}::{qualified}")
            if contract in contracts or len(contracts) >= MAX_VINTF_FRAGMENTS:
                raise invalid()
            contracts[contract] = {"format": kind, "version": version,
                                   "transport": transport, "arch": arch}
            declared += 1
            used_versions.add(version)

        for fqname in hal.findall("fqname"):
            if kind == "aidl":
                add(versions[0], leaf(fqname, instance))
            else:
                value = leaf(fqname, r"@" + version_pattern + r"::" + instance)
                version, qualified = value[1:].split("::")
                if versions and version not in versions:
                    raise invalid()
                add(version, qualified)
        for interface in hal.findall("interface"):
            container(interface, {"name", "instance"})
            if interface.attrib or not versions or not interface.findall("instance"):
                raise invalid()
            name = leaf(one(interface, "name"), identifier)
            for value in interface.findall("instance"):
                qualified = name + "/" + leaf(value, instance_name)
                for version in versions:
                    add(version, qualified)
        if not declared or set(versions) - used_versions:
            raise invalid()
    return contracts


def verify_device_vintf_selection(boot: BootOverlay) -> dict[str, Any] | None:
    selection = boot.metadata["profile"].get("vintf")
    if selection is None:
        return None
    try:
        validate_vintf_selection(selection)
    except ValueError as error:
        raise InputError(str(error)) from error
    aggregate = boot.files.get(DEVICE_MANIFEST)
    if aggregate is None:
        raise InputError("explicit device VINTF selection requires a prepared vendor aggregate")
    require_regular(aggregate.source, "prepared device VINTF aggregate")
    if (aggregate.source != boot.root / DEVICE_MANIFEST or
            aggregate.source.resolve() != boot.root.resolve() / DEVICE_MANIFEST):
        raise InputError("prepared device VINTF aggregate must be a regular file at its declared root")
    with aggregate.source.open("rb") as stream:
        data = stream.read(MAX_VINTF_BYTES + 1)
    actual = device_manifest_contracts(data, DEVICE_MANIFEST)
    if hashlib.sha256(data).hexdigest() != aggregate.sha256:
        raise InputError("prepared device VINTF aggregate changed during validation")
    expected = {}
    for contract in selection["device"]:
        transport = DEVICE_PROVIDERS[contract]
        kind = "aidl" if contract in KEYMINT_DEVICE else "hidl"
        version = (KEYMINT_DEVICE[contract][1] if kind == "aidl" else
                   contract.split("@", 1)[1].split("::", 1)[0])
        expected[contract] = {"format": kind, "version": version, "transport": transport,
                              "arch": "64" if transport == "passthrough" else ""}
    if actual != expected:
        raise InputError("prepared device VINTF aggregate differs from profile.vintf.device contracts")
    for path in (*boot.files, *boot.symlinks, *boot.directories):
        if (is_device_fragment(path) or is_other_device_aggregate(path) or
                (path in DEVICE_VINTF_DIRECTORIES and path not in boot.directories)):
            raise InputError(f"prepared device VINTF fragment conflicts with aggregate selection: {path}")
    return {"validation": "canonical-device-contracts-v1", "aggregate": DEVICE_MANIFEST,
            "aggregate_sha256": aggregate.sha256, "contracts": actual,
            "selection": selection["device"],
            "selection_sha256": canonical_digest(selection["device"]),
            "fragment_roots": list(DEVICE_FRAGMENT_ROOTS)}


def scan_aosp(archive: Path, boot: BootOverlay, device_selection: dict[str, Any] | None = None) -> tuple[
        str, dict[str, str], dict[str, str], dict[str, str], dict[str, Any], dict[str, bytes]]:
    require_regular(archive, "AOSP archive")
    archive_digest = sha256_file(archive)
    kinds: dict[str, str] = {}
    links: dict[str, str] = {}
    digests: dict[str, str] = {}
    hardlinks: dict[str, str] = {}
    generated: dict[str, bytes] = {}
    fragment_bytes = 0
    provenance_data: bytes | None = None
    count = 0
    with tarfile.open(archive, "r|gz") as source:
        for member in source:
            count += 1
            if count > MAX_ARCHIVE_MEMBERS:
                raise InputError("AOSP archive exceeds its member bound")
            name = member.name.rstrip("/")
            if name == AOSP_ROOT:
                relative = ""
            elif name.startswith(AOSP_ROOT + "/"):
                relative = name[len(AOSP_ROOT) + 1:]
            else:
                raise InputError(f"AOSP entry is outside {AOSP_ROOT}: {member.name}")
            if relative:
                relative_path(relative)
            if relative and relative in kinds:
                raise InputError(f"duplicate AOSP entry: {relative}")
            fragment = device_selection is not None and is_device_fragment(relative)
            if device_selection is not None:
                if relative in DEVICE_VINTF_DIRECTORIES and not member.isdir():
                    raise InputError(f"device VINTF directory is not a real directory: {relative}")
                if is_other_device_aggregate(relative):
                    raise InputError(f"ambiguous additional device VINTF aggregate: {relative}")
                if relative == DEVICE_MANIFEST and not member.isreg():
                    raise InputError("stock device VINTF aggregate is not a regular file")
            if fragment:
                if (not (member.isreg() or member.islnk()) or not relative.endswith(".xml") or
                        posixpath.dirname(relative) not in DEVICE_FRAGMENT_ROOTS):
                    raise InputError(f"unsupported device VINTF fragment kind or path: {relative}")
                if member.size > MAX_VINTF_BYTES or len(generated) >= MAX_VINTF_FRAGMENTS:
                    raise InputError("device VINTF fragments exceed their input bound")
                fragment_bytes += member.size
                if fragment_bytes > MAX_MANIFEST_BYTES:
                    raise InputError("device VINTF fragments exceed their total byte bound")
                generated[relative] = EMPTY_DEVICE_MANIFEST
            if member.isdir():
                kind = "dir"
            elif member.issym():
                kind = "symlink"
                links[relative] = normalize_existing_link(relative, member.linkname)
            elif member.isreg() or member.islnk():
                kind = "file"
            else:
                raise InputError(f"unsupported AOSP archive entry: {relative}")
            kinds[relative] = kind
            if kind == "file":
                if member.islnk():
                    target = member.linkname.rstrip("/")
                    if not target.startswith(AOSP_ROOT + "/"):
                        raise InputError(f"AOSP hardlink escapes its root: {relative}")
                    hardlinks[relative] = target[len(AOSP_ROOT) + 1:]
                    relative_path(hardlinks[relative])
                else:
                    stream = source.extractfile(member)
                    if stream is None:
                        raise InputError(f"AOSP archive has no payload for {relative}")
                    digest = hashlib.sha256()
                    provenance_chunks: list[bytes] = []
                    fragment_chunks: list[bytes] = []
                    provenance_size = 0
                    fragment_size = 0
                    while chunk := stream.read(COPY_CHUNK):
                        digest.update(chunk)
                        if fragment:
                            fragment_size += len(chunk)
                            if fragment_size > MAX_VINTF_BYTES:
                                raise InputError(f"device VINTF manifest exceeds its size bound: {relative}")
                            fragment_chunks.append(chunk)
                        if relative == "provenance.json":
                            provenance_size += len(chunk)
                            if provenance_size > MAX_MANIFEST_BYTES:
                                raise InputError("AOSP provenance exceeds its size bound")
                            provenance_chunks.append(chunk)
                    digests[relative] = digest.hexdigest()
                    if relative == "provenance.json":
                        provenance_data = b"".join(provenance_chunks)
                    if fragment:
                        device_manifest_contracts(b"".join(fragment_chunks), relative)
    if "provenance.json" not in kinds:
        raise InputError("AOSP archive lacks provenance.json")
    if provenance_data is None:
        raise InputError("AOSP provenance payload is missing")
    pending_hardlinks = dict(hardlinks)
    for relative, target in hardlinks.items():
        if (relative in generated) != (target in generated):
            raise InputError(f"AOSP hardlink crosses device VINTF selection: {relative}")
    while pending_hardlinks:
        progressed = False
        for relative, target in list(pending_hardlinks.items()):
            if target in digests:
                digests[relative] = digests[target]
                del pending_hardlinks[relative]
                progressed = True
        if not progressed:
            raise InputError("AOSP hardlink target is missing or cyclic")
    try:
        provenance = json.loads(provenance_data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InputError("AOSP provenance is invalid") from error
    source_info = provenance.get("source") if isinstance(provenance, dict) else None
    if not isinstance(source_info, dict) or source_info.get("sha256") != boot.metadata.get("sdk_sha256"):
        raise InputError("AOSP SDK hash does not match the prepared boot inputs")
    for name, target in links.items():
        guest_link_resolution(name, target)
    return archive_digest, kinds, links, digests, provenance, generated


def normalize_existing_link(name: str, target: str) -> str:
    guest_link_resolution(name, target)
    return target


def resolve_stock_alias(path: str, links: dict[str, str], kinds: dict[str, str], *,
                        follow_final: bool = True) -> str:
    """Resolve an overlay path through stock links, entirely as archive text."""
    pending = path.split("/")
    resolved: list[str] = []
    substitutions = 0
    while pending:
        component = pending.pop(0)
        candidate = "/".join([*resolved, component])
        is_final = not pending
        if candidate in links and (follow_final or not is_final):
            substitutions += 1
            if substitutions > 40:
                raise InputError(f"AOSP symlink loop at {path}")
            target = links[candidate]
            value = posixpath.normpath(posixpath.join("/", posixpath.dirname(candidate), target))
            if value == "/" or not value.startswith("/"):
                raise InputError(f"unsafe overlay alias: {path}")
            pending = value.lstrip("/").split("/") + pending
            resolved = []
        else:
            if candidate in kinds and kinds[candidate] == "file" and not is_final:
                raise InputError(f"overlay path crosses a file: {path}")
            resolved.append(component)
    return "/".join(resolved)


def verify_file_label_targets(
        policy: HostFile, stock_kinds: dict[str, str], stock_links: dict[str, str],
        overlay_files: dict[str, HostFile], overlay_symlinks: dict[str, str],
        overlay_directories: set[str], graphics_files: dict[str, HostFile]) -> None:
    """Require every installed policy file label to name an existing image path."""
    require_regular(policy.source, "installed Shield policy")
    with policy.source.open("rb") as stream:
        data = stream.read(MAX_POLICY_BYTES + 1)
    if len(data) > MAX_POLICY_BYTES:
        raise InputError("installed Shield policy exceeds its size bound")
    if hashlib.sha256(data).hexdigest() != policy.sha256:
        raise InputError("installed Shield policy changed while preparing")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InputError("installed Shield policy is not UTF-8") from error

    labels: list[tuple[str, str]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields or fields[0] != "file-label":
            continue
        if len(line) > MAX_POLICY_LINE_CHARS:
            raise InputError(f"file-label line exceeds its bound: {line_number}")
        if (len(fields) != 3 or re.fullmatch(r"[0-9]{1,10}", fields[1]) is None or
                int(fields[1]) > 0xffffffff or not fields[2].startswith("/")):
            raise InputError(f"malformed file-label in installed Shield policy: {line_number}")
        target = fields[2]
        if posixpath.normpath(target) != target or target == "/":
            raise InputError(f"unsafe file-label target in installed Shield policy: {target}")
        try:
            relative_path(target[1:])
        except InputError as error:
            raise InputError(f"unsafe file-label target in installed Shield policy: {target}") from error
        labels.append((fields[1], target))
        if len(labels) > MAX_FILE_LABELS:
            raise InputError("installed Shield policy exceeds its file-label bound")

    final_kinds = dict(stock_kinds)
    final_kinds.update({path: "file" for path in overlay_files})
    final_kinds.update({path: "symlink" for path in overlay_symlinks})
    final_kinds.update({path: "dir" for path in overlay_directories})
    for path in graphics_files:
        final_kinds[path] = "file"
        parent = posixpath.dirname(path)
        while parent:
            final_kinds.setdefault(parent, "dir")
            parent = posixpath.dirname(parent)
    final_links = {**stock_links, **overlay_symlinks}

    missing: list[tuple[str, str]] = []
    for label, target in labels:
        try:
            resolved = resolve_stock_alias(target[1:], final_links, final_kinds)
        except InputError as error:
            raise InputError(f"cannot resolve file-label {label} {target}: {error}") from error
        if resolved not in final_kinds:
            missing.append((label, target))
    if missing:
        if len(missing) == 1:
            label, target = missing[0]
            raise InputError(f"file-label {label} target is missing from the final Android image: {target}")
        rendered = ", ".join(target for _, target in missing[:3])
        suffix = ", ..." if len(missing) > 3 else ""
        raise InputError(f"final Android image is missing {len(missing)} file-label targets: {rendered}{suffix}")


def validate_graphics(directory: Path, kind: str, expected_files: set[str]) -> ComponentTree:
    manifest, manifest_sha = read_json_limited(directory / "build.json", f"{kind} build manifest")
    if manifest.get("kind") != kind or manifest.get("result") != "BUILT":
        raise InputError(f"{kind} output is not marked BUILT")
    if manifest.get("android_release") != "android-13.0.0_r2":
        raise InputError(f"{kind} targets a different Android release")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected_files:
        raise InputError(f"{kind} build manifest has an unexpected product set")
    actual = {entry.name for entry in os.scandir(directory) if entry.name != "build.json"}
    if actual != expected_files:
        raise InputError(f"{kind} output differs from its build manifest")
    tree = ComponentTree(root=directory, destination=ANDROID_ROOT)
    for name in sorted(expected_files):
        path = directory / name
        require_regular(path, f"{kind} product {name}")
        digest = sha256_file(path)
        if digest != files[name]:
            raise InputError(f"{kind} product hash mismatch: {name}")
        tree.files[f"{ANDROID_ROOT}/{name}"] = HostFile(path, digest, path.stat().st_mode)
    tree.digest = canonical_digest({"manifest": manifest_sha, "files": files})
    revisions: set[str] = set()
    headers = manifest.get("headers", {})
    for group in (headers.get("archives", {}), headers.get("files", {})):
        if not isinstance(group, dict):
            raise InputError(f"{kind} source pins are malformed")
        for pin in group.values():
            if (not isinstance(pin, dict) or not isinstance(pin.get("repository"), str) or
                    not re.fullmatch(r"[0-9a-f]{40}", str(pin.get("revision")))):
                raise InputError(f"{kind} lacks an exact source revision")
            revisions.add(f"{pin['repository']}@{pin['revision']}")
    for hashes, base in ((manifest.get("source_inputs", {}), ROOT / "graphics"),
                         (manifest.get("build_logic", {}), ROOT / "graphics")):
        if not isinstance(hashes, dict):
            raise InputError(f"{kind} input hashes are malformed")
        for name, digest in hashes.items():
            relative_path(name)
            source = base / name
            require_regular(source, f"{kind} source input {name}")
            if sha256_file(source) != digest:
                raise InputError(f"{kind} source input differs: {name}")
    input_lock = ROOT / "graphics/input-lock.json"
    if sha256_file(require_regular(input_lock, "graphics input lock")) != manifest.get("input_lock_sha256"):
        raise InputError(f"{kind} input lock differs")
    tree.pins = {"manifest_sha256": manifest_sha, "source_revisions": sorted(revisions),
                 "build_manifest": manifest}
    return tree


def validate_android_app(app: Path) -> ComponentTree:
    tree = scan_tree(require_directory(app, "native manager app"), "applications/android.app",
                     "native manager app")
    descriptor = app / "org.scarlet.Android.desktop"
    require_regular(descriptor, "manager app descriptor")
    text = descriptor.read_text()
    expected_exec = 'Exec=bin/android "--view-handle" "3" "--policy-factory-handle" "4"'
    required = ("X-Scarlet-AppFormat=1", "X-Scarlet-Target=aarch64-unknown-scarlet")
    if any(value not in text for value in required) or text.splitlines().count(expected_exec) != 1:
        raise InputError("manager app descriptor is not the native AArch64 manager")
    executable = app / "bin/android"
    require_regular(executable, "manager executable")
    header = executable.read_bytes()[:20]
    if header[:4] != b"\x7fELF" or header[18:20] != b"\xb7\x00":
        raise InputError("manager executable is not AArch64 ELF")
    tree.pins = {"descriptor_sha256": sha256_file(descriptor),
                 "executable_sha256": sha256_file(executable)}
    return tree


def validate_runtime(path: Path) -> HostFile:
    require_regular(path, "android runtime")
    header = path.read_bytes()[:20]
    if header[:4] != b"\x7fELF" or header[18:20] != b"\xb7\x00":
        raise InputError("android runtime is not AArch64 ELF")
    return HostFile(path, sha256_file(path), path.stat().st_mode)


def validate_manager_fs(path: Path) -> ComponentTree:
    tree = scan_tree(path, "", "manager filesystem")
    capability = path / "etc/stemd.d/capabilities/android.toml"
    require_regular(capability, "manager capability")
    try:
        document = tomllib.loads(capability.read_text())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise InputError("manager capability is invalid TOML") from error
    apps = document.get("application")
    if (not isinstance(apps, list) or len(apps) != 1 or apps[0].get("id") != "org.scarlet.Android" or
            apps[0].get("argv") != ["/applications/android.app/bin/android",
                                    "--view-handle", "3", "--policy-factory-handle", "4"] or
            apps[0].get("view") != [{"root": "/", "target": 3}] or
            apps[0].get("shield_policy_factory") != 4):
        raise InputError("manager capability does not grant the native app its View and policy factory")
    return tree


def add_owned(entries: dict[str, HostFile], directories: set[str], path: str,
              file: HostFile, owners: dict[str, str], owner: str) -> None:
    if path in entries or path in directories or path in owners:
        raise InputError(f"duplicate target: {path}")
    parts = PurePosixPath(path).parts
    for index in range(1, len(parts)):
        parent = "/".join(parts[:index])
        if owners.get(parent) == "file":
            raise InputError(f"target crosses a file: {path}")
        owners.setdefault(parent, "dir")
        directories.add(parent)
    entries[path] = file
    owners[path] = owner


def prepare_session(*, aosp_archive: Path, boot_inputs: Path, boot_manifest: Path | None,
                    android_app: Path, android_runtime: Path, graphics_hal: Path,
                    graphics_adapters: Path, manager_fs: Path,
                    aosp_sha256: str | None = None) -> SessionPlan:
    boot = verify_boot_inputs(boot_inputs, boot_manifest)
    device_selection = verify_device_vintf_selection(boot)
    archive_digest, stock_kinds, stock_links, stock_digests, provenance, generated_files = scan_aosp(
        aosp_archive, boot, device_selection)
    if aosp_sha256 is not None and archive_digest != aosp_sha256:
        raise InputError("AOSP archive SHA-256 mismatch")

    components = {
        "hal": validate_graphics(require_directory(graphics_hal, "graphics HAL"),
                                 "scarlet-graphics-hal-v1", {"gralloc.scarlet.so"}),
        "adapters": validate_graphics(require_directory(graphics_adapters, "graphics adapters"),
                                      "scarlet-graphics-adapters-v1", {
                                          "android.hardware.graphics.mapper@2.0-impl.scarlet.so",
                                          "android.hardware.graphics.allocator@2.0-service.scarlet",
                                          "android.hardware.graphics.composer@2.1-service.scarlet",
                                      }),
    }
    graphics_files: dict[str, HostFile] = {}
    graphics_installed_hashes: dict[str, str] = {}
    for component_name, tree in components.items():
        for source_path, item in tree.files.items():
            tail = source_path.removeprefix(ANDROID_ROOT + "/")
            target = GRAPHICS_INSTALL_PATHS.get(f"{component_name}/{tail}")
            if target is None or target in graphics_files:
                raise InputError(f"duplicate graphics target: {source_path}")
            graphics_files[target] = item
            graphics_installed_hashes[target] = item.sha256

    overlay_directories: set[str] = set()
    for declared in sorted(boot.directories, key=lambda value: (value.count("/"), value)):
        final = resolve_stock_alias(declared, stock_links, stock_kinds)
        existing = stock_kinds.get(final)
        if existing == "file":
            raise InputError(f"boot directory conflicts with AOSP: {declared}")
        if existing is None:
            overlay_directories.add(final)

    overlay_files: dict[str, HostFile] = {}
    boot_graphics_overrides: dict[str, dict[str, str]] = {}
    stock_content_overrides: dict[str, dict[str, str]] = {}
    replacements = boot.metadata.get("replacements", {})
    port_replacements = boot.metadata.get("port_replacements", {})
    for declared, item in boot.files.items():
        final = resolve_stock_alias(declared, stock_links, stock_kinds)
        if device_selection is not None and (
                is_device_fragment(final) or is_other_device_aggregate(final) or
                final in DEVICE_VINTF_DIRECTORIES):
            raise InputError(f"prepared device VINTF fragment conflicts with aggregate selection: {declared}")
        if final in overlay_files:
            raise InputError(f"duplicate resolved overlay target: {final}")
        if stock_kinds.get(final) in ("file", "dir", "symlink"):
            if stock_kinds[final] != "file":
                raise InputError(f"boot file conflicts with a stock non-file: {declared}")
            base_digest = stock_digests[final]
            if declared in replacements:
                if base_digest != replacements[declared]:
                    raise InputError(f"boot replacement conflicts with AOSP content: {declared}")
            elif base_digest != item.sha256:
                raise InputError(f"boot file conflicts with AOSP content: {declared}")
            if declared in replacements:
                replacement = port_replacements.get(declared, {})
                if not isinstance(replacement, dict) or replacement.get("sha256") != item.sha256:
                    raise InputError(f"boot replacement has no exact installed hash: {declared}")
                stock_content_overrides[declared] = {
                    "resolved": final,
                    "aosp_sha256": base_digest,
                    "installed_sha256": item.sha256,
                    "reason": replacement.get("reason"),
                }
        if final in GRAPHICS_INSTALL_PATHS.values():
            boot_graphics_overrides[final] = {
                "boot_input_sha256": item.sha256,
                "installed_sha256": graphics_installed_hashes[final],
                "replaced": item.sha256 != graphics_installed_hashes[final],
            }
            continue
        overlay_files[final] = item

    overlay_symlinks: dict[str, str] = {}
    for declared, target in boot.symlinks.items():
        final = resolve_stock_alias(declared, stock_links, stock_kinds, follow_final=False)
        if device_selection is not None and (
                is_device_fragment(final) or is_other_device_aggregate(final) or
                final in DEVICE_VINTF_DIRECTORIES):
            raise InputError(f"prepared device VINTF alias conflicts with aggregate selection: {declared}")
        if final in overlay_symlinks or final in overlay_files:
            raise InputError(f"duplicate resolved boot target: {final}")
        existing = stock_kinds.get(final)
        if existing == "symlink":
            if stock_links[final] != target:
                raise InputError(f"boot symlink conflicts with AOSP: {declared}")
            continue
        if existing is not None:
            raise InputError(f"boot symlink conflicts with AOSP: {declared}")
        overlay_symlinks[final] = target

    for path, data in sorted(generated_files.items()):
        stock_content_overrides[path] = {
            "resolved": path, "aosp_sha256": stock_digests[path],
            "installed_sha256": hashlib.sha256(data).hexdigest(),
            "reason": "supplemental device manifest neutralized by complete profile.vintf.device selection",
            "selection_sha256": device_selection["selection_sha256"],
        }

    for final in overlay_files:
        if final in stock_kinds or final in overlay_symlinks:
            continue
        parent = final.rsplit("/", 1)[0] if "/" in final else ""
        while parent:
            if parent in overlay_directories:
                break
            if parent in stock_links:
                raise InputError(f"overlay target is below a stock alias: {final}")
            if parent in overlay_symlinks:
                raise InputError(f"overlay target is below a boot symlink: {final}")
            overlay_directories.add(parent)
            parent = parent.rsplit("/", 1)[0] if "/" in parent else ""

    policy_source = boot.files.get(FILE_LABEL_POLICY)
    if policy_source is None:
        raise InputError(f"prepared boot inputs lack {FILE_LABEL_POLICY}")
    policy_target = resolve_stock_alias(FILE_LABEL_POLICY, stock_links, stock_kinds)
    installed_policy = overlay_files.get(policy_target)
    if installed_policy is None or installed_policy != policy_source:
        raise InputError("final image does not install the verified prepared Shield policy")
    verify_file_label_targets(installed_policy, stock_kinds, stock_links, overlay_files,
                              overlay_symlinks, overlay_directories, graphics_files)

    app = validate_android_app(android_app)
    runtime = validate_runtime(android_runtime)
    manager = validate_manager_fs(manager_fs)

    owners: dict[str, str] = {
        f"{ANDROID_ROOT}/{path}" if path else ANDROID_ROOT: kind
        for path, kind in stock_kinds.items()
    }
    native_entries: dict[str, HostFile] = {}
    native_directories: set[str] = set()
    for path, kind in stock_kinds.items():
        if kind == "dir":
            native_directories.add(f"{ANDROID_ROOT}/{path}" if path else ANDROID_ROOT)
    for path, item in overlay_files.items():
        owners.setdefault(f"{ANDROID_ROOT}/{path}", "file")
    for path in overlay_directories:
        owners[f"{ANDROID_ROOT}/{path}"] = "dir"
    for path in overlay_symlinks:
        owners.setdefault(f"{ANDROID_ROOT}/{path}", "symlink")

    for collection, owner in ((app.files, "app"), (manager.files, "manager")):
        for path in sorted(collection):
            add_owned(native_entries, native_directories, path, collection[path], owners, owner)
    for tree in (app, manager):
        for directory in sorted(tree.directories):
            if owners.get(directory, "dir") != "dir":
                raise InputError(f"directory conflicts with a file: {directory}")
            owners.setdefault(directory, "dir")
            native_directories.add(directory)
    add_owned(native_entries, native_directories, "bin/android-runtime", runtime, owners, "runtime")
    for relative, item in sorted(graphics_files.items()):
        path = f"{ANDROID_ROOT}/{relative}"
        existing = owners.get(path)
        if existing is not None and existing != "file":
            raise InputError(f"graphics target conflicts with a non-file: {path}")
        stock_path = relative
        if stock_path is None or stock_path not in stock_kinds:
            add_owned(native_entries, native_directories, path, item, owners, "graphics")
        else:
            native_entries[path] = item
            owners[path] = "graphics"
    for path in (*overlay_files, *overlay_symlinks):
        parts = PurePosixPath(path).parts
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if owners.get(parent) in ("file", "symlink"):
                raise InputError(f"overlay target crosses an alias: {path}")

    lock_inputs = {
        "aosp": {"archive_sha256": archive_digest, "provenance": provenance},
        "boot": {
            "manifest_sha256": boot.manifest_sha256,
            "inventory_sha256": canonical_digest({
                "files": boot.metadata["files"], "symlinks": boot.metadata["symlinks"],
                "directories": boot.metadata["directories"],
            }),
            "profile_sha256": canonical_digest(boot.metadata["profile"]),
            "profile_source_sha256": boot.metadata.get("profile_source_sha256"),
            "stock_init_sha256": canonical_digest(boot.metadata["stock_init"]),
            "source_scarlet_revision": boot.metadata.get("source_scarlet_revision"),
            "source_records": boot.metadata.get("source_records"),
            "graphics_overrides": boot_graphics_overrides,
            "stock_content_overrides": stock_content_overrides,
            "file_count": len(boot.files), "symlink_count": len(boot.symlinks),
            "directory_count": len(boot.directories),
        },
        "manager": {"tree_sha256": app.digest, **app.pins},
        "runtime": {"artifact_sha256": runtime.sha256},
        "manager_fs": {"tree_sha256": manager.digest},
        "graphics": {
            **{name: {"tree_sha256": tree.digest,
                      "manifest_sha256": tree.pins["manifest_sha256"],
                      "source_revisions": tree.pins["source_revisions"]}
               for name, tree in components.items()},
            "installed_overrides": boot_graphics_overrides,
        },
    }
    if device_selection is not None:
        lock_inputs["boot"]["device_vintf_selection"] = device_selection
    return SessionPlan(aosp_archive, archive_digest, stock_kinds, stock_links, stock_digests,
                       provenance, boot, overlay_files, overlay_symlinks, overlay_directories,
                       components, runtime, manager, native_entries, lock_inputs, generated_files)


def stock_tar_info(member: tarfile.TarInfo, name: str) -> tarfile.TarInfo:
    info = copy.copy(member)
    info.pax_headers = member.pax_headers.copy()
    info.name = name
    if "path" in info.pax_headers:
        info.pax_headers["path"] = name
    info.uname = info.gname = ""
    if info.islnk():
        target = member.linkname.rstrip("/")
        if target == AOSP_ROOT:
            relative = ""
        elif target.startswith(AOSP_ROOT + "/"):
            relative = target[len(AOSP_ROOT) + 1:]
        else:
            raise InputError(f"AOSP hardlink escapes its root: {member.name}")
        info.linkname = f"{OUTER_ROOT}/{ANDROID_ROOT}" + (f"/{relative}" if relative else "")
        if "linkpath" in info.pax_headers:
            info.pax_headers["linkpath"] = info.linkname
    return info


def new_directory(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type, info.uid, info.gid, info.mode, info.mtime = tarfile.DIRTYPE, 0, 0, 0o755, 0
    info.uname = info.gname = ""
    return info


def new_symlink(name: str, target: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type, info.linkname, info.uid, info.gid, info.mode, info.mtime = (
        tarfile.SYMTYPE, target, 0, 0, 0o777, 0)
    info.uname = info.gname = ""
    return info


def write_file(archive: tarfile.TarFile, info: tarfile.TarInfo, path: Path,
               expected: str | None) -> None:
    info.size = path.stat().st_size
    info.pax_headers.pop("size", None)
    with path.open("rb") as stream:
        archive.addfile(info, stream)
    if expected is not None and sha256_file(path) != expected:
        raise InputError(f"input changed while packaging: {path}")


def overlay_file_info(name: str, source: HostFile, stock: tarfile.TarInfo | None) -> tarfile.TarInfo:
    if stock is not None:
        info = stock_tar_info(stock, name)
        info.type = tarfile.REGTYPE
        info.linkname = ""
        info.size = source.source.stat().st_size
        return info
    info = tarfile.TarInfo(name)
    info.type, info.size, info.uid, info.gid = tarfile.REGTYPE, source.source.stat().st_size, 0, 0
    info.mode, info.mtime = default_mode(name, source.mode), 0
    info.uname = info.gname = ""
    return info


def write_archive(plan: SessionPlan, output: Path) -> None:
    overlaid = set(plan.overlay_files) | set(plan.generated_files)
    replaced_stock = set(plan.overlay_files)
    native = set(plan.native_entries)
    new_overlay_dirs = set(plan.overlay_directories)
    new_native_dirs = set()
    for path in native:
        parent = posixpath.dirname(path)
        while parent:
            new_native_dirs.add(parent)
            parent = posixpath.dirname(parent)
    stock_directories = {
        f"{OUTER_ROOT}/{ANDROID_ROOT}/{path}" if path else f"{OUTER_ROOT}/{ANDROID_ROOT}"
        for path, kind in plan.stock_kinds.items() if kind == "dir"
    }
    directories = {OUTER_ROOT, f"{OUTER_ROOT}/systems"}
    for path in plan.overlay_directories:
        target = f"{OUTER_ROOT}/{ANDROID_ROOT}/{path}"
        if target not in stock_directories:
            directories.add(target)
    for path in new_native_dirs:
        target = f"{OUTER_ROOT}/{path}"
        if target not in stock_directories:
            directories.add(target)
    written_directories: set[str] = set()

    with output.open("xb") as raw, \
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        for directory in sorted(directories, key=lambda value: (value.count("/"), value)):
            if directory not in written_directories:
                archive.addfile(new_directory(directory))
                written_directories.add(directory)

        with tarfile.open(plan.aosp_archive, "r|gz") as source:
            stock_members: dict[str, tarfile.TarInfo] = {}
            for member in source:
                name = member.name.rstrip("/")
                relative = "" if name == AOSP_ROOT else name[len(AOSP_ROOT) + 1:]
                stock_members[relative] = member
                if relative in replaced_stock:
                    continue
                target = f"{OUTER_ROOT}/{ANDROID_ROOT}" + (f"/{relative}" if relative else "")
                if relative in plan.generated_files:
                    info = stock_tar_info(member, target)
                    if member.islnk():
                        # Both ends of this link were checked to be in the
                        # fragment selection and receive the same empty XML.
                        archive.addfile(info)
                    elif member.isreg():
                        data = plan.generated_files[relative]
                        info.size = len(data)
                        info.pax_headers.pop("size", None)
                        archive.addfile(info, io.BytesIO(data))
                    else:
                        raise InputError(f"device VINTF fragment changed kind: {relative}")
                    continue
                if member.islnk():
                    link_relative = member.linkname[len(AOSP_ROOT) + 1:] if member.linkname.startswith(AOSP_ROOT + "/") else ""
                    if link_relative in overlaid:
                        raise InputError(
                            f"AOSP hardlink {relative} depends on an independently overlaid inode")
                    else:
                        archive.addfile(stock_tar_info(member, target))
                elif member.isfile():
                    info = stock_tar_info(member, target)
                    payload = source.extractfile(member)
                    if payload is None:
                        raise InputError(f"missing AOSP payload: {relative}")
                    archive.addfile(info, payload)
                else:
                    archive.addfile(stock_tar_info(member, target))
                    if member.isdir():
                        written_directories.add(target)

        for relative in sorted(new_overlay_dirs, key=lambda value: (value.count("/"), value)):
            target = f"{OUTER_ROOT}/{ANDROID_ROOT}/{relative}"
            if target not in written_directories:
                archive.addfile(new_directory(target))
                written_directories.add(target)
        for relative, item in sorted(plan.overlay_files.items()):
            target = f"{OUTER_ROOT}/{ANDROID_ROOT}/{relative}"
            write_file(archive, overlay_file_info(target, item, stock_members.get(relative)),
                       item.source, item.sha256)
        for relative, link in sorted(plan.overlay_symlinks.items()):
            archive.addfile(new_symlink(f"{OUTER_ROOT}/{ANDROID_ROOT}/{relative}", link))

        for path, item in sorted(plan.native_entries.items()):
            target = f"{OUTER_ROOT}/{path}"
            stock_relative = path.removeprefix(ANDROID_ROOT + "/") if path.startswith(ANDROID_ROOT + "/") else None
            stock = stock_members.get(stock_relative) if stock_relative is not None else None
            write_file(archive, overlay_file_info(target, item, stock), item.source, item.sha256)


def write_documents(plan: SessionPlan, version: str, bundle: Path, lock: Path,
                    archive_sha256: str, archive_url: str) -> None:
    archive_name = f"android-session-aarch64-{version}.tar.gz"
    manifest = (
        "# Generated by scarlet-bundle-android session producer.\n"
        f"# AOSP archive sha256:{plan.aosp_sha256}\n"
        f"# Boot profile sha256:{plan.boot.manifest_sha256}\n\n"
        "[[layers]]\nkind = \"archive\"\n"
        f"url = {json.dumps(archive_url)}\n"
        f"sha256 = {{ aarch64 = \"sha256:{archive_sha256}\" }}\n"
        "format = \"tar-gz\"\nstrip_components = 1\nto = \"/\"\n"
    )
    lock_document = {
        "schema": 1,
        "kind": "scarlet-android-session-lock-v1",
        "version": version,
        "archive": {"name": archive_name, "sha256": archive_sha256,
                    "root": OUTER_ROOT, "strip_components": 1, "to": "/"},
        "inputs": plan.lock_inputs,
    }
    bundle.write_text(manifest)
    lock.write_text(json.dumps(lock_document, sort_keys=True, indent=2) + "\n")


def build_session(*, aosp_archive: Path, boot_inputs: Path, boot_manifest: Path | None,
                  android_app: Path, android_runtime: Path, graphics_hal: Path,
                  graphics_adapters: Path, manager_fs: Path, version: str, output: Path,
                  aosp_sha256: str | None = None, archive_url: str | None = None) -> Path:
    if VERSION.fullmatch(version) is None:
        raise InputError("--version must look like v0.1.0")
    if aosp_sha256 is not None and HASH.fullmatch(aosp_sha256) is None:
        raise InputError("--aosp-sha256 must be a SHA-256 hex digest")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    archive_name = f"android-session-aarch64-{version}.tar.gz"
    archive_path = output / archive_name
    if archive_url is None:
        archive_url = archive_path.resolve().as_uri()
    if not archive_url or any(character in archive_url for character in "\r\n\0"):
        raise InputError("--archive-url must be a non-empty URL")
    bundle_path = output / "bundle.toml"
    lock_path = output / f"android-session-aarch64-{version}.lock.json"
    for path in (archive_path, bundle_path, lock_path):
        if path.exists() or path.is_symlink():
            raise InputError(f"refusing to overwrite an existing artifact: {path.name}")
    plan = prepare_session(aosp_archive=Path(aosp_archive), boot_inputs=Path(boot_inputs),
                           boot_manifest=Path(boot_manifest) if boot_manifest else None,
                           android_app=Path(android_app), android_runtime=Path(android_runtime),
                           graphics_hal=Path(graphics_hal), graphics_adapters=Path(graphics_adapters),
                           manager_fs=Path(manager_fs), aosp_sha256=aosp_sha256)
    with tempfile.TemporaryDirectory(prefix=".session-build-", dir=output) as directory:
        temporary = Path(directory)
        candidate_archive = temporary / archive_name
        write_archive(plan, candidate_archive)
        digest = sha256_file(candidate_archive)
        candidate_bundle = temporary / "bundle.toml"
        candidate_lock = temporary / lock_path.name
        write_documents(plan, version, candidate_bundle, candidate_lock, digest, archive_url)
        for candidate, target in ((candidate_archive, archive_path),
                                  (candidate_bundle, bundle_path), (candidate_lock, lock_path)):
            try:
                os.link(candidate, target)
            except FileExistsError as error:
                raise InputError(f"refusing to overwrite an existing artifact: {target.name}") from error
    print(archive_path)
    print(bundle_path)
    print(lock_path)
    return archive_path


def default_graphics_adapters() -> Path:
    current = ROOT / "producer/artifacts/graphics/validated-r2/adapters"
    return current if current.is_dir() else ROOT / "producer/artifacts/graphics/validated-r1/adapters"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aosp-archive", type=Path,
                        default=ROOT / "producer/artifacts/android-aarch64-v0.1.0.tar.gz")
    parser.add_argument("--aosp-sha256")
    parser.add_argument("--archive-url", help="layer URL; defaults to an absolute file:// URI "
                                               "for the output archive")
    parser.add_argument("--boot-inputs", type=Path, required=True)
    parser.add_argument("--boot-manifest", "--boot-profile", dest="boot_manifest", type=Path,
                        help="separate boot-profile.json; defaults to <boot-inputs>/boot-profile.json")
    parser.add_argument("--android-app", type=Path,
                        default=ROOT / "producer/artifacts/native-current/android.app")
    parser.add_argument("--android-runtime", type=Path, required=True)
    parser.add_argument("--graphics-hal", type=Path,
                        default=ROOT / "producer/artifacts/graphics/validated-r1/hal")
    parser.add_argument("--graphics-adapters", type=Path, default=default_graphics_adapters())
    parser.add_argument("--manager-fs", type=Path, default=ROOT / "manager/fs")
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build_session(**vars(args))
    except InputError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
