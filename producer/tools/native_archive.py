"""Validate the native Android overlay published beside the AOSP archive."""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import tarfile

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10 hosts use the packaged fallback.
    import tomli as tomllib

NATIVE_ROOT = "android-native-aarch64"
APP_ROOT = "applications/android.app"
APP_DESCRIPTOR = f"{APP_ROOT}/org.scarlet.Android.desktop"
APP_MANAGER = f"{APP_ROOT}/bin/android"
MANAGER = "bin/android-runtime"
CAPABILITY = "etc/stemd.d/capabilities/android.toml"
REQUIRED_FILES = (APP_DESCRIPTOR, APP_MANAGER, MANAGER, CAPABILITY)
MAX_MEMBERS = 50_000
MAX_METADATA_BYTES = 1024 * 1024
EXPECTED_EXEC = 'Exec=bin/android "--view-handle" "3" "--policy-factory-handle" "4"'


class NativeArchiveError(ValueError):
    """The native archive is incomplete, unsafe, or not a native overlay."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(name: str) -> str:
    value = name.rstrip("/")
    if value == NATIVE_ROOT:
        return ""
    if not value.startswith(NATIVE_ROOT + "/"):
        raise NativeArchiveError(f"native entry is outside {NATIVE_ROOT}: {name}")
    relative = value[len(NATIVE_ROOT) + 1:]
    path = PurePosixPath(relative)
    if (not relative or relative.startswith("/") or "\\" in relative or
            str(path) != relative or ".." in path.parts or "." in path.parts):
        raise NativeArchiveError(f"unsafe native archive path: {name}")
    return relative


def _aarch64_elf(data: bytes, label: str) -> None:
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[18:20] != b"\xb7\x00":
        raise NativeArchiveError(f"{label} is not an AArch64 ELF")


def _descriptor(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise NativeArchiveError("manager app descriptor is not UTF-8") from error
    required = ("X-Scarlet-AppFormat=1", "X-Scarlet-Target=aarch64-unknown-scarlet")
    if any(value not in text for value in required) or text.splitlines().count(EXPECTED_EXEC) != 1:
        raise NativeArchiveError("manager app descriptor is not the native AArch64 manager")


def _capability(data: bytes) -> None:
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise NativeArchiveError("manager capability is invalid TOML") from error
    applications = document.get("application")
    if (not isinstance(applications, list) or len(applications) != 1 or
            applications[0].get("id") != "org.scarlet.Android" or
            applications[0].get("argv") != [
                "/applications/android.app/bin/android", "--view-handle", "3",
                "--policy-factory-handle", "4"] or
            applications[0].get("view") != [{"root": "/", "target": 3}] or
            applications[0].get("shield_policy_factory") != 4):
        raise NativeArchiveError("manager capability does not grant the native app its View and policy factory")


def validate_native_archive(path: Path) -> dict[str, object]:
    """Check that the archive contains only the release-owned native overlay."""
    if not path.is_file() or path.is_symlink():
        raise NativeArchiveError("native archive is missing or is not a regular file")
    seen: dict[str, tarfile.TarInfo] = {}
    directories: set[str] = set()
    payloads: dict[str, bytes] = {}
    with tarfile.open(path, mode="r:gz") as archive:
        for count, member in enumerate(archive, 1):
            if count > MAX_MEMBERS:
                raise NativeArchiveError("native archive exceeds its member bound")
            relative = _relative(member.name)
            if relative in seen:
                raise NativeArchiveError(f"duplicate native entry: {relative or NATIVE_ROOT}")
            seen[relative] = member
            if member.isdir():
                directories.add(relative)
                continue
            if not member.isfile() or relative not in REQUIRED_FILES and not relative.startswith(APP_ROOT + "/"):
                raise NativeArchiveError(f"unexpected native entry: {relative}")
            stream = archive.extractfile(member)
            if stream is None:
                raise NativeArchiveError(f"native entry has no payload: {relative}")
            if relative in (APP_DESCRIPTOR, CAPABILITY):
                if member.size > MAX_METADATA_BYTES:
                    raise NativeArchiveError(f"native metadata exceeds its size bound: {relative}")
                payloads[relative] = stream.read(MAX_METADATA_BYTES + 1)
            elif relative in (APP_MANAGER, MANAGER):
                payloads[relative] = stream.read(20)
    missing = sorted(set(REQUIRED_FILES) - set(seen))
    if missing:
        raise NativeArchiveError("native archive is missing: " + ", ".join(missing))
    parents = {""}
    for name in seen:
        if seen[name].isfile():
            parent = PurePosixPath(name).parent
            while str(parent) != ".":
                parents.add(str(parent))
                parent = parent.parent
    unexpected_directories = sorted(directories - parents)
    if unexpected_directories:
        raise NativeArchiveError("unexpected native directory: " + unexpected_directories[0])
    for name in (APP_MANAGER, MANAGER):
        if not seen[name].mode & 0o111:
            raise NativeArchiveError(f"native executable is not executable: {name}")
    _descriptor(payloads[APP_DESCRIPTOR])
    _capability(payloads[CAPABILITY])
    _aarch64_elf(payloads[APP_MANAGER], "manager executable")
    _aarch64_elf(payloads[MANAGER], "android runtime")
    return {"sha256": sha256_file(path), "entries": len(seen)}
