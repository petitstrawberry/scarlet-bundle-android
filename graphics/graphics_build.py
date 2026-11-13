#!/usr/bin/env python3
"""Small shared input and build helpers for the standalone graphics bundle."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent
ARCHIVE_LIMIT = 8 * 1024**2
FILE_LIMIT = 2 * 1024**2
TREE_FILE_LIMIT = 16 * 1024**2
TREE_TOTAL_LIMIT = 256 * 1024**2
TREE_COUNT_LIMIT = 100_000


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_files(root):
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"header cache is not a regular directory: {root}")
    files = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"header cache contains an alias: {path}")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = sha256(path)
    return files


def tree_sha256(root):
    files = _tree_files(root)
    return hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verify_tree(root, expected, label):
    actual = tree_sha256(root)
    if actual != expected:
        raise ValueError(
            f"{label} header cache hash mismatch: expected {expected}, got {actual}"
        )
    return Path(root)


def download(url, limit):
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"download exceeds {limit} bytes: {url}")
    return data


def extract_pinned_archive(data, target, expected, label):
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError(f"{label} archive path escapes destination")
            if member.isdir() or member.issym() or member.islnk():
                continue
            if not member.isfile():
                raise ValueError(f"{label} archive contains an unsupported entry")
            total += member.size
            if (
                member.size > TREE_FILE_LIMIT
                or total > TREE_TOTAL_LIMIT
                or len(files) >= TREE_COUNT_LIMIT
                or member.name in files
            ):
                raise ValueError(f"{label} archive exceeds extraction limits")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"{label} archive has no file payload")
            content = stream.read()
            files[member.name] = content

    hashes = {
        name: hashlib.sha256(content).hexdigest()
        for name, content in files.items()
    }
    actual = hashlib.sha256(
        json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if actual != expected:
        raise ValueError(
            f"{label} header tree hash mismatch: expected {expected}, got {actual}"
        )

    target = Path(target)
    target.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return target


def _archive_url(pin):
    return (
        f"https://android.googlesource.com/{pin['repository']}/+archive/"
        f"{pin['revision']}/{pin['path']}.tar.gz"
    )


def _file_url(pin):
    return (
        f"https://android.googlesource.com/{pin['repository']}/+/"
        f"{pin['revision']}/{pin['path']}?format=TEXT"
    )


def _reused_tree(cache, name):
    cache = Path(cache)
    primary = cache / name
    if primary.is_dir():
        return primary
    alternate = cache / f"{name}-headers"
    if alternate.is_dir():
        return alternate
    raise ValueError(f"required header tree is missing from cache: {name}")


def prepare_adapter_headers(pins, reuse=None, work=None):
    roots = {}
    for name, pin in pins["archives"].items():
        label = f"adapter {name}"
        if reuse is not None:
            root = verify_tree(_reused_tree(reuse, name), pin["tree_sha256"], label)
        else:
            target = Path(work) / "headers" / name
            data = download(_archive_url(pin), ARCHIVE_LIMIT)
            root = extract_pinned_archive(data, target, pin["tree_sha256"], label)
        roots[name] = root
    return roots


def prepare_hal_headers(pins, reuse=None, work=None):
    if reuse is not None:
        cache = Path(reuse)
        for name, pin in pins["archives"].items():
            verify_tree(
                _reused_tree(cache, name),
                pin["tree_sha256"],
                f"HAL {name}",
            )
        for name, pin in pins["files"].items():
            candidates = [cache / "hardware" / name, cache / name]
            source = next((path for path in candidates if path.is_file()), None)
            if source is None:
                raise ValueError(f"HAL header is missing from cache: {name}")
            if source.is_symlink() or sha256(source) != pin["sha256"]:
                raise ValueError(f"HAL header hash mismatch in cache: {name}")
        return {
            "hardware": cache / "hardware",
            "system": _reused_tree(cache, "system"),
            "cutils": _reused_tree(cache, "cutils"),
        }

    work = Path(work)
    for name, pin in pins["archives"].items():
        target = work / "headers" / name
        data = download(_archive_url(pin), ARCHIVE_LIMIT)
        extract_pinned_archive(
            data, target, pin["tree_sha256"], f"HAL {name}"
        )
    for name, pin in pins["files"].items():
        raw = download(_file_url(pin), FILE_LIMIT)
        try:
            content = base64.b64decode(raw, validate=True)
        except ValueError as error:
            raise ValueError(f"HAL header is not valid base64: {name}") from error
        digest = hashlib.sha256(content).hexdigest()
        if digest != pin["sha256"]:
            raise ValueError(f"HAL header hash mismatch: {name}")
        target = work / "headers" / "hardware" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return {
        "hardware": work / "headers" / "hardware",
        "system": work / "headers" / "system",
        "cutils": work / "headers" / "cutils",
    }


def validate_libraries(android_root, lock=ROOT / "input-lock.json"):
    android_root = Path(android_root).resolve()
    metadata = json.loads(Path(lock).read_text())
    paths = []
    checked = {}
    for relative, expected in metadata["libraries"].items():
        name = PurePosixPath(relative)
        if name.is_absolute() or ".." in name.parts:
            raise ValueError(f"invalid locked library path: {relative}")
        path = android_root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"locked library is missing: {path}")
        actual = sha256(path)
        if actual != expected:
            raise ValueError(
                f"locked library hash mismatch: {relative}; expected {expected}, got {actual}"
            )
        paths.append(path)
        checked[relative] = actual
    return paths, checked


def validate_source_inputs():
    metadata = json.loads((ROOT / "input-lock.json").read_text())
    checked = {}
    for name, expected in metadata["source_inputs"].items():
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"locked graphics source is missing: {name}")
        actual = sha256(path)
        if actual != expected:
            raise ValueError(
                f"locked graphics source hash mismatch: {name}; expected {expected}, got {actual}"
            )
        checked[name] = actual
    return checked


def compiler_paths(ndk):
    host = {"Darwin": "darwin-x86_64", "Linux": "linux-x86_64"}.get(
        platform.system()
    )
    if host is None:
        raise ValueError(f"unsupported host platform: {platform.system()}")
    bin_dir = Path(ndk).resolve() / "toolchains/llvm/prebuilt" / host / "bin"
    compilers = {
        "cc": bin_dir / "aarch64-linux-android33-clang",
        "cxx": bin_dir / "aarch64-linux-android33-clang++",
        "readelf": bin_dir / "llvm-readelf",
    }
    for name, path in compilers.items():
        if not path.is_file():
            raise ValueError(f"NDK tool is missing ({name}): {path}")
    return compilers


def compiler_identity(compiler):
    return subprocess.check_output([str(compiler), "--version"], text=True)


def elf_needed(path, readelf):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
    if len(header) < 64 or header[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"not an ELF64 little-endian file: {path}")
    dynamic = subprocess.run(
        [str(readelf), "-d", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    names = re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", dynamic)
    if any("/" in name or not re.fullmatch(r"[\w.+@-]+", name) for name in names):
        raise ValueError(f"unsupported ELF dependency name in {path}: {names}")
    return names


def run_commands(commands, jobs):
    if jobs not in (1, 2):
        raise ValueError("jobs must be 1 or 2")
    failures = []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(subprocess.run, command, check=False): (index, command)
            for index, command in enumerate(commands, 1)
        }
        for future in as_completed(futures):
            index, command = futures[future]
            result = future.result()
            if result.returncode:
                failures.append((index, command, result.returncode))
            else:
                print(f"graphics build: command {index}/{len(commands)} passed")
    if failures:
        index, command, status = failures[0]
        rendered = " ".join(str(item) for item in command)
        raise RuntimeError(
            f"graphics build command {index} failed with status {status}: {rendered}"
        )


def write_record(path, record):
    Path(path).write_text(json.dumps(record, indent=2) + "\n")


def make_work_directory():
    return tempfile.TemporaryDirectory(prefix="scarlet-graphics-")


def require_clean_output(path):
    output = Path(path).resolve()
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    output.mkdir(parents=True)
    return output


def find_ndk_readelf(ndk):
    return compiler_paths(ndk)["readelf"]
