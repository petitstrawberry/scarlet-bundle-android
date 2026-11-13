#!/usr/bin/env python3
"""Validate, publish and pin a Scarlet Android userspace bundle release."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10 hosts use the packaged fallback.
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "petitstrawberry/scarlet-bundle-android"
VERSION_PATTERN = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
SOURCE_RECORD = "scarlet-android-corresponding-source-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def git(*arguments: str, text: bool = True) -> str:
    result = subprocess.run(["git", *arguments], cwd=ROOT, check=True,
                            capture_output=True, text=text)
    return result.stdout


def read_provenance(archive: Path) -> dict:
    with tarfile.open(archive, mode="r:gz") as bundle:
        member = bundle.getmember("android-aarch64/provenance.json")
        if not member.isfile() or member.size > 1024 * 1024:
            raise ValueError("invalid provenance member")
        stream = bundle.extractfile(member)
        if stream is None:
            raise ValueError("missing provenance payload")
        value = json.loads(stream.read())
    if not isinstance(value, dict):
        raise ValueError("invalid provenance")
    return value


def expected_manifest(version: str, archive_name: str, digest: str) -> dict:
    return {"layers": [{
        "kind": "archive",
        "url": (f"https://github.com/{REPOSITORY}/releases/download/"
                f"{version}/{archive_name}"),
        "sha256": {"aarch64": f"sha256:{digest}"},
        "format": "tar-gz",
        "strip_components": 1,
        "to": "/systems/android-aarch64",
    }]}


def packed_producer_sources(output: Path) -> None:
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                            capture_output=True).stdout
    names = [name.decode() for name in listed.split(b"\0") if name]
    if not names:
        raise ValueError("no tracked producer sources")
    with output.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                                                  mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(names):
            source = ROOT / name
            if not source.is_file() or source.is_symlink():
                continue
            info = tarfile.TarInfo("scarlet-bundle-android-sources/" + name)
            info.size = source.stat().st_size
            info.mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with source.open("rb") as stream:
                archive.addfile(info, stream)


def validate_release(*, artifact_dir: Path, version: str, build_revision: str,
                     source_archive: Path, source_url: str, source_sha256: str,
                     source_revision: str) -> tuple[str, dict[str, str]]:
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("VERSION must look like v0.1.0")
    if git("rev-parse", "HEAD").strip() != build_revision:
        raise ValueError("BUILD_REVISION does not match HEAD")
    if re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
        raise ValueError("source revision must be a 40-character Git revision")
    if not source_url.startswith("https://") or HASH_PATTERN.fullmatch(source_sha256) is None:
        raise ValueError("source archive requires an HTTPS URL and SHA-256")
    if not source_archive.is_file() or source_archive.is_symlink():
        raise ValueError("corresponding source archive is missing")
    if sha256_file(source_archive) != source_sha256:
        raise ValueError("corresponding source archive SHA-256 mismatch")

    archive_name = f"android-aarch64-{version}.tar.gz"
    archive = artifact_dir / archive_name
    manifest_path = artifact_dir / "bundle.toml"
    sums_path = artifact_dir / "SHA256SUMS"
    for path in (archive, manifest_path, sums_path):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing release input: {path.name}")
    digest = sha256_file(archive)
    if sums_path.read_text() != f"{digest}  {archive_name}\n":
        raise ValueError("SHA256SUMS does not match the archive")
    with manifest_path.open("rb") as stream:
        if tomllib.load(stream) != expected_manifest(version, archive_name, digest):
            raise ValueError("bundle.toml does not pin the verified archive")
    provenance = read_provenance(archive)
    source = provenance.get("source")
    properties = provenance.get("build_properties")
    if not isinstance(source, dict) or not isinstance(properties, str):
        raise ValueError("archive provenance is incomplete")
    fingerprint = re.search(r"^ro\.system\.build\.fingerprint=(.+)$", properties, re.M)
    build_id = re.search(r"^ro\.system\.build\.id=(.+)$", properties, re.M)
    if fingerprint is None or build_id is None:
        raise ValueError("archive provenance lacks Android identity")
    return archive_name, {
        "fingerprint": fingerprint.group(1),
        "build_id": build_id.group(1),
        "source_url": str(source.get("url", "")),
        "source_sha256": str(source.get("sha256", "")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-revision", required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    version = args.version
    artifact_dir = args.artifact_dir.resolve()
    archive_name, identity = validate_release(
        artifact_dir=artifact_dir, version=version, build_revision=args.build_revision,
        source_archive=args.source_archive.resolve(), source_url=args.source_url,
        source_sha256=args.source_sha256, source_revision=args.source_revision)
    if args.dry_run:
        print(json.dumps({"archive": archive_name, "identity": identity,
                          "revision": args.source_revision}, sort_keys=True))
        return 0

    source_name = f"sources-android-aarch64-{version}.tar.zst"
    source_path = artifact_dir / source_name
    if source_path.exists():
        raise ValueError(f"refusing to overwrite {source_path.name}")
    shutil.copyfile(args.source_archive, source_path)
    producer_name = f"producer-sources-android-aarch64-{version}.tar.gz"
    producer_path = artifact_dir / producer_name
    if producer_path.exists():
        raise ValueError(f"refusing to overwrite {producer_path.name}")
    packed_producer_sources(producer_path)
    record = {
        "kind": SOURCE_RECORD,
        "version": version,
        "binary": {"name": archive_name, "sha256": sha256_file(artifact_dir / archive_name)},
        "provenance": identity,
        "aosp_source": {
            "url": args.source_url,
            "sha256": args.source_sha256,
            "revision": args.source_revision,
        },
        "producer": {"repository": REPOSITORY, "revision": args.build_revision},
    }
    record_path = artifact_dir / "corresponding-source.json"
    record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    assets = [artifact_dir / archive_name, source_path, producer_path, record_path,
              artifact_dir / "SHA256SUMS", artifact_dir / "bundle.toml"]
    release_sums = artifact_dir / "SHA256SUMS.release"
    release_sums.write_text("".join(f"{sha256_file(path)}  {path.name}\n"
                                    for path in assets))
    assets.append(release_sums)

    if subprocess.run(["gh", "release", "view", version, "--repo", REPOSITORY],
                      cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        raise ValueError(f"release {version} already exists")
    subprocess.run([
        "gh", "release", "create", version, "--repo", REPOSITORY, "--draft",
        "--prerelease", "--target", args.build_revision,
        "--title", f"Android AArch64 userspace {version}",
        "--notes-file", str(ROOT / "producer/release-notes.md"),
        *[str(path) for path in assets],
    ], cwd=ROOT, check=True)
    uploaded = json.loads(subprocess.run(
        ["gh", "release", "view", version, "--repo", REPOSITORY, "--json", "assets"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout)["assets"]
    expected = {path.name: path.stat().st_size for path in assets}
    actual = {asset["name"]: asset["size"] for asset in uploaded}
    if actual != expected:
        raise ValueError("release upload is incomplete")

    pinned = ROOT / "bundles/android/bundle.toml"
    pinned.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(artifact_dir / "bundle.toml", pinned)
    git("config", "user.name", "github-actions[bot]")
    git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    git("add", str(pinned.relative_to(ROOT)))
    if subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT).returncode != 0:
        git("commit", "-m", f"Pin Android userspace bundle {version}")
        git("push", "origin", "HEAD:main")
    if args.publish:
        subprocess.run(["gh", "release", "edit", version, "--repo", REPOSITORY,
                        "--draft=false"], cwd=ROOT, check=True)
    print(f"Released {version}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, tomllib.TOMLDecodeError) as error:
        print(f"publish-release: {error}", file=sys.stderr)
        raise SystemExit(1)
