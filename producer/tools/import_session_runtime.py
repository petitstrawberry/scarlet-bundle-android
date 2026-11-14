#!/usr/bin/env python3
"""Package the pinned, previously assembled Android runtime without reselecting files.

The session input is a binary distribution, not an AOSP source build. Its full
input lock is retained alongside the upstream provenance inside the output.
Native Scarlet executables are built and packaged separately by release CI.
"""
from __future__ import annotations
import argparse
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'producer' / 'tests'))
from check_archive import check_archive

PREFIX = 'android-session-aarch64/systems/android-aarch64'
REQUIRED = {
    'system/apex/com.android.art/bin/dex2oat64',
    'vendor/lib64/hw/gralloc.scarlet.so',
    'vendor/lib64/hw/android.hardware.graphics.mapper@2.0-impl.scarlet.so',
    'vendor/bin/hw/android.hardware.graphics.composer@2.1-service.scarlet',
    'vendor/bin/hw/android.hardware.graphics.allocator@2.0-service.scarlet',
    'scarlet/boot/shield.policy', 'scarlet/lib/input-bridge.jar',
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def checked_input(path: Path, spec: dict) -> Path:
    if sha256(path) != spec['sha256']:
        raise ValueError('input SHA-256 mismatch: ' + path.name)
    return path


def fetch(cache: Path, spec: dict) -> Path:
    if not spec['url'].startswith('https://') or not re.fullmatch('[0-9a-f]{64}', spec['sha256']):
        raise ValueError('runtime input needs HTTPS and SHA-256')
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / spec['sha256']
    if not destination.exists():
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as stream:
            temporary = Path(stream.name)
        try:
            urllib.request.urlretrieve(spec['url'], temporary)
            checked_input(temporary, spec)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    return checked_input(destination, spec)


def runtime_name(name: str) -> str | None:
    if name.startswith('/') or '..' in PurePosixPath(name).parts:
        raise ValueError('unsafe session path: ' + name)
    if name == PREFIX:
        return 'android-aarch64'
    if name.startswith(PREFIX + '/'):
        return 'android-aarch64' + name[len(PREFIX):]
    return None


def repackage(source: Path, destination: Path, input_lock: dict, spec: dict, version: str) -> None:
    checked_input(source, spec['archive'])
    if input_lock['archive']['sha256'] != spec['archive']['sha256']:
        raise ValueError('session lock does not match archive')
    seen = set()
    with tarfile.open(source, 'r:gz') as original, destination.open('xb') as raw, \
            gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as output:
        for entry in original:
            name = runtime_name(entry.name)
            if name is None:
                continue
            if name in seen:
                raise ValueError('duplicate session path: ' + name)
            seen.add(name)
            member = copy.deepcopy(entry)
            member.name = name
            member.pax_headers.pop('path', None)
            if member.islnk():
                member.linkname = runtime_name(member.linkname)
                if member.linkname is None:
                    raise ValueError('hardlink outside runtime')
                member.pax_headers.pop('linkpath', None)
            content = original.extractfile(entry) if entry.isfile() else None
            if name == 'android-aarch64/provenance.json':
                provenance = json.load(content)
                provenance['version'] = version
                provenance['runtime_input'] = spec
                content = io.BytesIO((json.dumps(provenance, indent=2) + '\n').encode())
                member.size = len(content.getvalue())
            output.addfile(member, content)
            if content is not None:
                content.close()
        missing = {'android-aarch64/' + path for path in REQUIRED} - seen
        if missing:
            raise ValueError('runtime components missing: ' + ', '.join(sorted(missing)))
        member = tarfile.TarInfo('android-aarch64/session-input.lock.json')
        payload = (json.dumps(input_lock, indent=2, sort_keys=True) + '\n').encode()
        member.size, member.mode = len(payload), 0o644
        output.addfile(member, io.BytesIO(payload))
    check_archive(destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'producer/runtime-input.json')
    parser.add_argument('--session-archive', type=Path)
    parser.add_argument('--session-lock', type=Path)
    parser.add_argument('--cache', type=Path, default=ROOT / 'producer/cache/runtime')
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', args.version):
        raise ValueError('invalid release version')
    spec = json.loads(args.input.read_text())
    source = checked_input(args.session_archive, spec['archive']) if args.session_archive else fetch(args.cache, spec['archive'])
    lock = checked_input(args.session_lock, spec['lock']) if args.session_lock else fetch(args.cache, spec['lock'])
    args.output.mkdir(parents=True, exist_ok=True)
    name = f'android-aarch64-{args.version}.tar.gz'
    destination = args.output / name
    with tempfile.TemporaryDirectory(dir=args.output) as temporary:
        candidate = Path(temporary) / name
        repackage(source, candidate, json.loads(lock.read_text()), spec, args.version)
        os.link(candidate, destination)
    digest = sha256(destination)
    (args.output / 'SHA256SUMS').write_text(f'{digest}  {name}\n')
    (args.output / 'bundle.toml').write_text(
        '[[layers]]\nkind = "archive"\n'
        f'url = "https://github.com/petitstrawberry/scarlet-bundle-android/releases/download/{args.version}/{name}"\n'
        f'sha256 = {{ aarch64 = "sha256:{digest}" }}\n'
        'format = "tar-gz"\nstrip_components = 1\nto = "/systems/android-aarch64"\n')
    print(destination)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
