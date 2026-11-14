"""Pinned runtime import preserves inode data and rejects incomplete input."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import import_session_runtime as runtime

class RuntimeImportTests(unittest.TestCase):
    def test_path_boundary(self):
        self.assertIsNone(runtime.runtime_name('android-session-aarch64/bin/android-runtime'))
        self.assertEqual(runtime.runtime_name(runtime.PREFIX + '/system/bin/init'),
                         'android-aarch64/system/bin/init')
        with self.assertRaises(ValueError):
            runtime.runtime_name(runtime.PREFIX + '/../escape')

    def test_checksum_metadata_and_completeness(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'input.tar.gz'
            with tarfile.open(source, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(runtime.REQUIRED | {'provenance.json'}):
                    member = tarfile.TarInfo(runtime.PREFIX + '/' + path)
                    data = json.dumps({'source': {'tag': 'default'}}).encode() if path == 'provenance.json' else b'payload'
                    member.size = len(data)
                    member.uid, member.gid, member.mode = 123, 456, 0o750
                    member.pax_headers = {'SCHILY.xattr.security.selinux': 'label\0'}
                    archive.addfile(member, io.BytesIO(data))
            digest = runtime.sha256(source)
            spec = {'archive': {'sha256': digest}, 'lock': {'sha256': 'b' * 64}}
            lock = {'archive': {'sha256': digest}, 'inputs': {}}
            output = base / 'output.tar.gz'
            with patch.object(runtime, 'check_archive') as check:
                runtime.repackage(source, output, lock, spec, 'v1.0.0')
                check.assert_called_once_with(output)
            with tarfile.open(output) as archive:
                member = archive.getmember('android-aarch64/vendor/lib64/hw/gralloc.scarlet.so')
                self.assertEqual((member.uid, member.gid, member.mode), (123, 456, 0o750))
                self.assertEqual(member.pax_headers['SCHILY.xattr.security.selinux'], 'label\0')
                provenance = json.load(archive.extractfile('android-aarch64/provenance.json'))
                self.assertEqual(provenance['runtime_input'], spec)
                self.assertEqual(json.load(archive.extractfile('android-aarch64/session-input.lock.json')), lock)
            with patch.object(runtime, 'REQUIRED', runtime.REQUIRED | {'missing-component'}):
                with self.assertRaisesRegex(ValueError, 'runtime components missing'):
                    runtime.repackage(source, base / 'incomplete.tar.gz', lock, spec, 'v1.0.0')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                runtime.checked_input(source, {'sha256': '0' * 64})

if __name__ == '__main__':
    unittest.main()
