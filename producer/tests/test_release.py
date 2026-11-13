"""Release validation and registry tests."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import publish_release
import build_rootfs


class ReleaseTests(unittest.TestCase):
    def test_archive_manifest_pins_release_url_and_architecture_hash(self):
        self.assertEqual(
            publish_release.expected_manifest("v1.2.3", "android-aarch64-v1.2.3.tar.gz", "a" * 64),
            {"layers": [{
                "kind": "archive",
                "url": "https://github.com/petitstrawberry/scarlet-bundle-android/releases/download/v1.2.3/android-aarch64-v1.2.3.tar.gz",
                "sha256": {"aarch64": "sha256:" + "a" * 64},
                "format": "tar-gz",
                "strip_components": 1,
                "to": "/systems/android-aarch64",
            }]},
        )

    def test_release_requires_matching_binary_source_and_manifest(self):
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=publish_release.ROOT,
            check=True, capture_output=True, text=True).stdout.strip()
        version = "v1.2.3"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            artifacts = base / "artifacts"
            artifacts.mkdir()
            archive = artifacts / f"android-aarch64-{version}.tar.gz"
            provenance = {
                "source": {"url": "https://example.invalid/android.zip", "sha256": "b" * 64},
                "build_properties": (
                    "ro.system.build.fingerprint=Android/test/device:13/ID/1:userdebug/test-keys\n"
                    "ro.system.build.id=ID\n"),
            }
            with archive.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                                                          mtime=0) as compressed, \
                    tarfile.open(fileobj=compressed, mode="w|") as bundle:
                data = json.dumps(provenance).encode()
                member = tarfile.TarInfo("android-aarch64/provenance.json")
                member.size = len(data)
                bundle.addfile(member, io.BytesIO(data))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            (artifacts / "SHA256SUMS").write_text(
                f"{digest}  {archive.name}\n")
            manifest = publish_release.expected_manifest(version, archive.name, digest)
            layer = manifest["layers"][0]
            (artifacts / "bundle.toml").write_text(
                "[[layers]]\n"
                f"kind = \"{layer['kind']}\"\n"
                f"url = \"{layer['url']}\"\n"
                f"sha256 = {{ aarch64 = \"{layer['sha256']['aarch64']}\" }}\n"
                f"format = \"{layer['format']}\"\n"
                f"strip_components = {layer['strip_components']}\n"
                f"to = \"{layer['to']}\"\n")
            source = base / "source.tar.zst"
            source.write_bytes(b"source")
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            name, identity = publish_release.validate_release(
                artifact_dir=artifacts, version=version, build_revision=revision,
                source_archive=source, source_url="https://example.invalid/source.tar.zst",
                source_sha256=source_hash, source_revision="c" * 40)
            self.assertEqual(name, archive.name)
            self.assertEqual(identity["fingerprint"],
                             "Android/test/device:13/ID/1:userdebug/test-keys")
            self.assertEqual(identity["build_id"], "ID")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                publish_release.validate_release(
                    artifact_dir=artifacts, version=version, build_revision=revision,
                    source_archive=source, source_url="https://example.invalid/source.tar.zst",
                    source_sha256="d" * 64, source_revision="c" * 40)


if __name__ == "__main__":
    unittest.main()
