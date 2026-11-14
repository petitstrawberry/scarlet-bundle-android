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
import build_native


class ReleaseTests(unittest.TestCase):
    def test_archive_manifest_pins_release_url_and_architecture_hash(self):
        self.assertEqual(
            publish_release.expected_manifest(
                "v1.2.3", "android-aarch64-v1.2.3.tar.gz", "a" * 64,
                "android-native-aarch64-v1.2.3.tar.gz", "b" * 64),
            {"layers": [{
                "kind": "archive",
                "url": "https://github.com/petitstrawberry/scarlet-bundle-android/releases/download/v1.2.3/android-aarch64-v1.2.3.tar.gz",
                "sha256": {"aarch64": "sha256:" + "a" * 64},
                "format": "tar-gz",
                "strip_components": 1,
                "to": "/systems/android-aarch64",
            }, {
                "kind": "archive",
                "url": "https://github.com/petitstrawberry/scarlet-bundle-android/releases/download/v1.2.3/android-native-aarch64-v1.2.3.tar.gz",
                "sha256": {"aarch64": "sha256:" + "b" * 64},
                "format": "tar-gz",
                "strip_components": 1,
                "to": "/",
            }]},
        )

    def test_native_archive_contains_the_generated_app_runtime_and_grant(self):
        version = "v1.2.3"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            app = base / "android.app"
            binary = app / "bin/android"
            binary.parent.mkdir(parents=True)
            elf = bytearray(64)
            elf[:8] = b"\x7fELF\x02\x01\x01\x53"
            elf[16:18] = (2).to_bytes(2, "little")
            elf[18:20] = (183).to_bytes(2, "little")
            binary.write_bytes(elf)
            binary.chmod(0o755)
            (app / "org.scarlet.Android.desktop").write_text(
                "[Desktop Entry]\nType=Application\nName=Android\n"
                "Exec=bin/android \"--view-handle\" \"3\" \"--policy-factory-handle\" \"4\"\n"
                "X-Scarlet-AppFormat=1\nX-Scarlet-Target=aarch64-unknown-scarlet\n")
            runtime = base / "android-runtime"
            runtime.write_bytes(elf)
            runtime.chmod(0o755)
            manager = base / "manager"
            grant = manager / "etc/stemd.d/capabilities/android.toml"
            grant.parent.mkdir(parents=True)
            grant.write_text(
                '[[application]]\nid = "org.scarlet.Android"\n'
                'argv = ["/applications/android.app/bin/android", "--view-handle", "3", '
                '"--policy-factory-handle", "4"]\n'
                'shield_policy_factory = 4\n'
                '[[application.view]]\nroot = "/"\ntarget = 3\n')
            native = base / f"android-native-aarch64-{version}.tar.gz"
            digest = build_native.write_archive(app, runtime, manager, native)
            self.assertEqual(digest, hashlib.sha256(native.read_bytes()).hexdigest())
            identity = publish_release.native_archive.validate_native_archive(native)
            self.assertEqual(identity["sha256"], digest)
            with tarfile.open(native, "r:gz") as archive:
                names = archive.getnames()
            self.assertIn("android-native-aarch64/applications/android.app/bin/android", names)
            self.assertIn("android-native-aarch64/bin/android-runtime", names)
            self.assertIn("android-native-aarch64/etc/stemd.d/capabilities/android.toml", names)
            self.assertFalse(any("init" in name or "autostart" in name.lower() for name in names))
            unexpected = base / "unexpected-native.tar.gz"
            with tarfile.open(native, "r:gz") as source, tarfile.open(
                    unexpected, "w:gz") as target:
                for member in source:
                    target.addfile(member, source.extractfile(member) if member.isfile() else None)
                data = b"service\n"
                member = tarfile.TarInfo("android-native-aarch64/init/native.rc")
                member.size = len(data)
                target.addfile(member, io.BytesIO(data))
            with self.assertRaisesRegex(
                    publish_release.native_archive.NativeArchiveError,
                    "unexpected native (entry|directory)"):
                publish_release.native_archive.validate_native_archive(unexpected)

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
            app = base / "android.app"
            binary = app / "bin/android"
            binary.parent.mkdir(parents=True)
            elf = bytearray(64)
            elf[:8] = b"\x7fELF\x02\x01\x01\x53"
            elf[16:18] = (2).to_bytes(2, "little")
            elf[18:20] = (183).to_bytes(2, "little")
            binary.write_bytes(elf)
            binary.chmod(0o755)
            (app / "org.scarlet.Android.desktop").write_text(
                "[Desktop Entry]\nType=Application\nName=Android\n"
                "Exec=bin/android \"--view-handle\" \"3\" \"--policy-factory-handle\" \"4\"\n"
                "X-Scarlet-AppFormat=1\nX-Scarlet-Target=aarch64-unknown-scarlet\n")
            runtime = base / "android-runtime"
            runtime.write_bytes(elf)
            runtime.chmod(0o755)
            manager = base / "manager"
            grant = manager / "etc/stemd.d/capabilities/android.toml"
            grant.parent.mkdir(parents=True)
            grant.write_text(
                '[[application]]\nid = "org.scarlet.Android"\n'
                'argv = ["/applications/android.app/bin/android", "--view-handle", "3", '
                '"--policy-factory-handle", "4"]\n'
                'shield_policy_factory = 4\n'
                '[[application.view]]\nroot = "/"\ntarget = 3\n')
            native = artifacts / f"android-native-aarch64-{version}.tar.gz"
            native_digest = build_native.write_archive(app, runtime, manager, native)
            (artifacts / "SHA256SUMS").write_text(
                f"{digest}  {archive.name}\n{native_digest}  {native.name}\n")
            manifest = publish_release.expected_manifest(
                version, archive.name, digest, native.name, native_digest)
            lines = ["# Generated by scarlet-bundle-android.\n"]
            for layer in manifest["layers"]:
                lines.extend([
                    "\n[[layers]]\n", f"kind = \"{layer['kind']}\"\n",
                    f"url = \"{layer['url']}\"\n",
                    f"sha256 = {{ aarch64 = \"{layer['sha256']['aarch64']}\" }}\n",
                    f"format = \"{layer['format']}\"\n",
                    f"strip_components = {layer['strip_components']}\n",
                    f"to = \"{layer['to']}\"\n"])
            (artifacts / "bundle.toml").write_text("".join(lines))
            source = base / "source.tar.zst"
            source.write_bytes(b"source")
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            name, native_name, identity = publish_release.validate_release(
                artifact_dir=artifacts, version=version, build_revision=revision,
                source_archive=source, source_url="https://example.invalid/source.tar.zst",
                source_sha256=source_hash, source_revision="c" * 40)
            self.assertEqual(name, archive.name)
            self.assertEqual(native_name, native.name)
            self.assertEqual(identity["native_sha256"], native_digest)
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
