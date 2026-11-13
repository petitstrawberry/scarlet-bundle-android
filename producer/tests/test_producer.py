"""Image-to-archive regression tests; all images are temporary and unprivileged."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import build_rootfs as producer


@unittest.skipUnless(shutil.which("mke2fs") and shutil.which("debugfs"), "e2fsprogs required")
class ImageExportTests(unittest.TestCase):
    def test_complete_root_and_inode_attributes_survive_export(self):
        with tempfile.TemporaryDirectory(prefix="android-producer-test-") as directory:
            base = Path(directory)
            partitions = base / "partitions"
            partitions.mkdir()
            for name in ("system", "system_ext", "product", "vendor"):
                tree = base / (name + "-source")
                tree.mkdir()
                if name == "system":
                    (tree / "system/bin").mkdir(parents=True)
                    (tree / "system/bin/app").write_bytes(b"app contents")
                    os.link(tree / "system/bin/app", tree / "system/bin/app-link")
                    (tree / "init").symlink_to("/system/bin/app")
                    (tree / "init.environ.rc").write_text("source init configuration\n")
                    (tree / ".hidden").write_text("hidden path\n")
                    for mount in ("product", "system_ext", "vendor", "apex"):
                        (tree / mount).mkdir()
                else:
                    (tree / "payload").write_bytes(name.encode())
                image = partitions / (name + ".ext4")
                with image.open("wb") as stream:
                    stream.truncate(16 * 1024 * 1024)
                subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096",
                                "-d", str(tree), str(image)], check=True, capture_output=True)
            image = partitions / "system.ext4"
            label = base / "label"
            label.write_bytes(b"u:object_r:fixture_exec:s0\0")
            binary = base / "binary"
            binary.write_bytes(bytes.fromhex("01000002c0000000000000000000000000000000"))
            commands = "\n".join([
                "set_inode_field /system/bin/app uid 1000",
                "set_inode_field /system/bin/app gid 2000",
                "set_inode_field /system/bin/app mode 0104755",
                "set_inode_field /system/bin/app mtime 0x652801c3",
                f"ea_set -f {producer.quote_debugfs(label)} /system/bin/app security.selinux",
                f"ea_set -f {producer.quote_debugfs(binary)} /system/bin/app security.capability",
            ]) + "\n"
            result = subprocess.run(["debugfs", "-w", "-f", "-", str(image)], input=commands,
                                    text=True, check=True, capture_output=True)
            self.assertEqual(result.stderr.count("\n"), 1, result.stderr)
            work = base / "work"
            work.mkdir()
            root, metadata = producer.assemble_root(partitions, work)
            self.assertTrue((root / "init").is_symlink())
            self.assertEqual((root / "init.environ.rc").read_text(), "source init configuration\n")
            self.assertIn(".hidden", metadata)
            for partition in ("product", "system_ext", "vendor"):
                self.assertEqual((root / partition / "payload").read_text(), partition)
            first, second = base / "one.tar.gz", base / "two.tar.gz"
            producer.write_archive(root, first, metadata)
            producer.write_archive(root, second, metadata)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive:
                app = archive.getmember("android-aarch64/system/bin/app")
                self.assertEqual((app.uid, app.gid, app.mode), (1000, 2000, 0o4755))
                self.assertEqual(app.mtime, 0x652801c3)
                self.assertEqual(app.pax_headers["SCHILY.xattr.security.selinux"].encode(), label.read_bytes())
                self.assertEqual(app.pax_headers["SCHILY.xattr.security.capability"].encode("utf-8", "surrogateescape"), binary.read_bytes())
                self.assertEqual(archive.getmember("android-aarch64/init").linkname, "system/bin/app")
                hardlink = archive.getmember("android-aarch64/system/bin/app-link")
                self.assertTrue(hardlink.islnk())
                self.assertEqual(hardlink.linkname, app.name)
                self.assertEqual(archive.extractfile(hardlink).read(), b"app contents")

    def test_mountpoint_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            target = base / "target"
            target.symlink_to(source)
            with self.assertRaisesRegex(ValueError, "not a directory"):
                producer.merge_tree(source, target)


if __name__ == "__main__":
    unittest.main()
