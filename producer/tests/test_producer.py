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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_archive


class SymlinkMetadataTests(unittest.TestCase):
    def test_apex_absolute_alias_survives_mount_relocation(self):
        source = "system/apex/com.android.i18n/lib64/libbase.so"
        relocated = "apex/com.android.i18n/lib64/libbase.so"
        target = "/system/lib64/libbase.so"
        self.assertEqual(producer.normalize_link(source, target), target)
        self.assertEqual(producer.guest_link_resolution(source, target), target)
        self.assertEqual(producer.guest_link_resolution(relocated, target), target)

    def test_non_apex_absolute_alias_is_preserved(self):
        self.assertEqual(producer.normalize_link("init", "/system/bin/app"), "/system/bin/app")

    def test_stock_partition_root_alias_is_preserved(self):
        self.assertEqual(producer.normalize_link("system/product", "/product"), "/product")
        check_archive.validate_symlink("android-aarch64/system/product", "/product")
        with self.assertRaisesRegex(ValueError, "escapes"):
            producer.normalize_link("system/product", "/product-other")
        with self.assertRaisesRegex(ValueError, "escapes"):
            check_archive.validate_symlink("android-aarch64/system/product", "/product-other")

    def test_absolute_alias_must_stay_in_guest_userspace(self):
        with self.assertRaisesRegex(ValueError, "escapes the Android userspace"):
            producer.normalize_link(
                "init",
                "/outside/libbase.so",
            )

    def test_archive_validator_accepts_absolute_guest_aliases(self):
        check_archive.validate_symlink(
            "android-aarch64/system/apex/com.android.i18n/lib64/libbase.so",
            "/system/lib64/libbase.so",
        )
        check_archive.validate_symlink("android-aarch64/init", "/system/bin/app")
        with self.assertRaisesRegex(ValueError, "escapes Android userspace"):
            check_archive.validate_symlink(
                "android-aarch64/init",
                "/outside/libbase.so",
            )


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
                    (tree / "system/lib64").mkdir(parents=True)
                    (tree / "system/lib64/libbase.so").write_bytes(b"stock libbase\n")
                    (tree / "system/apex/com.android.i18n/lib64").mkdir(parents=True)
                    (tree / "system/apex/com.android.i18n/lib64/libbase.so").symlink_to(
                        "/system/lib64/libbase.so")
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
                self.assertEqual(archive.getmember("android-aarch64/init").linkname, "/system/bin/app")
                self.assertEqual(
                    archive.getmember(
                        "android-aarch64/system/apex/com.android.i18n/lib64/libbase.so"
                    ).linkname,
                    "/system/lib64/libbase.so",
                )
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
