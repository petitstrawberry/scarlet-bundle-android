"""Small integrity tests for the verified session archive producer."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import build_session as producer


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_bytes(path: Path, data: bytes, mode: int = 0o644) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def add_member(archive: tarfile.TarFile, info: tarfile.TarInfo, data: bytes | None = None) -> None:
    if data is not None:
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    else:
        archive.addfile(info)


def make_aosp_archive(path: Path, stock_hash: str) -> None:
    def info(name: str, kind: bytes, mode: int = 0o644, uid: int = 0, gid: int = 0,
             mtime: int = 1_700_000_000, linkname: str = "") -> tarfile.TarInfo:
        value = tarfile.TarInfo("android-aarch64" + (f"/{name}" if name else ""))
        value.type, value.mode, value.uid, value.gid = kind, mode, uid, gid
        value.mtime, value.linkname = mtime, linkname
        return value

    provenance = json.dumps({
        "schema": 1,
        "kind": "scarlet-android-aosp-userspace",
        "source": {"api": 33, "abi": "arm64-v8a", "tag": "default",
                   "url": "https://example.invalid/image.zip", "sha256": "a" * 64},
    }, sort_keys=True).encode() + b"\n"
    with path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        add_member(archive, info("", tarfile.DIRTYPE, 0o755, mtime=10))
        system = info("system", tarfile.DIRTYPE, 0o750, uid=1000, gid=2000, mtime=11)
        system.pax_headers["SCHILY.xattr.fixture.dir"] = "kept"
        add_member(archive, system)
        etc_dir = info("system/etc", tarfile.DIRTYPE, 0o700, uid=1002, gid=2002, mtime=12)
        etc_dir.pax_headers["SCHILY.xattr.fixture.etc"] = "stock directory"
        add_member(archive, etc_dir)
        stock = info("system/etc/cgroups.json", tarfile.REGTYPE, 0o640, uid=1001, gid=2001, mtime=13)
        stock.pax_headers["SCHILY.xattr.security.selinux"] = "u:object_r:system_file:s0\0"
        add_member(archive, stock, b"stock cgroup contents\n")
        add_member(archive, info("etc", tarfile.SYMTYPE, 0o777, linkname="system/etc"))
        add_member(archive, info("system/bin", tarfile.DIRTYPE, 0o755))
        add_member(archive, info("system/bin/foo64", tarfile.REGTYPE, 0o755), b"stock executable\n")
        add_member(archive, info("system/bin/foo", tarfile.SYMTYPE, 0o777, linkname="foo64"))
        add_member(archive, info("system/bin/foo-link", tarfile.LNKTYPE, 0o755,
                                 linkname="android-aarch64/system/bin/foo64"))
        add_member(archive, info("untouched", tarfile.REGTYPE, 0o444, uid=123, gid=456), b"untouched\n")
        add_member(archive, info("provenance.json", tarfile.REGTYPE), provenance)
    assert stock_hash == sha(b"stock cgroup contents\n")


def make_boot(root: Path, stock_hash: str) -> None:
    files = {
        "etc/boot-input.conf": b"configuration through stock alias\n",
        "system/etc/cgroups.json": b"explicit current cgroups\n",
        "system/etc/new.conf": b"new entry below a stock directory\n",
        "scarlet/boot/init.d/system/readme.rc": b"service fixture /system/bin/foo64\n",
        "scarlet/boot/service-policy.txt": b"service-policy-v1\n",
        "scarlet/lib/input-bridge.jar": b"PK\x03\x04fixture\n",
    }
    for name, data in files.items():
        write_bytes(root / name, data)
    directories = sorted({str(parent) for name in files for parent in Path(name).parents
                          if str(parent) != "."})
    document = {
        "kind": "scarlet-android-boot-inputs-v1",
        "result": "PREPARED",
        "sdk_sha256": "a" * 64,
        "profile_source_sha256": "b" * 64,
        "source_scarlet_revision": "c" * 40,
        "source_records": {"stock-init.json": "d" * 64},
        "files": {name: sha(data) for name, data in files.items()},
        "symlinks": {"system/bin/foo": "foo64"},
        "directories": directories,
        "replacements": {"system/etc/cgroups.json": stock_hash},
        "port_replacements": {"system/etc/cgroups.json": {
            "reason": "fixture explicit stock replacement",
            "sha256": sha(files["system/etc/cgroups.json"]),
            "source_sha256": stock_hash,
        }},
        "profile": {
            "version": 2,
            "name": "fixture",
            "boot_properties": {"ro.hardware": "scarlet", "ro.sf.lcd_density": "320"},
            "bootconfig": {"androidboot.hardware": "scarlet"},
            "subjects": {"u:r:init:s0": 1},
            "init_imports": ["/system/etc/init/hw/init.rc"],
        },
        "stock_init": {
            "kind": "scarlet-stock-init-assembly-v1",
            "result": "ASSEMBLED",
            "imports": ["/system/etc/init/hw/init.rc"],
            "files": {"scarlet/boot/init.d/system/readme.rc": sha(files["scarlet/boot/init.d/system/readme.rc"])},
        },
    }
    write_bytes(root / "boot-profile.json", (json.dumps(document, sort_keys=True, indent=2) + "\n").encode())


def make_graphics(directory: Path, kind: str, outputs: dict[str, bytes]) -> None:
    for name, data in outputs.items():
        write_bytes(directory / name, data, 0o755 if "service" in name else 0o644)
    lock = Path(__file__).resolve().parents[2] / "graphics/input-lock.json"
    manifest = {
        "kind": kind,
        "result": "BUILT",
        "android_release": "android-13.0.0_r2",
        "headers": {"archives": {"vndk": {
            "repository": "platform/prebuilts/vndk/v33", "revision": "e" * 40,
            "path": "arm64/include", "tree_sha256": "f" * 64,
        }}},
        "source_inputs": {},
        "build_logic": {},
        "input_lock_sha256": sha(lock.read_bytes()),
        "files": {name: sha(data) for name, data in outputs.items()},
    }
    write_bytes(directory / "build.json", (json.dumps(manifest, sort_keys=True) + "\n").encode())


def make_native(base: Path) -> tuple[Path, Path, Path, Path, Path]:
    elf = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8 + b"\x02\x00\xb7\x00" + b"\0" * 16
    app = base / "android.app"
    write_bytes(app / "bin/android", elf, 0o755)
    write_bytes(app / "org.scarlet.Android.desktop", (
        "[Desktop Entry]\nType=Application\nName=Android\n"
        'Exec=bin/android "--view-handle" "3"\n'
        "X-Scarlet-AppFormat=1\nX-Scarlet-Target=aarch64-unknown-scarlet\n"
    ).encode())
    runtime = write_bytes(base / "android-runtime", elf, 0o755)
    manager = base / "manager-fs"
    write_bytes(manager / "etc/stemd.d/capabilities/android.toml", (
        '[[application]]\nid = "org.scarlet.Android"\n'
        'argv = ["/applications/android.app/bin/android", "--view-handle", "3"]\n\n'
        '[[application.view]]\nroot = "/"\ntarget = 3\n'
    ).encode())
    hal = base / "graphics/hal"
    make_graphics(hal, "scarlet-graphics-hal-v1", {"gralloc.scarlet.so": b"hal"})
    adapters = base / "graphics/adapters"
    make_graphics(adapters, "scarlet-graphics-adapters-v1", {
        "android.hardware.graphics.mapper@2.0-impl.scarlet.so": b"mapper",
        "android.hardware.graphics.allocator@2.0-service.scarlet": b"allocator",
        "android.hardware.graphics.composer@2.1-service.scarlet": b"composer",
    })
    return app, runtime, hal, adapters, manager


class SessionArchiveTests(unittest.TestCase):
    def test_stock_alias_chains_and_cycles(self):
        links = {"etc": "system/etc", "system/etc": "../config"}
        kinds = {"etc": "symlink", "system/etc": "symlink", "config": "dir"}
        self.assertEqual(producer.resolve_stock_alias("etc/init.rc", links, kinds), "config/init.rc")
        self.assertEqual(producer.resolve_stock_alias("etc", links, kinds, follow_final=False), "etc")
        links["config"] = "etc"
        with self.assertRaisesRegex(producer.InputError, "symlink loop"):
            producer.resolve_stock_alias("etc/init.rc", links, kinds)

    def fixture(self, base: Path) -> dict[str, Path]:
        stock_hash = sha(b"stock cgroup contents\n")
        aosp = base / "aosp.tar.gz"
        make_aosp_archive(aosp, stock_hash)
        boot = base / "boot"
        make_boot(boot, stock_hash)
        app, runtime, hal, adapters, manager = make_native(base)
        return {"aosp": aosp, "boot": boot, "app": app, "runtime": runtime,
                "hal": hal, "adapters": adapters, "manager": manager,
                "stock_hash": stock_hash}

    def build(self, fixture: dict[str, Path], output: Path) -> Path:
        return producer.build_session(
            aosp_archive=fixture["aosp"], boot_inputs=fixture["boot"], boot_manifest=None,
            android_app=fixture["app"], android_runtime=fixture["runtime"],
            graphics_hal=fixture["hal"], graphics_adapters=fixture["adapters"],
            manager_fs=fixture["manager"], version="v1.2.3", output=output,
        )

    def test_archive_preserves_stock_metadata_and_pins_layers(self):
        with tempfile.TemporaryDirectory(prefix="session-test-") as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            first = self.build(fixture, base / "one")
            second = self.build(fixture, base / "two")
            self.assertEqual(first.read_bytes(), second.read_bytes())

            root = "android-session-aarch64"
            with tarfile.open(first) as archive:
                names = archive.getnames()
                self.assertEqual(len(names), len(set(names)))
                changed = archive.getmember(f"{root}/systems/android-aarch64/system/etc/cgroups.json")
                self.assertEqual(archive.extractfile(changed).read(), b"explicit current cgroups\n")
                self.assertEqual((changed.uid, changed.gid, changed.mode), (1001, 2001, 0o640))
                self.assertEqual(changed.mtime, 13)
                self.assertEqual(changed.pax_headers["SCHILY.xattr.security.selinux"],
                                 "u:object_r:system_file:s0\0")
                stock_dir = archive.getmember(f"{root}/systems/android-aarch64/system")
                self.assertEqual((stock_dir.uid, stock_dir.gid, stock_dir.mode), (1000, 2000, 0o750))
                self.assertEqual(stock_dir.pax_headers["SCHILY.xattr.fixture.dir"], "kept")
                etc_dir = archive.getmember(f"{root}/systems/android-aarch64/system/etc")
                self.assertEqual((etc_dir.uid, etc_dir.gid, etc_dir.mode), (1002, 2002, 0o700))
                self.assertEqual(etc_dir.pax_headers["SCHILY.xattr.fixture.etc"], "stock directory")
                etc = archive.getmember(f"{root}/systems/android-aarch64/etc")
                self.assertTrue(etc.issym())
                self.assertEqual(etc.linkname, "system/etc")
                self.assertFalse(any(name.startswith(f"{root}/systems/android-aarch64/etc/") for name in names))
                root_copy = archive.getmember(f"{root}/systems/android-aarch64/system/etc/boot-input.conf")
                self.assertEqual(archive.extractfile(root_copy).read(), b"configuration through stock alias\n")
                self.assertEqual((root_copy.uid, root_copy.gid, root_copy.mode), (0, 0, 0o644))
                self.assertEqual(archive.getmember(f"{root}/systems/android-aarch64/system/bin/foo").linkname,
                                 "foo64")
                self.assertEqual(archive.extractfile(
                    f"{root}/systems/android-aarch64/untouched").read(), b"untouched\n")
                bridge = archive.getmember(f"{root}/systems/android-aarch64/scarlet/lib/input-bridge.jar")
                self.assertEqual((bridge.uid, bridge.gid, bridge.mode), (0, 0, 0o644))
                runtime = archive.getmember(f"{root}/bin/android-runtime")
                self.assertEqual((runtime.uid, runtime.gid, runtime.mode), (0, 0, 0o755))
                app = archive.getmember(f"{root}/applications/android.app/bin/android")
                self.assertEqual((app.uid, app.gid, app.mode), (0, 0, 0o755))
                capability = archive.getmember(f"{root}/etc/stemd.d/capabilities/android.toml")
                self.assertEqual((capability.uid, capability.gid, capability.mode), (0, 0, 0o644))

            bundle = (base / "one/bundle.toml").read_text()
            self.assertNotIn("source =", bundle)
            self.assertIn(
                f'url = "{(base / "one/android-session-aarch64-v1.2.3.tar.gz").resolve().as_uri()}"',
                bundle)
            self.assertIn(f"sha256:{sha(first.read_bytes())}", bundle)
            self.assertIn('to = "/"', bundle)
            lock = json.loads((base / "one/android-session-aarch64-v1.2.3.lock.json").read_text())
            self.assertEqual(lock["inputs"]["boot"]["source_scarlet_revision"], "c" * 40)
            self.assertEqual(lock["inputs"]["graphics"]["adapters"]["source_revisions"],
                             ["platform/prebuilts/vndk/v33@" + "e" * 40])
            self.assertEqual(
                lock["inputs"]["boot"]["stock_content_overrides"]["system/etc/cgroups.json"]["aosp_sha256"],
                fixture["stock_hash"])
            self.assertEqual(
                lock["inputs"]["boot"]["stock_content_overrides"]["system/etc/cgroups.json"]["reason"],
                "fixture explicit stock replacement")

    def test_hash_mismatch_and_unassembled_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="session-test-") as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            manifest = fixture["boot"] / "boot-profile.json"
            document = json.loads(manifest.read_text())
            document["files"]["scarlet/lib/input-bridge.jar"] = "0" * 64
            manifest.write_text(json.dumps(document))
            with self.assertRaisesRegex(producer.InputError, "hash mismatch"):
                producer.verify_boot_inputs(fixture["boot"], None)

            document["files"]["scarlet/lib/input-bridge.jar"] = sha(
                (fixture["boot"] / "scarlet/lib/input-bridge.jar").read_bytes())
            document["stock_init"]["result"] = "NOT_ASSEMBLED"
            manifest.write_text(json.dumps(document))
            with self.assertRaisesRegex(producer.InputError, "ASSEMBLED"):
                producer.verify_boot_inputs(fixture["boot"], None)

    def test_path_aliases_autostart_and_conflicting_targets_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="session-test-") as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            manifest = fixture["boot"] / "boot-profile.json"
            document = json.loads(manifest.read_text())

            document["profile"]["boot_properties"]["ro.scarlet.autostart"] = "example/example.Main"
            manifest.write_text(json.dumps(document))
            with self.assertRaisesRegex(producer.InputError, "autostart"):
                producer.verify_boot_inputs(fixture["boot"], None)

            del document["profile"]["boot_properties"]["ro.scarlet.autostart"]
            document["symlinks"]["vendor/escape"] = "/etc/passwd"
            manifest.write_text(json.dumps(document))
            with self.assertRaisesRegex(producer.InputError, "escapes"):
                producer.verify_boot_inputs(fixture["boot"], None)

            document["symlinks"].pop("vendor/escape")
            document["directories"].append("../escape")
            manifest.write_text(json.dumps(document))
            with self.assertRaises(producer.InputError):
                producer.verify_boot_inputs(fixture["boot"], None)


if __name__ == "__main__":
    unittest.main()
