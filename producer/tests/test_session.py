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


DEFAULT_FILE_LABELS = (
    "/etc/boot-input.conf",
    "/system/bin/foo",
    "/system/etc/cgroups.json",
    "/system/etc/new.conf",
    "/system/new-alias.conf",
    "/vendor/lib64/hw/gralloc.scarlet.so",
)


def make_shield_policy(targets: tuple[str, ...] = DEFAULT_FILE_LABELS) -> bytes:
    lines = [
        "scarlet-android-boot-policy-v2",
        "label 1 u:r:init:s0",
        "label 2 u:object_r:system_file:s0",
    ]
    lines.extend(f"file-label 2 {target}" for target in targets)
    return ("\n".join(lines) + "\n").encode()


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


def make_aosp_archive(path: Path, stock_hash: str,
                      apex_link: str = "/system/lib64/libbase.so",
                      extra_members: tuple[tuple[tarfile.TarInfo, bytes | None], ...] = ()) -> None:
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
        add_member(archive, info("system/lib64", tarfile.DIRTYPE, 0o755))
        add_member(archive, info("system/lib64/libbase.so", tarfile.REGTYPE, 0o755),
                   b"stock libbase\n")
        add_member(archive, info("system/apex", tarfile.DIRTYPE, 0o755))
        add_member(archive, info("system/apex/com.android.i18n", tarfile.DIRTYPE, 0o755))
        add_member(archive, info("system/apex/com.android.i18n/lib64", tarfile.DIRTYPE, 0o755))
        add_member(archive, info(
            "system/apex/com.android.i18n/lib64/libbase.so", tarfile.SYMTYPE, 0o777,
            linkname=apex_link,
        ))
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
        for extra_info, data in extra_members:
            add_member(archive, extra_info, data)
    assert stock_hash == sha(b"stock cgroup contents\n")


def make_boot(root: Path, stock_hash: str) -> None:
    files = {
        "etc/boot-input.conf": b"configuration through stock alias\n",
        "system/etc/cgroups.json": b"explicit current cgroups\n",
        "system/etc/new.conf": b"new entry below a stock directory\n",
        "scarlet/boot/init.d/system/readme.rc": b"service fixture /system/bin/foo64\n",
        "scarlet/boot/shield.policy": make_shield_policy(),
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
        "symlinks": {
            "system/bin/foo": "foo64",
            "system/new-alias.conf": "etc/new.conf",
            "system/apex/com.android.i18n/lib64/libbase.so": "/system/lib64/libbase.so",
        },
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
        'Exec=bin/android "--view-handle" "3" "--policy-factory-handle" "4"\n'
        "X-Scarlet-AppFormat=1\nX-Scarlet-Target=aarch64-unknown-scarlet\n"
    ).encode())
    runtime = write_bytes(base / "android-runtime", elf, 0o755)
    manager = base / "manager-fs"
    write_bytes(manager / "etc/stemd.d/capabilities/android.toml", (
        '[[application]]\nid = "org.scarlet.Android"\n'
        'argv = ["/applications/android.app/bin/android", "--view-handle", "3", '
        '"--policy-factory-handle", "4"]\nshield_policy_factory = 4\n\n'
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


COMPOSER_CONTRACT = "android.hardware.graphics.composer@2.1::IComposer/default"
KEYMINT_CONTRACT = "android.hardware.security.keymint.IKeyMintDevice/default"
PREPARED_DEVICE = b'''<manifest version="5.0" type="device">
  <hal format="hidl">
    <name>android.hardware.graphics.composer</name>
    <transport>hwbinder</transport>
    <fqname>@2.1::IComposer/default</fqname>
  </hal>
  <hal format="aidl">
    <name>android.hardware.security.keymint</name>
    <version>2</version>
    <fqname>IKeyMintDevice/default</fqname>
  </hal>
</manifest>
'''
STOCK_POWER = b'''<manifest version="1.0" type="device">
  <hal format="aidl">
    <name>android.hardware.power</name><version>3</version>
    <fqname>IPower/default</fqname>
  </hal>
</manifest>
'''
STOCK_COMPOSER = b'''<manifest version="1.0" type="device">
  <hal format="hidl">
    <name>android.hardware.graphics.composer</name><transport>hwbinder</transport>
    <version>2.4</version>
    <interface><name>IComposer</name><instance>default</instance></interface>
  </hal>
</manifest>
'''
POWER_FRAGMENT = "vendor/etc/vintf/manifest/power-default.xml"
COMPOSER_FRAGMENT = "vendor/etc/vintf/manifest/android.hardware.graphics.composer@2.4.xml"
ODM_FRAGMENT = "odm/etc/vintf/manifest/power.xml"
FRAMEWORK_FRAGMENT = "system/etc/vintf/manifest/framework.xml"
APEX_FRAGMENT = "system/apex/com.android.i18n/etc/vintf/manifest/device.xml"


def vintf_member(path: str, data: bytes | None, kind: bytes = tarfile.REGTYPE,
                 linkname: str = "") -> tuple[tarfile.TarInfo, bytes | None]:
    info = tarfile.TarInfo(f"{producer.AOSP_ROOT}/{path}")
    info.type, info.uid, info.gid, info.mode, info.mtime = kind, 1007, 2007, 0o640, 1234
    info.linkname = linkname
    info.pax_headers = {"SCHILY.xattr.security.selinux": "u:object_r:vendor_configs_file:s0\0",
                        "SCHILY.xattr.fixture.vintf": "original metadata", "path": info.name}
    if data is not None:
        info.pax_headers["size"] = str(len(data))
    if linkname:
        info.pax_headers["linkpath"] = linkname
    return info, data


def prepared_file(boot: Path, name: str, data: bytes) -> None:
    write_bytes(boot / name, data)
    manifest = boot / "boot-profile.json"
    document = json.loads(manifest.read_text())
    document["files"][name] = sha(data)
    document["directories"] = sorted(path.relative_to(boot).as_posix()
                                     for path in boot.rglob("*") if path.is_dir())
    if name in document.get("port_replacements", {}):
        document["port_replacements"][name]["sha256"] = sha(data)
    manifest.write_text(json.dumps(document))


class SessionArchiveTests(unittest.TestCase):
    def test_stock_partition_root_alias_is_preserved(self):
        self.assertEqual(producer.normalize_existing_link("system/product", "/product"), "/product")
        self.assertEqual(producer.normalize_guest_link("system/product", "/product"), "/product")
        with self.assertRaisesRegex(producer.InputError, "escapes"):
            producer.normalize_existing_link("system/product", "/product-other")

    def test_native_contract_requires_both_capabilities(self):
        with tempfile.TemporaryDirectory(prefix="session-test-") as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            capability = fixture["manager"] / "etc/stemd.d/capabilities/android.toml"
            capability.write_text(capability.read_text().replace("shield_policy_factory = 4\n", ""))
            with self.assertRaisesRegex(producer.InputError, "View and policy factory"):
                producer.validate_manager_fs(fixture["manager"])

            descriptor = fixture["app"] / "org.scarlet.Android.desktop"
            descriptor.write_text(descriptor.read_text().replace(
                ' "--policy-factory-handle" "4"', ""))
            with self.assertRaisesRegex(producer.InputError, "native AArch64 manager"):
                producer.validate_android_app(fixture["app"])

    def test_stock_alias_chains_and_cycles(self):
        links = {"etc": "system/etc", "system/etc": "../config"}
        kinds = {"etc": "symlink", "system/etc": "symlink", "config": "dir"}
        self.assertEqual(producer.resolve_stock_alias("etc/init.rc", links, kinds), "config/init.rc")
        self.assertEqual(producer.resolve_stock_alias("etc", links, kinds, follow_final=False), "etc")
        links["config"] = "etc"
        with self.assertRaisesRegex(producer.InputError, "symlink loop"):
            producer.resolve_stock_alias("etc/init.rc", links, kinds)

    def test_prepared_links_retain_absolute_and_relative_target_forms(self):
        with tempfile.TemporaryDirectory(prefix="session-test-") as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            manifest = fixture["boot"] / "boot-profile.json"
            document = json.loads(manifest.read_text())
            document["symlinks"]["system/bin/foo"] = "./foo64"
            manifest.write_text(json.dumps(document))

            overlay = producer.verify_boot_inputs(fixture["boot"], None)
            self.assertEqual(overlay.symlinks["system/bin/foo"], "./foo64")
            self.assertEqual(
                overlay.symlinks["system/apex/com.android.i18n/lib64/libbase.so"],
                "/system/lib64/libbase.so",
            )

    def test_normalized_apex_alias_conflicts_with_absolute_boot_intent(self):
        with tempfile.TemporaryDirectory(prefix="session-test-") as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            make_aosp_archive(
                fixture["aosp"], fixture["stock_hash"],
                apex_link="../../../lib64/libbase.so",
            )
            with self.assertRaisesRegex(producer.InputError, "boot symlink conflicts with AOSP"):
                self.build(fixture, base / "conflict")

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

    def prepare(self, fixture: dict[str, Path]) -> producer.SessionPlan:
        return producer.prepare_session(
            aosp_archive=fixture["aosp"], boot_inputs=fixture["boot"], boot_manifest=None,
            android_app=fixture["app"], android_runtime=fixture["runtime"],
            graphics_hal=fixture["hal"], graphics_adapters=fixture["adapters"],
            manager_fs=fixture["manager"],
        )

    def vintf_fixture(self, base: Path, *, fragments=None, extra=()) -> dict[str, Path]:
        fixture = self.fixture(base)
        if fragments is None:
            fragments = (vintf_member(POWER_FRAGMENT, STOCK_POWER),
                         vintf_member(COMPOSER_FRAGMENT, STOCK_COMPOSER),
                         vintf_member(ODM_FRAGMENT, STOCK_POWER))
        directories = []
        for name in sorted(producer.DEVICE_VINTF_DIRECTORIES, key=lambda path: (path.count("/"), path)):
            entry, _ = vintf_member(name, None, tarfile.DIRTYPE)
            entry.mode = 0o750
            directories.append((entry, None))
        make_aosp_archive(fixture["aosp"], fixture["stock_hash"], extra_members=tuple(directories) + (
            vintf_member(producer.DEVICE_MANIFEST, STOCK_COMPOSER),
            vintf_member(FRAMEWORK_FRAGMENT, STOCK_POWER.replace(b'type="device"', b'type="framework"')),
            vintf_member(APEX_FRAGMENT, STOCK_POWER),
            vintf_member("vendor/bin/hw/power-service", b"stock power HAL payload\n"),
        ) + tuple(fragments) + tuple(extra))
        prepared_file(fixture["boot"], producer.DEVICE_MANIFEST, PREPARED_DEVICE)
        manifest = fixture["boot"] / "boot-profile.json"
        document = json.loads(manifest.read_text())
        document["profile"]["vintf"] = {"device": [COMPOSER_CONTRACT, KEYMINT_CONTRACT], "framework": []}
        document["replacements"][producer.DEVICE_MANIFEST] = sha(STOCK_COMPOSER)
        document["port_replacements"][producer.DEVICE_MANIFEST] = {
            "reason": "explicit profile aggregate", "sha256": sha(PREPARED_DEVICE),
            "source_sha256": sha(STOCK_COMPOSER),
        }
        manifest.write_text(json.dumps(document))
        return fixture

    def test_explicit_device_selection_neutralizes_stock_fragments_and_pins_evidence(self):
        with tempfile.TemporaryDirectory(prefix="session-vintf-") as directory:
            base = Path(directory)
            fixture = self.vintf_fixture(base)
            original_archive = sha(fixture["aosp"].read_bytes())
            prepared_snapshot = {path.relative_to(fixture["boot"]): path.read_bytes()
                                 for path in fixture["boot"].rglob("*") if path.is_file()}
            plan = self.prepare(fixture)
            expected = {POWER_FRAGMENT, COMPOSER_FRAGMENT, ODM_FRAGMENT}
            self.assertEqual(set(plan.generated_files), expected)
            self.assertTrue(all(data == producer.EMPTY_DEVICE_MANIFEST
                                for data in plan.generated_files.values()))
            installed_path = self.build(fixture, base / "selected")
            root = f"{producer.OUTER_ROOT}/{producer.ANDROID_ROOT}"
            with tarfile.open(fixture["aosp"]) as stock, tarfile.open(installed_path) as installed:
                paths = installed.getnames()
                self.assertEqual(len(paths), len(set(paths)))
                for member in stock:
                    relative = member.name.removeprefix(producer.AOSP_ROOT).lstrip("/")
                    target = root + ("/" + relative if relative else "")
                    self.assertIn(target, paths)
                    if relative not in expected:
                        continue
                    result = installed.getmember(target)
                    self.assertEqual(installed.extractfile(result).read(), producer.EMPTY_DEVICE_MANIFEST)
                    self.assertEqual((result.uid, result.gid, result.mode, result.mtime),
                                     (member.uid, member.gid, member.mode, member.mtime))
                    for key, value in member.pax_headers.items():
                        if key.startswith("SCHILY.xattr."):
                            self.assertEqual(result.pax_headers[key], value)
                self.assertEqual(installed.extractfile(f"{root}/{producer.DEVICE_MANIFEST}").read(),
                                 PREPARED_DEVICE)
                for path in (FRAMEWORK_FRAGMENT, APEX_FRAGMENT, "vendor/bin/hw/power-service"):
                    self.assertEqual(installed.extractfile(f"{root}/{path}").read(),
                                     stock.extractfile(f"{producer.AOSP_ROOT}/{path}").read())
            lock = json.loads((base / "selected/android-session-aarch64-v1.2.3.lock.json").read_text())
            boot_lock = lock["inputs"]["boot"]
            evidence = boot_lock["device_vintf_selection"]
            self.assertEqual(evidence["aggregate"], producer.DEVICE_MANIFEST)
            self.assertEqual(evidence["aggregate_sha256"], sha(PREPARED_DEVICE))
            self.assertEqual(evidence["selection"], [COMPOSER_CONTRACT, KEYMINT_CONTRACT])
            self.assertEqual(evidence["contracts"][COMPOSER_CONTRACT]["version"], "2.1")
            self.assertEqual(evidence["contracts"][KEYMINT_CONTRACT]["version"], "2")
            self.assertEqual(evidence["fragment_roots"], list(producer.DEVICE_FRAGMENT_ROOTS))
            for path in expected:
                override = boot_lock["stock_content_overrides"][path]
                original = STOCK_COMPOSER if path == COMPOSER_FRAGMENT else STOCK_POWER
                self.assertEqual(override["aosp_sha256"], sha(original))
                self.assertEqual(override["installed_sha256"], sha(producer.EMPTY_DEVICE_MANIFEST))
                self.assertEqual(override["selection_sha256"], evidence["selection_sha256"])
                self.assertIn("profile.vintf.device", override["reason"])
            self.assertNotIn(FRAMEWORK_FRAGMENT, boot_lock["stock_content_overrides"])
            self.assertNotIn(APEX_FRAGMENT, boot_lock["stock_content_overrides"])
            self.assertEqual(sha(fixture["aosp"].read_bytes()), original_archive)
            self.assertEqual({path.relative_to(fixture["boot"]): path.read_bytes()
                              for path in fixture["boot"].rglob("*") if path.is_file()}, prepared_snapshot)

    def test_no_explicit_device_selection_leaves_fragments_unchanged(self):
        with tempfile.TemporaryDirectory(prefix="session-vintf-") as directory:
            base = Path(directory)
            fixture = self.vintf_fixture(base)
            manifest = fixture["boot"] / "boot-profile.json"
            document = json.loads(manifest.read_text())
            document["profile"].pop("vintf")
            manifest.write_text(json.dumps(document))
            plan = self.prepare(fixture)
            self.assertEqual(plan.generated_files, {})
            self.assertNotIn("device_vintf_selection", plan.lock_inputs["boot"])
            output = base / "unchanged.tar.gz"
            producer.write_archive(plan, output)
            with tarfile.open(output) as archive:
                for path, data in ((POWER_FRAGMENT, STOCK_POWER), (COMPOSER_FRAGMENT, STOCK_COMPOSER)):
                    self.assertEqual(archive.extractfile(
                        f"{producer.OUTER_ROOT}/{producer.ANDROID_ROOT}/{path}").read(), data)

    def test_device_aggregate_checks_formats_versions_interfaces_and_transport(self):
        changes = {
            "wrong-hidl-version": PREPARED_DEVICE.replace(b"@2.1::", b"@2.4::"),
            "wrong-aidl-version": PREPARED_DEVICE.replace(b"<version>2</version>", b"<version>1</version>"),
            "wrong-interface": PREPARED_DEVICE.replace(b"IComposer", b"IUnprovided"),
            "wrong-format": PREPARED_DEVICE.replace(b'format="hidl"', b'format="aidl"'),
            "wrong-transport": PREPARED_DEVICE.replace(b"<transport>hwbinder</transport>",
                                                       b'<transport arch="64">passthrough</transport>'),
            "extra-declaration": PREPARED_DEVICE.replace(b"</manifest>",
                STOCK_POWER.split(b">", 1)[1]),
            "duplicate-declaration": PREPARED_DEVICE.replace(b"</manifest>",
                PREPARED_DEVICE.split(b">", 1)[1]),
            "override": PREPARED_DEVICE.replace(b'<hal format="hidl">', b'<hal format="hidl" override="true">'),
            "wrong-root-kind": PREPARED_DEVICE.replace(b"manifest", b"compatibility-matrix"),
            "wrong-root-type": PREPARED_DEVICE.replace(b'type="device"', b'type="framework"'),
            "malformed-xml": PREPARED_DEVICE[:-10],
            "oversize": b" " * (producer.MAX_VINTF_BYTES + 1),
            "entity": b'<!DOCTYPE manifest [<!ENTITY x "x">]>' + PREPARED_DEVICE,
        }
        for name, data in changes.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="session-vintf-") as directory:
                fixture = self.vintf_fixture(Path(directory))
                prepared_file(fixture["boot"], producer.DEVICE_MANIFEST, data)
                with self.assertRaises(producer.InputError):
                    self.prepare(fixture)
        with tempfile.TemporaryDirectory(prefix="session-vintf-") as directory:
            fixture = self.vintf_fixture(Path(directory))
            data = PREPARED_DEVICE.replace(b"<fqname>@2.1::IComposer/default</fqname>",
                b"<version>2.1</version><interface><name>IComposer</name><instance>default</instance></interface>")
            prepared_file(fixture["boot"], producer.DEVICE_MANIFEST, data)
            plan = self.prepare(fixture)
            self.assertEqual(plan.lock_inputs["boot"]["device_vintf_selection"]["aggregate_sha256"], sha(data))

    def test_device_fragments_reject_malformed_ambiguous_and_overlarge_inputs(self):
        cases = {
            "framework-type": (vintf_member(POWER_FRAGMENT, STOCK_POWER.replace(b'type="device"', b'type="framework"')),),
            "wrong-kind": (vintf_member(POWER_FRAGMENT, STOCK_POWER.replace(b"manifest", b"compatibility-matrix")),),
            "malformed": (vintf_member(POWER_FRAGMENT, b"<manifest>"),),
            "oversize": (vintf_member(POWER_FRAGMENT, b" " * (producer.MAX_VINTF_BYTES + 1)),),
            "symlink": (vintf_member(POWER_FRAGMENT, None, tarfile.SYMTYPE,
                                      "/system/etc/vintf/manifest/framework.xml"),),
            "directory": (vintf_member(POWER_FRAGMENT, None, tarfile.DIRTYPE),),
            "non-xml": (vintf_member(POWER_FRAGMENT + ".bak", STOCK_POWER),),
            "nested": (vintf_member("vendor/etc/vintf/manifest/nested/power.xml", STOCK_POWER),),
            "other-aggregate": (vintf_member("odm/etc/vintf/manifest.xml", STOCK_POWER),),
            "too-many": tuple(vintf_member(f"vendor/etc/vintf/manifest/power-{i}.xml", STOCK_POWER)
                              for i in range(producer.MAX_VINTF_FRAGMENTS + 1)),
        }
        for name, fragments in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="session-vintf-") as directory:
                fixture = self.vintf_fixture(Path(directory), fragments=fragments)
                with self.assertRaises(producer.InputError):
                    self.prepare(fixture)

    def test_prepared_fragment_and_aggregate_aliases_are_rejected(self):
        for name in (POWER_FRAGMENT, ODM_FRAGMENT, "odm/etc/vintf/manifest.xml"):
            with self.subTest(path=name), tempfile.TemporaryDirectory(prefix="session-vintf-") as directory:
                fixture = self.vintf_fixture(Path(directory))
                prepared_file(fixture["boot"], name, STOCK_POWER)
                with self.assertRaisesRegex(producer.InputError, "conflicts with aggregate selection"):
                    self.prepare(fixture)
        with tempfile.TemporaryDirectory(prefix="session-vintf-") as directory:
            base = Path(directory)
            fixture = self.vintf_fixture(base)
            aggregate = fixture["boot"] / producer.DEVICE_MANIFEST
            outside = write_bytes(base / "outside.xml", PREPARED_DEVICE)
            aggregate.unlink()
            aggregate.symlink_to(outside)
            with self.assertRaisesRegex(producer.InputError, "host symlink"):
                self.prepare(fixture)
        with tempfile.TemporaryDirectory(prefix="session-vintf-") as directory:
            fixture = self.vintf_fixture(Path(directory))
            # An identical manifest reached through a stock alias is still not
            # the controlled aggregate root required by the selection.
            make_aosp_archive(fixture["aosp"], fixture["stock_hash"], extra_members=(
                vintf_member(producer.DEVICE_MANIFEST, None, tarfile.SYMTYPE,
                             "/system/etc/vintf/manifest/framework.xml"),
                vintf_member(FRAMEWORK_FRAGMENT, STOCK_COMPOSER),
            ))
            with self.assertRaisesRegex(producer.InputError, "aggregate is not a regular file"):
                self.prepare(fixture)

    def test_fragment_hardlinks_preserve_links_and_reject_selection_crossings(self):
        link = "vendor/etc/vintf/manifest/power-alias.xml"
        with tempfile.TemporaryDirectory(prefix="session-vintf-") as directory:
            base = Path(directory)
            fixture = self.vintf_fixture(base, fragments=(
                vintf_member(POWER_FRAGMENT, STOCK_POWER),
                vintf_member(link, None, tarfile.LNKTYPE, f"{producer.AOSP_ROOT}/{POWER_FRAGMENT}"),
            ))
            plan = self.prepare(fixture)
            output = base / "hardlinks.tar.gz"
            producer.write_archive(plan, output)
            root = f"{producer.OUTER_ROOT}/{producer.ANDROID_ROOT}"
            with tarfile.open(output) as archive:
                member = archive.getmember(f"{root}/{link}")
                self.assertTrue(member.islnk())
                self.assertEqual(member.linkname, f"{root}/{POWER_FRAGMENT}")
                self.assertEqual(archive.extractfile(member).read(), producer.EMPTY_DEVICE_MANIFEST)
                self.assertEqual((member.uid, member.gid, member.mode), (1007, 2007, 0o640))
                self.assertEqual(member.pax_headers["SCHILY.xattr.fixture.vintf"], "original metadata")
            override = plan.lock_inputs["boot"]["stock_content_overrides"][link]
            self.assertEqual(override["aosp_sha256"], sha(STOCK_POWER))
            self.assertEqual(override["installed_sha256"], sha(producer.EMPTY_DEVICE_MANIFEST))
        for reverse in (False, True):
            with self.subTest(reverse=reverse), tempfile.TemporaryDirectory(prefix="session-vintf-") as directory:
                outside = "vendor/etc/power-copy.xml"
                source, target = (POWER_FRAGMENT, outside) if reverse else (outside, POWER_FRAGMENT)
                fixture = self.vintf_fixture(Path(directory), fragments=(
                    vintf_member(target, STOCK_POWER),
                    vintf_member(source, None, tarfile.LNKTYPE, f"{producer.AOSP_ROOT}/{target}"),
                ))
                with self.assertRaisesRegex(producer.InputError, "hardlink crosses device VINTF selection"):
                    self.prepare(fixture)

    def test_stock_camera_instance_and_multi_version_hidl_syntax(self):
        data = b'''<manifest version="1.0" type="device">
          <hal format="aidl"><name>android.hardware.camera.provider</name><version>1</version>
            <interface><name>ICameraProvider</name><instance>internal/0</instance></interface></hal>
          <hal><name>android.hardware.gnss</name><transport>hwbinder</transport>
            <version>2.0</version><version>1.1</version>
            <interface><name>IGnss</name><instance>default</instance></interface></hal>
        </manifest>'''
        contracts = producer.device_manifest_contracts(data, "stock syntax fixture")
        self.assertEqual(set(contracts), {
            "android.hardware.camera.provider.ICameraProvider/internal/0",
            "android.hardware.gnss@2.0::IGnss/default", "android.hardware.gnss@1.1::IGnss/default",
        })

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
                apex_alias = archive.getmember(
                    f"{root}/systems/android-aarch64/system/apex/com.android.i18n/lib64/libbase.so")
                self.assertTrue(apex_alias.issym())
                self.assertEqual(apex_alias.linkname, "/system/lib64/libbase.so")
                self.assertEqual(
                    producer.guest_link_resolution(
                        "apex/com.android.i18n/lib64/libbase.so", apex_alias.linkname),
                    "/system/lib64/libbase.so",
                )
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
            with tarfile.open(fixture["aosp"]) as stock:
                provenance = json.load(stock.extractfile(f"{producer.AOSP_ROOT}/provenance.json"))
            self.assertEqual(lock["inputs"]["aosp"]["provenance"], provenance)
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

    def test_file_label_targets_must_exist_in_the_final_image(self):
        missing_targets = ("/data/dalvik-cache", "/system/etc/absent.conf")
        for target in missing_targets:
            with self.subTest(target=target), \
                    tempfile.TemporaryDirectory(prefix="session-test-") as directory:
                base = Path(directory)
                fixture = self.fixture(base)
                policy = make_shield_policy(DEFAULT_FILE_LABELS + (target,))
                write_bytes(fixture["boot"] / "scarlet/boot/shield.policy", policy)
                manifest = fixture["boot"] / "boot-profile.json"
                document = json.loads(manifest.read_text())
                document["files"]["scarlet/boot/shield.policy"] = sha(policy)
                manifest.write_text(json.dumps(document))

                with self.assertRaises(producer.InputError) as raised:
                    self.build(fixture, base / "missing")
                self.assertIn("target is missing from the final Android image", str(raised.exception))
                self.assertIn(target, str(raised.exception))

    def test_file_labels_use_installed_policy_and_resolve_aliases(self):
        with tempfile.TemporaryDirectory(prefix="session-test-") as directory:
            base = Path(directory)
            fixture = self.fixture(base)
            archive_path = self.build(fixture, base / "aliases")
            root = "android-session-aarch64/systems/android-aarch64"
            policy_data = (fixture["boot"] / "scarlet/boot/shield.policy").read_bytes()
            with tarfile.open(archive_path) as archive:
                installed = archive.extractfile(
                    f"{root}/scarlet/boot/shield.policy").read()
                self.assertEqual(sha(installed), sha(policy_data))
                for target in (
                        "system/etc/boot-input.conf",
                        "system/bin/foo64",
                        "system/new-alias.conf",
                        "system/etc/new.conf",
                        "vendor/lib64/hw/gralloc.scarlet.so"):
                    self.assertIn(f"{root}/{target}", archive.getnames())

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
