"""Regressions for settings lost in older prepared boot inputs."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

PRODUCER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PRODUCER))

from policy.boot_profile import shield_policy
from policy.service_policy import (
    AID_HEADER_SHA256,
    GENERIC_MAGIC,
    GENERIC_PARTITIONS,
    SDK_POLICY_SHA256,
    SDK_POLICY_VERSION,
    _digest,
    apply_generic_boot_policy,
    relabel_policy,
)


def generic_manifest(relabels, evidence):
    rc = "system/etc/init/helper.rc"
    rc_sha256 = hashlib.sha256(b"service helper helper\n").hexdigest()
    executable = "/system/bin/helper"
    file_label = "u:object_r:helper_exec:s0"
    target = "u:r:helper:s0"
    service = {
        "service": "helper",
        "rc": rc,
        "rc_line": 1,
        "rc_sha256": rc_sha256,
        "executable": executable,
        "user": "root",
        "seclabel": None,
        "sockets": [],
        "principal": 0,
        "resolved_executable": executable,
        "executable_sha256": "0" * 64,
        "source_path": executable,
        "source_executable_sha256": "0" * 64,
        "source_file_label": file_label,
        "source_xattr": "security.selinux = helper_exec",
        "source_xattr_sha256": _digest((file_label + "\0").encode()),
        "context_validation": "stock-file-contexts",
        "file_label": file_label,
        "disposition": "source-derived",
        "target": target,
        "policy_rules": ["allow init helper_exec:file execute;"],
    }
    manifest = {
        "kind": GENERIC_MAGIC,
        "source_sha256": SDK_POLICY_SHA256,
        "policy_version": SDK_POLICY_VERSION,
        "partitions": GENERIC_PARTITIONS,
        "aid_header_sha256": AID_HEADER_SHA256,
        "sdk_sha256": "0" * 64,
        "boot_manifest_sha256": "0" * 64,
        "package_manifest_sha256": "0" * 64,
        "passwd_sha256": "0" * 64,
        "rc_files": {rc: rc_sha256},
        "services": [service],
        "file_labels": {executable: file_label},
        "exec_transitions": [["u:r:init:s0", file_label, target, 0]],
        "transitions": [],
        "socket_labels": [],
        "file_create_groups": [],
        "file_create_evidence": [],
        "file_relabels": relabels,
        "file_relabel_evidence": evidence,
    }
    manifest["manifest_sha256"] = _digest(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    return manifest


class BootPolicyTests(unittest.TestCase):
    def test_current_profile_disables_unsupported_perfetto_services(self):
        profile = json.loads(
            (PRODUCER.parent / "profiles/scarlet-arm64-flattened.json").read_text())
        properties = profile["boot_properties"]
        self.assertEqual(properties["persist.traced.enable"], "0")
        self.assertEqual(properties["persist.traced_perf.enable"], "0")
        self.assertEqual(
            properties["persist.device_config.global_settings.sys_traced"], "0")

    def test_current_profile_keeps_isolated_processes_and_persistent_labels(self):
        profile = json.loads(
            (PRODUCER.parent / "profiles/scarlet-arm64-flattened.json").read_text())
        targets = sorted({target for grants in profile["property_grants"].values()
                          for target in grants})
        contexts = "\n".join(f"test.{index} {target}" for index, target in enumerate(targets))
        records = [line.split() for line in shield_policy(profile, [contexts]).splitlines()]
        labels = {fields[2]: fields[1] for fields in records if fields[0] == "label"}
        isolated = {tuple(fields[1:]) for fields in records if fields[0] == "runtime-isolated"}
        self.assertEqual(isolated, {
            ("0", "90000", "99999", labels["u:r:zygote:s0"]),
            ("0", "90000", "99999", labels["u:r:webview_zygote:s0"]),
        })
        self.assertIn(["file-persistence", "b87a925304534ce4a2885a9fa9befbbf"], records)

    def test_stock_relabel_evidence_forms_compact_origin_and_target_sets(self):
        manifest = {
            "file_relabels": [
                ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:apex_module_data_file:s0", 1],
                ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:face_vendor_data_file:s0", 1],
                ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:system_data_file:s0", 1],
                ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:vendor_data_file:s0", 1],
                ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:aac_drc_prop:s0", 1],
            ],
            "file_relabel_evidence": [
                "allow init unlabeled:file { relabelfrom relabelto };",
                "allow init system_data_file:file relabelfrom;",
                "allow init vendor_data_file:file relabelfrom;",
                "allow init apex_module_data_file:file relabelto;",
                "allow init face_vendor_data_file:file relabelto;",
                "allow init property_type:file relabelto;",
                "allow init system_data_file:file relabelto;",
                "allow init vendor_data_file:file relabelto;",
            ],
        }
        groups, exact = relabel_policy(manifest)
        self.assertEqual(groups[("u:r:init:s0", 1)], (
            ("u:object_r:system_data_file:s0", "u:object_r:unlabeled:s0",
             "u:object_r:vendor_data_file:s0"),
            ("u:object_r:apex_module_data_file:s0", "u:object_r:face_vendor_data_file:s0",
             "u:object_r:system_data_file:s0", "u:object_r:vendor_data_file:s0"),
        ))
        self.assertEqual(exact, [
            ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:aac_drc_prop:s0", 1],
        ])

    def test_generic_relabels_emit_one_file_set_after_full_manifest_validation(self):
        evidence = [
            "allow init unlabeled:file { relabelfrom relabelto };",
            "allow init system_data_file:file relabelfrom;",
            "allow init vendor_data_file:file relabelfrom;",
            "allow init apex_module_data_file:file relabelto;",
            "allow init face_vendor_data_file:file relabelto;",
            "allow init system_data_file:file relabelto;",
            "allow init vendor_data_file:file relabelto;",
            "allow init property_type:file relabelto;",
        ]
        relabels = [
            ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:apex_module_data_file:s0", 1],
            ["u:r:init:s0", "u:object_r:system_data_file:s0", "u:object_r:apex_module_data_file:s0", 1],
            ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:face_vendor_data_file:s0", 1],
            ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:system_data_file:s0", 1],
            ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:vendor_data_file:s0", 1],
            ["u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:aac_drc_prop:s0", 1],
        ]
        manifest = generic_manifest(relabels, evidence)
        boot = ("scarlet-android-boot-policy-v2\nlabel 1 u:r:init:s0\n"
                "label 2 u:object_r:unlabeled:s0\nfile-default 2\n")
        output = apply_generic_boot_policy(boot, manifest)
        records = [line.split() for line in output.splitlines()]
        labels = {int(fields[1]): fields[2] for fields in records if fields and fields[0] == "label"}
        members = {}
        for fields in records:
            if fields and fields[0] == "set-member":
                members.setdefault(int(fields[1]), set()).add(labels[int(fields[2])])
        rule_sets = [fields for fields in records if fields and fields[0] == "file-set"]
        self.assertEqual(len(rule_sets), 1)
        source, origins, targets, kind, action, flags = rule_sets[0][1:]
        self.assertEqual(labels[int(source)], "u:r:init:s0")
        self.assertEqual(members[int(origins)], {
            "u:object_r:system_data_file:s0",
            "u:object_r:unlabeled:s0",
            "u:object_r:vendor_data_file:s0",
        })
        self.assertEqual(members[int(targets)], {
            "u:object_r:apex_module_data_file:s0",
            "u:object_r:face_vendor_data_file:s0",
            "u:object_r:system_data_file:s0",
            "u:object_r:vendor_data_file:s0",
        })
        self.assertEqual((kind, action, flags), ("1", "2", "1"))
        self.assertEqual(sum(fields[0] == "label-set" for fields in records), 2)
        exact_rules = [fields for fields in records if fields and fields[0] == "file-relabel"]
        self.assertEqual([(labels[int(fields[1])], labels[int(fields[2])],
                           labels[int(fields[3])], fields[4]) for fields in exact_rules], [
            ("u:r:init:s0", "u:object_r:unlabeled:s0", "u:object_r:aac_drc_prop:s0", "1"),
        ])

    def test_relabel_pair_requires_concrete_origin_evidence(self):
        manifest = {
            "file_relabels": [
                ["u:r:init:s0", "u:object_r:system_data_file:s0", "u:object_r:apex_module_data_file:s0", 1],
            ],
            "file_relabel_evidence": [
                "allow init apex_module_data_file:file relabelto;",
            ],
        }
        with self.assertRaisesRegex(ValueError, "origin evidence"):
            relabel_policy(manifest)


if __name__ == "__main__":
    unittest.main()
