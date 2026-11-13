"""Regressions for settings lost in older prepared boot inputs."""
import json
from pathlib import Path
import sys
import unittest

PRODUCER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PRODUCER))

from policy.boot_profile import shield_policy


class BootPolicyTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
