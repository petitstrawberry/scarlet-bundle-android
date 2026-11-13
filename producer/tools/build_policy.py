#!/usr/bin/env python3
"""Generate a session's Shield records from explicit, verified Android inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

PRODUCER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PRODUCER))

from policy.boot_profile import relative_path, shield_policy
from policy.inputs import sha256
from policy.service_policy import apply_boot_policy, validate_generic, validate_metadata

DEFAULT_CONTEXTS = (
    "system/etc/selinux/plat_property_contexts",
    "vendor/etc/selinux/vendor_property_contexts",
)
SOURCE_POLICY = "vendor/etc/selinux/precompiled_sepolicy"
MAX_INPUT_BYTES = 4 * 1024 * 1024


def read_input(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"policy input exceeds size bound: {path}")
    return data


def root_input(root: Path, name: str) -> Path:
    path = (root / relative_path(name)).resolve(strict=True)
    if not path.is_relative_to(root):
        raise ValueError(f"policy input escapes Android root: {name}")
    return path


def build(args: argparse.Namespace) -> dict:
    if args.output.exists():
        raise ValueError(f"output already exists: {args.output}")
    root = args.android_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Android root is not a directory")
    inputs = {
        "profile": read_input(args.profile),
        "service_policy": read_input(args.service_policy),
        "service_manifest": read_input(args.service_manifest),
        "generic_manifest": read_input(args.generic_manifest),
    }
    profile = json.loads(inputs["profile"])
    service_text = inputs["service_policy"].decode("utf-8")
    service = json.loads(inputs["service_manifest"])
    generic = validate_generic(json.loads(inputs["generic_manifest"]))
    lock = json.loads((PRODUCER / "lock.json").read_bytes())
    if generic.get("sdk_sha256") != lock["android"]["sha256"]:
        raise ValueError("generic policy uses a different SDK input")
    if service.get("generic_exec_manifest_sha256") != generic["manifest_sha256"]:
        raise ValueError("generic and service export selection differ")
    source = read_input(root_input(root, SOURCE_POLICY))
    validate_metadata(service, service_text, source=source)

    names = args.property_context or list(DEFAULT_CONTEXTS)
    if len(names) > 16 or len(names) != len(set(names)):
        raise ValueError("duplicate or excessive property context inputs")
    contexts = {name: read_input(root_input(root, name)) for name in names}
    # Check every exported init declaration before applying its native records.
    # The translator checks the content digests against the same manifest.
    for name in generic["rc_files"]:
        root_input(root, name)
    text = shield_policy(profile, [data.decode("utf-8") for data in contexts.values()],
                         generic, root)
    output = apply_boot_policy(text, service_text, service).encode("utf-8")
    digest = lambda data: hashlib.sha256(data).hexdigest()
    sources = [Path(__file__).resolve(), PRODUCER / "lock.json",
               *sorted((PRODUCER / "policy").glob("*.py"))]
    manifest = {
        "schema": 1,
        "kind": "scarlet-android-boot-policy-build-v1",
        "sdk_sha256": lock["android"]["sha256"],
        "inputs": {name: digest(data) for name, data in inputs.items()},
        "source_policy": {SOURCE_POLICY: digest(source)},
        "property_contexts": {name: digest(data) for name, data in contexts.items()},
        "init_declarations": generic["rc_files"],
        "build_sources": {str(path.relative_to(PRODUCER.parent)): sha256(path)
                          for path in sources},
        "files": {"shield.policy": digest(output)},
    }
    args.output.mkdir(parents=True)
    (args.output / "shield.policy").write_bytes(output)
    (args.output / "build.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path,
                        default=PRODUCER.parent / "profiles/scarlet-arm64-flattened.json")
    parser.add_argument("--android-root", type=Path, required=True,
                        help="assembled Android tree, including the declared APEX init files")
    parser.add_argument("--service-policy", type=Path, required=True)
    parser.add_argument("--service-manifest", type=Path, required=True)
    parser.add_argument("--generic-manifest", type=Path, required=True)
    parser.add_argument("--property-context", action="append", metavar="RELATIVE_PATH",
                        help="repeat to override the standard platform/vendor context files")
    parser.add_argument("--output", type=Path, required=True,
                        help="new output directory; existing outputs are never overwritten")
    args = parser.parse_args()
    try:
        manifest = build(args)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"error: {error}\n")
    print(f"shield.policy sha256={manifest['files']['shield.policy']}")


if __name__ == "__main__":
    main()
