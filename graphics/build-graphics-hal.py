#!/usr/bin/env python3
"""Build the Scarlet CPU gralloc and framebuffer HAL."""

import argparse
import json
from pathlib import Path

import graphics_build as inputs

ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--reuse-headers",
        type=Path,
        help="validated header tree containing system, cutils and hardware",
    )
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    args = parser.parse_args()

    pins = json.loads((ROOT / "headers.json").read_text())
    sources = inputs.validate_source_inputs()
    tools = inputs.compiler_paths(args.ndk)
    output = inputs.require_clean_output(args.output)
    with inputs.make_work_directory() as temporary:
        headers = inputs.prepare_hal_headers(
            pins, reuse=args.reuse_headers, work=temporary
        )
        flags = [
            str(tools["cc"]),
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
        ]
        for name in ("hardware", "system", "cutils"):
            flags.extend(["-isystem", str(headers[name])])
        command = flags + [
            "-shared",
            "-fPIC",
            "-Wl,-z,defs",
            str(ROOT / "gralloc.c"),
            "-ldl",
            "-o",
            str(output / "gralloc.scarlet.so"),
        ]
        inputs.run_commands([command], args.jobs)

        product = output / "gralloc.scarlet.so"
        record = {
            "kind": "scarlet-graphics-hal-v1",
            "result": "BUILT",
            "android_release": pins["release"],
            "headers": pins,
            "source_inputs": sources,
            "build_logic": {
                name: inputs.sha256(ROOT / name)
                for name in ("build-graphics-hal.py", "graphics_build.py")
            },
            "input_lock_sha256": inputs.sha256(ROOT / "input-lock.json"),
            "commands": [command],
            "compiler": inputs.compiler_identity(tools["cc"]),
            "files": {product.name: inputs.sha256(product)},
            "needed": {product.name: inputs.elf_needed(product, tools["readelf"])},
            "probes": "excluded",
            "readiness": "built; execution not asserted",
        }
        inputs.write_record(output / "build.json", record)
    print(f"Built {output / 'gralloc.scarlet.so'}")


if __name__ == "__main__":
    main()
