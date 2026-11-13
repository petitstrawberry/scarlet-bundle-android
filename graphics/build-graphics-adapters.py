#!/usr/bin/env python3
"""Build the stock gralloc0-to-HIDL graphics adapters."""

import argparse
import json
from pathlib import Path

import graphics_build as inputs

ROOT = Path(__file__).resolve().parent


def generate_dynamic_framebuffer_adapter(headers, output):
    source = headers / "composer-utils/hwc2onfbadapter"
    target = Path(output)
    target.mkdir()
    header = (source / "include/hwc2onfbadapter/HWC2OnFbAdapter.h").read_text()
    header = header.replace(
        "    void enableVsync(bool enable);\n",
        "    void enableVsync(bool enable);\n"
        "    void setHotplugCallback(HWC2_PFN_HOTPLUG callback, hwc2_callback_data_t data);\n"
        "    void setRefreshCallback(HWC2_PFN_REFRESH callback, hwc2_callback_data_t data);\n"
        "    void updateDisplayInfo(uint32_t width, uint32_t height, int xdpi_scaled,\n"
        "                           int ydpi_scaled);\n",
        1,
    )
    header = header.replace(
        "    Info mFbInfo{};\n",
        "    Info mFbInfo{};\n"
        "    hwc2_config_t mConfigId{0};\n"
        "    hwc2_config_t mNextConfigId{1};\n"
        "    mutable std::mutex mModesMutex;\n"
        "    std::mutex mBufferMutex;\n"
        "    HWC2_PFN_HOTPLUG mHotplugCallback{nullptr};\n"
        "    hwc2_callback_data_t mHotplugData{nullptr};\n"
        "    HWC2_PFN_REFRESH mRefreshCallback{nullptr};\n"
        "    hwc2_callback_data_t mRefreshData{nullptr};\n",
        1,
    )
    header = header.replace(
        "    static hwc2_config_t getConfigId();\n",
        "    hwc2_config_t getConfigId();\n",
        1,
    )
    header = header.replace(
        "    const Info& getInfo() const;\n",
        "    Info getInfo() const;\n"
        "    Info getConfigInfo(hwc2_config_t config) const;\n"
        "    bool setConfig(hwc2_config_t config);\n",
        1,
    )

    implementation = (source / "HWC2OnFbAdapter.cpp").read_text()
    implementation = implementation.replace(
        "#include <algorithm>\n", "#include <algorithm>\n#include <cstdio>\n", 1
    )
    implementation = implementation.replace(
        "        case HWC2_CALLBACK_HOTPLUG:\n"
        "            if (pointer) {\n"
        "                reinterpret_cast<HWC2_PFN_HOTPLUG>(pointer)(callbackData, adapter.getDisplayId(),\n"
        "                                                            HWC2_CONNECTION_CONNECTED);\n"
        "            }\n",
        "        case HWC2_CALLBACK_HOTPLUG:\n"
        "            adapter.setHotplugCallback(reinterpret_cast<HWC2_PFN_HOTPLUG>(pointer), callbackData);\n"
        "            if (pointer) {\n"
        "                reinterpret_cast<HWC2_PFN_HOTPLUG>(pointer)(callbackData, adapter.getDisplayId(),\n"
        "                                         HWC2_CONNECTION_CONNECTED);\n"
        "            }\n",
        1,
    )
    implementation = implementation.replace(
        "        case HWC2_CALLBACK_REFRESH:\n            break;\n",
        "        case HWC2_CALLBACK_REFRESH:\n"
        "            adapter.setRefreshCallback(reinterpret_cast<HWC2_PFN_REFRESH>(pointer), callbackData);\n"
        "            if (pointer) {\n"
        "                reinterpret_cast<HWC2_PFN_REFRESH>(pointer)(callbackData, adapter.getDisplayId());\n"
        "            }\n"
        "            break;\n",
        1,
    )
    implementation = implementation.replace(
        "hwc2_config_t HWC2OnFbAdapter::getConfigId() {\n    return 0;\n}\n",
        "hwc2_config_t HWC2OnFbAdapter::getConfigId() {\n"
        "    std::lock_guard<std::mutex> lock(mModesMutex);\n"
        "    return mConfigId;\n"
        "}\n",
        1,
    )
    old_state = (
        "void HWC2OnFbAdapter::setState(State state) {\n"
        "    mState = state;\n"
        "}\n"
        "\n"
        "HWC2OnFbAdapter::State HWC2OnFbAdapter::getState() const {\n"
        "    return mState;\n"
        "}\n"
    )
    new_state = (
        "void HWC2OnFbAdapter::setState(State state) {\n"
        "    std::lock_guard<std::mutex> lock(mModesMutex);\n"
        "    mState = state;\n"
        "}\n"
        "\n"
        "HWC2OnFbAdapter::State HWC2OnFbAdapter::getState() const {\n"
        "    std::lock_guard<std::mutex> lock(mModesMutex);\n"
        "    return mState;\n"
        "}\n"
    )
    if implementation.count(old_state) != 1:
        raise ValueError("changed HWC2 state accessors")
    implementation = implementation.replace(old_state, new_state, 1)

    old_attribute = (
        "    if (adapter.getConfigId() != config) {\n"
        "        return HWC2_ERROR_BAD_CONFIG;\n"
        "    }\n"
        "\n"
        "    const auto& info = adapter.getInfo();\n"
    )
    new_attribute = (
        "    const auto& info = adapter.getConfigInfo(config);\n"
        "    if (info.width == 0 || info.height == 0) {\n"
        "        return HWC2_ERROR_BAD_CONFIG;\n"
        "    }\n"
    )
    if implementation.count(old_attribute) != 1:
        raise ValueError("changed HWC2 attribute hook")
    implementation = implementation.replace(old_attribute, new_attribute, 1)

    old_set = (
        "    if (adapter.getConfigId() != config) {\n"
        "        return HWC2_ERROR_BAD_CONFIG;\n"
        "    }\n"
        "\n"
        "    return HWC2_ERROR_NONE;\n"
        "}\n"
    )
    new_set = (
        "    return adapter.setConfig(config) ? HWC2_ERROR_NONE : HWC2_ERROR_BAD_CONFIG;\n"
        "}\n"
    )
    if implementation.count(old_set) != 1:
        raise ValueError("changed HWC2 set config hook")
    implementation = implementation.replace(old_set, new_set, 1)

    old_present = (
        "    adapter.postBuffer();\n"
        "    *outPresentFence = -1;\n"
        "\n"
        "    return HWC2_ERROR_NONE;\n"
        "}\n"
    )
    new_present = (
        "    if (!adapter.postBuffer()) {\n"
        "        return HWC2_ERROR_UNSUPPORTED;\n"
        "    }\n"
        "    *outPresentFence = -1;\n"
        "\n"
        "    return HWC2_ERROR_NONE;\n"
        "}\n"
    )
    if implementation.count(old_present) != 1:
        raise ValueError("changed HWC2 present hook")
    implementation = implementation.replace(old_present, new_present, 1)

    old_buffer = (
        "void HWC2OnFbAdapter::setBuffer(buffer_handle_t buffer) {\n"
        "    if (mFbDevice->compositionComplete) {\n"
        "        mFbDevice->compositionComplete(mFbDevice);\n"
        "    }\n"
        "    mBuffer = buffer;\n"
        "}\n"
        "\n"
        "bool HWC2OnFbAdapter::postBuffer() {\n"
        "    int error = 0;\n"
        "    if (mBuffer) {\n"
        "        error = mFbDevice->post(mFbDevice, mBuffer);\n"
        "    }\n"
        "\n"
        "    return error == 0;\n"
        "}\n"
    )
    new_buffer = (
        "void HWC2OnFbAdapter::setBuffer(buffer_handle_t buffer) {\n"
        "    if (mFbDevice->compositionComplete) {\n"
        "        mFbDevice->compositionComplete(mFbDevice);\n"
        "    }\n"
        "    std::lock_guard<std::mutex> lock(mBufferMutex);\n"
        "    mBuffer = buffer;\n"
        "}\n"
        "\n"
        "bool HWC2OnFbAdapter::postBuffer() {\n"
        "    std::lock_guard<std::mutex> lock(mBufferMutex);\n"
        "    int error = 0;\n"
        "    if (mBuffer) {\n"
        "        error = mFbDevice->post(mFbDevice, mBuffer);\n"
        "    }\n"
        "\n"
        "    return error == 0;\n"
        "}\n"
    )
    if implementation.count(old_buffer) != 1:
        raise ValueError("changed HWC2 framebuffer buffer hooks")
    implementation = implementation.replace(old_buffer, new_buffer, 1)

    marker = (
        "const HWC2OnFbAdapter::Info& HWC2OnFbAdapter::getInfo() const {\n"
        "    return mFbInfo;\n"
        "}\n"
    )
    addition = (
        "\n"
        "HWC2OnFbAdapter::Info HWC2OnFbAdapter::getInfo() const {\n"
        "    std::lock_guard<std::mutex> lock(mModesMutex);\n"
        "    return mFbInfo;\n"
        "}\n"
        "HWC2OnFbAdapter::Info HWC2OnFbAdapter::getConfigInfo(hwc2_config_t config) const {\n"
        "    std::lock_guard<std::mutex> lock(mModesMutex);\n"
        "    return config == mConfigId ? mFbInfo : Info{};\n"
        "}\n"
        "bool HWC2OnFbAdapter::setConfig(hwc2_config_t config) {\n"
        "    std::lock_guard<std::mutex> lock(mModesMutex);\n"
        "    if (config != mConfigId) return false;\n"
        "    mState = State::MODIFIED;\n"
        "    return true;\n"
        "}\n"
        "\n"
        "void HWC2OnFbAdapter::updateDisplayInfo(uint32_t width, uint32_t height,\n"
        "                                             int xdpi_scaled, int ydpi_scaled) {\n"
        "    HWC2_PFN_HOTPLUG hotplug = nullptr;\n"
        "    hwc2_callback_data_t hotplug_data = nullptr;\n"
        "    {\n"
        "    std::lock_guard<std::mutex> lock(mModesMutex);\n"
        "    if (width == mFbInfo.width && height == mFbInfo.height &&\n"
        "        xdpi_scaled == mFbInfo.xdpi_scaled && ydpi_scaled == mFbInfo.ydpi_scaled) return;\n"
        "    mConfigId = mNextConfigId;\n"
        "    mNextConfigId = mNextConfigId == UINT32_MAX ? 1 : mNextConfigId + 1;\n"
        "    mFbInfo.width = width;\n"
        "    mFbInfo.height = height;\n"
        "    mFbInfo.xdpi_scaled = xdpi_scaled;\n"
        "    mFbInfo.ydpi_scaled = ydpi_scaled;\n"
        "    mState = State::MODIFIED;\n"
        "    hotplug = mHotplugCallback;\n"
        "    hotplug_data = mHotplugData;\n"
        "    std::fprintf(stderr, \"SCARLET_ANDROID_HWC_CONFIG config=%u hotplug=%p\\n\",\n"
        "                 mConfigId, reinterpret_cast<void*>(hotplug));\n"
        "    }\n"
        "    { std::lock_guard<std::mutex> lock(mBufferMutex); mBuffer = nullptr; }\n"
        "    if (hotplug) hotplug(hotplug_data, getDisplayId(), HWC2_CONNECTION_CONNECTED);\n"
        "}\n"
        "\n"
        "void HWC2OnFbAdapter::setHotplugCallback(HWC2_PFN_HOTPLUG callback, hwc2_callback_data_t data) {\n"
        "    std::lock_guard<std::mutex> lock(mModesMutex);\n"
        "    mHotplugCallback = callback;\n"
        "    mHotplugData = data;\n"
        "}\n"
        "\n"
        "void HWC2OnFbAdapter::setRefreshCallback(HWC2_PFN_REFRESH callback, hwc2_callback_data_t data) {\n"
        "    std::lock_guard<std::mutex> lock(mModesMutex);\n"
        "    mRefreshCallback = callback;\n"
        "    mRefreshData = data;\n"
        "}\n"
    )
    if implementation.count(marker) != 1:
        raise ValueError("changed HWC2 framebuffer adapter info hook")
    implementation = implementation.replace(marker, addition, 1)
    (target / "HWC2OnFbAdapter.cpp").write_text(implementation)
    include = target / "include/hwc2onfbadapter"
    include.mkdir(parents=True)
    (include / "HWC2OnFbAdapter.h").write_text(header)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--android-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--reuse-headers",
        type=Path,
        help="validated cache containing vndk33 and the HIDL utility trees",
    )
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    args = parser.parse_args()

    pins = json.loads((ROOT / "adapter-headers.json").read_text())
    sources = inputs.validate_source_inputs()
    libraries, library_hashes = inputs.validate_libraries(args.android_root)
    tools = inputs.compiler_paths(args.ndk)
    output = inputs.require_clean_output(args.output)

    with inputs.make_work_directory() as temporary:
        headers = inputs.prepare_adapter_headers(
            pins, reuse=args.reuse_headers, work=temporary
        )
        flags = [
            str(tools["cxx"]),
            "-std=c++17",
            "-O2",
            "-fPIC",
            "-fno-rtti",
            "-fno-exceptions",
            "-nostdinc++",
            "-nostdlib++",
            "-Wl,-z,defs",
            "-Wl,--as-needed",
        ]
        vndk = headers["vndk33"]
        includes = [
            "external/libcxx/include",
            "system/libhidl/base/include",
            "system/libhidl/transport/include",
            "system/libhwbinder/include",
            "system/libfmq/base",
            "system/libfmq/include",
            "system/core/libutils/include",
            "system/core/libcutils/include",
            "system/core/libcutils/include_outside_system",
            "system/core/libsystem/include",
            "system/libbase/include",
            "system/logging/liblog/include_vndk",
            "hardware/libhardware/include",
            "system/core/libsync/include",
        ]
        for path in includes:
            flags.extend(["-isystem", str(vndk / path)])
        for path in sorted((vndk / "generated-headers").rglob("gen")):
            flags.extend(["-isystem", str(path)])
        for path in sorted((headers["composer21-headers"]).rglob("gen")):
            flags.extend(["-isystem", str(path)])
        for name in ("mapper-utils", "allocator-utils"):
            for kind in ("hal", "passthrough"):
                flags.extend(
                    ["-isystem", str(headers[name] / kind / "include")]
                )
        for kind in ("hal", "passthrough", "resources", "command-buffer"):
            flags.extend(
                ["-isystem", str(headers["composer-utils"] / kind / "include")]
            )

        dynamic_adapter = generate_dynamic_framebuffer_adapter(
            headers["composer-utils"].parent,
            Path(temporary) / "generated-hwc2onfbadapter",
        )
        flags.extend(["-isystem", str(dynamic_adapter / "include")])
        link = [str(path) for path in libraries]
        products = {
            "android.hardware.graphics.mapper@2.0-impl.scarlet.so": (
                "mapper.cpp",
                ["-shared"],
            ),
            "android.hardware.graphics.allocator@2.0-service.scarlet": (
                "allocator-service.cpp",
                ["-pie"],
            ),
            "android.hardware.graphics.composer@2.1-service.scarlet": (
                "composer-service.cpp",
                ["-pie"],
            ),
        }
        commands = []
        for name, (source, extra) in products.items():
            command = flags + extra + [str(ROOT / source), *link, "-o", str(output / name)]
            if source == "composer-service.cpp":
                command[1:1] = [
                    str(dynamic_adapter / "HWC2OnFbAdapter.cpp"),
                    str(headers["composer-utils"] / "resources/ComposerResources.cpp"),
                ]
            commands.append(command)
        inputs.run_commands(commands, args.jobs)

        record = {
            "kind": "scarlet-graphics-adapters-v1",
            "result": "BUILT",
            "android_release": pins["release"],
            "headers": pins,
            "source_inputs": sources,
            "build_logic": {
                name: inputs.sha256(ROOT / name)
                for name in ("build-graphics-adapters.py", "graphics_build.py")
            },
            "input_lock_sha256": inputs.sha256(ROOT / "input-lock.json"),
            "libraries": library_hashes,
            "commands": commands,
            "compiler": inputs.compiler_identity(tools["cxx"]),
            "files": {
                name: inputs.sha256(output / name) for name in products
            },
            "needed": {
                name: inputs.elf_needed(output / name, tools["readelf"])
                for name in products
            },
            "probes": "excluded",
            "readiness": "built; daemon registration and composition not asserted",
        }
        inputs.write_record(output / "build.json", record)
    print(f"Built stock graphics adapters in {output}")


if __name__ == "__main__":
    main()
