"""Validation for the Android bundle's stock input selections."""
import re


SERVICE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+/[A-Za-z0-9_.-]+")
GRAPHICS_DEVICE = {
    "android.hardware.graphics.allocator@2.0::IAllocator/default": "hwbinder",
    "android.hardware.graphics.mapper@2.0::IMapper/default": "passthrough",
    "android.hardware.graphics.composer@2.1::IComposer/default": "hwbinder",
    "android.hardware.graphics.composer@2.4::IComposer/default": "hwbinder",
}
KEYMINT_DEVICE = {
    "android.hardware.security.keymint.IKeyMintDevice/default":
        ("android.hardware.security.keymint", "2", "IKeyMintDevice/default"),
    "android.hardware.security.keymint.IRemotelyProvisionedComponent/default":
        ("android.hardware.security.keymint", "2", "IRemotelyProvisionedComponent/default"),
    "android.hardware.security.secureclock.ISecureClock/default":
        ("android.hardware.security.secureclock", "1", "ISecureClock/default"),
    "android.hardware.security.sharedsecret.ISharedSecret/default":
        ("android.hardware.security.sharedsecret", "1", "ISharedSecret/default"),
}
HEALTH_CONTRACT = "android.hardware.health@2.1::IHealth/default"
AUDIO_CONTRACT = "android.hardware.audio@7.1::IDevicesFactory/default"
AUDIO_EFFECT_CONTRACT = "android.hardware.audio.effect@7.0::IEffectsFactory/default"
AUDIO_EFFECT_LEGACY_CONTRACT = "android.hardware.audio.effect@7.1::IEffectsFactory/default"
GATEKEEPER_CONTRACT = "android.hardware.gatekeeper@1.0::IGatekeeper/default"
DEVICE_PROVIDERS = {**GRAPHICS_DEVICE, HEALTH_CONTRACT: "hwbinder", AUDIO_CONTRACT: "hwbinder",
                    AUDIO_EFFECT_CONTRACT: "hwbinder", AUDIO_EFFECT_LEGACY_CONTRACT: "hwbinder",
                    GATEKEEPER_CONTRACT: "hwbinder",
                    **{contract: "aidl" for contract in KEYMINT_DEVICE}}
FRAMEWORK_HIDL = {
    "android.hidl.allocator@1.0::IAllocator/ashmem",
    "android.hidl.manager@1.2::IServiceManager/default",
    "android.hidl.token@1.0::ITokenManager/default",
    "android.frameworks.sensorservice@1.0::ISensorManager/default",
    "android.frameworks.schedulerservice@1.0::ISchedulingPolicyService/default",
    "android.system.net.netd@1.1::INetd/default",
}

SUSPEND = "system_suspend"
CONTRACT = "android.system.suspend.ISystemSuspend/default"
HW_MANAGER = "hwservicemanager"
GRAPHICS = "graphics_cpu"
INSTALLER = "installd"
KEYSTORE = "keystore2"
KEYMINT = "keymint"
GATEKEEPER = "gatekeeper"
STORAGED = "storaged"
ODSIGN = "odsign"
HEALTH = "health"
VOLD = "vold"
LMKD = "lmkd"
NETD = "netd"
AUDIOSERVER = "audioserver"
AUDIO_HAL = "audio_hal"

BPF_PROVIDER = "netd-iptables-trafficstats-v2"
BPF_BACKEND = "quota2-native-ipv4"
BPF_STATUS = "unsupported"
BPF_NETD_READINESS = "source-repair-required"
BPF_STOCK_RC = "system/etc/init/bpfloader.rc"
BPF_PROFILE_FIELDS = {
    "provider": BPF_PROVIDER,
    "backend": BPF_BACKEND,
    "source_rc": BPF_STOCK_RC,
    "bpf_progs_loaded": False,
    "bpf_status": BPF_STATUS,
    "readiness": BPF_NETD_READINESS,
}


def graphics_selection(device):
    base = {
        "android.hardware.graphics.allocator@2.0::IAllocator/default",
        "android.hardware.graphics.mapper@2.0::IMapper/default",
    }
    return any(
        set(device) == base | {
            f"android.hardware.graphics.composer@{version}::IComposer/default"
        }
        for version in ["2.1", "2.4"]
    )


def validate_vintf_selection(selection):
    if not isinstance(selection, dict) or set(selection) != {"framework", "device"}:
        raise ValueError("invalid VINTF selection")
    names = selection["framework"]
    if (not isinstance(names, list) or len(names) > 64 or
            any(not isinstance(name, str) or len(name) > 256 or
                not (SERVICE.fullmatch(name) or name in FRAMEWORK_HIDL) for name in names) or
            len(set(names)) != len(names)):
        raise ValueError("invalid framework VINTF service selection")
    device = selection["device"]
    if (not isinstance(device, list) or len(device) > len(DEVICE_PROVIDERS) or
            any(not isinstance(name, str) or name not in DEVICE_PROVIDERS for name in device) or
            len(set(device)) != len(device)):
        raise ValueError("device HAL declarations require a configured Scarlet provider")
    return selection


def validate_network_provider(profile):
    if "network_provider" not in profile:
        return None
    selected = profile["network_provider"]
    if (not isinstance(selected, dict) or
            set(selected) != set(BPF_PROFILE_FIELDS) | {"source_sha256"} or
            any(selected.get(key) != value for key, value in BPF_PROFILE_FIELDS.items()) or
            selected.get("bpf_progs_loaded") is not False or
            not isinstance(selected.get("source_sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", selected["source_sha256"]) or
            NETD not in profile.get("host_services", [])):
        raise ValueError("unsupported Scarlet userspace BPF provider selection")
    return selected


def validate_host_services(profile):
    names = profile.get("host_services", [])
    if (not isinstance(names, list) or len(names) > 15 or
            any(name not in (
                SUSPEND, HW_MANAGER, GRAPHICS, INSTALLER, ODSIGN, HEALTH, VOLD, LMKD,
                NETD, AUDIOSERVER, AUDIO_HAL, KEYSTORE, KEYMINT, GATEKEEPER, STORAGED,
            ) for name in names) or
            len(set(names)) != len(names)):
        raise ValueError("unsupported stock host service selection")
    validate_network_provider(profile)
    selected = CONTRACT in profile.get("vintf", {}).get("framework", [])
    if selected != (SUSPEND in names):
        raise ValueError("SystemSuspend requires both its host provider and VINTF contract")
    if FRAMEWORK_HIDL.intersection(profile.get("vintf", {}).get("framework", [])) and HW_MANAGER not in names:
        raise ValueError("HIDL framework management requires its stock provider")
    device = profile.get("vintf", {}).get("device", [])
    keymint_contracts = set(KEYMINT_DEVICE)
    graphics = [name for name in device if name not in
                (HEALTH_CONTRACT, AUDIO_CONTRACT, AUDIO_EFFECT_CONTRACT,
                 AUDIO_EFFECT_LEGACY_CONTRACT, GATEKEEPER_CONTRACT, *keymint_contracts)]
    if (GRAPHICS in names and (HW_MANAGER not in names or not graphics_selection(graphics)) or
            GRAPHICS not in names and graphics):
        raise ValueError("graphics services require their exact device inventory and hardware-service manager")
    if ((HEALTH in names) != (HEALTH_CONTRACT in device) or
            HEALTH in names and HW_MANAGER not in names):
        raise ValueError("Health requires its exact device contract and hardware-service manager")
    audio_device = (AUDIO_CONTRACT in device and
                    (AUDIO_EFFECT_CONTRACT in device or AUDIO_EFFECT_LEGACY_CONTRACT in device))
    if ((AUDIO_HAL in names) != audio_device or
            AUDIO_HAL in names and HW_MANAGER not in names):
        raise ValueError("Audio HAL requires its exact device contract and hardware-service manager")
    keymint_selected = bool(set(device) & keymint_contracts)
    if ((KEYMINT in names) != keymint_selected or
            keymint_selected and set(device) & keymint_contracts != keymint_contracts):
        raise ValueError("KeyMint requires its exact device contract inventory")
    if KEYSTORE in names and KEYMINT not in names:
        raise ValueError("Keystore2 requires the software KeyMint provider")
    gatekeeper_selected = GATEKEEPER_CONTRACT in profile.get("vintf", {}).get("device", [])
    if ((GATEKEEPER in names) != gatekeeper_selected or
            gatekeeper_selected and HW_MANAGER not in names):
        raise ValueError("GateKeeper requires its exact device contract and hardware-service manager")
    return names


def validate_packages(profile):
    if "package_set" in profile and profile["package_set"] != "stock-home":
        raise ValueError("unsupported Android package selection")
