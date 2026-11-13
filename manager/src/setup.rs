//! Construct Android's execution views using explicitly delegated authority.
use std::{
    environment::{Environment, VfsView},
    shield::Policy,
};

pub fn prepare(
    native: VfsView,
) -> Result<(Environment, VfsView, Policy, super::native_display::Setup), &'static str> {
    let android = native
        .rooted_at("/systems/android-aarch64")
        .map_err(|_| "Android image root")?;
    std::vm::configure_layout(24, 16).map_err(|_| "Android address layout")?;
    std::shield::hide_kernel_addresses().map_err(|_| "Shield kernel address constraint")?;
    let upper = VfsView::create("tmpfs", "size=64M").map_err(|_| "Android device storage")?;
    let devices = VfsView::overlay(&native, "/dev", Some((&upper, "/")))
        .map_err(|_| "Android device overlay")?;
    for path in ["/__properties__", "/socket", "/binderfs", "/cgroup_info"] {
        devices
            .create_directory(path)
            .map_err(|_| "Android device directory")?;
    }
    let aliases = VfsView::create("android-binder", "aliases").map_err(|_| "Binder aliases")?;
    let devices = VfsView::overlay(&aliases, "/", Some((&devices, "/")))
        .map_err(|_| "Binder device aliases")?;
    android
        .bind("/dev", &devices, "/")
        .map_err(|_| "Android device view")?;
    android
        .mount("/dev/binderfs", "android-binder", "")
        .map_err(|_| "Binder filesystem")?;
    for path in ["/__properties__", "/cgroup_info"] {
        android
            .bind(&std::format!("/dev{path}"), &upper, path)
            .map_err(|_| "Android device storage bind")?;
    }
    for path in ["/dev/pts", "/tmp"] {
        android
            .bind(path, &native, path)
            .map_err(|_| "Android shared endpoint")?;
    }
    let discovery = VfsView::create("linux-device-tree", "").map_err(|_| "device discovery")?;
    android
        .bind("/sys/devices", &discovery, "/")
        .map_err(|_| "Android device discovery")?;
    let power = VfsView::create("linux-power-supply", "").map_err(|_| "power supply telemetry")?;
    android
        .bind("/sys/class/power_supply", &power, "/")
        .map_err(|_| "Android power supplies")?;

    let (policy, version) = super::boot_profile::policy(&android)?;
    let security_options = match version {
        Some(version) => std::format!(
            "policy={},policy_version={version}",
            policy.as_handle().as_raw(),
        ),
        None => std::format!("policy={}", policy.as_handle().as_raw()),
    };
    let security = VfsView::create("android-selinux", &security_options)
        .map_err(|_| "Android policy correspondence")?;
    android
        .bind("/sys/fs/selinux", &security, "/")
        .map_err(|_| "Android policy view")?;
    policy.apply(1).map_err(|_| "Android manager subject")?;
    let resources =
        std::resource_group::ResourceGroup::create_root().map_err(|_| "Android resource root")?;
    resources
        .enter(0)
        .map_err(|_| "Android resource membership")?;
    let display = super::native_display::prepare(&android)?.ok_or("Android display setup")?;
    let environment = Environment::create().map_err(|_| "Android Environment")?;
    environment
        .set_root("scarlet", &native)
        .map_err(|_| "native View registration")?;
    environment
        .set_root("android-aarch64", &android)
        .map_err(|_| "Android View registration")?;
    environment.seal().map_err(|_| "Android Environment seal")?;
    Ok((environment, android, policy, display))
}
