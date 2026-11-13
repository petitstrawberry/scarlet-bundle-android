#![no_std]
#![no_main]

extern crate scarlet_std as std;

mod app_policy;
mod boot_profile;
mod input_bridge;
mod native_display;
mod setup;

use std::{
    environment::{HandleMapping, VfsView},
    handle::Handle,
    println,
    process_scope::ProcessScope,
};

fn wait_for_program(pid: i32) -> Result<i32, &'static str> {
    for _ in 0..500 {
        let (waited, status) = std::task::waitpid(pid, std::task::WAIT_NOHANG);
        if waited == pid {
            return Ok(status);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err("Android child termination timed out")
}

struct Session {
    scope: ProcessScope,
    init: i32,
    reaped: bool,
    closed: bool,
}

impl Session {
    fn finish(&mut self) -> Result<(), &'static str> {
        if self.closed {
            return Ok(());
        }
        self.scope
            .set_reaper(0)
            .map_err(|_| "Android scope reaper")?;
        let mut delivered = false;
        for _ in 0..100 {
            if !delivered {
                delivered = self.scope.terminate().is_ok();
            }
            // Native window/bridge children are stopped before this call. The
            // remaining children are init and adopted members of this scope.
            for _ in 0..1024 {
                let (pid, _) = std::task::waitpid(-1, std::task::WAIT_NOHANG);
                if pid <= 0 {
                    break;
                }
                if pid == self.init {
                    self.reaped = true;
                }
            }
            let status = self.scope.status().map_err(|_| "Android scope status")?;
            if delivered && self.reaped && status.live == 0 && status.members == 0 {
                self.closed = true;
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Err("Android process scope cleanup timed out")
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            println!("android: {}", error);
        }
    }
}

fn run(stdio: &[Handle]) -> Result<i32, &'static str> {
    let args = std::env::args_vec();
    if args.len() != 3 || args[1] != "--view-handle" {
        return Err("usage: android --view-handle FD (an explicitly delegated native View)");
    }
    let raw: i32 = args[2].parse().map_err(|_| "invalid View descriptor")?;
    if raw < 3 {
        return Err("View descriptor overlaps standard I/O");
    }
    // SAFETY: the launch contract transfers this owned descriptor exactly once.
    let native =
        VfsView::from_handle(unsafe { Handle::from_raw(raw) }.map_err(|_| "View descriptor")?)
            .map_err(|_| "View capability required")?;
    // Validate administration before changing any Android state. A use-only
    // View cannot be converted into construction authority by this program.
    let native = native
        .clone_mounts()
        .map_err(|_| "View administration required")?;
    let handles: std::vec::Vec<_> = stdio
        .iter()
        .enumerate()
        .map(|(target, source)| HandleMapping {
            source,
            target: target as u32,
        })
        .collect();

    let (environment, android, policy, display) = setup::prepare(native)?;
    let executable = android
        .open("/system/bin/init", 0)
        .map_err(|_| "stock Android init")?;
    let scope = ProcessScope::create().map_err(|_| "Android process scope")?;
    let (gate_read, gate_write) = std::task::pipe().map_err(|_| "init startup gate")?;

    // Fork before the policy worker and input bridge start threads. The child
    // waits for their setup to finish rather than relying on boot delays.
    let pid = std::task::fork();
    if pid < 0 {
        return Err("Android init fork");
    }
    if pid == 0 {
        drop(gate_write);
        let start = (|| -> Result<core::convert::Infallible, &'static str> {
            // Enroll before waiting, so setup failure in the parent can always
            // stop this child. A scope closed first rejects late enrollment.
            // SAFETY: supported native namespace flags and a live C string.
            let result = unsafe {
                std::syscall::syscall2(
                    std::syscall::Syscall::CreateNamespace,
                    3,
                    c"android".as_ptr() as usize,
                )
            };
            if result != 0 {
                return Err("Android PID/mount namespace");
            }
            scope.enter().map_err(|_| "Android scope membership")?;
            scope.set_reaper(0).map_err(|_| "Android orphan reaper")?;
            let mut ready = [0];
            if gate_read
                .as_stream()
                .map_err(|_| "init gate")?
                .read(&mut ready)
                .map_err(|_| "init gate read")?
                != 1
                || ready != [1]
            {
                return Err("Android manager setup failed");
            }
            drop(gate_read);
            environment
                .exec_with_abi(
                    "android-aarch64",
                    &executable,
                    &["/system/bin/init", "second_stage"],
                    &[
                        "PATH=/system/bin:/system/xbin",
                        "ANDROID_ROOT=/system",
                        "ANDROID_DATA=/data",
                    ],
                    "/",
                    &handles,
                )
                .map_err(|_| "stock Android init exec")
        })();
        let Err(error) = start;
        println!("android: {}", error);
        std::task::exit(1);
    }
    drop(gate_read);
    let mut session = Session {
        scope,
        init: pid,
        reaped: false,
        closed: false,
    };
    let worker = app_policy::start(policy, &android)?;
    let mut display = display.start(&environment, &handles)?;
    display.set_session(pid as u32);
    gate_write
        .as_stream()
        .map_err(|_| "init gate writer")?
        .write_all(&[1])
        .map_err(|_| "init gate release")?;
    drop(gate_write);
    println!("android: stock init started, host pid={}", pid);

    let status = loop {
        let (waited, status) = std::task::waitpid(pid, std::task::WAIT_NOHANG);
        if waited == pid {
            session.reaped = true;
            break status;
        }
        if waited < 0 {
            // Native wait does not distinguish an interrupted wait from a
            // missing child. Recheck instead of ending a live session.
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        if worker.failed() {
            return Err("Android app policy worker failed");
        }
        if let Some(status) = display.exit_status() {
            break status;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    // Reap the separately owned native children first, then drain Android's
    // process scope without consuming another supervisor's child status.
    drop(display);
    session.finish()?;
    worker.finish()?;
    Ok(status)
}

#[unsafe(no_mangle)]
fn main() -> i32 {
    // Keep standard streams alive through error reporting and session cleanup.
    // Owning them inside run() would close stdout before its error is printed.
    let mut stdio = std::vec::Vec::new();
    for descriptor in 0..3 {
        // SAFETY: these descriptors were transferred as this program's stdio.
        match unsafe { Handle::from_raw(descriptor) } {
            Ok(handle) => stdio.push(handle),
            Err(_) => {
                println!("android: standard I/O unavailable");
                return 1;
            }
        }
    }
    match run(&stdio) {
        Ok(status) => status,
        Err(error) => {
            println!("android: {}", error);
            1
        }
    }
}
