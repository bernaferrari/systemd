// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-mount / systemd-umount
//
// PORT-SYNC: src/mount/mount-tool.c

use systemd_mount_rs::invoked_as_umount;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help(program: &str) {
    if invoked_as_umount(program) {
        println!("systemd-umount [OPTIONS...] WHAT|WHERE...");
        println!();
        println!("Unmount one or more mount points.");
    } else {
        println!("systemd-mount [OPTIONS...] WHAT [WHERE]");
        println!("systemd-mount [OPTIONS...] --tmpfs [NAME] WHERE");
        println!("systemd-mount [OPTIONS...] --list");
        println!("systemd-mount [OPTIONS...] --umount WHAT|WHERE...");
        println!();
        println!("Establish a mount or auto-mount point.");
    }
}

fn print_version(program: &str) {
    let name = if invoked_as_umount(program) {
        "systemd-umount"
    } else {
        "systemd-mount"
    };
    println!("{} {}", name, VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let program = args.first().map(String::as_str).unwrap_or("systemd-mount");

    // systemd-mount is a D-Bus transient-unit client, not a mount(2) wrapper.
    // Reject every operational request before parsing paths, consulting /proc,
    // or invoking mount/umount until the full bus lifecycle is available.
    match args.as_slice() {
        [_, flag] if flag == "-h" || flag == "--help" => {
            print_help(program);
            return;
        }
        [_, flag] if flag == "--version" => {
            print_version(program);
            return;
        }
        _ => {}
    }

    eprintln!(
        "{}: native Rust mount operations are not implemented; refusing to operate",
        if invoked_as_umount(program) {
            "systemd-umount"
        } else {
            "systemd-mount"
        }
    );
    std::process::exit(1);
}
