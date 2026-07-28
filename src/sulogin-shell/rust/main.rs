// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-sulogin-shell

use systemd_sulogin_shell_rs::{SPECIAL_DEFAULT_TARGET, build_sulogin_cmdline, determine_target};

fn print_help() {
    eprintln!("Usage: systemd-sulogin-shell [emergency|rescue]");
    eprintln!();
    eprintln!("  -h --help             Show this help");
    eprintln!("     --version          Show package version");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut is_emergency = false;

    for arg in &args[1..] {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--version" => {
                eprintln!("systemd-sulogin-shell {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "emergency" => is_emergency = true,
            _ => {}
        }
    }

    let target = determine_target(is_emergency);
    let _ = target;
    let cmdline_parts = build_sulogin_cmdline(is_emergency);

    let (program, argv): (&str, Vec<&str>) = match cmdline_parts.split_first() {
        Some((&p, rest)) => (p, rest.to_vec()),
        None => {
            eprintln!("sulogin-shell: no sulogin command available");
            std::process::exit(1);
        }
    };

    #[cfg(target_os = "linux")]
    {
        let c_program = std::ffi::CString::new(program).unwrap();
        let c_args: Vec<std::ffi::CString> = std::iter::once(c_program.clone())
            .chain(argv.iter().map(|a| std::ffi::CString::new(*a).unwrap()))
            .collect();
        let c_args_ptrs: Vec<*const std::ffi::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
        unsafe {
            libc::execvp(c_program.as_ptr(), c_args_ptrs.as_ptr());
        }
        eprintln!("sulogin-shell: execvp failed");
        std::process::exit(127);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = program;
        let _ = argv;
        eprintln!("sulogin-shell: exec not available on this platform");
        std::process::exit(127);
    }
}
