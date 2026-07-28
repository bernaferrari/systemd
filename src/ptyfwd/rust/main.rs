// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-ptyfwd
//
// PORT-SYNC: src/ptyfwd/ptyfwd-tool.c

use systemd_ptyfwd_rs::ptyfwd::{PtyForwardConfig, is_valid_pty_path};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-ptyfwd [OPTIONS...] [COMMAND...]");
    println!();
    println!("  -h --help             Show this help");
    println!("     --version          Show package version");
    println!("     --quiet            Suppress output");
    println!("     --read-only        Read-only PTY");
    println!("     --background=COLOR Set background color");
    println!("     --title=TITLE      Set terminal title");
}

fn print_version() {
    println!("systemd-ptyfwd {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut quiet = false;
    let mut read_only = false;
    let mut _background: Option<String> = None;
    let mut _title: Option<String> = None;
    let mut command: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--version" => {
                print_version();
                return;
            }
            "--quiet" => quiet = true,
            "--read-only" => read_only = true,
            s if s.starts_with("--background=") => {
                _background = Some(s[13..].to_string());
            }
            s if s.starts_with("--background") => {
                i += 1;
                if i < args.len() {
                    _background = Some(args[i].clone());
                }
            }
            s if s.starts_with("--title=") => {
                _title = Some(s[8..].to_string());
            }
            s if s.starts_with("--title") => {
                i += 1;
                if i < args.len() {
                    _title = Some(args[i].clone());
                }
            }
            s if s.starts_with('-') => {
                eprintln!("ptyfwd: unknown option: {}", s);
                std::process::exit(1);
            }
            other => command.push(other.to_string()),
        }
        i += 1;
    }

    if command.is_empty() {
        command.push("/bin/bash".to_string());
    }

    let config = PtyForwardConfig::new();
    if let Err(e) = config.validate() {
        eprintln!("ptyfwd: config error: {:?}", e);
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::io::{Read, Write};

        let ptx_path = CString::new("/dev/ptmx").unwrap();
        let ptx_fd = unsafe {
            libc::open(
                ptx_path.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if ptx_fd < 0 {
            eprintln!("ptyfwd: failed to open /dev/ptmx");
            std::process::exit(1);
        }

        if unsafe { libc::grantpt(ptx_fd) } != 0 || unsafe { libc::unlockpt(ptx_fd) } != 0 {
            eprintln!("ptyfwd: failed to configure PTY");
            unsafe { libc::close(ptx_fd) };
            std::process::exit(1);
        }

        let pts_name = unsafe {
            let mut buf = [0u8; 256];
            libc::ptsname_r(ptx_fd, buf.as_mut_ptr().cast::<libc::c_char>(), buf.len());
            let len = buf.iter().position(|&b| b == 0).unwrap_or(0);
            String::from_utf8_lossy(&buf[..len]).to_string()
        };

        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                unsafe { libc::close(libc::posix_openpt(libc::O_RDWR)) };

                let pts_fd = unsafe {
                    libc::open(
                        CString::new(pts_name.as_str()).unwrap().as_ptr(),
                        libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
                    )
                };

                if pts_fd >= 0 && !read_only {
                    let mut stdin_buf = [0u8; 4096];
                    let stdin_fd = 0;
                    loop {
                        let n = match std::io::stdin().read(&mut stdin_buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        unsafe {
                            libc::write(pts_fd, stdin_buf[..n].as_ptr() as *const libc::c_void, n);
                        }
                    }
                }

                match nix::sys::wait::waitpid(child, None) {
                    Ok(status) => {
                        if !quiet {
                            eprintln!("ptyfwd: child exited: {:?}", status);
                        }
                    }
                    Err(e) => {
                        eprintln!("ptyfwd: waitpid failed: {}", e);
                    }
                }
            }
            Ok(nix::unistd::ForkResult::Child) => {
                unsafe {
                    libc::close(ptx_fd);
                    libc::setsid();

                    let pts_c = CString::new(pts_name.as_str()).unwrap();
                    let pts_slave = libc::open(pts_c.as_ptr(), libc::O_RDWR);
                    if pts_slave >= 0 {
                        libc::dup2(pts_slave, 0);
                        libc::dup2(pts_slave, 1);
                        libc::dup2(pts_slave, 2);
                        if pts_slave > 2 {
                            libc::close(pts_slave);
                        }
                    }
                }

                let c_argv0 = CString::new(command[0].clone()).unwrap();
                let c_args: Vec<CString> = command
                    .iter()
                    .map(|a| CString::new(a.as_str()).unwrap())
                    .collect();
                let c_ptrs: Vec<*const libc::c_char> = c_args
                    .iter()
                    .map(|a| a.as_ptr())
                    .chain(std::iter::null())
                    .collect();
                unsafe {
                    libc::execvp(c_argv0.as_ptr(), c_ptrs.as_ptr());
                }
                eprintln!("ptyfwd: execvp failed");
                std::process::exit(127);
            }
            Err(e) => {
                eprintln!("ptyfwd: fork failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("ptyfwd: PTY forwarding requires Linux");
        eprintln!("  command={}", command.join(" "));
        std::process::exit(1);
    }
}
