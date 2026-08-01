// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-pty-forward
//
// PORT-SYNC: src/ptyfwd/ptyfwd-tool.c

use systemd_shared_rs::unsafe_ffi;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const PROGRAM: &str = "systemd-pty-forward";

fn print_help() {
    println!("{PROGRAM} [OPTIONS...] COMMAND ...");
    println!();
    println!("  -h --help             Show this help");
    println!("     --version          Show package version");
    println!("  -q --quiet            Suppress output");
    println!("     --read-only        Read-only PTY");
    println!("     --background=COLOR Set background color");
    println!("     --title=TITLE      Set terminal title");
}

fn print_version() {
    println!("{PROGRAM} {VERSION}");
}

fn parse_args() -> Result<(bool, bool, Vec<String>), String> {
    let args: Vec<String> = std::env::args().collect();
    let mut quiet = false;
    let mut read_only = false;
    let mut command = Vec::new();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return Err(String::new());
            }
            "--version" => {
                print_version();
                return Err(String::new());
            }
            "-q" | "--quiet" => quiet = true,
            "--read-only" => read_only = true,
            "--background" | "--title" => {
                i += 1;
                if i == args.len() {
                    return Err(format!(
                        "{PROGRAM}: option {} requires an argument",
                        args[i - 1]
                    ));
                }
            }
            value if value.starts_with("--background=") || value.starts_with("--title=") => {}
            "--" => {
                command.extend_from_slice(&args[i + 1..]);
                break;
            }
            value if value.starts_with('-') => {
                return Err(format!("{PROGRAM}: unknown option: {value}"));
            }
            _ => {
                // Match OPTION_PARSER_STOP_AT_FIRST_NONOPTION: the command and all
                // following arguments belong to the child, even if they start with '-'.
                command.extend_from_slice(&args[i..]);
                break;
            }
        }
        i += 1;
    }

    if command.is_empty() {
        return Err(format!("{PROGRAM}: Expected command line, refusing."));
    }

    Ok((quiet, read_only, command))
}

#[cfg(target_os = "linux")]
fn open_pty_pair() -> std::io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: `/dev/ptmx` is a static, NUL-terminated pathname and the flags
    // follow the open(2) contract without requiring a mode argument.
    let raw_master = unsafe_ffi!({
        libc::open(
            c"/dev/ptmx".as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    });
    if raw_master < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: `raw_master` was returned by open(2) above and is uniquely owned
    // here, so transferring it into OwnedFd arranges exactly one close(2).
    let master = unsafe_ffi!(OwnedFd::from_raw_fd(raw_master));

    // SAFETY: `master` is a valid Unix98 PTY master FD. Linux devpts grants
    // access when the PTY is created; like openpt_allocate(), only unlock it.
    if unsafe_ffi!(libc::unlockpt(master.as_raw_fd())) != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // TIOCGPTPEER can transiently return EIO while the peer becomes usable.
    // Keep the same bounded retry policy as pty_open_peer(): 20 50ms sleeps.
    let mut retry = 0;
    let raw_slave = loop {
        // SAFETY: TIOCGPTPEER is the race-free peer-opening ioctl used by the
        // C implementation. The final argument is the peer open(2) flags it
        // expects, and `master` remains valid for this call.
        let fd = unsafe_ffi!({
            libc::ioctl(
                master.as_raw_fd(),
                libc::TIOCGPTPEER,
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        });
        if fd >= 0 {
            break fd;
        }

        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EIO) {
            return Err(error);
        }

        // pty_open_peer() allows 20 retries, or roughly one second total.
        // The sleep occurs before fork, so it cannot violate child fork rules.
        if retry >= 20 {
            return Err(error);
        }
        retry += 1;
        std::thread::sleep(std::time::Duration::from_millis(50));
    };

    // SAFETY: TIOCGPTPEER returned a newly owned descriptor on success.
    let slave = unsafe_ffi!(OwnedFd::from_raw_fd(raw_slave));
    Ok((master, slave))
}

#[cfg(target_os = "linux")]
fn child_exec(
    master_fd: std::os::fd::RawFd,
    slave_fd: std::os::fd::RawFd,
    original_parent_pid: libc::pid_t,
    argv0: *const libc::c_char,
    argv: *const *const libc::c_char,
) -> ! {
    // This branch runs only in the post-fork child.
    // SAFETY: descriptors and argv were created before fork and remain valid
    // in the copied address space; this path reaches execvp(3) without Rust work.
    unsafe_ffi!({
        libc::close(master_fd);

        if libc::dup2(slave_fd, libc::STDIN_FILENO) < 0
            || libc::dup2(slave_fd, libc::STDOUT_FILENO) < 0
            || libc::dup2(slave_fd, libc::STDERR_FILENO) < 0
        {
            libc::_exit(1);
        }
        if slave_fd > libc::STDERR_FILENO {
            libc::close(slave_fd);
        }

        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) < 0 {
            libc::_exit(1);
        }
        // PR_SET_PDEATHSIG does not deliver a signal when the parent died in
        // the small window before the prctl call. Mirror safe_fork_full()'s
        // post-install check so the child cannot survive that race.
        let current_parent_pid = libc::getppid();
        if current_parent_pid != 0 && current_parent_pid != original_parent_pid {
            libc::_exit(1);
        }
        if libc::setsid() < 0 || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) < 0 {
            libc::_exit(1);
        }

        libc::execvp(argv0, argv);
        // Match the C helper's `_exit(EXIT_FAILURE)` on failed execvp(3).
        libc::_exit(1);
    })
}

#[cfg(target_os = "linux")]
fn wait_status_code(status: nix::sys::wait::WaitStatus) -> i32 {
    match status {
        nix::sys::wait::WaitStatus::Exited(_, code) => code,
        nix::sys::wait::WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
        _ => 1,
    }
}

#[cfg(target_os = "linux")]
fn run() -> i32 {
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;

    let (_quiet, read_only, command) = match parse_args() {
        Ok(parsed) => parsed,
        Err(message) if message.is_empty() => return 0,
        Err(message) => {
            eprintln!("{message}");
            return 1;
        }
    };

    // Construct argv before fork so an interior NUL is reported normally and
    // the child does not allocate or panic between fork and exec.
    let c_args: Vec<CString> = match command
        .iter()
        .map(|argument| CString::new(argument.as_str()))
        .collect()
    {
        Ok(arguments) => arguments,
        Err(_) => {
            eprintln!("{PROGRAM}: command contains an interior NUL byte");
            return 1;
        }
    };
    let c_argv: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|argument| argument.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let (master, slave) = match open_pty_pair() {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("{PROGRAM}: failed to acquire pseudo tty: {error}");
            return 1;
        }
    };

    // SAFETY: getpid(2) takes no arguments and only returns the caller's PID.
    let original_parent_pid = unsafe_ffi!(libc::getpid());

    // SAFETY: No application threads have been created yet. The child only
    // performs the limited post-fork setup below before execvp.
    match unsafe_ffi!(nix::unistd::fork()) {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            drop(slave);

            let mut output = File::from(master);
            if !read_only {
                let input = match output.try_clone() {
                    Ok(input) => input,
                    Err(error) => {
                        eprintln!("{PROGRAM}: failed to duplicate pseudo tty: {error}");
                        return 1;
                    }
                };
                let _input_thread = match std::thread::Builder::new()
                    .name("ptyfwd-input".to_string())
                    .spawn(move || {
                        let mut stdin = io::stdin().lock();
                        let mut input = input;
                        let _ = io::copy(&mut stdin, &mut input);
                    }) {
                    Ok(thread) => thread,
                    Err(error) => {
                        eprintln!("{PROGRAM}: failed to start input forwarding: {error}");
                        return 1;
                    }
                };
            }

            let mut stdout = io::stdout().lock();
            if let Err(error) = io::copy(&mut output, &mut stdout)
                && error.raw_os_error() != Some(libc::EIO)
            {
                eprintln!("{PROGRAM}: failed to forward pseudo tty output: {error}");
            }

            match nix::sys::wait::waitpid(child, None) {
                Ok(status) => wait_status_code(status),
                Err(error) => {
                    eprintln!("{PROGRAM}: waitpid failed: {error}");
                    1
                }
            }
        }
        Ok(nix::unistd::ForkResult::Child) => {
            child_exec(
                master.as_raw_fd(),
                slave.as_raw_fd(),
                original_parent_pid,
                c_args[0].as_ptr(),
                c_argv.as_ptr(),
            );
        }
        Err(error) => {
            eprintln!("{PROGRAM}: fork failed: {error}");
            1
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    std::process::exit(run());

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("{PROGRAM}: PTY forwarding requires Linux");
        std::process::exit(1);
    }
}
