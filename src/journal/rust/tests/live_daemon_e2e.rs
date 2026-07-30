// SPDX-License-Identifier: LGPL-2.1-or-later

#![cfg(unix)]

use nix::libc;
use nix::sys::signal::{Signal, kill};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, UnixAddr, recvmsg};
use nix::unistd::Pid;
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::io;
use std::io::{IoSliceMut, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use systemd_libsystemd_rs::id128_util::SdId128;
use systemd_libsystemd_rs::sd_id128_api::{sd_id128_get_machine, sd_id128_randomize};
use systemd_libsystemd_rs::sd_journal_file::{
    HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID, JOURNAL_FILE_SIZE_MIN, append_journal_record_unindexed,
    create_empty_journal_file_at, open_journal_file_at, render_journal_file_as_text,
};

const RUNTIME_ROOT_ENV: &str = "SYSTEMD_JOURNAL_RUNTIME_ROOT";
const STORAGE_MODE_ENV: &str = "SYSTEMD_JOURNAL_STORAGE";
const NAMESPACE_ENV: &str = "SYSTEMD_JOURNAL_NAMESPACE";
const RATE_LIMIT_INTERVAL_ENV: &str = "SYSTEMD_JOURNALD_RATE_LIMIT_INTERVAL_USEC";
const RATE_LIMIT_BURST_ENV: &str = "SYSTEMD_JOURNALD_RATE_LIMIT_BURST";
const SYSTEM_MAX_FILES_ENV: &str = "SYSTEMD_JOURNAL_SYSTEM_MAX_FILES";
const PROC_ROOT_ENV: &str = "SYSTEMD_JOURNAL_PROC_ROOT";
const RUN_SYSTEMD_ROOT_ENV: &str = "SYSTEMD_JOURNAL_RUN_SYSTEMD_ROOT";
const ACTIVE_JOURNAL_FILE_NAME: &str = "system.journal";

fn journald_bin() -> &'static str {
    env!("CARGO_BIN_EXE_systemd-journald")
}

fn journalctl_bin() -> &'static str {
    env!("CARGO_BIN_EXE_journalctl")
}

fn unique_artifact_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = PathBuf::from("/tmp").join(format!("rje-{prefix}-{}-{ts}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn wait_for_socket(path: &Path, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("socket did not appear at {}", path.display()),
    ))
}

fn stop_daemon(mut child: Child) {
    let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }
}

fn spawn_daemon(
    root: &Path,
    artifact_dir: &Path,
    log_name: &str,
    extra_env: &[(&str, &str)],
) -> Child {
    let stdout_path = artifact_dir.join(format!("{log_name}.stdout.log"));
    let stderr_path = artifact_dir.join(format!("{log_name}.stderr.log"));
    let stdout = fs::File::create(stdout_path).unwrap();
    let stderr = fs::File::create(stderr_path).unwrap();

    let mut cmd = Command::new(journald_bin());
    cmd.env(RUNTIME_ROOT_ENV, root)
        .env(STORAGE_MODE_ENV, "volatile")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.spawn().unwrap()
}

fn spawn_daemon_with_restored_stream_fd(
    root: &Path,
    artifact_dir: &Path,
    log_name: &str,
    restored_fd: libc::c_int,
) -> Child {
    let stdout_path = artifact_dir.join(format!("{log_name}.stdout.log"));
    let stderr_path = artifact_dir.join(format!("{log_name}.stderr.log"));
    let stdout = fs::File::create(stdout_path).unwrap();
    let stderr = fs::File::create(stderr_path).unwrap();

    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("LISTEN_PID=$$ LISTEN_FDS=1 exec \"$1\"")
        .arg("sh")
        .arg(journald_bin());
    cmd.env(RUNTIME_ROOT_ENV, root)
        .env(STORAGE_MODE_ENV, "volatile")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    // SAFETY: pre_exec runs after fork and before exec; restored_fd is owned by
    // this launch path, and fd 3 is the documented socket-activation target.
    unsafe {
        cmd.pre_exec(move || {
            if restored_fd != 3 && libc::dup2(restored_fd, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            let flags = libc::fcntl(3, libc::F_GETFD);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        });
    }

    let child = cmd.spawn().unwrap();
    // SAFETY: the parent owns restored_fd and no longer needs it after spawn.
    let _ = unsafe { libc::close(restored_fd) };
    child
}

fn read_all_journal_text(root: &Path) -> String {
    let mut files = fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name == ACTIVE_JOURNAL_FILE_NAME
                        || name.starts_with(&format!("{ACTIVE_JOURNAL_FILE_NAME}."))
                        || name.ends_with(".journal")
                })
        })
        .collect::<Vec<_>>();
    files.sort();

    let mut out = String::new();
    for path in files {
        if let Ok(text) = render_journal_file_as_text(&path) {
            out.push_str(&format!("## {}\n{text}\n", path.display()));
        }
    }
    out
}

fn seed_journal_text_records(path: &Path, records: &[&str]) {
    let file_id = sd_id128_randomize().unwrap_or_else(|_| SdId128::null());
    let machine_id = sd_id128_get_machine().unwrap_or_else(|_| SdId128::null());
    let seqnum_id = sd_id128_randomize().unwrap_or_else(|_| SdId128::null());
    let mut journal = match open_journal_file_at(path, true) {
        Ok(journal) => journal,
        Err(err) if err.kind() == io::ErrorKind::NotFound => create_empty_journal_file_at(
            path,
            0o644,
            JOURNAL_FILE_SIZE_MIN,
            file_id,
            machine_id,
            seqnum_id,
            HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
            0,
        )
        .unwrap(),
        Err(err) => panic!("failed to open journal {}: {err}", path.display()),
    };

    for record in records {
        let owned_fields = record
            .split('|')
            .filter(|field| !field.is_empty())
            .map(|field| {
                if field.contains('=') {
                    field.as_bytes().to_vec()
                } else {
                    format!("MESSAGE={field}").into_bytes()
                }
            })
            .collect::<Vec<_>>();
        let field_refs = owned_fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        append_journal_record_unindexed(
            &mut journal.file,
            &mut journal.header,
            1,
            1,
            SdId128::null(),
            &field_refs,
        )
        .unwrap();
    }

    journal.file.sync_all().unwrap();
}

fn send_with_retry(sender: &UnixDatagram, socket: &Path, payload: &[u8]) -> io::Result<()> {
    let mut last_error = None;
    for _ in 0..16 {
        match sender.send_to(payload, socket) {
            Ok(_) => return Ok(()),
            Err(err)
                if err.raw_os_error() == Some(libc::ENOBUFS)
                    || err.kind() == io::ErrorKind::WouldBlock =>
            {
                last_error = Some(err);
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::other(format!("failed to send datagram to {}", socket.display()))
    }))
}

fn rotated_archive_name(seq: u64, realtime_usec: u64) -> String {
    format!("journal@00000000000000000000000000000000-{seq:016x}-{realtime_usec:016x}.journal")
}

fn count_archived_logs(root: &Path) -> usize {
    fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("journal@") && name.ends_with(".journal"))
        })
        .count()
}

fn wait_for_journal_contains(root: &Path, needle: &str, timeout: Duration) -> io::Result<String> {
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < timeout {
        last = read_all_journal_text(root);
        if last.contains(needle) {
            return Ok(last);
        }
        thread::sleep(Duration::from_millis(20));
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "journal did not contain `{needle}` within {:?}\nlast snapshot:\n{last}",
            timeout
        ),
    ))
}

fn recv_notify_fd(socket: &UnixDatagram, timeout: Duration) -> io::Result<libc::c_int> {
    socket.set_nonblocking(true)?;
    let start = Instant::now();

    while start.elapsed() < timeout {
        let mut payload = [0_u8; 256];
        let mut iov = [IoSliceMut::new(&mut payload)];
        let mut cmsg_space = nix::cmsg_space!([libc::c_int; 1]);

        match recvmsg::<UnixAddr>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(msg) => {
                for cmsg in msg
                    .cmsgs()
                    .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?
                {
                    if let ControlMessageOwned::ScmRights(fds) = cmsg
                        && let Some(fd) = fds.first()
                    {
                        return Ok(*fd);
                    }
                }
            }
            Err(errno)
                if errno == nix::errno::Errno::EAGAIN || errno == nix::errno::Errno::EINTR =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(errno) => return Err(io::Error::from_raw_os_error(errno as i32)),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "timed out waiting for fdstore notification",
    ))
}

fn write_fake_proc_context(
    proc_root: &Path,
    pid: i32,
    cgroup: &str,
    command: &str,
    uid: u32,
    gid: u32,
) -> PathBuf {
    let pid_dir = proc_root.join(pid.to_string());
    fs::create_dir_all(pid_dir.join("attr")).unwrap();
    fs::write(pid_dir.join("comm"), format!("{command}\n")).unwrap();
    fs::write(
        pid_dir.join("cmdline"),
        format!("{command}\0--flag\0value with space\0"),
    )
    .unwrap();
    fs::write(
        pid_dir.join("status"),
        format!(
            "Name:\t{command}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nCapEff:\t0000000000000001\n"
        ),
    )
    .unwrap();
    fs::write(pid_dir.join("cgroup"), format!("0::{}\n", cgroup)).unwrap();
    fs::write(pid_dir.join("loginuid"), format!("{uid}\n")).unwrap();
    fs::write(pid_dir.join("sessionid"), "5\n").unwrap();
    fs::write(
        pid_dir.join("attr/current"),
        "system_u:system_r:demo_t:s0\n",
    )
    .unwrap();

    let exe_target = proc_root.join(format!("{command}.exe"));
    fs::write(&exe_target, b"demo").unwrap();
    std::os::unix::fs::symlink(&exe_target, pid_dir.join("exe")).unwrap();
    exe_target
}

fn write_invocation_link(run_systemd_root: &Path, unit: &str, id: &str) {
    let units_dir = run_systemd_root.join("units");
    fs::create_dir_all(&units_dir).unwrap();
    std::os::unix::fs::symlink(id, units_dir.join(format!("invocation:{unit}"))).unwrap();
}

fn write_unit_runtime_symlink(run_systemd_root: &Path, prefix: &str, unit: &str, target: &str) {
    let units_dir = run_systemd_root.join("units");
    fs::create_dir_all(&units_dir).unwrap();
    std::os::unix::fs::symlink(target, units_dir.join(format!("{prefix}:{unit}"))).unwrap();
}

fn write_unit_extra_fields(run_systemd_root: &Path, unit: &str, fields: &[&[u8]]) {
    let units_dir = run_systemd_root.join("units");
    fs::create_dir_all(&units_dir).unwrap();
    let mut blob = Vec::new();
    for field in fields {
        blob.extend_from_slice(&(field.len() as u64).to_le_bytes());
        blob.extend_from_slice(field);
    }
    fs::write(units_dir.join(format!("log-extra-fields:{unit}")), blob).unwrap();
}

#[test]
fn live_journald_binary_handles_ingress_and_rotate() {
    let artifact_dir = unique_artifact_dir("journald-ingress-rotate");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    fs::create_dir_all(&root).unwrap();

    let daemon = spawn_daemon(&root, &artifact_dir, "daemon", &[]);

    let socket = root.join("socket");
    let dev_log = root.join("dev-log");
    wait_for_socket(&socket, Duration::from_secs(3)).unwrap();
    wait_for_socket(&dev_log, Duration::from_secs(3)).unwrap();

    let sender = UnixDatagram::unbound().unwrap();
    send_with_retry(
        &sender,
        &dev_log,
        b"<13>Jan  1 12:00:00 app[100]: hello-syslog",
    )
    .unwrap();
    send_with_retry(&sender, &socket, b"MESSAGE=hello-native\n").unwrap();
    send_with_retry(&sender, &socket, b"6,9,500,-;hello-kmsg\n").unwrap();
    send_with_retry(
        &sender,
        &socket,
        b"type=SYSCALL msg=audit(1700000000.123:42): pid=1001 uid=1000 gid=1000",
    )
    .unwrap();

    let rotate_status = Command::new(journald_bin())
        .env(RUNTIME_ROOT_ENV, &root)
        .env(STORAGE_MODE_ENV, "volatile")
        .arg("--rotate")
        .status()
        .unwrap();
    assert!(rotate_status.success());

    send_with_retry(&sender, &socket, b"MESSAGE=after-rotate\n").unwrap();

    wait_for_journal_contains(&root, "after-rotate", Duration::from_secs(3))
        .expect("after-rotate message should be persisted before shutdown");

    stop_daemon(daemon);
    let combined = read_all_journal_text(&root);
    fs::write(artifact_dir.join("combined-journal.txt"), &combined).unwrap();

    assert!(combined.contains("transport=syslog"));
    assert!(combined.contains("transport=journal"));
    assert!(!combined.contains("transport=kernel"));
    assert!(!combined.contains("transport=audit"));
    assert!(!combined.contains("_AUDIT_TYPE="));
    assert!(!combined.contains("_AUDIT_TYPE_NAME="));
    assert!(combined.contains("transport=raw"));
    assert!(combined.contains("after-rotate"));
    assert!(root.join("rotated").exists());
    assert!(
        fs::read_dir(&root)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .any(|path| path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".journal")))
    );
}

#[test]
fn live_journald_binary_preserves_log_continuity_across_restart() {
    let artifact_dir = unique_artifact_dir("journald-restart");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    fs::create_dir_all(&root).unwrap();
    let socket = root.join("socket");
    let dev_log = root.join("dev-log");

    let sender = UnixDatagram::unbound().unwrap();

    let daemon1 = spawn_daemon(&root, &artifact_dir, "daemon-1", &[]);
    wait_for_socket(&socket, Duration::from_secs(3)).unwrap();
    wait_for_socket(&dev_log, Duration::from_secs(3)).unwrap();
    sender.send_to(b"MESSAGE=first-run\n", &socket).unwrap();
    thread::sleep(Duration::from_millis(50));
    stop_daemon(daemon1);

    let daemon2 = spawn_daemon(&root, &artifact_dir, "daemon-2", &[]);
    wait_for_socket(&socket, Duration::from_secs(3)).unwrap();
    wait_for_socket(&dev_log, Duration::from_secs(3)).unwrap();
    sender.send_to(b"MESSAGE=second-run\n", &socket).unwrap();
    thread::sleep(Duration::from_millis(50));
    stop_daemon(daemon2);

    let combined = read_all_journal_text(&root);
    fs::write(artifact_dir.join("restart-journal.txt"), &combined).unwrap();

    assert!(combined.contains("first-run"));
    assert!(combined.contains("second-run"));
}

#[test]
fn live_journald_binary_accepts_stdout_stream_messages() {
    let artifact_dir = unique_artifact_dir("journald-stdout-stream");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    fs::create_dir_all(&root).unwrap();

    let daemon = spawn_daemon(&root, &artifact_dir, "daemon", &[]);
    let stdout_socket = root.join("stdout");
    wait_for_socket(&stdout_socket, Duration::from_secs(3)).unwrap();

    let mut stream = UnixStream::connect(&stdout_socket).unwrap();
    stream.shutdown(Shutdown::Read).unwrap();
    stream.write_all(b"svc\n\n5\n1\n0\n0\n0\n").unwrap();
    stream
        .write_all(b"hello stdout\n<13>prefixed\ntrailing-eof")
        .unwrap();
    drop(stream);

    wait_for_journal_contains(&root, "trailing-eof", Duration::from_secs(3)).unwrap();
    stop_daemon(daemon);

    let combined = read_all_journal_text(&root);
    fs::write(artifact_dir.join("stdout-stream.txt"), &combined).unwrap();

    assert!(combined.contains("transport=stdout"));
    assert!(combined.contains("SYSLOG_IDENTIFIER=svc"));
    assert!(combined.contains("_STREAM_ID="));
    assert!(combined.contains("MESSAGE=hello stdout"));
    assert!(combined.contains("MESSAGE=prefixed"));
    assert!(combined.contains("SYSLOG_FACILITY=1"));
    assert!(combined.contains("PRIORITY=5"));
    assert!(combined.contains("MESSAGE=trailing-eof"));
    assert!(combined.contains("_LINE_BREAK=eof"));
}

#[test]
fn live_journald_binary_marks_stdout_line_max_splits() {
    let artifact_dir = unique_artifact_dir("journald-stdout-line-max");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    fs::create_dir_all(&root).unwrap();

    let daemon = spawn_daemon(&root, &artifact_dir, "daemon", &[]);
    let stdout_socket = root.join("stdout");
    wait_for_socket(&stdout_socket, Duration::from_secs(3)).unwrap();

    let mut stream = UnixStream::connect(&stdout_socket).unwrap();
    stream.shutdown(Shutdown::Read).unwrap();
    stream.write_all(b"svc\n\n5\n0\n0\n0\n0\n").unwrap();
    stream.write_all(&vec![b'x'; 50 * 1024]).unwrap();
    drop(stream);

    wait_for_journal_contains(&root, "_LINE_BREAK=line-max", Duration::from_secs(3)).unwrap();
    stop_daemon(daemon);

    let combined = read_all_journal_text(&root);
    fs::write(artifact_dir.join("stdout-line-max.txt"), &combined).unwrap();

    assert!(combined.contains("transport=stdout"));
    assert!(combined.contains("_LINE_BREAK=line-max"));
}

#[test]
fn live_journald_binary_restores_stdout_stream_from_fdstore() {
    let artifact_dir = unique_artifact_dir("journald-stdout-restore");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    fs::create_dir_all(&root).unwrap();

    let notify_socket = artifact_dir.join("notify.sock");
    let notify = UnixDatagram::bind(&notify_socket).unwrap();

    let daemon1 = spawn_daemon(
        &root,
        &artifact_dir,
        "daemon-1",
        &[("NOTIFY_SOCKET", notify_socket.to_str().unwrap())],
    );
    let stdout_socket = root.join("stdout");
    wait_for_socket(&stdout_socket, Duration::from_secs(3)).unwrap();

    let mut stream = UnixStream::connect(&stdout_socket).unwrap();
    stream.shutdown(Shutdown::Read).unwrap();
    stream.write_all(b"svc\n\n5\n0\n0\n0\n0\n").unwrap();
    stream.write_all(b"before-restart\n").unwrap();

    let restored_fd = recv_notify_fd(&notify, Duration::from_secs(3)).unwrap();
    wait_for_journal_contains(&root, "before-restart", Duration::from_secs(3)).unwrap();
    stop_daemon(daemon1);

    let daemon2 =
        spawn_daemon_with_restored_stream_fd(&root, &artifact_dir, "daemon-2", restored_fd);
    wait_for_socket(&stdout_socket, Duration::from_secs(3)).unwrap();

    stream.write_all(b"after-restart\n").unwrap();
    wait_for_journal_contains(&root, "after-restart", Duration::from_secs(3)).unwrap();
    stop_daemon(daemon2);

    let combined = read_all_journal_text(&root);
    fs::write(artifact_dir.join("stdout-restore.txt"), &combined).unwrap();

    assert!(combined.contains("MESSAGE=before-restart"));
    assert!(combined.contains("MESSAGE=after-restart"));
    assert!(combined.contains("SYSLOG_IDENTIFIER=svc"));
    assert!(combined.contains("transport=stdout"));
}

#[test]
#[cfg(target_os = "linux")]
fn live_journald_binary_reads_dev_kmsg_when_available() {
    let artifact_dir = unique_artifact_dir("journald-dev-kmsg");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    fs::create_dir_all(&root).unwrap();

    if OpenOptions::new().read(true).open("/dev/kmsg").is_err() {
        eprintln!("skipping: /dev/kmsg is not readable in this environment");
        return;
    }
    let mut writer = match OpenOptions::new().write(true).open("/dev/kmsg") {
        Ok(file) => file,
        Err(_) => {
            eprintln!("skipping: /dev/kmsg is not writable in this environment");
            return;
        }
    };

    let daemon = spawn_daemon(&root, &artifact_dir, "daemon-kmsg", &[]);
    let socket = root.join("socket");
    wait_for_socket(&socket, Duration::from_secs(3)).unwrap();

    let marker = format!(
        "rje-kmsg-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    writeln!(writer, "<6>{marker}").unwrap();
    writer.flush().unwrap();

    let combined = wait_for_journal_contains(&root, &marker, Duration::from_secs(3))
        .expect("daemon should ingest /dev/kmsg marker when device access is available");
    stop_daemon(daemon);

    fs::write(artifact_dir.join("dev-kmsg.log"), &combined).unwrap();
    assert!(combined.contains("transport=kernel"));
    assert!(combined.contains(&marker));
    let seqnum = fs::read_to_string(root.join("kernel-seqnum"))
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok());
    assert!(seqnum.is_some_and(|value| value > 0));
}

#[test]
#[cfg(not(target_os = "linux"))]
fn live_journald_binary_reads_dev_kmsg_when_available() {}

#[test]
#[cfg(target_os = "linux")]
fn live_journald_binary_emits_rate_limit_suppression_markers() {
    let artifact_dir = unique_artifact_dir("journald-rate-limit");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    let proc_root = artifact_dir.join("proc");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&proc_root).unwrap();

    let sender_pid = std::process::id() as i32;
    write_fake_proc_context(
        &proc_root,
        sender_pid,
        "/system.slice/rate-limit-demo.service",
        "rate-limit-demo",
        1000,
        1000,
    );

    let daemon = spawn_daemon(
        &root,
        &artifact_dir,
        "daemon",
        &[
            (RATE_LIMIT_INTERVAL_ENV, "100000"),
            (RATE_LIMIT_BURST_ENV, "1"),
            (PROC_ROOT_ENV, proc_root.to_str().unwrap()),
        ],
    );

    let stdout_socket = root.join("stdout");
    wait_for_socket(&stdout_socket, Duration::from_secs(3)).unwrap();

    let mut stream = UnixStream::connect(&stdout_socket).unwrap();
    stream
        .write_all(b"rate-limit-demo\n\n6\n0\n0\n0\n0\n")
        .unwrap();
    for idx in 0..120 {
        writeln!(stream, "burst-{idx}").unwrap();
    }
    thread::sleep(Duration::from_millis(150));
    writeln!(stream, "burst-post-window").unwrap();
    let _ = stream.shutdown(Shutdown::Both);

    thread::sleep(Duration::from_millis(100));
    stop_daemon(daemon);

    let log = render_journal_file_as_text(&root.join(ACTIVE_JOURNAL_FILE_NAME)).unwrap();
    fs::write(artifact_dir.join("rate-limit.log"), &log).unwrap();
    assert!(log.contains("burst-0"));
    assert!(log.contains("MESSAGE_ID=a596d6fe7bfa4994828e72309e95d61e"));
    assert!(log.contains("N_DROPPED="));
}

#[test]
#[cfg(not(target_os = "linux"))]
fn live_journald_binary_emits_rate_limit_suppression_markers() {}

#[test]
#[cfg(target_os = "linux")]
fn live_journald_binary_requires_unit_context_for_rate_limit() {
    let artifact_dir = unique_artifact_dir("journald-no-unit-rate-limit");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    let proc_root = artifact_dir.join("proc");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&proc_root).unwrap();

    let daemon = spawn_daemon(
        &root,
        &artifact_dir,
        "daemon-no-unit-rate-limit",
        &[
            (RATE_LIMIT_INTERVAL_ENV, "100000"),
            (RATE_LIMIT_BURST_ENV, "1"),
            (PROC_ROOT_ENV, proc_root.to_str().unwrap()),
        ],
    );

    let dev_log = root.join("dev-log");
    wait_for_socket(&dev_log, Duration::from_secs(3)).unwrap();
    let sender = UnixDatagram::unbound().unwrap();
    for idx in 0..6 {
        let payload = format!("<13>Jan  1 12:00:00 app[100]: no-unit-{idx}");
        send_with_retry(&sender, &dev_log, payload.as_bytes()).unwrap();
    }
    thread::sleep(Duration::from_millis(150));
    stop_daemon(daemon);

    let log = render_journal_file_as_text(&root.join(ACTIVE_JOURNAL_FILE_NAME)).unwrap();
    fs::write(artifact_dir.join("no-unit-rate-limit.log"), &log).unwrap();
    assert!(log.contains("MESSAGE=no-unit-0"));
    assert!(log.contains("MESSAGE=no-unit-5"));
    assert!(!log.contains("MESSAGE_ID=a596d6fe7bfa4994828e72309e95d61e"));
    assert!(!log.contains("N_DROPPED="));
}

#[test]
#[cfg(not(target_os = "linux"))]
fn live_journald_binary_requires_unit_context_for_rate_limit() {}

#[test]
#[cfg(target_os = "linux")]
fn live_journald_binary_enriches_trusted_metadata_from_proc_context() {
    let artifact_dir = unique_artifact_dir("journald-trusted-context");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    let proc_root = artifact_dir.join("proc");
    let run_systemd_root = artifact_dir.join("run-systemd");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&proc_root).unwrap();
    fs::create_dir_all(&run_systemd_root).unwrap();

    let sender_pid = std::process::id() as i32;
    let exe_target = write_fake_proc_context(
        &proc_root,
        sender_pid,
        "/system.slice/live-demo.service",
        "live-demo",
        1000,
        1000,
    );
    write_invocation_link(
        &run_systemd_root,
        "live-demo.service",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    write_unit_runtime_symlink(
        &run_systemd_root,
        "log-level-max",
        "live-demo.service",
        "notice",
    );
    write_unit_extra_fields(
        &run_systemd_root,
        "live-demo.service",
        &[b"DEPLOYMENT=live-blue"],
    );

    let daemon = spawn_daemon(
        &root,
        &artifact_dir,
        "daemon-trusted-context",
        &[
            (PROC_ROOT_ENV, proc_root.to_str().unwrap()),
            (RUN_SYSTEMD_ROOT_ENV, run_systemd_root.to_str().unwrap()),
        ],
    );
    let dev_log = root.join("dev-log");
    wait_for_socket(&dev_log, Duration::from_secs(3)).unwrap();

    let sender = UnixDatagram::unbound().unwrap();
    send_with_retry(&sender, &dev_log, b"<14>app[123]: trusted-live-info").unwrap();
    send_with_retry(&sender, &dev_log, b"<13>app[123]: trusted-live").unwrap();
    let log = wait_for_journal_contains(&root, "trusted-live", Duration::from_secs(3)).unwrap();
    stop_daemon(daemon);

    fs::write(artifact_dir.join("trusted-context.log"), &log).unwrap();
    assert!(!log.contains("trusted-live-info"));
    assert!(log.contains("_COMM=live-demo"));
    assert!(log.contains(&format!("_EXE={}", exe_target.display())));
    assert!(log.contains("_CMDLINE=live-demo --flag 'value with space'"));
    assert!(log.contains("_CAP_EFFECTIVE=0000000000000001"));
    assert!(log.contains("_SELINUX_CONTEXT=system_u:system_r:demo_t:s0"));
    assert!(log.contains("_AUDIT_SESSION=5"));
    assert!(log.contains("_AUDIT_LOGINUID=1000"));
    assert!(log.contains("_SYSTEMD_CGROUP=/system.slice/live-demo.service"));
    assert!(log.contains("_SYSTEMD_UNIT=live-demo.service"));
    assert!(log.contains("_SYSTEMD_SLICE=system.slice"));
    assert!(log.contains("_SYSTEMD_INVOCATION_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    assert!(log.contains("DEPLOYMENT=live-blue"));
}

#[test]
#[cfg(not(target_os = "linux"))]
fn live_journald_binary_enriches_trusted_metadata_from_proc_context() {}

#[test]
fn live_journald_binary_startup_housekeeping_applies_max_files() {
    let artifact_dir = unique_artifact_dir("journald-startup-housekeeping");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    fs::create_dir_all(&root).unwrap();

    seed_journal_text_records(&root.join(ACTIVE_JOURNAL_FILE_NAME), &["active"]);
    fs::write(root.join(rotated_archive_name(1, 1)), vec![b'X'; 256]).unwrap();
    fs::write(root.join(rotated_archive_name(2, 2)), vec![b'X'; 256]).unwrap();
    fs::write(root.join(rotated_archive_name(3, 3)), vec![b'X'; 256]).unwrap();

    let daemon = spawn_daemon(
        &root,
        &artifact_dir,
        "daemon-housekeeping",
        &[(SYSTEM_MAX_FILES_ENV, "1")],
    );
    let socket = root.join("socket");
    wait_for_socket(&socket, Duration::from_secs(3)).unwrap();
    stop_daemon(daemon);

    let archived_count = count_archived_logs(&root);
    assert!(archived_count <= 1, "archived_count={archived_count}");
}

#[test]
fn live_journald_binary_rotate_action_applies_post_rotate_vacuum_limits() {
    let artifact_dir = unique_artifact_dir("journald-rotate-vacuum-action");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    fs::create_dir_all(&root).unwrap();

    seed_journal_text_records(&root.join(ACTIVE_JOURNAL_FILE_NAME), &["before rotate"]);
    fs::write(root.join(rotated_archive_name(1, 1)), vec![b'X'; 256]).unwrap();
    fs::write(root.join(rotated_archive_name(2, 2)), vec![b'X'; 256]).unwrap();

    let status = Command::new(journald_bin())
        .env(RUNTIME_ROOT_ENV, &root)
        .env(STORAGE_MODE_ENV, "volatile")
        .env(SYSTEM_MAX_FILES_ENV, "1")
        .arg("--rotate")
        .status()
        .unwrap();
    assert!(status.success());

    let archived_count = count_archived_logs(&root);
    assert!(archived_count <= 1, "archived_count={archived_count}");
}

#[test]
fn live_journald_binary_namespaced_policy_and_fields() {
    let artifact_dir = unique_artifact_dir("journald-namespace-policy");
    eprintln!("artifact_dir={}", artifact_dir.display());
    let root = artifact_dir.join("runtime");
    fs::create_dir_all(&root).unwrap();

    let daemon = spawn_daemon(
        &root,
        &artifact_dir,
        "daemon-namespace",
        &[(NAMESPACE_ENV, "tenant-a")],
    );
    let socket = root.join("socket");
    wait_for_socket(&socket, Duration::from_secs(3)).unwrap();
    let sender = UnixDatagram::unbound().unwrap();
    send_with_retry(&sender, &socket, b"MESSAGE=namespaced payload\n").unwrap();
    thread::sleep(Duration::from_millis(80));
    stop_daemon(daemon);

    let log = render_journal_file_as_text(&root.join(ACTIVE_JOURNAL_FILE_NAME)).unwrap();
    fs::write(artifact_dir.join("namespace.log"), &log).unwrap();
    assert!(log.contains("_NAMESPACE=tenant-a"));

    let flush_status = Command::new(journald_bin())
        .env(RUNTIME_ROOT_ENV, &root)
        .env(STORAGE_MODE_ENV, "volatile")
        .env(NAMESPACE_ENV, "tenant-a")
        .arg("--flush")
        .status()
        .unwrap();
    assert!(flush_status.success());

    let relinquish_status = Command::new(journald_bin())
        .env(RUNTIME_ROOT_ENV, &root)
        .env(STORAGE_MODE_ENV, "volatile")
        .env(NAMESPACE_ENV, "tenant-a")
        .arg("--relinquish-var")
        .status()
        .unwrap();
    assert!(relinquish_status.success());

    assert!(!root.join("flushed").exists());
    assert!(!root.join("relinquished-var").exists());
}

#[test]
fn live_journalctl_binary_execs_configured_backend() {
    let artifact_dir = unique_artifact_dir("journalctl-shim");
    eprintln!("artifact_dir={}", artifact_dir.display());

    let backend = artifact_dir.join("journalctl-c");
    let args_capture = artifact_dir.join("backend-args.txt");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexit 0\n",
        args_capture.display()
    );
    fs::write(&backend, script).unwrap();
    let mut perms = fs::metadata(&backend).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&backend, perms).unwrap();

    let status = Command::new(journalctl_bin())
        .env("SYSTEMD_JOURNALCTL_BACKEND", &backend)
        .arg("--version")
        .arg("--since=today")
        .status()
        .unwrap();
    assert!(status.success());

    let args = fs::read_to_string(args_capture).unwrap();
    assert!(args.contains("--version"));
    assert!(args.contains("--since=today"));
}
