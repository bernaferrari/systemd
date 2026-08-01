// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Runtime for systemd-socket-proxyd
//
// PORT-SYNC: src/socket-proxy/socket-proxyd.c

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::env;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use systemd_socket_proxy_rs::{
    DEFAULT_EXIT_IDLE_TIME, ProxyConfig, ProxyError, RemoteAddress, at_connection_limit,
    parse_remote_host,
};

const SD_LISTEN_FDS_START: RawFd = 3;

struct StopNotifier;

impl Drop for StopNotifier {
    fn drop(&mut self) {
        let _ = notify("STOPPING=1\nSTATUS=Shutting down...");
    }
}

struct CompletionSignal {
    result: Option<Result<(), String>>,
    sender: mpsc::Sender<Result<(), String>>,
    wake: UnixDatagram,
}

impl CompletionSignal {
    fn complete(mut self, result: io::Result<()>) {
        self.result = Some(result.map_err(|error| error.to_string()));
    }
}

impl Drop for CompletionSignal {
    fn drop(&mut self) {
        let result = self.result.take().unwrap_or_else(|| {
            Err("connection worker terminated before reporting a result".to_string())
        });
        let _ = self.sender.send(result);
        let _ = self.wake.send(&[1]);
    }
}

struct UnixSocketAddress {
    address: libc::sockaddr_un,
    length: libc::socklen_t,
}

struct AddressInfo(*mut libc::addrinfo);

impl Drop for AddressInfo {
    fn drop(&mut self) {
        // SAFETY: getaddrinfo(3) returned this list and ownership has not
        // been transferred or freed elsewhere.
        unsafe_ffi!(libc::freeaddrinfo(self.0));
    }
}

fn unix_socket_address(path: &str) -> io::Result<UnixSocketAddress> {
    if path.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix socket address contains a NUL byte",
        ));
    }

    // SAFETY: A zeroed sockaddr_un is a valid starting representation.
    let mut address = unsafe_ffi!(mem::zeroed::<libc::sockaddr_un>());
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_offset = mem::offset_of!(libc::sockaddr_un, sun_path);

    let used = if let Some(name) = path.strip_prefix('@') {
        let name = name.as_bytes();
        if name.len() >= address.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "abstract Unix socket address is too long",
            ));
        }
        for (destination, source) in address.sun_path[1..].iter_mut().zip(name) {
            *destination = *source as libc::c_char;
        }
        1usize
            .checked_add(name.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address overflow"))?
    } else {
        let path = path.as_bytes();
        if path.len() >= address.sun_path.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unix socket path is too long",
            ));
        }
        for (destination, source) in address.sun_path.iter_mut().zip(path) {
            *destination = *source as libc::c_char;
        }
        path.len()
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address overflow"))?
    };

    let length = path_offset
        .checked_add(used)
        .and_then(|length| libc::socklen_t::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address is too long"))?;
    Ok(UnixSocketAddress { address, length })
}

fn owned_socket(
    domain: libc::c_int,
    socket_type: libc::c_int,
    protocol: libc::c_int,
) -> io::Result<OwnedFd> {
    // SAFETY: socket(2) has no Rust aliasing requirements. On success the
    // returned descriptor is immediately placed under unique RAII ownership.
    let raw = unsafe_ffi!(libc::socket(
        domain,
        socket_type | libc::SOCK_CLOEXEC,
        protocol
    ));
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket(2) returned a new, uniquely owned descriptor.
    Ok(unsafe_ffi!(OwnedFd::from_raw_fd(raw)))
}

fn connect_unix_abstract(path: &str) -> io::Result<OwnedFd> {
    let address = unix_socket_address(path)?;
    let socket = owned_socket(libc::AF_UNIX, libc::SOCK_STREAM, 0)?;
    // SAFETY: address points to an initialized sockaddr_un for the supplied
    // length, and socket remains owned for the duration of connect(2).
    let result = unsafe_ffi!({
        libc::connect(
            socket.as_raw_fd(),
            &address.address as *const _ as *const libc::sockaddr,
            address.length,
        )
    });
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn address_info_error(code: libc::c_int) -> io::Error {
    // SAFETY: gai_strerror(3) returns a process-owned NUL-terminated string
    // for every result code and the pointer is only borrowed here.
    let message = unsafe_ffi!({
        let pointer = libc::gai_strerror(code);
        if pointer.is_null() {
            format!("name resolution failed with error {code}")
        } else {
            CStr::from_ptr(pointer).to_string_lossy().into_owned()
        }
    });
    io::Error::other(message)
}

fn connect_tcp(host: &str, service: &str) -> io::Result<OwnedFd> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let host = CString::new(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "host contains a NUL byte"))?;
    let service = CString::new(service)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "service contains a NUL byte"))?;
    let hints = libc::addrinfo {
        ai_flags: 0,
        ai_family: libc::AF_UNSPEC,
        ai_socktype: libc::SOCK_STREAM,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: std::ptr::null_mut(),
        ai_canonname: std::ptr::null_mut(),
        ai_next: std::ptr::null_mut(),
    };
    let mut result = std::ptr::null_mut();
    // SAFETY: host/service are valid C strings, hints is initialized, and
    // result points to writable storage for the returned owned list.
    let resolved = unsafe_ffi!(libc::getaddrinfo(
        host.as_ptr(),
        service.as_ptr(),
        &hints,
        &mut result
    ));
    if resolved != 0 {
        return Err(address_info_error(resolved));
    }
    if result.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "name resolution returned no addresses",
        ));
    }
    let addresses = AddressInfo(result);
    let mut current = addresses.0;
    let mut last_error = None;

    while !current.is_null() {
        // SAFETY: current traverses the getaddrinfo-owned linked list and
        // remains valid while addresses is alive.
        let address = unsafe_ffi!(&*current);
        if !address.ai_addr.is_null() && address.ai_addrlen > 0 {
            match owned_socket(address.ai_family, address.ai_socktype, address.ai_protocol) {
                Ok(socket) => {
                    // SAFETY: ai_addr/ai_addrlen describe a sockaddr owned
                    // by the live address-info list.
                    let connected = unsafe_ffi!({
                        libc::connect(socket.as_raw_fd(), address.ai_addr, address.ai_addrlen)
                    });
                    if connected == 0 {
                        return Ok(socket);
                    }
                    last_error = Some(io::Error::last_os_error());
                }
                Err(error) => last_error = Some(error),
            }
        }
        current = address.ai_next;
    }

    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no usable remote address")))
}

fn connect_remote(remote: &RemoteAddress) -> io::Result<OwnedFd> {
    match remote {
        RemoteAddress::Tcp { host, port } => connect_tcp(host, port),
        RemoteAddress::Unix(path) if path.starts_with('@') => connect_unix_abstract(path),
        RemoteAddress::Unix(path) => {
            let stream = UnixStream::connect(path)?;
            Ok(stream.into())
        }
    }
}

fn shutdown(fd: RawFd, how: libc::c_int) -> io::Result<()> {
    // SAFETY: fd is borrowed from a live socket for the duration of the call.
    if unsafe_ffi!(libc::shutdown(fd, how)) < 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::ENOTCONN | libc::EINVAL)) {
            return Err(error);
        }
    }
    Ok(())
}

fn forward_one(mut input: File, mut output: File) -> io::Result<u64> {
    match io::copy(&mut input, &mut output) {
        Ok(copied) => {
            shutdown(output.as_raw_fd(), libc::SHUT_WR)?;
            Ok(copied)
        }
        Err(error) => {
            let _ = shutdown(input.as_raw_fd(), libc::SHUT_RDWR);
            let _ = shutdown(output.as_raw_fd(), libc::SHUT_RDWR);
            Err(error)
        }
    }
}

fn proxy_bidirectionally(client: OwnedFd, remote: OwnedFd) -> io::Result<()> {
    let client = File::from(client);
    let remote = File::from(remote);
    let client_read = client.try_clone()?;
    let remote_write = remote.try_clone()?;

    thread::scope(|scope| {
        let upstream = scope.spawn(move || forward_one(client_read, remote_write));
        let downstream = forward_one(remote, client);
        let upstream = upstream
            .join()
            .map_err(|_| io::Error::other("forwarding thread panicked"))?;
        upstream?;
        downstream?;
        Ok(())
    })
}

fn spawn_connection(
    client: OwnedFd,
    remote: RemoteAddress,
    sender: mpsc::Sender<Result<(), String>>,
    wake: UnixDatagram,
) -> io::Result<()> {
    let signal = CompletionSignal {
        result: None,
        sender,
        wake,
    };
    thread::Builder::new()
        .name("socket-proxy-connection".to_string())
        .spawn(move || {
            let result =
                connect_remote(&remote).and_then(|target| proxy_bidirectionally(client, target));
            signal.complete(result);
        })
        .map(|_| ())
}

fn socket_option(fd: RawFd, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value = 0;
    let mut length = libc::socklen_t::try_from(mem::size_of_val(&value))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "option length overflow"))?;
    // SAFETY: value and length are writable for getsockopt(2), and fd is a
    // borrowed activated descriptor.
    let result = unsafe_ffi!({
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            &mut value as *mut _ as *mut libc::c_void,
            &mut length,
        )
    });
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

fn configure_listener(fd: RawFd) -> io::Result<()> {
    if socket_option(fd, libc::SO_TYPE)? != libc::SOCK_STREAM
        || socket_option(fd, libc::SO_ACCEPTCONN)? == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "passed descriptor is not a listening stream socket",
        ));
    }

    // SAFETY: fcntl(2) only reads or updates flags on this borrowed fd.
    let status_flags = unsafe_ffi!(libc::fcntl(fd, libc::F_GETFL));
    if status_flags < 0
        || unsafe_ffi!(libc::fcntl(
            fd,
            libc::F_SETFL,
            status_flags | libc::O_NONBLOCK
        )) < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above, for descriptor flags.
    let descriptor_flags = unsafe_ffi!(libc::fcntl(fd, libc::F_GETFD));
    if descriptor_flags < 0
        || unsafe_ffi!(libc::fcntl(
            fd,
            libc::F_SETFD,
            descriptor_flags | libc::FD_CLOEXEC
        )) < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn activated_listeners() -> Result<Vec<OwnedFd>, ProxyError> {
    let listen_pid = env::var("LISTEN_PID").ok();
    let listen_fds = env::var("LISTEN_FDS").ok();
    // SAFETY: run() calls this before it creates worker threads, and this
    // executable does not expose activated_listeners() to concurrent callers.
    unsafe_ffi!({
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");
        env::remove_var("LISTEN_FDNAMES");
    });

    let pid_matches = listen_pid
        .as_deref()
        .and_then(|value| value.parse::<u32>().ok())
        == Some(std::process::id());
    if !pid_matches {
        return Err(ProxyError::NoSocketsPassed);
    }
    let count = listen_fds
        .as_deref()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .ok_or(ProxyError::NoSocketsPassed)?;
    let last = usize::try_from(SD_LISTEN_FDS_START)
        .ok()
        .and_then(|start| start.checked_add(count))
        .filter(|last| *last <= RawFd::MAX as usize)
        .ok_or_else(|| ProxyError::EventLoopError("too many activated sockets".to_string()))?;
    let last = RawFd::try_from(last)
        .map_err(|_| ProxyError::EventLoopError("too many activated sockets".to_string()))?;

    let mut listeners = Vec::with_capacity(count);
    for raw in SD_LISTEN_FDS_START..last {
        // SAFETY: matching LISTEN_PID/LISTEN_FDS transfers ownership of this
        // contiguous descriptor range to the service.
        listeners.push(unsafe_ffi!(OwnedFd::from_raw_fd(raw)));
    }
    for listener in &listeners {
        let raw = listener.as_raw_fd();
        configure_listener(raw).map_err(|error| {
            ProxyError::EventLoopError(format!("invalid activated socket {raw}: {error}"))
        })?;
    }
    Ok(listeners)
}

fn accept_one(listener: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: listener is a live listening socket. Null address arguments are
    // explicitly permitted by accept4(2); a successful fd is uniquely owned.
    let accepted = unsafe_ffi!({
        libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    });
    if accepted < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: accept4(2) returned a new, uniquely owned descriptor.
        Ok(unsafe_ffi!(OwnedFd::from_raw_fd(accepted)))
    }
}

fn notify(message: &str) -> io::Result<()> {
    let path = match env::var("NOTIFY_SOCKET") {
        Ok(path) => path,
        Err(env::VarError::NotPresent) => return Ok(()),
        Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
    };
    if !path.starts_with('/') && !path.starts_with('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET is not an absolute or abstract Unix address",
        ));
    }
    let address = unix_socket_address(&path)?;
    let socket = owned_socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0)?;
    // SAFETY: all pointers describe initialized buffers valid for sendto(2).
    let sent = unsafe_ffi!({
        libc::sendto(
            socket.as_raw_fd(),
            message.as_ptr() as *const libc::c_void,
            message.len(),
            libc::MSG_NOSIGNAL,
            &address.address as *const _ as *const libc::sockaddr,
            address.length,
        )
    });
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else if sent as usize != message.len() {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short sd_notify datagram",
        ))
    } else {
        Ok(())
    }
}

fn poll_timeout(deadline: Option<Instant>) -> Option<libc::c_int> {
    let deadline = deadline?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Some(0);
    }
    let millis = remaining.as_millis().saturating_add(1);
    Some(libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX))
}

fn drain_wake(socket: &UnixDatagram) -> io::Result<()> {
    let mut buffer = [0u8; 128];
    loop {
        match socket.recv(&mut buffer) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn idle_deadline(idle_time: Option<Duration>) -> Option<Instant> {
    idle_time.and_then(|duration| Instant::now().checked_add(duration))
}

fn earliest_deadline(left: Option<Instant>, right: Option<Instant>) -> Option<Instant> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

fn watchdog_interval() -> Option<Duration> {
    let pid_matches = env::var("WATCHDOG_PID")
        .ok()
        .map(|value| value.parse::<u32>().ok() == Some(std::process::id()))
        .unwrap_or(true);
    if !pid_matches {
        return None;
    }
    let usec = env::var("WATCHDOG_USEC")
        .ok()?
        .parse::<u64>()
        .ok()
        .filter(|usec| *usec > 0)?
        .checked_div(2)?
        .max(1);
    Some(Duration::from_micros(usec))
}

pub(crate) fn run(config: ProxyConfig) -> Result<(), ProxyError> {
    let listeners = activated_listeners()?;
    let remote = parse_remote_host(&config.remote_host);
    let idle_time = (config.exit_idle_time != DEFAULT_EXIT_IDLE_TIME)
        .then(|| Duration::from_micros(config.exit_idle_time));
    let (wake_reader, wake_writer) =
        UnixDatagram::pair().map_err(|error| ProxyError::EventLoopError(error.to_string()))?;
    wake_reader
        .set_nonblocking(true)
        .map_err(|error| ProxyError::EventLoopError(error.to_string()))?;
    // This datagram is only a poll wake-up; the mpsc channel is
    // authoritative. A worker must not block in Drop if listener handling is
    // temporarily busy. If the datagram queue is full, an earlier wake-up is
    // already pending and draining it also drains all queued completions.
    wake_writer
        .set_nonblocking(true)
        .map_err(|error| ProxyError::EventLoopError(error.to_string()))?;
    let (completion_sender, completion_receiver) = mpsc::channel();
    let mut active_connections = 0usize;
    let mut deadline = idle_deadline(idle_time);
    let watchdog_interval = watchdog_interval();
    let mut watchdog_deadline = idle_deadline(watchdog_interval);

    let _stop_notifier = StopNotifier;
    let _ = notify("READY=1\nSTATUS=Processing requests...");

    loop {
        while let Ok(result) = completion_receiver.try_recv() {
            active_connections = active_connections.checked_sub(1).ok_or_else(|| {
                ProxyError::EventLoopError(
                    "received a completion without an active connection".to_string(),
                )
            })?;
            if let Err(error) = result {
                eprintln!("socket-proxyd: forwarding failed: {error}");
            }
            if active_connections == 0 {
                deadline = idle_deadline(idle_time);
            }
        }

        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            return Ok(());
        }
        if watchdog_deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            let _ = notify("WATCHDOG=1");
            watchdog_deadline = idle_deadline(watchdog_interval);
        }

        let mut poll_fds = Vec::with_capacity(listeners.len() + 1);
        poll_fds.push(libc::pollfd {
            fd: wake_reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        poll_fds.extend(listeners.iter().map(|listener| libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }));

        // SAFETY: poll_fds is a writable contiguous array for the specified
        // element count and remains alive throughout poll(2).
        let ready = unsafe_ffi!({
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                poll_timeout(earliest_deadline(deadline, watchdog_deadline)).unwrap_or(-1),
            )
        });
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ProxyError::EventLoopError(error.to_string()));
        }
        if ready == 0 {
            continue;
        }

        if poll_fds[0].revents & libc::POLLIN != 0 {
            drain_wake(&wake_reader)
                .map_err(|error| ProxyError::EventLoopError(error.to_string()))?;
            continue;
        }
        if poll_fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(ProxyError::EventLoopError(
                "connection completion socket failed".to_string(),
            ));
        }

        for (listener, event) in listeners.iter().zip(&poll_fds[1..]) {
            if event.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(ProxyError::EventLoopError(
                    "activated listening socket failed".to_string(),
                ));
            }
            if event.revents & libc::POLLIN == 0 {
                continue;
            }

            let client = match accept_one(listener.as_raw_fd()) {
                Ok(client) => client,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    eprintln!("socket-proxyd: failed to accept socket: {error}");
                    continue;
                }
            };

            if at_connection_limit(active_connections, config.connections_max) {
                eprintln!("socket-proxyd: {}", ProxyError::ConnectionLimitReached);
                continue;
            }

            let wake = wake_writer
                .try_clone()
                .map_err(|error| ProxyError::EventLoopError(error.to_string()))?;
            active_connections += 1;
            deadline = None;
            if let Err(error) =
                spawn_connection(client, remote.clone(), completion_sender.clone(), wake)
            {
                eprintln!("socket-proxyd: failed to spawn connection worker: {error}");
            }
        }
    }
}
