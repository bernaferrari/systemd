// SPDX-License-Identifier: LGPL-2.1-or-later

use super::*;

impl JournalRuntime {
    pub fn run_daemon(&self) -> Result<(), JournaldError> {
        let _signal_guard = install_shutdown_signal_handlers()?;
        self.run_startup_housekeeping()?;
        self.run_daemon_loop(|| SHUTDOWN_REQUESTED.load(Ordering::SeqCst))
    }

    pub(super) fn run_startup_housekeeping(&self) -> Result<(), JournaldError> {
        let limits = StorageVacuumLimits::from_env();
        let _ = self.vacuum_root(
            self.root(),
            limits.max_use,
            limits.n_max_files,
            limits.max_use,
        )?;
        self.flush_to_persistent(true)?;

        let state = self.storage_state();
        if let Some(active) = state.active_root() {
            if active != self.root() {
                let _ =
                    self.vacuum_root(active, limits.max_use, limits.n_max_files, limits.max_use)?;
            }
        }

        Ok(())
    }

    pub(super) fn run_daemon_loop<F>(&self, mut should_shutdown: F) -> Result<(), JournaldError>
    where
        F: FnMut() -> bool,
    {
        self.ensure_root()?;
        let mut limiter = PeerRateLimiter::new(RateLimitConfig::from_env());
        let mut kmsg_sequence = KmsgSequenceTracker::with_next_expected(self.load_kernel_seqnum());
        let mut dev_kmsg = DevKmsgReader::open().ok();
        #[cfg(target_os = "linux")]
        let mut audit_netlink = AuditNetlinkReceiver::open().ok();
        let PreparedDaemonSockets {
            native_socket,
            native_guard: _native_socket_guard,
            syslog_socket,
            syslog_guard: _syslog_socket_guard,
            stdout_listener,
            stdout_guard: _stdout_socket_guard,
            restored_stdout_fds,
        } = self.prepare_daemon_sockets()?;
        let mut stdout_streams = self.restore_stdout_streams(restored_stdout_fds)?;

        let mut buf = vec![0_u8; 65536];
        loop {
            if should_shutdown() {
                break;
            }

            if let Some(reader) = dev_kmsg.as_mut() {
                if self.drain_dev_kmsg(reader, &mut kmsg_sequence).is_err() {
                    dev_kmsg = None;
                }
            }
            #[cfg(target_os = "linux")]
            if let Some(receiver) = audit_netlink.as_mut() {
                if self.drain_audit_netlink(receiver).is_err() {
                    audit_netlink = None;
                }
            }

            let mut handled_datagram = false;
            handled_datagram |= self.drain_socket_datagrams(
                &native_socket,
                &mut buf,
                IngressSource::NativeSocketDatagram,
                &mut limiter,
            )?;
            handled_datagram |= self.drain_socket_datagrams(
                &syslog_socket,
                &mut buf,
                IngressSource::SyslogSocketDatagram,
                &mut limiter,
            )?;
            handled_datagram |=
                self.accept_stdout_streams(&stdout_listener, &mut stdout_streams)?;
            handled_datagram |= self.drain_stdout_streams(&mut stdout_streams, &mut limiter)?;

            if !handled_datagram {
                std::thread::sleep(Duration::from_millis(DAEMON_POLL_TIMEOUT_MS));
            }
        }

        Ok(())
    }

    pub(super) fn prepare_daemon_sockets(&self) -> Result<PreparedDaemonSockets, JournaldError> {
        let mut native_socket = None;
        let mut syslog_socket = None;
        let mut stdout_listener = None;
        let mut restored_stdout_fds = Vec::new();

        for passed_fd in sd_listen_fds_with_names(true).map_err(|err| {
            JournaldError::InvalidArgument(format!("socket activation parse failed: {err:?}"))
        })? {
            if parse_stream_state_file_name(&passed_fd.name).is_some() {
                restored_stdout_fds.push(passed_fd.fd);
                continue;
            }

            let fd = passed_fd.fd;
            if sd_is_socket_unix(
                fd,
                Some(libc::SOCK_DGRAM),
                None,
                Some(self.socket_path().as_os_str().as_bytes()),
            )
            .unwrap_or(false)
            {
                if native_socket.is_none() {
                    // SAFETY: socket activation transferred ownership of this
                    // unique datagram descriptor to the daemon.
                    let socket = unsafe { UnixDatagram::from_raw_fd(fd) };
                    self.configure_daemon_datagram_socket(&socket)?;
                    native_socket = Some(socket);
                } else {
                    safe_close_fd(fd);
                }
                continue;
            }
            if sd_is_socket_unix(
                fd,
                Some(libc::SOCK_DGRAM),
                None,
                Some(self.dev_log_path().as_os_str().as_bytes()),
            )
            .unwrap_or(false)
            {
                if syslog_socket.is_none() {
                    // SAFETY: socket activation transferred ownership of this
                    // unique datagram descriptor to the daemon.
                    let socket = unsafe { UnixDatagram::from_raw_fd(fd) };
                    self.configure_daemon_datagram_socket(&socket)?;
                    syslog_socket = Some(socket);
                } else {
                    safe_close_fd(fd);
                }
                continue;
            }
            if sd_is_socket_unix(
                fd,
                Some(libc::SOCK_STREAM),
                Some(true),
                Some(self.stdout_path().as_os_str().as_bytes()),
            )
            .unwrap_or(false)
            {
                if stdout_listener.is_none() {
                    // SAFETY: socket activation transferred ownership of this
                    // unique listening descriptor to the daemon.
                    let listener = unsafe { UnixListener::from_raw_fd(fd) };
                    self.configure_daemon_stream_listener(&listener)?;
                    stdout_listener = Some(listener);
                } else {
                    safe_close_fd(fd);
                }
                continue;
            }

            restored_stdout_fds.push(fd);
        }

        let (native_socket, native_guard) = match native_socket {
            Some(socket) => (socket, None),
            None => {
                let (socket, guard) = self.bind_daemon_datagram_socket(&self.socket_path())?;
                (socket, Some(guard))
            }
        };
        let (syslog_socket, syslog_guard) = match syslog_socket {
            Some(socket) => (socket, None),
            None => {
                let (socket, guard) = self.bind_daemon_datagram_socket(&self.dev_log_path())?;
                (socket, Some(guard))
            }
        };
        let (stdout_listener, stdout_guard) = match stdout_listener {
            Some(listener) => (listener, None),
            None => {
                let (listener, guard) = self.bind_daemon_stream_listener(&self.stdout_path())?;
                (listener, Some(guard))
            }
        };

        Ok(PreparedDaemonSockets {
            native_socket,
            native_guard,
            syslog_socket,
            syslog_guard,
            stdout_listener,
            stdout_guard,
            restored_stdout_fds,
        })
    }

    pub(super) fn bind_daemon_datagram_socket(
        &self,
        path: &Path,
    ) -> Result<(UnixDatagram, SocketPathGuard), JournaldError> {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }

        let socket = UnixDatagram::bind(path)?;
        let guard = SocketPathGuard::new(path.to_path_buf());
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        self.configure_daemon_datagram_socket(&socket)?;

        Ok((socket, guard))
    }

    pub(super) fn configure_daemon_datagram_socket(
        &self,
        socket: &UnixDatagram,
    ) -> Result<(), JournaldError> {
        #[cfg(not(target_os = "linux"))]
        socket.set_read_timeout(Some(Duration::from_millis(DAEMON_POLL_TIMEOUT_MS)))?;
        #[cfg(target_os = "linux")]
        {
            use nix::sys::socket::{setsockopt, sockopt};
            setsockopt(socket, sockopt::PassCred, &true)
                .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
            let _ = set_socket_bool_option(socket.as_raw_fd(), libc::SO_PASSSEC, true);
            set_socket_bool_option(socket.as_raw_fd(), libc::SO_TIMESTAMP, true)?;
        }
        Ok(())
    }

    pub(super) fn bind_daemon_stream_listener(
        &self,
        path: &Path,
    ) -> Result<(UnixListener, SocketPathGuard), JournaldError> {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }

        let listener = UnixListener::bind(path)?;
        let guard = SocketPathGuard::new(path.to_path_buf());
        fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
        self.configure_daemon_stream_listener(&listener)?;
        Ok((listener, guard))
    }

    pub(super) fn configure_daemon_stream_listener(
        &self,
        listener: &UnixListener,
    ) -> Result<(), JournaldError> {
        listener.set_nonblocking(true)?;
        enable_stream_passcred(listener.as_raw_fd())?;
        Ok(())
    }

    pub(super) fn drain_socket_datagrams(
        &self,
        socket: &UnixDatagram,
        buf: &mut [u8],
        source: IngressSource,
        limiter: &mut PeerRateLimiter,
    ) -> Result<bool, JournaldError> {
        let mut handled_any = false;

        loop {
            let (len, peer, metadata) = match recv_datagram_with_metadata(socket, buf) {
                Ok(result) => result,
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(handled_any)
                }
                Err(err) => return Err(err.into()),
            };

            handled_any = true;
            self.append_socket_datagram_with_metadata(
                &buf[..len],
                peer.as_deref(),
                metadata,
                source,
                Some(limiter),
            )?;
        }
    }

    pub(super) fn accept_stdout_streams(
        &self,
        listener: &UnixListener,
        streams: &mut Vec<StdoutStreamConnection>,
    ) -> Result<bool, JournaldError> {
        let mut handled_any = false;

        loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    handled_any = true;
                    stream.set_nonblocking(true)?;
                    streams.push(StdoutStreamConnection::new(stream)?);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(handled_any),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err.into()),
            }
        }
    }

    pub(super) fn drain_stdout_streams(
        &self,
        streams: &mut Vec<StdoutStreamConnection>,
        limiter: &mut PeerRateLimiter,
    ) -> Result<bool, JournaldError> {
        let mut handled_any = false;
        let mut index = 0;

        while index < streams.len() {
            let (keep_open, handled_stream) =
                self.process_stdout_stream(&mut streams[index], limiter)?;
            handled_any |= handled_stream;
            if keep_open {
                index += 1;
            } else {
                self.terminate_stdout_stream(&streams[index]);
                streams.remove(index);
            }
        }

        Ok(handled_any)
    }

    pub(super) fn process_stdout_stream(
        &self,
        stream: &mut StdoutStreamConnection,
        limiter: &mut PeerRateLimiter,
    ) -> Result<(bool, bool), JournaldError> {
        let mut handled_any = false;
        let mut eof = false;

        loop {
            match recv_stdout_stream_message(&stream.stream)? {
                Some(StdoutStreamRead::Data { payload, creds }) => {
                    handled_any = true;
                    if let Some(creds) = creds {
                        if stream
                            .creds
                            .map(|current| current.pid != creds.pid)
                            .unwrap_or(false)
                        {
                            self.drain_stdout_stream_frames(
                                stream,
                                Some(StdoutLineBreak::PidChange),
                                limiter,
                            )?;
                        }
                        stream.creds = Some(creds);
                    }
                    stream.buffer.extend_from_slice(&payload);
                }
                Some(StdoutStreamRead::Eof) => {
                    eof = true;
                    break;
                }
                None => break,
            }
        }

        self.drain_stdout_stream_frames(stream, eof.then_some(StdoutLineBreak::Eof), limiter)?;
        handled_any |= eof || !stream.buffer.is_empty();

        if eof {
            return Ok((false, true));
        }

        Ok((true, handled_any))
    }

    pub(super) fn terminate_stdout_stream(&self, stream: &StdoutStreamConnection) {
        if let Some(state_file) = &stream.state_file {
            let _ = fs::remove_file(state_file);
        }
    }

    pub(super) fn drain_stdout_stream_frames(
        &self,
        stream: &mut StdoutStreamConnection,
        force_flush: Option<StdoutLineBreak>,
        limiter: &mut PeerRateLimiter,
    ) -> Result<(), JournaldError> {
        loop {
            let Some((line, line_break)) =
                stream.next_frame(stdout_stream_line_max(stream.state), force_flush)
            else {
                return Ok(());
            };
            if self
                .process_stdout_stream_frame(stream, &line, line_break, limiter)?
                .is_err()
            {
                return Err(JournaldError::InvalidArgument(
                    "stdout stream control protocol line not properly terminated".to_string(),
                ));
            }
        }
    }

    pub(super) fn process_stdout_stream_frame(
        &self,
        stream: &mut StdoutStreamConnection,
        line: &[u8],
        line_break: StdoutLineBreak,
        limiter: &mut PeerRateLimiter,
    ) -> Result<Result<(), ()>, JournaldError> {
        let text = String::from_utf8_lossy(line).into_owned();
        match stream.state {
            StdoutStreamState::Identifier => {
                if line_break != StdoutLineBreak::Newline {
                    return Ok(Err(()));
                }
                if !text.is_empty() {
                    stream.identifier = Some(text);
                }
                stream.state = StdoutStreamState::UnitId;
                Ok(Ok(()))
            }
            StdoutStreamState::UnitId => {
                if line_break != StdoutLineBreak::Newline {
                    return Ok(Err(()));
                }
                if stream.creds.map(|cred| cred.uid == 0).unwrap_or(false) && !text.is_empty() {
                    stream.unit_id = Some(text);
                }
                stream.state = StdoutStreamState::Priority;
                Ok(Ok(()))
            }
            StdoutStreamState::Priority => {
                if line_break != StdoutLineBreak::Newline {
                    return Ok(Err(()));
                }
                let Ok(priority) = text.parse::<u32>() else {
                    return Ok(Err(()));
                };
                if priority > 999 {
                    return Ok(Err(()));
                }
                stream.priority = priority;
                stream.state = StdoutStreamState::LevelPrefix;
                Ok(Ok(()))
            }
            StdoutStreamState::LevelPrefix => {
                if line_break != StdoutLineBreak::Newline {
                    return Ok(Err(()));
                }
                let Some(value) = parse_stream_boolean(&text) else {
                    return Ok(Err(()));
                };
                stream.level_prefix = value;
                stream.state = StdoutStreamState::ForwardToSyslog;
                Ok(Ok(()))
            }
            StdoutStreamState::ForwardToSyslog => {
                if line_break != StdoutLineBreak::Newline {
                    return Ok(Err(()));
                }
                let Some(value) = parse_stream_boolean(&text) else {
                    return Ok(Err(()));
                };
                stream.forward_to_syslog = value;
                stream.state = StdoutStreamState::ForwardToKmsg;
                Ok(Ok(()))
            }
            StdoutStreamState::ForwardToKmsg => {
                if line_break != StdoutLineBreak::Newline {
                    return Ok(Err(()));
                }
                let Some(value) = parse_stream_boolean(&text) else {
                    return Ok(Err(()));
                };
                stream.forward_to_kmsg = value;
                stream.state = StdoutStreamState::ForwardToConsole;
                Ok(Ok(()))
            }
            StdoutStreamState::ForwardToConsole => {
                if line_break != StdoutLineBreak::Newline {
                    return Ok(Err(()));
                }
                let Some(value) = parse_stream_boolean(&text) else {
                    return Ok(Err(()));
                };
                stream.forward_to_console = value;
                stream.state = StdoutStreamState::Running;
                self.persist_stdout_stream_state(stream)?;
                self.notify_store_stdout_stream(stream)?;
                Ok(Ok(()))
            }
            StdoutStreamState::Running => {
                self.append_stdout_stream_message(stream, line, line_break, Some(limiter))?;
                Ok(Ok(()))
            }
        }
    }

    pub(super) fn restore_stdout_streams(
        &self,
        restored_fds: Vec<libc::c_int>,
    ) -> Result<Vec<StdoutStreamConnection>, JournaldError> {
        let streams_dir = self.stdout_streams_dir();
        let Ok(entries) = fs::read_dir(&streams_dir) else {
            for fd in restored_fds {
                safe_close_fd(fd);
            }
            return Ok(Vec::new());
        };

        let mut restored = Vec::new();
        let mut available = restored_fds;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(identity) = parse_stream_state_file_name(file_name) else {
                continue;
            };
            let Some(index) = available
                .iter()
                .position(|fd| socket_identity_from_fd(*fd).ok() == Some(identity))
            else {
                let _ = fs::remove_file(&path);
                continue;
            };

            let fd = available.swap_remove(index);
            // SAFETY: swap_remove transfers the sole ownership of this live
            // stream descriptor into UnixStream.
            let stream = unsafe { UnixStream::from_raw_fd(fd) };
            stream.set_nonblocking(true)?;
            let mut connection = StdoutStreamConnection::new(stream)?;
            connection.state = StdoutStreamState::Running;
            connection.fdstore = true;
            connection.state_file = Some(path.clone());
            self.load_stdout_stream_state(&mut connection)?;
            restored.push(connection);
        }

        for fd in available {
            safe_close_fd(fd);
        }

        Ok(restored)
    }

    pub(super) fn persist_stdout_stream_state(
        &self,
        stream: &mut StdoutStreamConnection,
    ) -> Result<(), JournaldError> {
        if stream.state != StdoutStreamState::Running {
            return Ok(());
        }
        let state_file = match &stream.state_file {
            Some(path) => path.clone(),
            None => {
                let (dev, ino) = socket_identity_from_fd(stream.stream.as_raw_fd())?;
                let path = self.stdout_streams_dir().join(format!("{dev}:{ino}"));
                stream.state_file = Some(path.clone());
                path
            }
        };

        fs::create_dir_all(self.stdout_streams_dir())?;
        let tmp_path = state_file.with_extension("tmp");
        let mut file = File::create(&tmp_path)?;
        writeln!(file, "# This is private data. Do not parse")?;
        writeln!(file, "PRIORITY={}", stream.priority)?;
        writeln!(file, "LEVEL_PREFIX={}", boolean_digit(stream.level_prefix))?;
        writeln!(
            file,
            "FORWARD_TO_SYSLOG={}",
            boolean_digit(stream.forward_to_syslog)
        )?;
        writeln!(
            file,
            "FORWARD_TO_KMSG={}",
            boolean_digit(stream.forward_to_kmsg)
        )?;
        writeln!(
            file,
            "FORWARD_TO_CONSOLE={}",
            boolean_digit(stream.forward_to_console)
        )?;
        writeln!(file, "STREAM_ID={}", stream.stream_id)?;
        if let Some(identifier) = &stream.identifier {
            writeln!(file, "IDENTIFIER={identifier}")?;
        }
        if let Some(unit_id) = &stream.unit_id {
            writeln!(file, "UNIT={unit_id}")?;
        }
        file.flush()?;
        fs::rename(tmp_path, state_file)?;
        Ok(())
    }

    pub(super) fn load_stdout_stream_state(
        &self,
        stream: &mut StdoutStreamConnection,
    ) -> Result<(), JournaldError> {
        let Some(state_file) = &stream.state_file else {
            return Ok(());
        };
        let text = fs::read_to_string(state_file)?;
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "PRIORITY" => {
                    if let Ok(priority) = value.parse::<u32>() {
                        if priority <= 999 {
                            stream.priority = priority;
                        }
                    }
                }
                "LEVEL_PREFIX" => {
                    if let Some(value) = parse_stream_boolean(value) {
                        stream.level_prefix = value;
                    }
                }
                "FORWARD_TO_SYSLOG" => {
                    if let Some(value) = parse_stream_boolean(value) {
                        stream.forward_to_syslog = value;
                    }
                }
                "FORWARD_TO_KMSG" => {
                    if let Some(value) = parse_stream_boolean(value) {
                        stream.forward_to_kmsg = value;
                    }
                }
                "FORWARD_TO_CONSOLE" => {
                    if let Some(value) = parse_stream_boolean(value) {
                        stream.forward_to_console = value;
                    }
                }
                "IDENTIFIER" if !value.is_empty() => {
                    stream.identifier = Some(value.to_string());
                }
                "UNIT" if !value.is_empty() => {
                    stream.unit_id = Some(value.to_string());
                }
                "STREAM_ID" if !value.is_empty() => {
                    stream.stream_id = value.to_string();
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub(super) fn notify_store_stdout_stream(
        &self,
        stream: &mut StdoutStreamConnection,
    ) -> Result<(), JournaldError> {
        if stream.fdstore {
            return Ok(());
        }
        match notify_store_fd(stream.stream.as_raw_fd()) {
            Ok(()) => stream.fdstore = true,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        Ok(())
    }

    pub(super) fn append_stdout_stream_message(
        &self,
        stream: &StdoutStreamConnection,
        line: &[u8],
        line_break: StdoutLineBreak,
        limiter: Option<&mut PeerRateLimiter>,
    ) -> Result<(), JournaldError> {
        let message = String::from_utf8_lossy(line).into_owned();
        let (priority, message) =
            parse_stdout_priority_prefix(&message, stream.priority, stream.level_prefix);
        if message.is_empty() {
            return Ok(());
        }

        let severity = (priority % 8) as u8;
        let facility = (priority / 8) as u8;
        let mut extra_fields = vec![("_STREAM_ID".to_string(), stream.stream_id.clone())];
        if let Some(unit_id) = &stream.unit_id {
            extra_fields.push(("UNIT".to_string(), unit_id.clone()));
        }
        match line_break {
            StdoutLineBreak::Newline => {}
            StdoutLineBreak::Nul => {
                extra_fields.push(("_LINE_BREAK".to_string(), "nul".to_string()));
            }
            StdoutLineBreak::LineMax => {
                extra_fields.push(("_LINE_BREAK".to_string(), "line-max".to_string()));
            }
            StdoutLineBreak::Eof => {
                extra_fields.push(("_LINE_BREAK".to_string(), "eof".to_string()));
            }
            StdoutLineBreak::PidChange => {
                extra_fields.push(("_LINE_BREAK".to_string(), "pid-change".to_string()));
            }
        }

        let context = stream.creds.and_then(|cred| {
            self.client_context_for_pid(
                cred,
                stream.unit_id.as_deref(),
                stream.selinux_label.as_deref(),
            )
        });
        let record = IngressRecord {
            transport: IngressTransport::Stdout,
            message,
            priority: Some(priority % 8),
            facility: (facility != 0).then_some(facility),
            severity: Some(severity),
            syslog_identifier: stream.identifier.clone(),
            syslog_pid: None,
            syslog_timestamp: None,
            kmsg_sequence: None,
            source_boottime_timestamp: None,
            source_monotonic_timestamp: None,
            object_pid: None,
            extra_fields,
            native_fields: None,
        };
        if !self.context_keeps_log(context.as_ref(), &record) {
            return Ok(());
        }
        if let Some(limiter) = limiter {
            if !self.apply_context_rate_limit(limiter, context.as_ref(), priority % 8)? {
                return Ok(());
            }
        }

        self.append_classified_ingress_with_context(
            line,
            None,
            stream.creds,
            record,
            context.as_ref(),
            None,
        )
    }
}
