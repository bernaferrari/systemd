// SPDX-License-Identifier: LGPL-2.1-or-later

use super::*;

#[derive(Debug, Clone, Default)]
pub(super) struct ClientContext {
    pub(super) pid: i32,
    pub(super) uid: Option<u32>,
    pub(super) gid: Option<u32>,
    pub(super) comm: Option<String>,
    pub(super) exe: Option<String>,
    pub(super) cmdline: Option<String>,
    pub(super) cap_effective: Option<String>,
    pub(super) label: Option<String>,
    pub(super) audit_session: Option<u32>,
    pub(super) audit_loginuid: Option<u32>,
    pub(super) cgroup: Option<String>,
    pub(super) session: Option<String>,
    pub(super) owner_uid: Option<u32>,
    pub(super) unit: Option<String>,
    pub(super) user_unit: Option<String>,
    pub(super) slice: Option<String>,
    pub(super) user_slice: Option<String>,
    pub(super) invocation_id: Option<String>,
    pub(super) extra_fields: Vec<Vec<u8>>,
    pub(super) extra_fields_mtime_nsec: Option<u64>,
    pub(super) log_level_max: Option<u8>,
    pub(super) log_ratelimit_interval_usec: Option<u64>,
    pub(super) log_ratelimit_burst: Option<u32>,
    pub(super) log_filter_allowed_patterns: Arc<Vec<CompiledPattern>>,
    pub(super) log_filter_denied_patterns: Arc<Vec<CompiledPattern>>,
    pub(super) timestamp_usec: u64,
}

#[derive(Debug, Default)]
pub(super) struct ClientContextCache {
    pub(super) entries: BTreeMap<i32, ClientContext>,
}

#[derive(Debug)]
pub(super) struct ClientContextRoots {
    proc: PathBuf,
    run_systemd: PathBuf,
    run_user: PathBuf,
}

impl ClientContextRoots {
    pub(super) fn current() -> Self {
        Self {
            proc: proc_root(),
            run_systemd: run_systemd_root(),
            run_user: run_user_root(),
        }
    }
}

impl ClientContextCache {
    pub(super) fn get_or_refresh(
        &mut self,
        pid: i32,
        creds: Option<PeerCredentials>,
        label_override: Option<&str>,
        unit_id_hint: Option<&str>,
        roots: &ClientContextRoots,
    ) -> ClientContext {
        let now = now_micros_u64();
        let refresh = match self.entries.get(&pid) {
            Some(context) => {
                now.saturating_sub(context.timestamp_usec) >= CLIENT_CONTEXT_REFRESH_USEC
                    || creds.is_some_and(|cred| {
                        context.uid != Some(cred.uid) || context.gid != Some(cred.gid)
                    })
                    || label_override.is_some_and(|label| context.label.as_deref() != Some(label))
            }
            None => true,
        };
        let expired = self.entries.get(&pid).is_some_and(|context| {
            now.saturating_sub(context.timestamp_usec) >= CLIENT_CONTEXT_MAX_USEC
        });
        if expired {
            self.entries.remove(&pid);
        }

        if !refresh {
            let mut context = self.entries.get(&pid).cloned().unwrap_or_default();
            overlay_creds(&mut context, creds);
            if let Some(label) = label_override {
                context.label = Some(label.to_string());
            }
            return context;
        }

        let existing = self.entries.get(&pid).cloned();
        let context =
            collect_client_context(pid, creds, label_override, unit_id_hint, existing, roots);
        self.entries.insert(pid, context.clone());
        self.prune(now);
        context
    }

    fn prune(&mut self, now: u64) {
        self.entries.retain(|_, context| {
            now.saturating_sub(context.timestamp_usec) < CLIENT_CONTEXT_MAX_USEC
        });

        while self.entries.len() > CLIENT_CONTEXT_CACHE_MAX {
            let Some((&oldest_pid, _)) = self
                .entries
                .iter()
                .min_by_key(|(_, context)| context.timestamp_usec)
            else {
                break;
            };
            self.entries.remove(&oldest_pid);
        }
    }
}

fn overlay_creds(context: &mut ClientContext, creds: Option<PeerCredentials>) {
    if let Some(creds) = creds {
        context.pid = creds.pid;
        context.uid = Some(creds.uid);
        context.gid = Some(creds.gid);
    }
}

fn collect_client_context(
    pid: i32,
    creds: Option<PeerCredentials>,
    label_override: Option<&str>,
    unit_id_hint: Option<&str>,
    existing: Option<ClientContext>,
    roots: &ClientContextRoots,
) -> ClientContext {
    let mut context = existing.unwrap_or_default();
    context.pid = pid;
    context.timestamp_usec = now_micros_u64();
    overlay_creds(&mut context, creds);

    if context.uid.is_none() {
        context.uid = read_status_ids(&roots.proc, pid).map(|(uid, _)| uid);
    }
    if context.gid.is_none() {
        context.gid = read_status_ids(&roots.proc, pid).map(|(_, gid)| gid);
    }
    if let Some(comm) = read_pid_comm(&roots.proc, pid) {
        context.comm = Some(comm);
    }
    if let Some(exe) = read_pid_exe(&roots.proc, pid) {
        context.exe = Some(exe);
    }
    if let Some(cmdline) = read_pid_cmdline(&roots.proc, pid) {
        context.cmdline = Some(cmdline);
    }
    if let Some(cap_effective) = read_pid_cap_effective(&roots.proc, pid) {
        context.cap_effective = Some(cap_effective);
    }
    if let Some(label) = label_override {
        context.label = Some(label.to_string());
    } else if let Some(label) = read_pid_label(&roots.proc, pid) {
        context.label = Some(label);
    }
    if let Some(audit_session) = read_pid_audit_session(&roots.proc, pid) {
        context.audit_session = Some(audit_session);
    }
    if let Some(audit_loginuid) = read_pid_audit_loginuid(&roots.proc, pid) {
        context.audit_loginuid = Some(audit_loginuid);
    }
    if let Some(cgroup) = read_pid_cgroup_path(&roots.proc, pid) {
        if let Some((allowed_patterns, denied_patterns)) = read_cgroup_log_filter_patterns(&cgroup)
        {
            context.log_filter_allowed_patterns = Arc::new(allowed_patterns);
            context.log_filter_denied_patterns = Arc::new(denied_patterns);
        }
        apply_cgroup_context(&mut context, &cgroup, unit_id_hint);
    } else if context.unit.is_none() {
        context.unit = unit_id_hint.map(str::to_string);
    }
    if let Some(invocation_id) = read_invocation_id(
        &roots.run_systemd,
        &roots.run_user,
        context.owner_uid,
        context.unit.as_deref(),
        context.user_unit.as_deref(),
    ) {
        context.invocation_id = Some(invocation_id);
    }
    if let Some(unit) = context.unit.as_deref() {
        if let Some(log_level_max) = read_unit_log_level_max(&roots.run_systemd, unit) {
            context.log_level_max = Some(log_level_max);
        }
        if let Some((extra_fields, extra_fields_mtime_nsec)) = read_unit_extra_fields(
            &roots.run_systemd,
            unit,
            &context.extra_fields,
            context.extra_fields_mtime_nsec,
        ) {
            context.extra_fields = extra_fields;
            context.extra_fields_mtime_nsec = extra_fields_mtime_nsec;
        }
        if let Some(interval_usec) = read_unit_rate_limit_interval_usec(&roots.run_systemd, unit) {
            context.log_ratelimit_interval_usec = Some(interval_usec);
        }
        if let Some(burst) = read_unit_rate_limit_burst(&roots.run_systemd, unit) {
            context.log_ratelimit_burst = Some(burst);
        }
    }

    context
}

pub(super) fn client_context_check_keep_log(
    context: Option<&ClientContext>,
    message: &str,
) -> bool {
    let Some(context) = context else {
        return true;
    };

    for regex in context.log_filter_denied_patterns.iter() {
        if pattern_matches(regex, message, false)
            .map(|result| result.matched)
            .unwrap_or(false)
        {
            return false;
        }
    }

    for regex in context.log_filter_allowed_patterns.iter() {
        if pattern_matches(regex, message, false)
            .map(|result| result.matched)
            .unwrap_or(false)
        {
            return true;
        }
    }

    context.log_filter_allowed_patterns.is_empty()
}

pub(super) fn compile_filter_nulstr(bytes: &[u8]) -> Option<Vec<CompiledPattern>> {
    let mut compiled = Vec::new();
    for pattern in bytes.split(|byte| *byte == b'\0') {
        if pattern.is_empty() {
            continue;
        }
        let pattern = std::str::from_utf8(pattern).ok()?;
        let regex = pattern_compile(pattern, PatternCompileCase::Sensitive).ok()?;
        compiled.push(regex);
    }
    Some(compiled)
}

pub(super) fn read_cgroup_log_filter_patterns(
    cgroup_path: &str,
) -> Option<(Vec<CompiledPattern>, Vec<CompiledPattern>)> {
    let unit_path = cgroup_fs_root().join(cgroup_path.trim_start_matches('/'));
    let xattr = match read_path_xattr(&unit_path, "user.journald_log_filter_patterns") {
        Ok(Some(xattr)) => xattr,
        Ok(None) => return Some((Vec::new(), Vec::new())),
        Err(_) => return None,
    };

    let delimiter = xattr.iter().position(|byte| *byte == 0xff)?;
    dlopen_pcre2().ok()?;
    let allowed = compile_filter_nulstr(&xattr[..delimiter])?;
    let denied = compile_filter_nulstr(&xattr[delimiter + 1..])?;
    Some((allowed, denied))
}

#[cfg(target_os = "linux")]
pub(super) fn read_path_xattr(path: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
    use std::ffi::CString;

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid xattr path"))?;
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid xattr name"))?;

    // SAFETY: path and name are live NUL-terminated strings; a null value
    // pointer with size zero performs the documented size query.
    let size = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let err = io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(libc::ENODATA) | Some(libc::EOPNOTSUPP)
        ) {
            return Ok(None);
        }
        return Err(err);
    }

    let mut buf = vec![0_u8; size as usize];
    // SAFETY: both C strings remain live and buf exposes exactly buf.len()
    // writable bytes.
    let rc = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(rc as usize);
    Ok(Some(buf))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn read_path_xattr(_path: &Path, _name: &str) -> io::Result<Option<Vec<u8>>> {
    Ok(None)
}

pub(super) fn is_probable_unit_name(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let known_suffix = [
        ".service", ".slice", ".scope", ".socket", ".mount", ".target",
    ];
    if !known_suffix.iter().any(|suffix| value.ends_with(suffix)) {
        return false;
    }

    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '@'))
}

pub(super) fn append_client_context_fields(
    fields: &mut Vec<String>,
    prefix: &str,
    context: &ClientContext,
) {
    let name = |field: &str| {
        if prefix.is_empty() {
            field.to_string()
        } else {
            format!("{prefix}{}", field.trim_start_matches('_'))
        }
    };

    if context.pid > 0 {
        fields.push(format!("{}={}", name("_PID"), context.pid));
    }
    if let Some(uid) = context.uid {
        fields.push(format!("{}={uid}", name("_UID")));
    }
    if let Some(gid) = context.gid {
        fields.push(format!("{}={gid}", name("_GID")));
    }
    if let Some(comm) = &context.comm {
        fields.push(format!("{}={}", name("_COMM"), sanitize_field_value(comm)));
    }
    if let Some(exe) = &context.exe {
        fields.push(format!("{}={}", name("_EXE"), sanitize_field_value(exe)));
    }
    if let Some(cmdline) = &context.cmdline {
        fields.push(format!(
            "{}={}",
            name("_CMDLINE"),
            sanitize_field_value(cmdline)
        ));
    }
    if let Some(cap_effective) = &context.cap_effective {
        fields.push(format!("{}={cap_effective}", name("_CAP_EFFECTIVE")));
    }
    if let Some(label) = &context.label {
        fields.push(format!(
            "{}={}",
            name("_SELINUX_CONTEXT"),
            sanitize_field_value(label)
        ));
    }
    if let Some(audit_session) = context.audit_session {
        fields.push(format!("{}={audit_session}", name("_AUDIT_SESSION")));
    }
    if let Some(audit_loginuid) = context.audit_loginuid {
        fields.push(format!("{}={audit_loginuid}", name("_AUDIT_LOGINUID")));
    }
    if let Some(cgroup) = &context.cgroup {
        fields.push(format!(
            "{}={}",
            name("_SYSTEMD_CGROUP"),
            sanitize_field_value(cgroup)
        ));
    }
    if let Some(session) = &context.session {
        fields.push(format!(
            "{}={}",
            name("_SYSTEMD_SESSION"),
            sanitize_field_value(session)
        ));
    }
    if let Some(owner_uid) = context.owner_uid {
        fields.push(format!("{}={owner_uid}", name("_SYSTEMD_OWNER_UID")));
    }
    if let Some(unit) = &context.unit {
        fields.push(format!(
            "{}={}",
            name("_SYSTEMD_UNIT"),
            sanitize_field_value(unit)
        ));
    }
    if let Some(user_unit) = &context.user_unit {
        fields.push(format!(
            "{}={}",
            name("_SYSTEMD_USER_UNIT"),
            sanitize_field_value(user_unit)
        ));
    }
    if let Some(slice) = &context.slice {
        fields.push(format!(
            "{}={}",
            name("_SYSTEMD_SLICE"),
            sanitize_field_value(slice)
        ));
    }
    if let Some(user_slice) = &context.user_slice {
        fields.push(format!(
            "{}={}",
            name("_SYSTEMD_USER_SLICE"),
            sanitize_field_value(user_slice)
        ));
    }
    if let Some(invocation_id) = &context.invocation_id {
        fields.push(format!(
            "{}={invocation_id}",
            name("_SYSTEMD_INVOCATION_ID")
        ));
    }
}

pub(super) fn append_client_context_extra_fields(
    fields: &mut Vec<Vec<u8>>,
    context: &ClientContext,
) {
    for field in &context.extra_fields {
        let Some(eq) = field.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        if journal_field_valid(&field[..eq], false) {
            fields.push(field.clone());
        }
    }
}

pub(super) fn parse_log_level(text: &str) -> Option<u8> {
    match text.trim() {
        "emerg" => Some(0),
        "alert" => Some(1),
        "crit" => Some(2),
        "err" => Some(3),
        "warning" => Some(4),
        "notice" => Some(5),
        "info" => Some(6),
        "debug" => Some(7),
        raw => raw.parse::<u8>().ok().filter(|level| *level <= 7),
    }
}

pub(super) fn units_runtime_path(run_systemd_root: &Path, prefix: &str, unit: &str) -> PathBuf {
    run_systemd_root
        .join("units")
        .join(format!("{prefix}:{unit}"))
}

pub(super) fn stat_mtime_nsec(metadata: &fs::Metadata) -> u64 {
    (metadata.mtime() as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(metadata.mtime_nsec() as u64)
}

pub(super) fn read_unit_symlink_or_file(
    run_systemd_root: &Path,
    prefix: &str,
    unit: &str,
) -> Option<String> {
    let path = units_runtime_path(run_systemd_root, prefix, unit);
    if let Ok(target) = fs::read_link(&path) {
        return Some(target.as_os_str().to_string_lossy().trim().to_string());
    }

    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_string())
}

pub(super) fn read_unit_log_level_max(run_systemd_root: &Path, unit: &str) -> Option<u8> {
    parse_log_level(&read_unit_symlink_or_file(
        run_systemd_root,
        "log-level-max",
        unit,
    )?)
}

pub(super) fn read_unit_extra_fields(
    run_systemd_root: &Path,
    unit: &str,
    existing_fields: &[Vec<u8>],
    existing_mtime_nsec: Option<u64>,
) -> Option<(Vec<Vec<u8>>, Option<u64>)> {
    let path = units_runtime_path(run_systemd_root, "log-extra-fields", unit);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return existing_mtime_nsec.map(|mtime| (existing_fields.to_vec(), Some(mtime)));
        }
        Err(_) => return None,
    };

    let mtime_nsec = stat_mtime_nsec(&metadata);
    if existing_mtime_nsec == Some(mtime_nsec) {
        return Some((existing_fields.to_vec(), Some(mtime_nsec)));
    }

    let mut data = fs::read(&path).ok()?;
    let metadata = fs::metadata(&path).ok()?;
    let mtime_nsec = stat_mtime_nsec(&metadata);

    let mut extra_fields = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let header_end = offset.checked_add(std::mem::size_of::<u64>())?;
        if header_end > data.len() {
            return None;
        }

        let mut len_bytes = [0u8; std::mem::size_of::<u64>()];
        len_bytes.copy_from_slice(&data[offset..header_end]);
        let field_len = usize::try_from(u64::from_le_bytes(len_bytes)).ok()?;
        if field_len < 2 {
            return None;
        }

        let field_start = header_end;
        let field_end = field_start.checked_add(field_len)?;
        if field_end > data.len() {
            return None;
        }

        let field = &data[field_start..field_end];
        let eq = field.iter().position(|byte| *byte == b'=')?;
        if !journal_field_valid(&field[..eq], false) {
            return None;
        }

        extra_fields.push(field.to_vec());
        offset = field_end;
    }

    data.clear();
    Some((extra_fields, Some(mtime_nsec)))
}

pub(super) fn read_unit_rate_limit_interval_usec(
    run_systemd_root: &Path,
    unit: &str,
) -> Option<u64> {
    read_unit_symlink_or_file(run_systemd_root, "log-rate-limit-interval", unit)?
        .parse::<u64>()
        .ok()
}

pub(super) fn read_unit_rate_limit_burst(run_systemd_root: &Path, unit: &str) -> Option<u32> {
    read_unit_symlink_or_file(run_systemd_root, "log-rate-limit-burst", unit)?
        .parse::<u32>()
        .ok()
}

pub(super) fn proc_root() -> PathBuf {
    std::env::var_os(PROC_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/proc"))
}

pub(super) fn run_systemd_root() -> PathBuf {
    std::env::var_os(RUN_SYSTEMD_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/systemd"))
}

pub(super) fn run_user_root() -> PathBuf {
    std::env::var_os(RUN_USER_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/user"))
}

pub(super) fn cgroup_fs_root() -> PathBuf {
    std::env::var_os(CGROUP_FS_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup"))
}

pub(super) fn read_proc_text(proc_root: &Path, pid: i32, suffix: &str) -> Option<String> {
    fs::read_to_string(proc_root.join(pid.to_string()).join(suffix)).ok()
}

pub(super) fn read_proc_bytes(proc_root: &Path, pid: i32, suffix: &str) -> Option<Vec<u8>> {
    fs::read(proc_root.join(pid.to_string()).join(suffix)).ok()
}

pub(super) fn read_pid_comm(proc_root: &Path, pid: i32) -> Option<String> {
    let comm = read_proc_text(proc_root, pid, "comm")?;
    let comm = comm.trim_end_matches('\n').trim_end_matches('\0').trim();
    (!comm.is_empty()).then(|| comm.to_string())
}

pub(super) fn read_pid_exe(proc_root: &Path, pid: i32) -> Option<String> {
    let exe = fs::read_link(proc_root.join(pid.to_string()).join("exe")).ok()?;
    let exe = exe.as_os_str().to_string_lossy().into_owned();
    (!exe.is_empty()).then_some(exe)
}

pub(super) fn read_pid_cmdline(proc_root: &Path, pid: i32) -> Option<String> {
    let cmdline = read_proc_bytes(proc_root, pid, "cmdline")?;
    let args = cmdline
        .split(|byte| *byte == b'\0')
        .filter(|arg| !arg.is_empty())
        .map(|arg| quote_cmdline_argument(&String::from_utf8_lossy(arg)))
        .collect::<Vec<_>>();
    (!args.is_empty()).then(|| args.join(" "))
}

pub(super) fn quote_cmdline_argument(arg: &str) -> String {
    if arg
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '-' | '.' | ':' | '@'))
    {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\\''"))
}

pub(super) fn read_status_ids(proc_root: &Path, pid: i32) -> Option<(u32, u32)> {
    let status = read_proc_text(proc_root, pid, "status")?;
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
        }
    }
    Some((uid?, gid?))
}

pub(super) fn read_pid_cap_effective(proc_root: &Path, pid: i32) -> Option<String> {
    let status = read_proc_text(proc_root, pid, "status")?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .map(str::trim)?;
    (!value.is_empty() && value != "0000000000000000").then(|| value.to_ascii_lowercase())
}

pub(super) fn read_pid_label(proc_root: &Path, pid: i32) -> Option<String> {
    let label = read_proc_text(proc_root, pid, "attr/current")?;
    let label = label.trim_end_matches('\n').trim_end_matches('\0').trim();
    (!label.is_empty()).then(|| label.to_string())
}

pub(super) fn read_pid_audit_loginuid(proc_root: &Path, pid: i32) -> Option<u32> {
    let text = read_proc_text(proc_root, pid, "loginuid")?;
    parse_loginuid(&text).ok()?.uid
}

pub(super) fn read_pid_audit_session(proc_root: &Path, pid: i32) -> Option<u32> {
    let text = read_proc_text(proc_root, pid, "sessionid")?;
    parse_sessionid(&text).ok()?.id
}

pub(super) fn read_pid_cgroup_path(proc_root: &Path, pid: i32) -> Option<String> {
    let content = read_proc_text(proc_root, pid, "cgroup")?;
    content.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let _ = parts.next();
        let _ = parts.next();
        let cgroup = parts.next()?.trim();
        (!cgroup.is_empty()).then(|| cgroup.to_string())
    })
}

pub(super) fn apply_cgroup_context(
    context: &mut ClientContext,
    cgroup_path: &str,
    unit_id_hint: Option<&str>,
) {
    let parsed = parse_cgroup_context(cgroup_path, unit_id_hint);
    context.cgroup = Some(parsed.cgroup);
    context.session = parsed.session;
    context.owner_uid = parsed.owner_uid;
    context.unit = parsed.unit;
    context.user_unit = parsed.user_unit;
    context.slice = parsed.slice;
    context.user_slice = parsed.user_slice;
}

#[derive(Debug, Default)]
pub(super) struct ParsedCgroupContext {
    pub(super) cgroup: String,
    pub(super) session: Option<String>,
    pub(super) owner_uid: Option<u32>,
    pub(super) unit: Option<String>,
    pub(super) user_unit: Option<String>,
    pub(super) slice: Option<String>,
    pub(super) user_slice: Option<String>,
}

pub(super) fn parse_cgroup_context(
    cgroup_path: &str,
    unit_id_hint: Option<&str>,
) -> ParsedCgroupContext {
    let segments = cgroup_path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let owner_uid = segments
        .iter()
        .find_map(|segment| parse_owner_uid_segment(segment));
    let session = segments.iter().find_map(|segment| {
        segment
            .strip_prefix("session-")
            .and_then(|value| value.strip_suffix(".scope"))
            .map(str::to_string)
    });
    let slices = segments
        .iter()
        .copied()
        .filter(|segment| segment.ends_with(".slice"))
        .collect::<Vec<_>>();
    let non_slice_units = segments
        .iter()
        .copied()
        .filter(|segment| is_probable_unit_name(segment) && !segment.ends_with(".slice"))
        .collect::<Vec<_>>();

    let unit = if owner_uid.is_some() {
        non_slice_units
            .iter()
            .copied()
            .find(|segment| segment.starts_with("user@") && segment.ends_with(".service"))
            .map(str::to_string)
            .or_else(|| unit_id_hint.map(str::to_string))
            .or_else(|| non_slice_units.last().map(|segment| (*segment).to_string()))
    } else {
        non_slice_units
            .last()
            .map(|segment| (*segment).to_string())
            .or_else(|| unit_id_hint.map(str::to_string))
    };
    let user_unit = if owner_uid.is_some() {
        non_slice_units
            .iter()
            .copied()
            .rev()
            .find(|segment| Some(*segment) != unit.as_deref())
            .map(str::to_string)
    } else {
        None
    };
    let slice = owner_uid
        .and_then(|uid| {
            let owned = format!("user-{uid}.slice");
            slices.iter().copied().find(|segment| *segment == owned)
        })
        .map(str::to_string)
        .or_else(|| slices.last().map(|segment| (*segment).to_string()));
    let user_slice = if owner_uid.is_some() {
        slices
            .iter()
            .copied()
            .rev()
            .find(|segment| Some(*segment) != slice.as_deref())
            .map(str::to_string)
            .or_else(|| slice.clone())
    } else {
        None
    };

    ParsedCgroupContext {
        cgroup: cgroup_path.to_string(),
        session,
        owner_uid,
        unit,
        user_unit,
        slice,
        user_slice,
    }
}

pub(super) fn parse_owner_uid_segment(segment: &str) -> Option<u32> {
    segment
        .strip_prefix("user-")
        .and_then(|value| value.strip_suffix(".slice"))
        .and_then(|value| value.parse::<u32>().ok())
}

pub(super) fn read_invocation_id(
    run_systemd_root: &Path,
    run_user_root: &Path,
    owner_uid: Option<u32>,
    unit: Option<&str>,
    user_unit: Option<&str>,
) -> Option<String> {
    let unit = unit?;
    let path = if let (Some(owner_uid), Some(user_unit)) = (owner_uid, user_unit) {
        run_user_root
            .join(owner_uid.to_string())
            .join("systemd/units")
            .join(format!("invocation:{user_unit}"))
    } else {
        run_systemd_root
            .join("units")
            .join(format!("invocation:{unit}"))
    };
    let target = fs::read_link(path).ok()?;
    let target = target.as_os_str().to_string_lossy().trim().to_string();
    (target.len() == 32 && target.chars().all(|ch| ch.is_ascii_hexdigit()))
        .then(|| target.to_ascii_lowercase())
}
