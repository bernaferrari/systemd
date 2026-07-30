// SPDX-License-Identifier: LGPL-2.1-or-later

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StorageMode {
    Auto,
    Persistent,
    Volatile,
    None,
}

impl StorageMode {
    pub(super) fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "persistent" => Some(Self::Persistent),
            "volatile" => Some(Self::Volatile),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StorageState {
    pub(super) mode: StorageMode,
    pub(super) runtime_root: PathBuf,
    pub(super) persistent_root: PathBuf,
    pub(super) flushed: bool,
    pub(super) persistent_available: bool,
    pub(super) relinquish_requested: bool,
}

impl StorageState {
    pub(super) fn active_root(&self) -> Option<&Path> {
        if self.relinquish_requested {
            return match self.mode {
                StorageMode::None => None,
                _ => Some(self.runtime_root.as_path()),
            };
        }

        match self.mode {
            StorageMode::None => None,
            StorageMode::Volatile => Some(self.runtime_root.as_path()),
            StorageMode::Persistent => Some(self.persistent_root.as_path()),
            StorageMode::Auto => {
                if self.flushed && self.persistent_available {
                    Some(self.persistent_root.as_path())
                } else {
                    Some(self.runtime_root.as_path())
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct StorageVacuumLimits {
    pub(super) max_use: u64,
    pub(super) n_max_files: u64,
}

impl Default for StorageVacuumLimits {
    fn default() -> Self {
        Self {
            max_use: u64::MAX,
            n_max_files: 0,
        }
    }
}

impl StorageVacuumLimits {
    pub(super) fn from_env() -> Self {
        let mut limits = Self::default();

        if let Ok(raw) = std::env::var(SYSTEM_MAX_USE_ENV)
            && let Ok(parsed) = parse_size(&raw)
        {
            limits.max_use = parsed;
        }
        if let Ok(raw) = std::env::var(SYSTEM_MAX_FILES_ENV)
            && let Ok(parsed) = raw.trim().parse::<u64>()
        {
            limits.n_max_files = parsed;
        }

        limits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RotatePolicy {
    max_file_size: Option<u64>,
}

impl RotatePolicy {
    pub(super) fn from_env() -> Self {
        let max_file_size = std::env::var(SYSTEM_MAX_FILE_SIZE_ENV)
            .ok()
            .and_then(|raw| parse_size(&raw).ok())
            .filter(|value| *value > 0);
        Self { max_file_size }
    }
}

impl JournalRuntime {
    pub(super) fn rate_limit_root(&self) -> PathBuf {
        self.storage_state()
            .active_root()
            .unwrap_or_else(|| self.root())
            .to_path_buf()
    }

    pub(super) fn configured_storage_mode(&self) -> StorageMode {
        std::env::var(STORAGE_MODE_ENV)
            .ok()
            .and_then(|value| StorageMode::parse(&value))
            .unwrap_or(StorageMode::Auto)
    }

    pub(super) fn persistent_storage_root(&self) -> PathBuf {
        std::env::var(STORAGE_PERSISTENT_ROOT_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| match self.namespace() {
                Some(namespace) => PathBuf::from(format!("/var/log/journal.{namespace}")),
                None => PathBuf::from("/var/log/journal"),
            })
    }

    pub(super) fn storage_state(&self) -> StorageState {
        let persistent_root = self.persistent_storage_root();
        let persistent_available = fs::metadata(&persistent_root)
            .map(|meta| meta.is_dir())
            .unwrap_or(false);
        StorageState {
            mode: self.configured_storage_mode(),
            runtime_root: self.root.clone(),
            persistent_root,
            flushed: self.is_namespaced_instance() || self.marker_path(FLUSH_MARKER_NAME).exists(),
            persistent_available,
            relinquish_requested: !self.is_namespaced_instance()
                && self.marker_path(RELINQUISH_MARKER_NAME).exists(),
        }
    }

    pub(super) fn active_log_path(&self) -> Result<PathBuf, JournaldError> {
        let state = self.storage_state();
        let Some(root) = state.active_root() else {
            return Err(JournaldError::InvalidArgument(
                "journald storage mode disables writes".to_string(),
            ));
        };
        Ok(root.join(LOG_FILE_NAME))
    }

    pub(super) fn marker_path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    pub(super) fn ensure_root(&self) -> Result<(), JournaldError> {
        fs::create_dir_all(&self.root)?;
        Ok(())
    }

    pub(super) fn journal_file_paths(&self) -> Result<Vec<PathBuf>, JournaldError> {
        self.journal_file_paths_in(self.root())
    }

    pub(super) fn journal_file_paths_in(&self, root: &Path) -> Result<Vec<PathBuf>, JournaldError> {
        let mut files = Vec::new();
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if self.is_journal_file(&path) {
                    files.push(path);
                }
            }
        }

        files.sort_by_key(|path| self.rotation_index(path));
        Ok(files)
    }

    pub(super) fn is_journal_file(&self, path: &Path) -> bool {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return false;
        };

        name == LOG_FILE_NAME
            || Self::rotation_suffix(name).is_some()
            || Self::archived_rotation_metadata(name).is_some()
    }

    pub(super) fn rotation_suffix(name: &str) -> Option<u64> {
        let prefix = format!("{LOG_FILE_NAME}.");
        name.strip_prefix(&prefix)?.parse().ok()
    }

    pub(super) fn archived_rotation_metadata(name: &str) -> Option<(u64, u64)> {
        let core = name.strip_suffix(".journal")?;
        let at = core.rfind('@')?;
        let rest = &core[at + 1..];
        if rest.len() != 66 {
            return None;
        }

        let seqnum_id = &rest[..32];
        let separator_1 = rest.as_bytes()[32];
        let seqnum_hex = &rest[33..49];
        let separator_2 = rest.as_bytes()[49];
        let realtime_hex = &rest[50..66];
        if separator_1 != b'-' || separator_2 != b'-' {
            return None;
        }
        if !seqnum_id.bytes().all(|ch| ch.is_ascii_hexdigit())
            || !seqnum_hex.bytes().all(|ch| ch.is_ascii_hexdigit())
            || !realtime_hex.bytes().all(|ch| ch.is_ascii_hexdigit())
        {
            return None;
        }

        let seqnum = u64::from_str_radix(seqnum_hex, 16).ok()?;
        let realtime = u64::from_str_radix(realtime_hex, 16).ok()?;
        Some((seqnum, realtime))
    }

    pub(super) fn rotated_archive_name(seqnum: u64, realtime_usec: u64) -> String {
        format!("journal@{ROTATED_SEQNUM_ID}-{seqnum:016x}-{realtime_usec:016x}.journal")
    }

    pub(super) fn rotation_index(&self, path: &Path) -> u64 {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return u64::MAX;
        };

        if name == LOG_FILE_NAME {
            0
        } else if let Some((seqnum, _)) = Self::archived_rotation_metadata(name) {
            seqnum
        } else {
            Self::rotation_suffix(name).unwrap_or(u64::MAX - 1)
        }
    }

    pub(super) fn journal_machine_id() -> SdId128 {
        sd_id128_get_machine().unwrap_or_else(|_| SdId128::null())
    }

    pub(super) fn journal_boot_id() -> SdId128 {
        sd_id128_get_boot().unwrap_or_else(|_| SdId128::null())
    }

    pub(super) fn journal_seqnum_id() -> SdId128 {
        sd_id128_randomize().unwrap_or_else(|_| SdId128::null())
    }

    pub(super) fn open_or_create_journal_at(
        &self,
        log_path: &Path,
    ) -> Result<JournalFileOnDisk, JournaldError> {
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut journal = match open_journal_file_at(log_path, true) {
            Ok(journal) => journal,
            Err(err) if err.kind() == io::ErrorKind::NotFound => create_empty_journal_file_at(
                log_path,
                0o644,
                JOURNAL_FILE_SIZE_MIN,
                Self::journal_seqnum_id(),
                Self::journal_machine_id(),
                Self::journal_seqnum_id(),
                HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
                journal_incompatible_flags(),
            )?,
            Err(err) => return Err(err.into()),
        };

        if journal.header.state != STATE_ONLINE {
            journal.header.state = STATE_ONLINE;
            write_journal_header(&mut journal.file, &journal.header)?;
        }

        Ok(journal)
    }

    pub(super) fn active_or_create(&self) -> Result<JournalFileOnDisk, JournaldError> {
        let log_path = self.active_log_path()?;
        self.open_or_create_journal_at(&log_path)
    }

    pub(super) fn sync_file_if_present(&self, path: &Path) -> Result<(), JournaldError> {
        match File::open(path) {
            Ok(file) => {
                file.sync_all()?;
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    pub(super) fn append_fields_to_active_log(
        &self,
        fields: &[Vec<u8>],
    ) -> Result<(), JournaldError> {
        let trailer_size = fields.len().checked_add(1).ok_or_else(|| {
            JournaldError::InvalidArgument("journal entry field count overflows".to_string())
        })?;
        let entry_size = fields
            .iter()
            .try_fold(trailer_size, |size, field| {
                if !field
                    .iter()
                    .position(|byte| *byte == b'=')
                    .is_some_and(|eq| eq > 0)
                {
                    return None;
                }
                size.checked_add(field.len())
            })
            .ok_or_else(|| {
                JournaldError::InvalidArgument(
                    "journal entry is malformed or its size overflows".to_string(),
                )
            })?;
        if entry_size > ENTRY_SIZE_MAX {
            return Err(JournaldError::InvalidArgument(format!(
                "journal entry size {entry_size} exceeds {ENTRY_SIZE_MAX}"
            )));
        }

        let mut journal = self.active_or_create()?;
        let realtime = now_micros_u64();
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        append_journal_record_unindexed(
            &mut journal.file,
            &mut journal.header,
            realtime,
            realtime,
            Self::journal_boot_id(),
            &field_refs,
        )?;
        journal.file.sync_all()?;
        Ok(())
    }

    pub(super) fn append_with_rotate_retry<F>(
        &self,
        mut append_once: F,
    ) -> Result<(), JournaldError>
    where
        F: FnMut() -> Result<(), JournaldError>,
    {
        self.rotate_if_proactive_threshold_reached()?;
        match append_once() {
            Ok(()) => Ok(()),
            Err(first) if Self::should_retry_append_after_rotate(&first) => {
                let _ = self.rotate()?;
                append_once()
            }
            Err(err) => Err(err),
        }
    }

    pub(super) fn should_retry_append_after_rotate(error: &JournaldError) -> bool {
        let JournaldError::Io(err) = error else {
            return false;
        };

        const EREMCHG_LINUX: i32 = 78;
        const ENOTNAM_LINUX: i32 = 118;
        matches!(
            err.raw_os_error(),
            Some(errno)
                if matches!(
                    errno,
                    libc::E2BIG
                        | libc::EFBIG
                        | libc::EDQUOT
                        | libc::ENOSPC
                        | libc::EROFS
                        | libc::EIO
                        | libc::EHOSTDOWN
                        | libc::EBUSY
                        | libc::EPROTONOSUPPORT
                        | libc::EBADMSG
                        | libc::ENODATA
                        | libc::ESHUTDOWN
                        | libc::EADDRNOTAVAIL
                        | libc::EIDRM
                        | libc::EILSEQ
                        | EREMCHG_LINUX
                        | ENOTNAM_LINUX
                )
        )
    }

    pub fn flush(&self) -> Result<(), JournaldError> {
        self.flush_to_persistent(false)
    }

    pub(super) fn flush_to_persistent(&self, require_flag_file: bool) -> Result<(), JournaldError> {
        if self.is_namespaced_instance() {
            return Ok(());
        }

        let state = self.storage_state();
        if state.mode == StorageMode::None {
            return Ok(());
        }
        if require_flag_file && !state.flushed {
            return Ok(());
        }

        self.ensure_root()?;
        let runtime_log = state.runtime_root.join(LOG_FILE_NAME);
        let persistent_log = state.persistent_root.join(LOG_FILE_NAME);

        if state.runtime_root == state.persistent_root {
            for path in self.journal_file_paths_in(&state.runtime_root)? {
                self.sync_file_if_present(&path)?;
            }
        } else if runtime_log.exists() {
            fs::create_dir_all(&state.persistent_root)?;
            let records = read_journal_records(&runtime_log)?;
            let mut persistent = self.open_or_create_journal_at(&persistent_log)?;
            for record in &records {
                let field_refs = record.fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
                append_journal_record_unindexed(
                    &mut persistent.file,
                    &mut persistent.header,
                    record.realtime,
                    record.monotonic,
                    record.boot_id,
                    &field_refs,
                )?;
            }
            persistent.file.sync_all()?;

            for entry in fs::read_dir(&state.runtime_root)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && self.is_journal_file(&path) {
                    let _ = fs::remove_file(path);
                }
            }
        }

        for path in self.journal_file_paths_in(&state.runtime_root)? {
            self.sync_file_if_present(&path)?;
        }
        if state.runtime_root != state.persistent_root {
            for path in self.journal_file_paths_in(&state.persistent_root)? {
                self.sync_file_if_present(&path)?;
            }
        }

        fs::write(
            self.marker_path(FLUSH_MARKER_NAME),
            format!("ts={}\n", now_micros()),
        )?;
        Ok(())
    }

    pub fn reopen(&self) -> Result<(), JournaldError> {
        self.ensure_root()?;
        match fs::remove_file(self.marker_path(RELINQUISH_MARKER_NAME)) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }

        if self.configured_storage_mode() != StorageMode::None {
            let _ = self.active_or_create()?;
        }

        fs::write(
            self.marker_path("reopened"),
            format!("ts={}\n", now_micros()),
        )?;
        Ok(())
    }

    pub(super) fn rotate_active_log(&self) -> Result<RotateReport, JournaldError> {
        self.ensure_root()?;

        let previous_log = self.active_log_path()?;
        if let Some(parent) = previous_log.parent() {
            fs::create_dir_all(parent)?;
        }
        if previous_log.exists() {
            self.ensure_archive_minimum_size(&previous_log)?;
            let next_index = self.next_rotation_index(previous_log.parent())?;
            let rotated_root = previous_log
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let rotated =
                rotated_root.join(Self::rotated_archive_name(next_index, now_micros_u64()));
            fs::rename(&previous_log, &rotated)?;
        }

        let new_log = self.touch_log_file_at(&previous_log)?;
        fs::write(
            self.marker_path(ROTATE_MARKER_NAME),
            format!("ts={}\n", now_micros()),
        )?;

        Ok(RotateReport {
            previous_log,
            new_log,
        })
    }

    pub fn rotate(&self) -> Result<RotateReport, JournaldError> {
        let report = self.rotate_active_log()?;
        let limits = StorageVacuumLimits::from_env();
        let active_root = report
            .new_log
            .parent()
            .unwrap_or_else(|| self.root())
            .to_path_buf();
        let _ = self.vacuum_root(
            active_root.as_path(),
            limits.max_use,
            limits.n_max_files,
            limits.max_use,
        )?;
        Ok(report)
    }

    pub(super) fn rotate_if_proactive_threshold_reached(&self) -> Result<(), JournaldError> {
        let policy = RotatePolicy::from_env();
        let active = self.active_log_path()?;
        let size_threshold_reached = policy
            .max_file_size
            .and_then(|max_file_size| {
                fs::metadata(&active)
                    .ok()
                    .map(|meta| meta.len() >= max_file_size)
            })
            .unwrap_or(false);
        let structural_rotation_suggested = open_journal_file_at(&active, false)
            .map(|journal| journal_file_rotate_suggested(&journal.header, None, now_micros_u64()))
            .unwrap_or(false);
        let should_rotate = size_threshold_reached || structural_rotation_suggested;
        if should_rotate {
            let _ = self.rotate()?;
        }
        Ok(())
    }

    pub fn relinquish_var(&self) -> Result<(), JournaldError> {
        if self.is_namespaced_instance() {
            return Ok(());
        }

        self.ensure_root()?;

        let persistent = self.persistent_storage_root();
        let status = match fs::metadata(&persistent) {
            Ok(metadata) if metadata.is_dir() => "present",
            Ok(_) => "not-a-directory",
            Err(err) if err.kind() == io::ErrorKind::NotFound => "missing",
            Err(err) => return Err(err.into()),
        };

        let contents = format!(
            "ts={}\npersistent_path={}\nstatus={}\n",
            now_micros(),
            persistent.display(),
            status
        );
        fs::write(self.marker_path(RELINQUISH_MARKER_NAME), contents)?;
        if self.configured_storage_mode() != StorageMode::None {
            let _ = self.active_or_create()?;
        }
        Ok(())
    }

    pub fn smart_relinquish_var(&self) -> Result<bool, JournaldError> {
        if self.is_namespaced_instance() {
            return Ok(false);
        }

        let persistent = self.persistent_storage_root();
        let should_relinquish = match fs::metadata(&persistent) {
            Ok(metadata) if metadata.is_dir() => fs::read_dir(&persistent)?.next().is_some(),
            Ok(_) => false,
            Err(err) if err.kind() == io::ErrorKind::NotFound => false,
            Err(err) => return Err(err.into()),
        };

        if should_relinquish {
            self.relinquish_var()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn vacuum_size(&self, limit: u64) -> Result<VacuumReport, JournaldError> {
        let state = self.storage_state();
        let Some(root) = state.active_root() else {
            return Err(JournaldError::InvalidArgument(
                "journald storage mode disables vacuuming".to_string(),
            ));
        };
        self.vacuum_root(root, limit, 0, limit)
    }

    pub(super) fn vacuum_root(
        &self,
        root: &Path,
        max_use: u64,
        n_max_files: u64,
        reported_limit: u64,
    ) -> Result<VacuumReport, JournaldError> {
        fs::create_dir_all(root)?;
        let now = now_micros_u64();
        let vacuum =
            journal_directory_vacuum(root, max_use, n_max_files, 0, now).map_err(|errno| {
                let code = if errno < 0 { -errno } else { errno };
                JournaldError::Io(io::Error::from_raw_os_error(code))
            })?;

        let removed_files = vacuum
            .deleted
            .iter()
            .map(|name| root.join(name))
            .collect::<Vec<_>>();
        let bytes_removed = vacuum.freed;
        let remaining_files = self.journal_file_paths_in(root)?;
        let bytes_remaining = self.total_size(remaining_files.iter())?;

        fs::write(
            self.marker_path("vacuumed"),
            format!(
                "ts={}\npath={}\nlimit={max_use}\nmax_files={n_max_files}\nremaining={bytes_remaining}\n",
                now_micros(),
                root.display(),
            ),
        )?;

        Ok(VacuumReport {
            removed_files,
            bytes_removed,
            bytes_remaining,
            limit: reported_limit,
        })
    }

    pub fn dump_catalog(&self) -> Result<String, JournaldError> {
        let mut catalog: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for path in self.journal_file_paths()? {
            let text = match render_journal_file_as_text(&path) {
                Ok(text) => text,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
            };

            for line in text.lines() {
                let Some((_, payload_hex)) = line.split_once("payload_hex=") else {
                    continue;
                };
                let payload_hex = payload_hex.split('|').next().unwrap_or(payload_hex);

                let payload = match hex_decode(payload_hex.trim()) {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };

                let text = String::from_utf8_lossy(&payload);
                if let Some(entry) = parse_catalog_payload(&text) {
                    catalog
                        .entry(entry.message_id)
                        .or_default()
                        .insert(entry.message);
                }
            }
        }

        let mut out = String::new();
        if catalog.is_empty() {
            out.push_str("catalog: empty\n");
            return Ok(out);
        }

        for (message_id, messages) in catalog {
            for message in messages {
                out.push_str(&format!("MESSAGE_ID={message_id} MESSAGE={message}\n"));
            }
        }

        Ok(out)
    }

    pub(super) fn next_rotation_index(&self, root: Option<&Path>) -> Result<u64, JournaldError> {
        let root = root.unwrap_or_else(|| self.root());
        let mut next = 1;
        for path in self.journal_file_paths_in(root)? {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if let Some((index, _)) = Self::archived_rotation_metadata(name) {
                    next = next.max(index + 1);
                } else if let Some(index) = Self::rotation_suffix(name) {
                    next = next.max(index + 1);
                }
            }
        }

        Ok(next)
    }

    pub(super) fn ensure_archive_minimum_size(&self, path: &Path) -> Result<(), JournaldError> {
        let size = file_size(path)?;
        if size >= JOURNAL_VACUUM_MIN_FILE_SIZE {
            return Ok(());
        }

        let mut file = OpenOptions::new().append(true).open(path)?;
        let pad = vec![b' '; (JOURNAL_VACUUM_MIN_FILE_SIZE - size) as usize];
        file.write_all(&pad)?;
        Ok(())
    }

    pub(super) fn touch_log_file_at(&self, path: &Path) -> Result<PathBuf, JournaldError> {
        let _ = self.open_or_create_journal_at(path)?;
        Ok(path.to_path_buf())
    }

    pub(super) fn total_size<'a, I>(&self, paths: I) -> Result<u64, JournaldError>
    where
        I: IntoIterator<Item = &'a PathBuf>,
    {
        let mut total = 0;
        for path in paths {
            total += file_size(path)?;
        }
        Ok(total)
    }
}

fn parse_catalog_payload(text: &str) -> Option<CatalogEntry> {
    let mut message_id = None;
    let mut message = None;

    for line in text.lines() {
        if let Some(value) = line.strip_prefix("MESSAGE_ID=") {
            message_id = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("MESSAGE=") {
            message = Some(value.trim().to_string());
        }
    }

    let message = message.or_else(|| text.lines().next().map(|line| line.trim().to_string()))?;
    let message_id = message_id.unwrap_or_else(|| {
        let preview = if message.is_empty() {
            "empty".to_string()
        } else {
            sanitize_preview(&message)
        };
        format!("payload:{preview}")
    });

    Some(CatalogEntry {
        message_id,
        message,
    })
}

struct CatalogEntry {
    message_id: String,
    message: String,
}

fn sanitize_preview(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '\n' | '\r' | '\t' => ' ',
            '|' | '%' => '_',
            _ => ch,
        })
        .take(64)
        .collect()
}

pub(super) fn display_path(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .map(|ch| match ch {
            '\n' | '\r' | '\t' => ' ',
            '|' | '%' => '_',
            _ => ch,
        })
        .collect()
}

pub(super) fn now_micros() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}

pub(super) fn now_micros_u64() -> u64 {
    now_micros().min(u64::MAX as u128) as u64
}

fn file_size(path: &Path) -> Result<u64, JournaldError> {
    Ok(fs::metadata(path)?.len())
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, JournaldError> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err(JournaldError::InvalidArgument(format!(
            "invalid hex payload length: {text}"
        )));
    }

    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out.push((hi << 4) | lo);
    }

    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, JournaldError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(JournaldError::InvalidArgument(format!(
            "invalid hex digit: {}",
            byte as char
        ))),
    }
}
