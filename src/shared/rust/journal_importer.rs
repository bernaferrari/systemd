// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/journal-importer.c, src/shared/journal-importer.h
//
// Journal entry importer — reads and parses journal entries from streams.
//
// Supports two modes:
// - Active (fd-based): reads directly from a file descriptor using std::io::Read.
// - Passive (push-based): data is supplied externally via push_data().
//
// Entries are line-based text fields (KEY=VALUE\n) or binary fields
// (FIELDNAME\n followed by a little-endian u64 size, binary data, and \n).
// Empty lines (\n) mark entry boundaries.

use crate::journal_field::journal_field_valid as validate_journal_field;
use std::io::{self, Read};

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum total size of a single journal entry (all fields combined).
pub const ENTRY_SIZE_MAX: usize = 1024 * 1024 * 770;

/// Maximum entry size for unprivileged users.
pub const ENTRY_SIZE_UNPRIV_MAX: usize = 1024 * 1024 * 32;

/// Maximum size of a single field's data payload.
pub const DATA_SIZE_MAX: usize = 1024 * 1024 * 768;

/// Buffer growth chunk size for line reading.
pub const LINE_CHUNK: usize = 8 * 1024;

/// Maximum number of fields in a single journal entry.
pub const ENTRY_FIELD_COUNT_MAX: usize = 1024;

const USEC_INFINITY: u64 = u64::MAX;
const REALTIME_THRESHOLD: u64 = 1;

// ── Error types ───────────────────────────────────────────────────────────

/// Errors that can occur during journal import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImporterError {
    /// I/O error reading from the source.
    Io(String),
    /// Entry exceeds maximum allowed size.
    EntryTooLarge(usize),
    /// Binary field data size exceeds DATA_SIZE_MAX.
    DataSizeExceeded(u64),
    /// Entry contains more fields than the journal format permits.
    TooManyFields,
    /// Expected a newline terminator after binary data.
    ExpectedNewline(u8),
    /// Failed to parse a timestamp value.
    InvalidTimestamp(String),
    /// Timestamp is syntactically valid but out of range.
    TimestampOutOfRange(String),
    /// Invalid field name.
    InvalidFieldName(String),
    /// Cannot read more data in passive mode; caller must push_data().
    WouldBlock,
    /// Importer has reached end-of-stream.
    Eof,
    /// Out of memory.
    OutOfMemory,
}

impl std::fmt::Display for ImporterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::EntryTooLarge(size) => {
                write!(f, "Entry size {size} exceeds maximum {DATA_SIZE_MAX}")
            }
            Self::DataSizeExceeded(size) => {
                write!(
                    f,
                    "Field data size {size} exceeds DATA_SIZE_MAX ({DATA_SIZE_MAX})"
                )
            }
            Self::TooManyFields => {
                write!(f, "Entry exceeds {ENTRY_FIELD_COUNT_MAX} fields")
            }
            Self::ExpectedNewline(byte) => {
                write!(f, "Expected newline after binary data, got 0x{byte:02x}")
            }
            Self::InvalidTimestamp(msg) => write!(f, "Invalid timestamp: {msg}"),
            Self::TimestampOutOfRange(msg) => write!(f, "Timestamp out of range: {msg}"),
            Self::InvalidFieldName(name) => write!(f, "Invalid field name: {name}"),
            Self::WouldBlock => write!(f, "Would block (passive mode)"),
            Self::Eof => write!(f, "End of stream"),
            Self::OutOfMemory => write!(f, "Out of memory"),
        }
    }
}

impl std::error::Error for ImporterError {}

impl From<io::Error> for ImporterError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ── Result type ───────────────────────────────────────────────────────────

/// Result alias for importer operations.
pub type ImporterResult<T> = Result<T, ImporterError>;

// ── Timestamp ─────────────────────────────────────────────────────────────

/// Dual timestamp with realtime and monotonic components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualTimestamp {
    pub realtime: u64,
    pub monotonic: u64,
}

impl Default for DualTimestamp {
    fn default() -> Self {
        Self {
            realtime: USEC_INFINITY,
            monotonic: USEC_INFINITY,
        }
    }
}

impl DualTimestamp {
    /// Create a timestamp with both components set to zero.
    pub fn zero() -> Self {
        Self {
            realtime: 0,
            monotonic: 0,
        }
    }
}

/// Check if a realtime timestamp is valid (non-zero and not infinity).
pub fn valid_realtime(t: u64) -> bool {
    t >= REALTIME_THRESHOLD && t < USEC_INFINITY
}

/// Check if a monotonic timestamp is valid (not infinity).
pub fn valid_monotonic(t: u64) -> bool {
    t < USEC_INFINITY
}

// ── Importer state ────────────────────────────────────────────────────────

/// Internal state machine for the journal importer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImporterState {
    /// Waiting to read, or reading a text line.
    Line = 0,
    /// Reading binary data size header (8-byte LE u64).
    DataStart = 1,
    /// Reading binary field data payload.
    Data = 2,
    /// Expecting newline terminator after binary data.
    DataFinish = 3,
    /// Stream has been fully consumed.
    Eof = 4,
}

impl Default for ImporterState {
    fn default() -> Self {
        Self::Line
    }
}

// ── Process result ────────────────────────────────────────────────────────

/// Result of processing one step of the import state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessResult {
    /// An entry is complete (empty line was received). Fields are ready.
    EntryReady,
    /// More data needs to be processed (continue calling process_data()).
    Continue,
    /// End of stream reached.
    Eof,
    /// A text field was accepted. Contains opaque `(field_name, field_value)` bytes.
    ///
    /// Journal export fields are not UTF-8 strings. In particular, a text field
    /// may contain NUL or non-UTF-8 bytes after its `=` separator.
    FieldAccepted(Vec<u8>, Vec<u8>),
    /// A special/meta field was handled (cursor, seqnum, timestamps, etc.).
    FieldIgnored,
    /// A binary field header was received. State is now DataStart.
    BinaryFieldStart(Vec<u8>),
    /// Binary field data was received and assembled.
    BinaryFieldComplete(Vec<u8>, Vec<u8>),
}

// ── Journal Importer ──────────────────────────────────────────────────────

/// Journal entry importer that parses the journal export format.
///
/// The journal export format consists of:
/// - Text fields: `FIELD_NAME=value\n`
/// - Binary fields: `FIELD_NAME\n` + LE u64 size + raw bytes + `\n`
/// - Entry separator: empty line `\n`
///
/// Two usage modes:
/// - **Active mode**: reads from an `impl Read` (e.g., `File`, `TcpStream`).
/// - **Passive mode**: external code pushes data via `push_data()`.
#[derive(Debug)]
pub struct JournalImporter<R: Read> {
    /// The data source reader. In passive mode this is not used.
    reader: Option<R>,
    /// If true, the importer does not attempt to read from the source.
    passive_fd: bool,
    /// Optional human-readable name for logging/debugging.
    name: Option<String>,

    /// Internal buffer for accumulated data.
    buf: Vec<u8>,
    /// Offset to the start of unprocessed data in the buffer.
    offset: usize,
    /// Number of bytes scanned since the last newline.
    scanned: usize,
    /// Total number of valid bytes in the buffer.
    filled: usize,

    /// Name of the current binary field. Keeping this separately avoids
    /// reconstructing it from mutable buffer offsets.
    field_name: Option<Vec<u8>>,
    /// Size of the binary data payload being read.
    data_size: u64,

    /// Current state machine state.
    state: ImporterState,
    /// Parsed timestamps from special fields.
    ts: DualTimestamp,
    /// Boot ID from the `_BOOT_ID=` field.
    boot_id: Option<[u8; 16]>,
    /// Pending binary field assembled in Data state, delivered in DataFinish state.
    pending_binary_field: Option<(Vec<u8>, Vec<u8>)>,
    /// Number and encoded size of accepted fields in the current entry.
    entry_field_count: usize,
    entry_data_size: usize,
}

impl<R: Read> JournalImporter<R> {
    /// Create a new active-mode importer that reads from the given source.
    pub fn new(reader: R) -> Self {
        Self {
            reader: Some(reader),
            passive_fd: false,
            name: None,
            buf: Vec::new(),
            offset: 0,
            scanned: 0,
            filled: 0,
            field_name: None,
            data_size: 0,
            state: ImporterState::Line,
            ts: DualTimestamp::default(),
            boot_id: None,
            pending_binary_field: None,
            entry_field_count: 0,
            entry_data_size: 0,
        }
    }

    /// Create a new passive-mode importer where data must be pushed externally.
    /// No reader is used; `push_data()` must be called to supply input.
    pub fn new_passive() -> Self {
        Self {
            reader: None,
            passive_fd: true,
            name: None,
            buf: Vec::new(),
            offset: 0,
            scanned: 0,
            filled: 0,
            field_name: None,
            data_size: 0,
            state: ImporterState::Line,
            ts: DualTimestamp::default(),
            boot_id: None,
            pending_binary_field: None,
            entry_field_count: 0,
            entry_data_size: 0,
        }
    }

    /// Set a human-readable name for this importer (for diagnostics).
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    /// Get the current importer state.
    pub fn state(&self) -> ImporterState {
        self.state
    }

    /// Check if the importer has reached end-of-stream.
    pub fn is_eof(&self) -> bool {
        self.state == ImporterState::Eof
    }

    /// Get the parsed dual timestamp.
    pub fn timestamp(&self) -> DualTimestamp {
        self.ts
    }

    /// Get the parsed boot ID, if any.
    pub fn boot_id(&self) -> Option<[u8; 16]> {
        self.boot_id
    }

    /// Get the number of bytes remaining in the internal buffer.
    pub fn bytes_remaining(&self) -> usize {
        self.filled
    }

    // ── Internal buffer management ──────────────────────────────────────

    /// Ensure the buffer has room for `needed` initialized bytes.
    fn ensure_capacity(&mut self, needed: usize) -> ImporterResult<()> {
        if needed > ENTRY_SIZE_MAX {
            return Err(ImporterError::EntryTooLarge(needed));
        }
        let current_cap = self.buf.len();
        if current_cap >= needed {
            return Ok(());
        }
        let additional = needed - current_cap;
        // Grow in LINE_CHUNK-sized increments, without exceeding the maximum
        // buffer size accepted by the C importer.
        let grow = additional.max(LINE_CHUNK).min(ENTRY_SIZE_MAX - current_cap);
        self.buf
            .try_reserve(grow)
            .map_err(|_| ImporterError::OutOfMemory)?;
        self.buf.resize(needed, 0);
        Ok(())
    }

    /// Read more data from the reader into the buffer.
    /// Returns the number of bytes read, 0 on EOF, or error.
    fn read_more(&mut self) -> ImporterResult<usize> {
        if self.passive_fd {
            return Err(ImporterError::WouldBlock);
        }
        if self.filled >= ENTRY_SIZE_MAX {
            return Err(ImporterError::EntryTooLarge(self.filled));
        }

        let min_cap = self
            .filled
            .checked_add(LINE_CHUNK)
            .map_or(ENTRY_SIZE_MAX, |size| size.min(ENTRY_SIZE_MAX));
        self.ensure_capacity(min_cap)?;

        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| ImporterError::Io("no reader available".into()))?;

        let available = self.buf.len() - self.filled;
        let n = reader.read(&mut self.buf[self.filled..self.filled + available])?;
        self.filled += n;
        Ok(n)
    }

    /// Consume the buffer, moving unprocessed data to the front and
    /// optionally shrinking the allocation.
    fn compact_buffer(&mut self) {
        let remain = self.filled - self.offset;
        if remain == 0 {
            self.offset = 0;
            self.scanned = 0;
            self.filled = 0;
        } else if self.offset > self.buf.len().saturating_sub(self.filled) && self.offset > remain {
            self.buf.copy_within(self.offset..self.filled, 0);
            self.offset = 0;
            self.scanned = 0;
            self.filled = remain;
        }

        // Shrink buffer if filled is less than half the capacity.
        let mut target = self.buf.len();
        while target > 16 * LINE_CHUNK && self.filled < target / 2 {
            target /= 2;
        }
        if target < self.buf.len() {
            self.buf.shrink_to(target);
        }
    }

    // ── Line reading ───────────────────────────────────────────────────

    /// Scan for a newline in the already-buffered data starting from `start`.
    /// Returns the offset of the newline relative to the buffer start, or None.
    fn find_newline(&self, start: usize) -> Option<usize> {
        self.buf[start..self.filled]
            .iter()
            .position(|&b| b == b'\n')
            .map(|pos| start + pos)
    }

    /// Read a complete line from the buffer (or from the reader).
    /// Returns the line slice (including the trailing newline) and its length.
    fn get_line(&mut self) -> ImporterResult<Option<(&[u8], usize)>> {
        loop {
            let start = self.scanned.max(self.offset);

            if let Some(nl_pos) = self.find_newline(start) {
                let line = &self.buf[self.offset..nl_pos + 1];
                let size = nl_pos + 1 - self.offset;
                self.offset += size;
                return Ok(Some((line, size)));
            }

            self.scanned = self.filled;
            if self.scanned >= DATA_SIZE_MAX {
                return Err(ImporterError::EntryTooLarge(DATA_SIZE_MAX));
            }

            match self.read_more() {
                Ok(0) => return Ok(None), // EOF
                Ok(_) => continue,
                Err(ImporterError::WouldBlock) => return Err(ImporterError::WouldBlock),
                Err(e) => return Err(e),
            }
        }
    }

    // ── Fixed-size reading ─────────────────────────────────────────────

    /// Ensure exactly `size` bytes are available starting at `self.offset`.
    /// Returns a slice to the data on success.
    fn fill_fixed_size(&mut self, size: usize) -> ImporterResult<Option<&[u8]>> {
        loop {
            if self.filled - self.offset >= size {
                let data = &self.buf[self.offset..self.offset + size];
                self.offset += size;
                return Ok(Some(data));
            }

            if self.passive_fd {
                return Err(ImporterError::WouldBlock);
            }

            // Ensure buffer has room.
            let needed = self
                .offset
                .checked_add(size)
                .ok_or(ImporterError::EntryTooLarge(ENTRY_SIZE_MAX))?;
            self.ensure_capacity(needed)?;

            match self.read_more() {
                Ok(0) => return Ok(None), // EOF
                Ok(_) => continue,
                Err(ImporterError::WouldBlock) => return Err(ImporterError::WouldBlock),
                Err(e) => return Err(e),
            }
        }
    }

    /// Read the 8-byte little-endian data size for a binary field.
    fn get_data_size(&mut self) -> ImporterResult<Option<u64>> {
        let data = match self.fill_fixed_size(8)? {
            Some(d) => d,
            None => return Ok(None),
        };

        let size = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if size > DATA_SIZE_MAX as u64 {
            return Err(ImporterError::DataSizeExceeded(size));
        }

        Ok(Some(size))
    }

    /// Read the binary data payload.
    fn get_data_data(&mut self, size: u64) -> ImporterResult<Option<Vec<u8>>> {
        let data = match self.fill_fixed_size(size as usize)? {
            Some(d) => d,
            None => return Ok(None),
        };
        Ok(Some(data.to_vec()))
    }

    /// Verify the trailing newline after binary data.
    fn get_data_newline(&mut self) -> ImporterResult<()> {
        let data = match self.fill_fixed_size(1)? {
            Some(d) => d,
            None => {
                self.state = ImporterState::Eof;
                return Err(ImporterError::Eof);
            }
        };

        if data[0] != b'\n' {
            return Err(ImporterError::ExpectedNewline(data[0]));
        }

        Ok(())
    }

    // ── Special field processing ───────────────────────────────────────

    /// Process special/meta fields that affect importer state.
    ///
    /// Returns:
    /// - `Ok(Some(ProcessResult::FieldIgnored))` if the field was consumed
    ///   as a special field and should not be stored.
    /// - `Ok(None)` if the field is not special and should be stored normally.
    /// - `Err` on parse errors.
    fn process_special_field(&mut self, line: &[u8]) -> ImporterResult<Option<ProcessResult>> {
        // Fields we silently ignore — cannot be replicated on the receiving side.
        if line.starts_with(b"__CURSOR=")
            || line.starts_with(b"__SEQNUM=")
            || line.starts_with(b"__SEQNUM_ID=")
        {
            return Ok(Some(ProcessResult::FieldIgnored));
        }

        // __REALTIME_TIMESTAMP=<usec>
        if let Some(value) = line.strip_prefix(b"__REALTIME_TIMESTAMP=") {
            let x = parse_decimal_u64(value).ok_or_else(|| {
                ImporterError::InvalidTimestamp("invalid __REALTIME_TIMESTAMP".into())
            })?;
            if !valid_realtime(x) {
                return Err(ImporterError::TimestampOutOfRange(
                    "__REALTIME_TIMESTAMP out of range".into(),
                ));
            }
            self.ts.realtime = x;
            return Ok(Some(ProcessResult::FieldIgnored));
        }

        // __MONOTONIC_TIMESTAMP=<usec>
        if let Some(value) = line.strip_prefix(b"__MONOTONIC_TIMESTAMP=") {
            let x = parse_decimal_u64(value).ok_or_else(|| {
                ImporterError::InvalidTimestamp("invalid __MONOTONIC_TIMESTAMP".into())
            })?;
            if !valid_monotonic(x) {
                return Err(ImporterError::TimestampOutOfRange(
                    "__MONOTONIC_TIMESTAMP out of range".into(),
                ));
            }
            self.ts.monotonic = x;
            return Ok(Some(ProcessResult::FieldIgnored));
        }

        // _BOOT_ID=<uuid-string> — store the boot ID but still save the field.
        if let Some(value) = line.strip_prefix(b"_BOOT_ID=") {
            self.boot_id = Some(parse_boot_id(value)?);
            // Return None so the field is stored in the normal fashion.
            return Ok(None);
        }

        // Any other __-prefixed field is unknown — ignore it.
        if line.starts_with(b"__") {
            return Ok(Some(ProcessResult::FieldIgnored));
        }

        // Not a special field.
        Ok(None)
    }

    // ── Binary field assembly ──────────────────────────────────────────

    /// Assemble the C-compatible iovec payload for a binary field:
    /// `field_name`, `=`, then the opaque payload. The length prefix and
    /// trailing newline are framing and are deliberately not part of it.
    fn assemble_binary_field(field_name: &[u8], data: &[u8]) -> ImporterResult<Vec<u8>> {
        let field_size = field_name
            .len()
            .checked_add(1)
            .and_then(|size| size.checked_add(data.len()))
            .ok_or(ImporterError::EntryTooLarge(ENTRY_SIZE_MAX))?;
        if field_size > ENTRY_SIZE_MAX {
            return Err(ImporterError::EntryTooLarge(field_size));
        }

        let mut result = Vec::new();
        result
            .try_reserve_exact(field_size)
            .map_err(|_| ImporterError::OutOfMemory)?;
        result.extend_from_slice(field_name);
        result.push(b'=');
        result.extend_from_slice(data);
        Ok(result)
    }

    /// Account for one DATA object and its entry-array offset/trailer bytes.
    fn register_field(&mut self, field_size: usize) -> ImporterResult<()> {
        let field_count = self
            .entry_field_count
            .checked_add(1)
            .ok_or(ImporterError::TooManyFields)?;
        if field_count > ENTRY_FIELD_COUNT_MAX {
            return Err(ImporterError::TooManyFields);
        }

        let data_size = self
            .entry_data_size
            .checked_add(field_size)
            .ok_or(ImporterError::EntryTooLarge(ENTRY_SIZE_MAX))?;
        let encoded_size = data_size
            .checked_add(field_count)
            .and_then(|size| size.checked_add(1))
            .ok_or(ImporterError::EntryTooLarge(ENTRY_SIZE_MAX))?;
        if encoded_size > ENTRY_SIZE_MAX {
            return Err(ImporterError::EntryTooLarge(encoded_size));
        }

        self.entry_field_count = field_count;
        self.entry_data_size = data_size;
        Ok(())
    }

    // ── State machine ──────────────────────────────────────────────────

    /// Process one step of the import state machine.
    ///
    /// Call this repeatedly until it returns `EntryReady`, `Eof`, or an error.
    /// Between calls (especially when `WouldBlock` is returned in passive mode),
    /// call `push_data()` to supply more input.
    pub fn process_data(&mut self) -> ImporterResult<ProcessResult> {
        match self.state {
            ImporterState::Line => {
                debug_assert_eq!(self.data_size, 0);
                self.process_line_state()
            }
            ImporterState::DataStart => {
                debug_assert_eq!(self.data_size, 0);
                self.process_data_start_state()
            }
            ImporterState::Data => self.process_data_state(),
            ImporterState::DataFinish => self.process_data_finish_state(),
            ImporterState::Eof => Ok(ProcessResult::Eof),
        }
    }

    fn process_line_state(&mut self) -> ImporterResult<ProcessResult> {
        let (n, line_data) = {
            let (line_bytes, n) = match self.get_line()? {
                Some(result) => result,
                None => {
                    self.state = ImporterState::Eof;
                    return Ok(ProcessResult::Eof);
                }
            };
            debug_assert!(n > 0);
            debug_assert_eq!(line_bytes[n - 1], b'\n');
            (n, line_bytes.to_vec())
        };

        if n == 1 {
            return Ok(ProcessResult::EntryReady);
        }

        if let Some(sep_pos) = line_data.iter().position(|&b| b == b'=') {
            let field_name = &line_data[..sep_pos];

            if !validate_journal_field(field_name, true) {
                return Ok(ProcessResult::Continue);
            }

            let field = &line_data[..n - 1];
            match self.process_special_field(field)? {
                Some(result) => return Ok(result),
                None => {
                    self.register_field(n - 1)?;
                    return Ok(ProcessResult::FieldAccepted(
                        field_name.to_vec(),
                        line_data[sep_pos + 1..n - 1].to_vec(),
                    ));
                }
            }
        } else {
            let field_name = &line_data[..n - 1];

            if !validate_journal_field(field_name, true) {
                return Ok(ProcessResult::Continue);
            }

            self.field_name = Some(field_name.to_vec());
            self.state = ImporterState::DataStart;

            Ok(ProcessResult::Continue)
        }
    }

    fn process_data_start_state(&mut self) -> ImporterResult<ProcessResult> {
        debug_assert_eq!(self.data_size, 0);

        let size = match self.get_data_size()? {
            Some(s) => s,
            None => {
                self.state = ImporterState::Eof;
                return Ok(ProcessResult::Eof);
            }
        };

        self.data_size = size;

        // If data_size is zero, skip directly to expecting the newline.
        self.state = if size > 0 {
            ImporterState::Data
        } else {
            ImporterState::DataFinish
        };

        Ok(ProcessResult::Continue)
    }

    fn process_data_state(&mut self) -> ImporterResult<ProcessResult> {
        debug_assert!(self.data_size > 0);

        let data: Vec<u8> = match self.get_data_data(self.data_size)? {
            Some(d) => d.to_vec(),
            None => {
                self.state = ImporterState::Eof;
                return Ok(ProcessResult::Eof);
            }
        };

        let field_name = self.field_name.clone().ok_or_else(|| {
            ImporterError::Io("binary payload received without a field name".into())
        })?;
        let assembled = Self::assemble_binary_field(&field_name, &data)?;
        self.register_field(assembled.len())?;
        self.state = ImporterState::DataFinish;

        // Store the assembled field for retrieval.
        self.pending_binary_field = Some((field_name, assembled));

        Ok(ProcessResult::Continue)
    }

    fn process_data_finish_state(&mut self) -> ImporterResult<ProcessResult> {
        match self.get_data_newline() {
            Ok(()) => {
                if let Some((name, data)) = self.pending_binary_field.take() {
                    self.data_size = 0;
                    self.field_name = None;
                    self.state = ImporterState::Line;
                    Ok(ProcessResult::BinaryFieldComplete(name, data))
                } else if self.field_name.take().is_some() {
                    // journal-importer.c warns about a zero-length binary
                    // field but does not add it to the iovec.
                    self.data_size = 0;
                    self.state = ImporterState::Line;
                    Ok(ProcessResult::Continue)
                } else {
                    self.data_size = 0;
                    self.state = ImporterState::Line;
                    Ok(ProcessResult::Continue)
                }
            }
            Err(ImporterError::Eof) => {
                self.state = ImporterState::Eof;
                Ok(ProcessResult::Eof)
            }
            Err(e) => Err(e),
        }
    }
}

impl<R: Read> JournalImporter<R> {
    /// Push external data into the importer's buffer (for passive mode).
    ///
    /// After pushing data, call `process_data()` to process it.
    pub fn push_data(&mut self, data: &[u8]) -> ImporterResult<()> {
        if self.state == ImporterState::Eof {
            return Err(ImporterError::Eof);
        }

        let new_filled = self
            .filled
            .checked_add(data.len())
            .ok_or(ImporterError::EntryTooLarge(ENTRY_SIZE_MAX))?;
        self.ensure_capacity(new_filled)?;

        self.buf[self.filled..self.filled + data.len()].copy_from_slice(data);
        self.filled = new_filled;

        Ok(())
    }

    /// Drop processed data and compact the buffer.
    ///
    /// Call this after consuming all fields from a completed entry.
    pub fn drop_iovw(&mut self) {
        self.compact_buffer();
        self.entry_field_count = 0;
        self.entry_data_size = 0;
    }
}

/// Placeholder struct for passive importers (no reader).
/// Use `JournalImporter::new_passive()` with a `std::io::Empty` reader,
/// or use the `PassiveJournalImporter` type alias below.
impl JournalImporter<std::io::Empty> {
    /// Convenience constructor for passive-mode importers.
    pub fn new_passive_empty() -> Self {
        Self::new_passive()
    }
}

/// Parse canonical decimal syntax without converting opaque journal data to
/// UTF-8. This has the same deliberately strict, fail-closed behavior needed
/// for journal metadata fields.
fn parse_decimal_u64(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }

    value.iter().try_fold(0u64, |number, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        number.checked_mul(10)?.checked_add(u64::from(*byte - b'0'))
    })
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parse the exact identifier forms accepted by `sd_id128_from_string()`:
/// 32 hexadecimal bytes, or a UUID with dashes at 8/13/18/23.
fn parse_boot_id(value: &[u8]) -> ImporterResult<[u8; 16]> {
    let plain = match value.len() {
        32 => value,
        36 if [8, 13, 18, 23].iter().all(|&index| value[index] == b'-') => {
            // A fixed-size local buffer avoids accepting dashes in arbitrary
            // positions and keeps the conversion entirely byte based.
            let mut compact = [0u8; 32];
            let mut source = 0;
            let mut target = 0;
            while source < value.len() {
                if value[source] != b'-' {
                    compact[target] = value[source];
                    target += 1;
                }
                source += 1;
            }
            return parse_boot_id(&compact);
        }
        _ => return Err(ImporterError::InvalidFieldName("invalid _BOOT_ID".into())),
    };

    let mut result = [0u8; 16];
    for (index, output) in result.iter_mut().enumerate() {
        let high = hex_value(plain[index * 2])
            .ok_or_else(|| ImporterError::InvalidFieldName("invalid _BOOT_ID".into()))?;
        let low = hex_value(plain[index * 2 + 1])
            .ok_or_else(|| ImporterError::InvalidFieldName("invalid _BOOT_ID".into()))?;
        *output = (high << 4) | low;
    }
    Ok(result)
}

/// Validate a realtime timestamp value.
pub fn validate_realtime_timestamp(value: &str) -> ImporterResult<u64> {
    let x = parse_decimal_u64(value.as_bytes())
        .ok_or_else(|| ImporterError::InvalidTimestamp(format!("'{value}'")))?;
    if !valid_realtime(x) {
        return Err(ImporterError::TimestampOutOfRange(format!("realtime {x}")));
    }
    Ok(x)
}

/// Validate a monotonic timestamp value.
pub fn validate_monotonic_timestamp(value: &str) -> ImporterResult<u64> {
    let x = parse_decimal_u64(value.as_bytes())
        .ok_or_else(|| ImporterError::InvalidTimestamp(format!("'{value}'")))?;
    if !valid_monotonic(x) {
        return Err(ImporterError::TimestampOutOfRange(format!("monotonic {x}")));
    }
    Ok(x)
}

/// Parse a special field and return its effect.
/// This is a standalone function useful for testing without a full importer.
pub fn parse_special_field(line: &str) -> SpecialFieldResult {
    if line.starts_with("__CURSOR=")
        || line.starts_with("__SEQNUM=")
        || line.starts_with("__SEQNUM_ID=")
    {
        return SpecialFieldResult::Ignored;
    }

    if let Some(value) = line.strip_prefix("__REALTIME_TIMESTAMP=") {
        return match validate_realtime_timestamp(value) {
            Ok(x) => SpecialFieldResult::RealtimeTimestamp(x),
            Err(_) => SpecialFieldResult::Error,
        };
    }

    if let Some(value) = line.strip_prefix("__MONOTONIC_TIMESTAMP=") {
        return match validate_monotonic_timestamp(value) {
            Ok(x) => SpecialFieldResult::MonotonicTimestamp(x),
            Err(_) => SpecialFieldResult::Error,
        };
    }

    if let Some(value) = line.strip_prefix("_BOOT_ID=") {
        return match parse_boot_id(value.as_bytes()) {
            Ok(id) => SpecialFieldResult::BootId(id),
            Err(_) => SpecialFieldResult::Error,
        };
    }

    if line.starts_with("__") {
        return SpecialFieldResult::Ignored;
    }

    SpecialFieldResult::NotSpecial
}

/// Result of parsing a special/meta field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialFieldResult {
    /// Field is not special — should be stored normally.
    NotSpecial,
    /// Field was consumed as a meta field and should be ignored.
    Ignored,
    /// Field contained a valid realtime timestamp.
    RealtimeTimestamp(u64),
    /// Field contained a valid monotonic timestamp.
    MonotonicTimestamp(u64),
    /// Field contained a boot ID.
    BootId([u8; 16]),
    /// Parse error.
    Error,
}

// ── Helper: cursor escape for display ────────────────────────────────────

/// Escape a single byte for display (replaces C's cescape_char).
/// Returns a short string representation.
pub fn cescape_byte(b: u8) -> String {
    match b {
        b'\\' => r"\\".into(),
        b'"' => r#"\""#.into(),
        b'\n' => r"\n".into(),
        b'\r' => r"\r".into(),
        b'\t' => r"\t".into(),
        0 => r"\0".into(),
        c if c < b' ' || c == 0x7f => format!("\\x{c:02x}"),
        c => (c as char).to_string(),
    }
}

/// Escape a byte slice for display (replaces C's cellescape).
pub fn cellescape(data: &[u8], max_len: usize) -> String {
    let mut out = String::new();
    for &b in data.iter().take(max_len) {
        out.push_str(&cescape_byte(b));
        if out.len() >= max_len {
            break;
        }
    }
    out
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn text_field(name: &[u8], value: &[u8]) -> ProcessResult {
        ProcessResult::FieldAccepted(name.to_vec(), value.to_vec())
    }

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert!(ENTRY_SIZE_MAX > DATA_SIZE_MAX);
        assert!(DATA_SIZE_MAX < ENTRY_SIZE_MAX);
        assert!(ENTRY_SIZE_UNPRIV_MAX < ENTRY_SIZE_MAX);
        assert_eq!(LINE_CHUNK, 8 * 1024);
        assert_eq!(ENTRY_FIELD_COUNT_MAX, 1024);
        assert!(DATA_SIZE_MAX < ENTRY_SIZE_MAX);
    }

    #[test]
    fn test_importer_state_values() {
        assert_eq!(ImporterState::Line as i32, 0);
        assert_eq!(ImporterState::DataStart as i32, 1);
        assert_eq!(ImporterState::Data as i32, 2);
        assert_eq!(ImporterState::DataFinish as i32, 3);
        assert_eq!(ImporterState::Eof as i32, 4);
    }

    #[test]
    fn test_importer_state_default() {
        assert_eq!(ImporterState::default(), ImporterState::Line);
    }

    // ── Timestamp validation ──────────────────────────────────────────

    #[test]
    fn test_valid_realtime() {
        assert!(valid_realtime(1));
        assert!(valid_realtime(1000000));
        assert!(valid_realtime(u64::MAX - 1));
        assert!(!valid_realtime(0));
        assert!(!valid_realtime(u64::MAX)); // USEC_INFINITY
    }

    #[test]
    fn test_valid_monotonic() {
        assert!(valid_monotonic(0));
        assert!(valid_monotonic(1000000));
        assert!(!valid_monotonic(u64::MAX)); // USEC_INFINITY
    }

    #[test]
    fn test_dual_timestamp_default() {
        let ts = DualTimestamp::default();
        assert_eq!(ts.realtime, u64::MAX);
        assert_eq!(ts.monotonic, u64::MAX);
    }

    #[test]
    fn test_dual_timestamp_zero() {
        let ts = DualTimestamp::zero();
        assert_eq!(ts.realtime, 0);
        assert_eq!(ts.monotonic, 0);
    }

    #[test]
    fn test_validate_realtime_timestamp() {
        assert_eq!(validate_realtime_timestamp("12345").unwrap(), 12345);
        assert!(validate_realtime_timestamp("0").is_err());
        assert!(validate_realtime_timestamp("abc").is_err());
    }

    #[test]
    fn test_validate_monotonic_timestamp() {
        assert_eq!(validate_monotonic_timestamp("0").unwrap(), 0);
        assert_eq!(validate_monotonic_timestamp("98765").unwrap(), 98765);
        assert!(validate_monotonic_timestamp("abc").is_err());
    }

    #[test]
    fn test_entry_field_count_limit_is_enforced() {
        let mut importer = JournalImporter::<std::io::Empty>::new_passive();
        importer.entry_field_count = ENTRY_FIELD_COUNT_MAX;
        assert_eq!(
            importer.register_field(1),
            Err(ImporterError::TooManyFields)
        );
    }

    #[test]
    fn test_drop_iovw_resets_entry_accounting() {
        let mut importer = JournalImporter::<std::io::Empty>::new_passive();
        importer.register_field(8).unwrap();
        importer.drop_iovw();
        assert_eq!(importer.entry_field_count, 0);
        assert_eq!(importer.entry_data_size, 0);
    }

    // ── Special field parsing ─────────────────────────────────────────

    #[test]
    fn test_parse_special_field_cursor() {
        assert_eq!(
            parse_special_field("__CURSOR=some-cursor-value"),
            SpecialFieldResult::Ignored
        );
    }

    #[test]
    fn test_parse_special_field_seqnum() {
        assert_eq!(
            parse_special_field("__SEQNUM=42"),
            SpecialFieldResult::Ignored
        );
        assert_eq!(
            parse_special_field("__SEQNUM_ID=abc"),
            SpecialFieldResult::Ignored
        );
    }

    #[test]
    fn test_parse_special_field_realtime() {
        assert_eq!(
            parse_special_field("__REALTIME_TIMESTAMP=12345"),
            SpecialFieldResult::RealtimeTimestamp(12345)
        );
        // Invalid value
        assert_eq!(
            parse_special_field("__REALTIME_TIMESTAMP=notanumber"),
            SpecialFieldResult::Error
        );
        // Zero is invalid for realtime
        assert_eq!(
            parse_special_field("__REALTIME_TIMESTAMP=0"),
            SpecialFieldResult::Error
        );
    }

    #[test]
    fn test_parse_special_field_monotonic() {
        assert_eq!(
            parse_special_field("__MONOTONIC_TIMESTAMP=67890"),
            SpecialFieldResult::MonotonicTimestamp(67890)
        );
        // Zero is valid for monotonic
        assert_eq!(
            parse_special_field("__MONOTONIC_TIMESTAMP=0"),
            SpecialFieldResult::MonotonicTimestamp(0)
        );
    }

    #[test]
    fn test_parse_special_field_boot_id() {
        let result = parse_special_field("_BOOT_ID=1234567890abcdef1234567890abcdef");
        assert_eq!(
            result,
            SpecialFieldResult::BootId(parse_boot_id(b"1234567890abcdef1234567890abcdef").unwrap())
        );
        assert!(matches!(result, SpecialFieldResult::BootId(_)));
    }

    #[test]
    fn test_parse_special_field_unknown_dunder() {
        assert_eq!(
            parse_special_field("__UNKNOWN_FIELD=value"),
            SpecialFieldResult::Ignored
        );
    }

    #[test]
    fn test_parse_special_field_not_special() {
        assert_eq!(
            parse_special_field("MESSAGE=hello"),
            SpecialFieldResult::NotSpecial
        );
        assert_eq!(
            parse_special_field("_COMM=systemd"),
            SpecialFieldResult::NotSpecial
        );
    }

    // ── Escape utilities ──────────────────────────────────────────────

    #[test]
    fn test_cescape_byte() {
        assert_eq!(cescape_byte(b'\\'), r"\\");
        assert_eq!(cescape_byte(b'\n'), r"\n");
        assert_eq!(cescape_byte(b'\t'), r"\t");
        assert_eq!(cescape_byte(b'\r'), r"\r");
        assert_eq!(cescape_byte(0), r"\0");
        assert_eq!(cescape_byte(b'a'), "a");
    }

    #[test]
    fn test_cellescape() {
        assert_eq!(cellescape(b"hello", 64), "hello");
        assert_eq!(cellescape(b"he\nllo", 64), "he\\nllo");
        assert_eq!(cellescape(b"ab", 3), "ab");
        assert_eq!(cellescape(b"abcd", 3), "abc"); // truncated
    }

    // ── Boot ID parsing ───────────────────────────────────────────────

    #[test]
    fn test_parse_boot_id() {
        let id = parse_boot_id(b"1234567890abcdef1234567890abcdef").unwrap();
        assert_eq!(
            id,
            [
                0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
                0xcd, 0xef
            ]
        );
    }

    #[test]
    fn test_parse_boot_id_with_dashes() {
        let no_dash = parse_boot_id(b"1234567890abcdef1234567890abcdef").unwrap();
        let with_dash = parse_boot_id(b"12345678-90ab-cdef-1234-567890abcdef").unwrap();
        assert_eq!(no_dash, with_dash);
    }

    #[test]
    fn test_parse_boot_id_invalid() {
        assert!(parse_boot_id(b"short").is_err());
        assert!(parse_boot_id(b"12345678-90ab-cdef-1234-567890abcdeg").is_err());
    }

    // ── Active mode: text field parsing ───────────────────────────────

    #[test]
    fn test_active_text_field() {
        let input = b"MESSAGE=hello world\n\n";
        let mut imp = JournalImporter::new(Cursor::new(input));
        assert_eq!(imp.state(), ImporterState::Line);

        let result = imp.process_data().unwrap();
        assert_eq!(result, text_field(b"MESSAGE", b"hello world"));

        let result = imp.process_data().unwrap();
        assert_eq!(result, ProcessResult::EntryReady);
    }

    #[test]
    fn test_text_field_preserves_non_utf8_and_nul_bytes() {
        let input = b"MESSAGE=before\0after\xff\n\n";
        let mut imp = JournalImporter::new(Cursor::new(input));

        assert_eq!(
            imp.process_data().unwrap(),
            text_field(b"MESSAGE", b"before\0after\xff")
        );
        assert_eq!(imp.process_data().unwrap(), ProcessResult::EntryReady);
    }

    #[test]
    fn test_active_multiple_fields() {
        let input = b"_PID=1234\n_COMM=test\nMESSAGE=hi\n\n";
        let mut imp = JournalImporter::new(Cursor::new(input));

        let r1 = imp.process_data().unwrap();
        assert_eq!(r1, text_field(b"_PID", b"1234"));

        let r2 = imp.process_data().unwrap();
        assert_eq!(r2, text_field(b"_COMM", b"test"));

        let r3 = imp.process_data().unwrap();
        assert_eq!(r3, text_field(b"MESSAGE", b"hi"));

        let r4 = imp.process_data().unwrap();
        assert_eq!(r4, ProcessResult::EntryReady);
    }

    #[test]
    fn test_active_eof() {
        let input = b"MESSAGE=hello\n";
        let mut imp = JournalImporter::new(Cursor::new(input));

        let result = imp.process_data().unwrap();
        assert_eq!(result, text_field(b"MESSAGE", b"hello"));

        // No trailing newline or empty line — should hit EOF.
        let result = imp.process_data().unwrap();
        assert_eq!(result, ProcessResult::Eof);
    }

    #[test]
    fn test_active_empty_input() {
        let input: &[u8] = b"";
        let mut imp = JournalImporter::new(Cursor::new(input));

        let result = imp.process_data().unwrap();
        assert_eq!(result, ProcessResult::Eof);
        assert!(imp.is_eof());
    }

    // ── Active mode: special fields ───────────────────────────────────

    #[test]
    fn test_active_realtime_timestamp() {
        let input = b"__REALTIME_TIMESTAMP=12345\nMESSAGE=test\n\n";
        let mut imp = JournalImporter::new(Cursor::new(input));

        let r1 = imp.process_data().unwrap();
        assert_eq!(r1, ProcessResult::FieldIgnored);
        assert_eq!(imp.timestamp().realtime, 12345);

        let r2 = imp.process_data().unwrap();
        assert_eq!(r2, text_field(b"MESSAGE", b"test"));

        let r3 = imp.process_data().unwrap();
        assert_eq!(r3, ProcessResult::EntryReady);
    }

    #[test]
    fn test_active_cursor_ignored() {
        let input = b"__CURSOR=abc\nMESSAGE=test\n\n";
        let mut imp = JournalImporter::new(Cursor::new(input));

        let r1 = imp.process_data().unwrap();
        assert_eq!(r1, ProcessResult::FieldIgnored);

        let r2 = imp.process_data().unwrap();
        assert_eq!(r2, text_field(b"MESSAGE", b"test"));
    }

    // ── Passive mode ──────────────────────────────────────────────────

    #[test]
    fn test_passive_push_and_process() {
        let mut imp = JournalImporter::<std::io::Empty>::new_passive();

        // Push a complete text field + empty line.
        imp.push_data(b"MESSAGE=hello\n\n").unwrap();

        let r1 = imp.process_data().unwrap();
        assert_eq!(r1, text_field(b"MESSAGE", b"hello"));

        let r2 = imp.process_data().unwrap();
        assert_eq!(r2, ProcessResult::EntryReady);
    }

    #[test]
    fn test_passive_partial_push() {
        let mut imp = JournalImporter::<std::io::Empty>::new_passive();

        // Push partial data — no newline yet.
        imp.push_data(b"MESSAGE=hel").unwrap();

        let result = imp.process_data();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ImporterError::WouldBlock);

        // Push the rest.
        imp.push_data(b"lo\n\n").unwrap();

        let r1 = imp.process_data().unwrap();
        assert_eq!(r1, text_field(b"MESSAGE", b"hello"));

        let r2 = imp.process_data().unwrap();
        assert_eq!(r2, ProcessResult::EntryReady);
    }

    #[test]
    fn test_passive_push_after_eof() {
        let mut imp = JournalImporter::<std::io::Empty>::new_passive();

        // Process with no data should return WouldBlock, not EOF.
        // EOF only happens after a read returns 0 in active mode.
        imp.push_data(b"").unwrap();
        // Empty push — should process nothing and return WouldBlock.
        let result = imp.process_data();
        assert_eq!(result.unwrap_err(), ImporterError::WouldBlock);
    }

    // ── Binary field parsing ──────────────────────────────────────────

    #[test]
    fn test_active_binary_field_zero_size() {
        // Binary field with zero-length data:
        // FIELDNAME\n + LE u64(0) + \n
        let mut input = Vec::new();
        input.extend_from_slice(b"BINARY_FIELD\n");
        input.extend_from_slice(&0u64.to_le_bytes());
        input.push(b'\n');
        // Entry separator
        input.push(b'\n');

        let mut imp = JournalImporter::new(Cursor::new(input));

        // First call reads the field name line, transitions to DataStart
        let r1 = imp.process_data().unwrap();
        assert_eq!(r1, ProcessResult::Continue);
        assert_eq!(imp.state(), ImporterState::DataStart);

        // Second call reads the size (0), transitions to DataFinish
        let r2 = imp.process_data().unwrap();
        assert_eq!(r2, ProcessResult::Continue);
        assert_eq!(imp.state(), ImporterState::DataFinish);

        // Third call reads the trailing newline, transitions back to Line
        let r3 = imp.process_data().unwrap();
        assert_eq!(r3, ProcessResult::Continue);
        assert_eq!(imp.state(), ImporterState::Line);

        let r4 = imp.process_data().unwrap();
        assert_eq!(r4, ProcessResult::EntryReady);
    }

    #[test]
    fn test_active_binary_field_with_data() {
        let mut input = Vec::new();
        input.extend_from_slice(b"COREDUMP\n");
        let data = b"hello";
        input.extend_from_slice(&(data.len() as u64).to_le_bytes());
        input.extend_from_slice(data);
        input.push(b'\n');
        input.push(b'\n');

        let mut imp = JournalImporter::new(Cursor::new(input));

        let r1 = imp.process_data().unwrap();
        assert_eq!(r1, ProcessResult::Continue);
        assert_eq!(imp.state(), ImporterState::DataStart);

        let r2 = imp.process_data().unwrap();
        assert_eq!(r2, ProcessResult::Continue);
        assert_eq!(imp.state(), ImporterState::Data);

        let r3 = imp.process_data().unwrap();
        assert_eq!(r3, ProcessResult::Continue);
        assert_eq!(imp.state(), ImporterState::DataFinish);

        let r4 = imp.process_data().unwrap();
        assert_eq!(
            r4,
            ProcessResult::BinaryFieldComplete(b"COREDUMP".to_vec(), b"COREDUMP=hello".to_vec(),)
        );
        assert_eq!(imp.state(), ImporterState::Line);

        let r5 = imp.process_data().unwrap();
        assert_eq!(r5, ProcessResult::EntryReady);
    }

    #[test]
    fn test_passive_binary_field_fragmented_and_byte_preserving() {
        let mut imp = JournalImporter::<std::io::Empty>::new_passive();
        imp.push_data(b"COREDUMP\n").unwrap();
        assert_eq!(imp.process_data().unwrap(), ProcessResult::Continue);
        assert_eq!(imp.process_data(), Err(ImporterError::WouldBlock));

        imp.push_data(&3u64.to_le_bytes()[..4]).unwrap();
        assert_eq!(imp.process_data(), Err(ImporterError::WouldBlock));
        imp.push_data(&3u64.to_le_bytes()[4..]).unwrap();
        assert_eq!(imp.process_data().unwrap(), ProcessResult::Continue);
        assert_eq!(imp.process_data(), Err(ImporterError::WouldBlock));

        imp.push_data(b"\0\xffx\n").unwrap();
        assert_eq!(imp.process_data().unwrap(), ProcessResult::Continue);
        assert_eq!(
            imp.process_data().unwrap(),
            ProcessResult::BinaryFieldComplete(b"COREDUMP".to_vec(), b"COREDUMP=\0\xffx".to_vec(),)
        );
    }

    #[test]
    fn test_truncated_binary_field_fails_closed() {
        let mut input = Vec::new();
        input.extend_from_slice(b"COREDUMP\n");
        input.extend_from_slice(&3u64.to_le_bytes());
        input.extend_from_slice(b"\0\xff");

        let mut imp = JournalImporter::new(Cursor::new(input));
        assert_eq!(imp.process_data().unwrap(), ProcessResult::Continue);
        assert_eq!(imp.process_data().unwrap(), ProcessResult::Continue);
        assert_eq!(imp.process_data().unwrap(), ProcessResult::Eof);
        assert!(imp.is_eof());
    }

    #[test]
    fn test_binary_field_size_too_large() {
        let mut input = Vec::new();
        input.extend_from_slice(b"BINARY_FIELD\n");
        input.extend_from_slice(&(DATA_SIZE_MAX as u64 + 1).to_le_bytes());

        let mut imp = JournalImporter::new(Cursor::new(input));

        let r1 = imp.process_data().unwrap();
        assert_eq!(r1, ProcessResult::Continue);
        assert_eq!(imp.state(), ImporterState::DataStart);

        let r2 = imp.process_data();
        assert!(matches!(r2, Err(ImporterError::DataSizeExceeded(_))));
    }

    #[test]
    fn test_binary_field_bad_newline() {
        let mut input = Vec::new();
        input.extend_from_slice(b"FIELD\n");
        input.extend_from_slice(&0u64.to_le_bytes());
        input.push(b'X'); // Not a newline!

        let mut imp = JournalImporter::new(Cursor::new(input));

        imp.process_data().unwrap(); // Line -> DataStart
        imp.process_data().unwrap(); // DataStart -> DataFinish
        let r3 = imp.process_data();
        assert!(matches!(r3, Err(ImporterError::ExpectedNewline(b'X'))));
    }

    // ── Invalid field handling ────────────────────────────────────────

    #[test]
    fn test_invalid_field_ignored() {
        let input = b"1bad=value\nMESSAGE=ok\n\n";
        let mut imp = JournalImporter::new(Cursor::new(input));

        let r1 = imp.process_data().unwrap();
        assert_eq!(r1, ProcessResult::Continue);

        let r2 = imp.process_data().unwrap();
        assert_eq!(r2, text_field(b"MESSAGE", b"ok"));

        let r3 = imp.process_data().unwrap();
        assert_eq!(r3, ProcessResult::EntryReady);
    }

    #[test]
    fn test_empty_field_name_ignored() {
        // An empty line after the first non-empty line is the entry separator.
        // But a line starting with '=' has an empty field name.
        let input = b"=value\nMESSAGE=ok\n\n";
        let mut imp = JournalImporter::new(Cursor::new(input));

        let r1 = imp.process_data().unwrap();
        assert_eq!(r1, ProcessResult::Continue);

        let r2 = imp.process_data().unwrap();
        assert_eq!(r2, text_field(b"MESSAGE", b"ok"));
    }

    // ── Importer metadata ─────────────────────────────────────────────

    #[test]
    fn test_set_name() {
        let mut imp = JournalImporter::new(Cursor::new(b""));
        imp.set_name("test-importer");
        assert_eq!(imp.name.as_deref(), Some("test-importer"));
    }

    #[test]
    fn test_bytes_remaining() {
        let mut imp = JournalImporter::<std::io::Empty>::new_passive();
        assert_eq!(imp.bytes_remaining(), 0);

        imp.push_data(b"hello").unwrap();
        assert_eq!(imp.bytes_remaining(), 5);
    }

    #[test]
    fn test_drop_iovw() {
        let mut imp = JournalImporter::<std::io::Empty>::new_passive();
        imp.push_data(b"MESSAGE=test\n\n").unwrap();

        // Process the field
        imp.process_data().unwrap();
        imp.process_data().unwrap(); // EntryReady

        // Drop should compact the buffer
        imp.drop_iovw();
    }

    // ── Error display ─────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = ImporterError::EntryTooLarge(DATA_SIZE_MAX);
        assert!(e.to_string().contains("exceeds"));

        let e = ImporterError::DataSizeExceeded(999999);
        assert!(e.to_string().contains("999999"));

        let e = ImporterError::ExpectedNewline(0x41);
        assert!(e.to_string().contains("41"));

        let e = ImporterError::WouldBlock;
        assert!(e.to_string().contains("Would block"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broken");
        let imp_err: ImporterError = io_err.into();
        assert!(matches!(imp_err, ImporterError::Io(_)));
    }

    // ── EOF handling ──────────────────────────────────────────────────

    #[test]
    fn test_eof_after_entry() {
        let input = b"MESSAGE=done\n\n";
        let mut imp = JournalImporter::new(Cursor::new(input));

        imp.process_data().unwrap(); // FieldAccepted
        imp.process_data().unwrap(); // EntryReady

        // Next call should return EOF
        let result = imp.process_data().unwrap();
        assert_eq!(result, ProcessResult::Eof);
    }

    #[test]
    fn test_process_after_eof() {
        let input = b"\n";
        let mut imp = JournalImporter::new(Cursor::new(input));

        let result = imp.process_data().unwrap();
        assert_eq!(result, ProcessResult::EntryReady);

        let result = imp.process_data().unwrap();
        assert_eq!(result, ProcessResult::Eof);

        // Subsequent calls should also return EOF
        let result = imp.process_data().unwrap();
        assert_eq!(result, ProcessResult::Eof);
    }

    // ── ProcessResult equality ────────────────────────────────────────

    #[test]
    fn test_process_result_equality() {
        assert_eq!(ProcessResult::EntryReady, ProcessResult::EntryReady);
        assert_eq!(ProcessResult::Continue, ProcessResult::Continue);
        assert_eq!(ProcessResult::Eof, ProcessResult::Eof);
        assert_eq!(text_field(b"A", b"B"), text_field(b"A", b"B"));
        assert_ne!(text_field(b"A", b"B"), text_field(b"A", b"C"));
    }
}
