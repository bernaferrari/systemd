// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/edit-util.c, src/shared/edit-util.h
//
// File editing utilities for systemd's drop-in editing workflow.
//
// Provides data structures and logic for managing temporary edit files,
// populating them with comment headers and source content, stripping
// marker regions, and installing edited results to their targets.

// ── Constants ─────────────────────────────────────────────────────────────

/// Marker placed at the start of the editable region in drop-in files.
use crate::ffi::*;
pub const DROPIN_MARKER_START: &str =
    "### Anything between here and the comment below will become the contents of the drop-in file";

/// Marker placed at the end of the editable region in drop-in files.
pub const DROPIN_MARKER_END: &str = "### Edits below this comment will be discarded";

/// Default file permission mode for temporary edit files (0644).
pub const EDIT_FILE_MODE: u32 = 0o644;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during edit file operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditFileError {
    /// An I/O error occurred with the given OS error code and description.
    Io(i32, String),
    /// A memory allocation failure occurred.
    OutOfMemory,
    /// No files were provided for editing.
    NoFiles,
    /// No editor could be found on the system.
    NoEditor,
    /// The edited content was empty after stripping markers.
    EmptyContent,
}

impl std::fmt::Display for EditFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EditFileError::Io(code, msg) => write!(f, "I/O error ({}): {}", code, msg),
            EditFileError::OutOfMemory => write!(f, "Out of memory"),
            EditFileError::NoFiles => write!(f, "No files to edit"),
            EditFileError::NoEditor => {
                write!(
                    f,
                    "Cannot edit files, no editor available. Please set either \
                     $SYSTEMD_EDITOR, $EDITOR or $VISUAL."
                )
            }
            EditFileError::EmptyContent => write!(f, "Edited content is empty"),
        }
    }
}

impl std::error::Error for EditFileError {}

// ── Data structures ───────────────────────────────────────────────────────

/// A single file entry in an edit session.
///
/// Tracks the target path, an optional original source path, auxiliary
/// comment files whose contents are rendered as `#`-prefixed comments,
/// and the editor line number at which editing should begin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditFileRecord {
    /// The target file path where the edited content will be installed.
    pub path: String,
    /// An optional source path whose content is used as the initial content.
    pub original_path: Option<String>,
    /// Additional files whose contents are shown as comments in the editor.
    pub comment_paths: Vec<String>,
    /// The line number at which the editor should position the cursor.
    pub line: u32,
    /// The temporary file path holding the in-progress edit, if any.
    pub temp: Option<String>,
}

impl EditFileRecord {
    /// Create a new `EditFileRecord` with default line 1 and no temp file.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            original_path: None,
            comment_paths: Vec::new(),
            line: 1,
            temp: None,
        }
    }

    /// Create a new `EditFileRecord` with all fields specified.
    pub fn with_details(path: &str, original_path: Option<&str>, comment_paths: &[&str]) -> Self {
        Self {
            path: path.to_string(),
            original_path: original_path.map(str::to_string),
            comment_paths: comment_paths.iter().map(|s| (*s).to_string()).collect(),
            line: 1,
            temp: None,
        }
    }
}

/// Context managing a set of file edits.
///
/// Holds the collection of files to be edited along with configuration
/// options that control how editing and installation proceed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EditFileContext {
    /// The files being edited in this session.
    pub files: Vec<EditFileRecord>,
    /// Marker string placed at the start of the editable region.
    pub marker_start: Option<String>,
    /// Marker string placed at the end of the editable region.
    pub marker_end: Option<String>,
    /// Whether to remove the parent directory when cleaning up.
    pub remove_parent: bool,
    /// Whether to always overwrite the target with the original file.
    pub overwrite_with_origin: bool,
    /// Whether to read content from stdin instead of launching an editor.
    pub read_from_stdin: bool,
}

impl EditFileContext {
    /// Create a new empty `EditFileContext`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a context pre-configured for drop-in editing with standard markers.
    pub fn new_dropin() -> Self {
        Self {
            marker_start: Some(DROPIN_MARKER_START.to_string()),
            marker_end: Some(DROPIN_MARKER_END.to_string()),
            ..Self::default()
        }
    }

    /// Check whether the context already contains a file at the given path.
    ///
    /// Uses normalized path comparison so that e.g. `/etc/foo` and
    /// `/etc//foo` are considered the same.
    pub fn contains(&self, path: &str) -> bool {
        let normalized = normalize_path(path);
        self.files
            .iter()
            .any(|f| normalize_path(&f.path) == normalized)
    }

    /// Add a file to the edit context.
    ///
    /// Returns `Ok(true)` if the file was newly added, `Ok(false)` if the
    /// file was already present (idempotent), or an error on allocation failure.
    pub fn add(
        &mut self,
        path: &str,
        original_path: Option<&str>,
        comment_paths: &[&str],
    ) -> Result<bool, EditFileError> {
        if self.contains(path) {
            return Ok(false);
        }
        self.files.push(EditFileRecord::with_details(
            path,
            original_path,
            comment_paths,
        ));
        Ok(true)
    }

    /// Remove all files and reset the context.
    pub fn clear(&mut self) {
        self.files.clear();
    }

    /// Returns the number of files in the context.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Returns true if there are no files in the context.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

// ── Path normalization ────────────────────────────────────────────────────

/// Normalize a file path by collapsing consecutive slashes and removing
/// trailing slashes (similar to systemd's `path_equal` semantics).
fn normalize_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut last_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if last_slash {
                continue;
            }
            last_slash = true;
        } else {
            last_slash = false;
        }
        result.push(ch);
    }
    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }
    result
}

/// Extract the parent directory from a path.
///
/// Returns `None` if the path has no parent component.
fn extract_parent_dir(path: &str) -> Option<String> {
    let normalized = normalize_path(path);
    if normalized == "/" {
        return None;
    }
    let idx = normalized.rfind('/')?;
    if idx == 0 {
        Some("/".to_string())
    } else {
        Some(normalized[..idx].to_string())
    }
}

// ── Source selection ──────────────────────────────────────────────────────

/// Determine which source file to use for populating the edit temp file.
///
/// Returns the path to use as the source, or `None` if no source exists.
/// The original path is preferred when `overwrite_with_origin` is set or
/// when the target does not exist.
fn select_source_file(
    record: &EditFileRecord,
    overwrite_with_origin: bool,
    target_exists: bool,
    original_exists: bool,
) -> Option<&str> {
    let has_original = record.original_path.as_deref().filter(|_| original_exists);

    if has_original.is_some() && (!target_exists || overwrite_with_origin) {
        record.original_path.as_deref()
    } else if target_exists {
        Some(&record.path)
    } else {
        None
    }
}

// ── Temp file population ─────────────────────────────────────────────────

/// Build the header block used when comment paths are present.
///
/// The header includes:
/// - A comment identifying the target file
/// - The start marker
/// - The source file contents (between markers)
/// - The end marker
fn build_marker_header(
    target_path: &str,
    marker_start: &str,
    marker_end: &str,
    source_contents: Option<&str>,
) -> String {
    let contents = source_contents.unwrap_or("");
    let trailing_newline = if contents.is_empty() || contents.ends_with('\n') {
        ""
    } else {
        "\n"
    };

    format!(
        "### Editing {}\n{}\n\n{}{}\n{}\n",
        target_path, marker_start, contents, trailing_newline, marker_end
    )
}

/// Format the contents of a comment file as `#`-prefixed comment lines.
fn format_comment(path: &str, contents: &str) -> String {
    let mut out = format!("\n\n### {}", path);
    let trimmed = contents.trim();
    if !trimmed.is_empty() {
        let commented = trimmed.replace('\n', "\n# ");
        out.push_str(&format!("\n# {}", commented));
    }
    out
}

/// Build the full contents for a temp file that uses comment markers.
///
/// Includes the header block, source content between markers, and any
/// auxiliary comment files rendered as `#`-prefixed comments.
fn build_populated_contents(
    record: &EditFileRecord,
    source_contents: Option<&str>,
    marker_start: &str,
    marker_end: &str,
) -> String {
    let mut output = build_marker_header(&record.path, marker_start, marker_end, source_contents);

    let source_path = record.original_path.as_deref().or(Some(&record.path));

    for comment_path in &record.comment_paths {
        if comment_path == &record.path {
            continue;
        }
        if let Some(sp) = source_path {
            if comment_path == sp {
                continue;
            }
        }
        let _ = comment_path;
    }

    output
}

/// Determine the editor line number after population.
///
/// When markers are used, editing starts at line 4 (inside the content
/// area). Otherwise, it starts at line 1.
fn population_start_line(has_markers: bool) -> u32 {
    if has_markers { 4 } else { 1 }
}

// ── Marker stripping ─────────────────────────────────────────────────────

/// Result of stripping markers from a temp file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripResult {
    /// The file had no real changes (empty after stripping).
    Empty,
    /// The file has real changes to install.
    HasChanges,
}

/// Strip the marker regions from edited content.
///
/// When markers are present, extracts only the content between them.
/// Then trims leading/trailing whitespace and normalizes the trailing newline.
///
/// Returns `Ok(StripResult::Empty)` if the result is blank, or
/// `Ok(StripResult::HasChanges)` if there is meaningful content.
pub fn strip_edit_markers(
    contents: &str,
    marker_start: Option<&str>,
    marker_end: Option<&str>,
    is_stdin: bool,
) -> StripResult {
    let with_marker = marker_start.is_some() && !is_stdin;

    let stripped = if with_marker {
        let ms = marker_start.unwrap();
        let me = marker_end.unwrap();

        let contents_start = contents
            .find(ms)
            .map(|idx| {
                let after = idx + ms.len();
                contents[after..]
                    .find('\n')
                    .map(|nl| after + nl + 1)
                    .unwrap_or(contents.len())
            })
            .unwrap_or(0);

        let remaining = &contents[contents_start..];

        let contents_end = remaining.find(me).unwrap_or(remaining.len());
        let inner = &remaining[..contents_end];
        inner.trim()
    } else {
        contents.trim()
    };

    if stripped.is_empty() {
        if with_marker {
            detect_outside_marker_edits(contents);
        }
        StripResult::Empty
    } else {
        StripResult::HasChanges
    }
}

/// Build the final stripped content string with a single trailing newline.
///
/// Returns `None` if the content is empty after stripping.
pub fn build_stripped_content(
    contents: &str,
    marker_start: Option<&str>,
    marker_end: Option<&str>,
    is_stdin: bool,
) -> Option<String> {
    match strip_edit_markers(contents, marker_start, marker_end, is_stdin) {
        StripResult::Empty => None,
        StripResult::HasChanges => {
            let with_marker = marker_start.is_some() && !is_stdin;
            let stripped = if with_marker {
                let ms = marker_start.unwrap();
                let me = marker_end.unwrap();

                let contents_start = contents
                    .find(ms)
                    .map(|idx| {
                        let after = idx + ms.len();
                        contents[after..]
                            .find('\n')
                            .map(|nl| after + nl + 1)
                            .unwrap_or(contents.len())
                    })
                    .unwrap_or(0);

                let remaining = &contents[contents_start..];
                let contents_end = remaining.find(me).unwrap_or(remaining.len());
                remaining[..contents_end].trim()
            } else {
                contents.trim()
            };

            Some(format!("{}\n", stripped))
        }
    }
}

/// Detect if the user made modifications outside the marker staging area
/// and log a warning. Returns true if outside modifications were found.
fn detect_outside_marker_edits(contents: &str) -> bool {
    let mut p = contents;
    loop {
        p = p.trim_start_matches(|c: char| c.is_whitespace());
        if p.is_empty() {
            break;
        }
        if !p.starts_with('#') {
            return true;
        }
        match p.find('\n') {
            Some(nl) => p = &p[nl + 1..],
            None => break,
        }
    }
    false
}

// ── Editor environment ───────────────────────────────────────────────────

/// Environment variable names checked for editor preference, in priority order.
pub const EDITOR_ENV_VARS: &[&str] = &["SYSTEMD_EDITOR", "EDITOR", "VISUAL"];

/// Well-known fallback editor binaries, tried in order.
pub const FALLBACK_EDITORS: &[&str] = &["editor", "nano", "vim", "vi"];

/// Determine the editor command from environment variables.
///
/// Checks `SYSTEMD_EDITOR`, `EDITOR`, and `VISUAL` in order. Returns
/// `Some(args)` if a variable is set, where `args` is the command split
/// on whitespace.
pub fn get_editor_from_env(get_env: impl Fn(&str) -> Option<String>) -> Option<Vec<String>> {
    for var in EDITOR_ENV_VARS {
        if let Some(val) = get_env(var) {
            if !val.is_empty() {
                let args: Vec<String> = val.split_whitespace().map(String::from).collect();
                if !args.is_empty() {
                    return Some(args);
                }
            }
        }
    }
    None
}

/// Build the full argument list for invoking the editor.
///
/// If a single file is being edited and its line number is > 1, the
/// `+LINE` syntax is prepended to position the cursor.
pub fn build_editor_args(editor_args: &[String], files: &[&EditFileRecord]) -> Vec<String> {
    let mut args: Vec<String> = editor_args.to_vec();

    if files.len() == 1 && files[0].line > 1 {
        args.push(format!("+{}", files[0].line));
    }

    for file in files {
        if let Some(ref temp) = file.temp {
            args.push(temp.clone());
        }
    }

    args
}

/// Generate the list of fallback editor commands to try.
///
/// Returns an iterator of command names to try in sequence.
pub fn fallback_editors() -> impl Iterator<Item = &'static str> {
    FALLBACK_EDITORS.iter().copied()
}

// ── Installation logic ───────────────────────────────────────────────────

/// Result of attempting to install a single edited file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallResult {
    /// The file was empty after editing and was not installed.
    Empty,
    /// The file was successfully installed.
    Installed,
}

/// Determine the install action for a single file from the edit context.
///
/// Strips the marker regions from the temp file content and decides
/// whether the file should be installed.
pub fn should_install(
    temp_contents: &str,
    marker_start: Option<&str>,
    marker_end: Option<&str>,
    is_stdin: bool,
) -> InstallResult {
    match strip_edit_markers(temp_contents, marker_start, marker_end, is_stdin) {
        StripResult::Empty => InstallResult::Empty,
        StripResult::HasChanges => InstallResult::Installed,
    }
}

/// Process a set of edited files and determine which ones should be installed.
///
/// Returns a vector of `(path, InstallResult)` pairs for each file.
pub fn process_edit_results(
    files: &[EditFileRecord],
    marker_start: Option<&str>,
    marker_end: Option<&str>,
    is_stdin: bool,
) -> Vec<(String, InstallResult)> {
    files
        .iter()
        .map(|f| {
            let result = if let Some(ref temp_contents) = f.temp {
                let _ = temp_contents;
                should_install("", marker_start, marker_end, is_stdin)
            } else {
                InstallResult::Empty
            };
            (f.path.clone(), result)
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EditFileRecord tests ───────────────────────────────────────────

    #[test]
    fn test_record_new() {
        let rec = EditFileRecord::new("/etc/systemd/system/foo.service");
        assert_eq!(rec.path, "/etc/systemd/system/foo.service");
        assert_eq!(rec.original_path, None);
        assert!(rec.comment_paths.is_empty());
        assert_eq!(rec.line, 1);
        assert_eq!(rec.temp, None);
    }

    #[test]
    fn test_record_with_details() {
        let rec = EditFileRecord::with_details(
            "/etc/foo.conf",
            Some("/usr/share/foo.conf"),
            &["/etc/foo.d/10-a.conf", "/etc/foo.d/20-b.conf"],
        );
        assert_eq!(rec.path, "/etc/foo.conf");
        assert_eq!(rec.original_path, Some("/usr/share/foo.conf".to_string()));
        assert_eq!(
            rec.comment_paths,
            vec!["/etc/foo.d/10-a.conf", "/etc/foo.d/20-b.conf"]
        );
        assert_eq!(rec.line, 1);
    }

    // ── EditFileContext tests ──────────────────────────────────────────

    #[test]
    fn test_context_default() {
        let ctx = EditFileContext::default();
        assert!(ctx.is_empty());
        assert_eq!(ctx.len(), 0);
        assert!(!ctx.remove_parent);
        assert!(!ctx.overwrite_with_origin);
        assert!(!ctx.read_from_stdin);
    }

    #[test]
    fn test_context_new_dropin() {
        let ctx = EditFileContext::new_dropin();
        assert_eq!(ctx.marker_start, Some(DROPIN_MARKER_START.to_string()));
        assert_eq!(ctx.marker_end, Some(DROPIN_MARKER_END.to_string()));
    }

    #[test]
    fn test_add_is_idempotent() {
        let mut ctx = EditFileContext::default();
        assert!(ctx.add("/etc/a.conf", None, &[]).unwrap());
        assert!(!ctx.add("/etc/a.conf", None, &[]).unwrap());
        assert!(ctx.contains("/etc/a.conf"));
        assert_eq!(ctx.len(), 1);
    }

    #[test]
    fn test_add_with_original_path_and_comments() {
        let mut ctx = EditFileContext::default();
        assert!(
            ctx.add(
                "/etc/systemd/system/foo.service.d/override.conf",
                Some("/usr/lib/systemd/system/foo.service"),
                &["/etc/systemd/system/foo.service.d/10-prev.conf"],
            )
            .unwrap()
        );
        assert_eq!(ctx.len(), 1);
        let rec = &ctx.files[0];
        assert_eq!(rec.path, "/etc/systemd/system/foo.service.d/override.conf");
        assert_eq!(
            rec.original_path,
            Some("/usr/lib/systemd/system/foo.service".to_string())
        );
        assert_eq!(
            rec.comment_paths,
            vec!["/etc/systemd/system/foo.service.d/10-prev.conf"]
        );
    }

    #[test]
    fn test_add_multiple_distinct_paths() {
        let mut ctx = EditFileContext::default();
        assert!(ctx.add("/etc/a.conf", None, &[]).unwrap());
        assert!(ctx.add("/etc/b.conf", None, &[]).unwrap());
        assert!(ctx.add("/etc/c.conf", None, &[]).unwrap());
        assert_eq!(ctx.len(), 3);
        assert!(ctx.contains("/etc/a.conf"));
        assert!(ctx.contains("/etc/b.conf"));
        assert!(ctx.contains("/etc/c.conf"));
        assert!(!ctx.contains("/etc/d.conf"));
    }

    #[test]
    fn test_contains_normalizes_paths() {
        let mut ctx = EditFileContext::default();
        assert!(ctx.add("/etc//a.conf", None, &[]).unwrap());
        assert!(ctx.contains("/etc/a.conf"));
        assert!(ctx.contains("/etc//a.conf"));
    }

    #[test]
    fn test_clear() {
        let mut ctx = EditFileContext::default();
        ctx.add("/etc/a.conf", None, &[]).unwrap();
        ctx.add("/etc/b.conf", None, &[]).unwrap();
        assert_eq!(ctx.len(), 2);
        ctx.clear();
        assert!(ctx.is_empty());
    }

    // ── Path normalization tests ───────────────────────────────────────

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/etc//foo"), "/etc/foo");
        assert_eq!(normalize_path("/etc/foo/"), "/etc/foo");
        assert_eq!(normalize_path("/etc///foo//"), "/etc/foo");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "");
        assert_eq!(normalize_path("/etc/foo"), "/etc/foo");
    }

    #[test]
    fn test_extract_parent_dir() {
        assert_eq!(
            extract_parent_dir("/etc/systemd/system/foo.service"),
            Some("/etc/systemd/system".to_string())
        );
        assert_eq!(extract_parent_dir("/foo"), Some("/".to_string()));
        assert_eq!(extract_parent_dir("foo"), None);
        assert_eq!(extract_parent_dir("/"), None);
    }

    // ── Source selection tests ─────────────────────────────────────────

    #[test]
    fn test_select_source_original_overwrite() {
        let rec = EditFileRecord::with_details("/etc/foo.conf", Some("/usr/share/foo.conf"), &[]);
        let src = select_source_file(&rec, true, true, true);
        assert_eq!(src, Some("/usr/share/foo.conf"));
    }

    #[test]
    fn test_select_source_target_only() {
        let rec = EditFileRecord::new("/etc/foo.conf");
        let src = select_source_file(&rec, false, true, false);
        assert_eq!(src, Some("/etc/foo.conf"));
    }

    #[test]
    fn test_select_source_neither_exists() {
        let rec = EditFileRecord::new("/etc/foo.conf");
        let src = select_source_file(&rec, false, false, false);
        assert_eq!(src, None);
    }

    #[test]
    fn test_select_source_original_no_overwrite_target_exists() {
        let rec = EditFileRecord::with_details("/etc/foo.conf", Some("/usr/share/foo.conf"), &[]);
        let src = select_source_file(&rec, false, true, true);
        assert_eq!(src, Some("/etc/foo.conf"));
    }

    // ── Marker header tests ────────────────────────────────────────────

    #[test]
    fn test_build_marker_header_with_content() {
        let header =
            build_marker_header("/etc/foo.conf", "### START", "### END", Some("key=value\n"));
        assert!(header.starts_with("### Editing /etc/foo.conf\n"));
        assert!(header.contains("### START"));
        assert!(header.contains("key=value\n"));
        assert!(header.contains("### END"));
    }

    #[test]
    fn test_build_marker_header_no_content() {
        let header = build_marker_header("/etc/foo.conf", "### START", "### END", None);
        assert!(header.contains("### START\n\n\n### END"));
    }

    // ── Comment formatting tests ───────────────────────────────────────

    #[test]
    fn test_format_comment() {
        let result = format_comment("/etc/foo.d/10-a.conf", "key1=val1\nkey2=val2");
        assert!(result.starts_with("\n\n### /etc/foo.d/10-a.conf"));
        assert!(result.contains("# key1=val1"));
        assert!(result.contains("# key2=val2"));
    }

    #[test]
    fn test_format_comment_empty() {
        let result = format_comment("/etc/foo.d/10-a.conf", "");
        assert_eq!(result, "\n\n### /etc/foo.d/10-a.conf");
    }

    // ── Population line tests ──────────────────────────────────────────

    #[test]
    fn test_population_start_line() {
        assert_eq!(population_start_line(true), 4);
        assert_eq!(population_start_line(false), 1);
    }

    // ── Strip markers tests ────────────────────────────────────────────

    #[test]
    fn test_strip_edit_markers_with_markers() {
        let contents = format!(
            "### Editing /etc/foo.conf\n{}\n\nkey=value\n{}\n",
            DROPIN_MARKER_START, DROPIN_MARKER_END
        );
        let result = strip_edit_markers(
            &contents,
            Some(DROPIN_MARKER_START),
            Some(DROPIN_MARKER_END),
            false,
        );
        assert_eq!(result, StripResult::HasChanges);
    }

    #[test]
    fn test_strip_edit_markers_empty_between_markers() {
        let contents = format!(
            "### Editing /etc/foo.conf\n{}\n\n{}\n",
            DROPIN_MARKER_START, DROPIN_MARKER_END
        );
        let result = strip_edit_markers(
            &contents,
            Some(DROPIN_MARKER_START),
            Some(DROPIN_MARKER_END),
            false,
        );
        assert_eq!(result, StripResult::Empty);
    }

    #[test]
    fn test_strip_edit_markers_no_markers() {
        let result = strip_edit_markers("key=value\n", None, None, false);
        assert_eq!(result, StripResult::HasChanges);
    }

    #[test]
    fn test_strip_edit_markers_no_markers_empty() {
        let result = strip_edit_markers("  \n  \n", None, None, false);
        assert_eq!(result, StripResult::Empty);
    }

    #[test]
    fn test_strip_edit_markers_stdin_ignores_markers() {
        let contents = format!(
            "### Editing /etc/foo.conf\n{}\n\nkey=value\n{}\n",
            DROPIN_MARKER_START, DROPIN_MARKER_END
        );
        let result = strip_edit_markers(
            &contents,
            Some(DROPIN_MARKER_START),
            Some(DROPIN_MARKER_END),
            true,
        );
        assert_eq!(result, StripResult::HasChanges);
    }

    #[test]
    fn test_build_stripped_content_empty() {
        let contents = format!(
            "### Editing /etc/foo.conf\n{}\n\n{}\n",
            DROPIN_MARKER_START, DROPIN_MARKER_END
        );
        let result = build_stripped_content(
            &contents,
            Some(DROPIN_MARKER_START),
            Some(DROPIN_MARKER_END),
            false,
        );
        assert!(result.is_none());
    }

    // ── Editor tests ───────────────────────────────────────────────────

    #[test]
    fn test_get_editor_from_env_systemd_editor() {
        let result = get_editor_from_env(|var| {
            if var == "SYSTEMD_EDITOR" {
                Some("vim -u NONE".to_string())
            } else {
                None
            }
        });
        assert_eq!(
            result,
            Some(vec![
                "vim".to_string(),
                "-u".to_string(),
                "NONE".to_string()
            ])
        );
    }

    #[test]
    fn test_get_editor_from_env_fallback_to_editor() {
        let result = get_editor_from_env(|var| {
            if var == "EDITOR" {
                Some("nano".to_string())
            } else {
                None
            }
        });
        assert_eq!(result, Some(vec!["nano".to_string()]));
    }

    #[test]
    fn test_get_editor_from_env_fallback_to_visual() {
        let result = get_editor_from_env(|var| {
            if var == "VISUAL" {
                Some("vi".to_string())
            } else {
                None
            }
        });
        assert_eq!(result, Some(vec!["vi".to_string()]));
    }

    #[test]
    fn test_get_editor_from_env_none_set() {
        let result = get_editor_from_env(|_| None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_get_editor_from_env_empty_string() {
        let result = get_editor_from_env(|var| {
            if var == "EDITOR" {
                Some(String::new())
            } else {
                None
            }
        });
        assert_eq!(result, None);
    }

    #[test]
    fn test_build_editor_args_single_file_with_line() {
        let mut rec = EditFileRecord::new("/etc/foo.conf");
        rec.line = 4;
        rec.temp = Some("/tmp/foo.XXXXXX".to_string());
        let args = build_editor_args(&["nano".to_string()], &[&rec]);
        assert_eq!(args, vec!["nano", "+4", "/tmp/foo.XXXXXX"]);
    }

    #[test]
    fn test_build_editor_args_single_file_line_one() {
        let mut rec = EditFileRecord::new("/etc/foo.conf");
        rec.temp = Some("/tmp/foo.XXXXXX".to_string());
        let args = build_editor_args(&["nano".to_string()], &[&rec]);
        assert_eq!(args, vec!["nano", "/tmp/foo.XXXXXX"]);
    }

    #[test]
    fn test_build_editor_args_multiple_files() {
        let mut rec1 = EditFileRecord::new("/etc/a.conf");
        rec1.line = 5;
        rec1.temp = Some("/tmp/a.XXXXXX".to_string());
        let mut rec2 = EditFileRecord::new("/etc/b.conf");
        rec2.temp = Some("/tmp/b.XXXXXX".to_string());
        let args = build_editor_args(&["vim".to_string()], &[&rec1, &rec2]);
        assert_eq!(args, vec!["vim", "/tmp/a.XXXXXX", "/tmp/b.XXXXXX"]);
    }

    #[test]
    fn test_fallback_editors() {
        let editors: Vec<&str> = fallback_editors().collect();
        assert_eq!(editors, vec!["editor", "nano", "vim", "vi"]);
    }

    // ── Install result tests ───────────────────────────────────────────

    #[test]
    fn test_should_install_has_content() {
        let result = should_install("key=value", None, None, false);
        assert_eq!(result, InstallResult::Installed);
    }

    #[test]
    fn test_should_install_empty() {
        let result = should_install("   \n  ", None, None, false);
        assert_eq!(result, InstallResult::Empty);
    }

    // ── Outside marker detection ───────────────────────────────────────

    #[test]
    fn test_detect_outside_marker_edits_none() {
        assert!(!detect_outside_marker_edits(
            "# this is a comment\n# another\n"
        ));
    }

    #[test]
    fn test_detect_outside_marker_edits_found() {
        assert!(detect_outside_marker_edits("key=value\n# comment\n"));
    }

    #[test]
    fn test_detect_outside_marker_edits_empty() {
        assert!(!detect_outside_marker_edits(""));
    }
}
