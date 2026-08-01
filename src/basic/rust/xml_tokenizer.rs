// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=shared.xml-tokenizer; authority=src/shared/xml.c,src/shared/xml.h
//
// Simplified XML tokenizer. Supports basic XML syntax with HTML5-like
// simplifications (e.g. unquoted attribute values).

use libc::{c_char, c_uint, c_void};
use std::ffi::CStr;

use crate::ffi::Errno;

// ── XML token type constants ────────────────────────────────────────────

pub const XML_END: i32 = 0;
pub const XML_TEXT: i32 = 1;
pub const XML_TAG_OPEN: i32 = 2;
pub const XML_TAG_CLOSE: i32 = 3;
pub const XML_TAG_CLOSE_EMPTY: i32 = 4;
pub const XML_ATTRIBUTE_NAME: i32 = 5;
pub const XML_ATTRIBUTE_VALUE: i32 = 6;

// ── Internal state constants ────────────────────────────────────────────

const STATE_NULL: usize = 0;
const STATE_TEXT: usize = 1;
const STATE_TAG: usize = 2;
const STATE_ATTRIBUTE: usize = 3;

const WHITESPACE: &[u8] = b" \t\n\r";

// ── Error type ──────────────────────────────────────────────────────────

/// Errors returned by the XML tokenizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlError {
    /// Invalid XML syntax.
    Invalid,
    /// Out of memory.
    NoMemory,
}

impl std::fmt::Display for XmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XmlError::Invalid => write!(f, "invalid XML syntax"),
            XmlError::NoMemory => write!(f, "out of memory"),
        }
    }
}

impl std::error::Error for XmlError {}

// ── Token result ────────────────────────────────────────────────────────

/// A single XML token produced by the tokenizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlToken {
    /// End of input.
    End,
    /// Text content.
    Text(String),
    /// Opening tag with name.
    TagOpen(String),
    /// Closing tag with name.
    TagClose(String),
    /// Empty tag close (e.g. `<br/>`).
    TagCloseEmpty,
    /// Attribute name.
    AttributeName(String),
    /// Attribute value.
    AttributeValue(String),
}

impl XmlToken {
    /// Returns the token type as an i32 constant (for C compatibility).
    pub fn token_type(&self) -> i32 {
        match self {
            XmlToken::End => XML_END,
            XmlToken::Text(_) => XML_TEXT,
            XmlToken::TagOpen(_) => XML_TAG_OPEN,
            XmlToken::TagClose(_) => XML_TAG_CLOSE,
            XmlToken::TagCloseEmpty => XML_TAG_CLOSE_EMPTY,
            XmlToken::AttributeName(_) => XML_ATTRIBUTE_NAME,
            XmlToken::AttributeValue(_) => XML_ATTRIBUTE_VALUE,
        }
    }
}

// ── XML Tokenizer state ─────────────────────────────────────────────────

/// Stateful XML tokenizer. Wraps a string input and produces tokens one at a time.
#[derive(Debug)]
pub struct XmlTokenizer<'a> {
    input: &'a str,
    pos: usize,
    state: usize,
    line: u32,
}

impl<'a> XmlTokenizer<'a> {
    /// Create a new tokenizer over the given input string.
    pub fn new(input: &'a str) -> Self {
        XmlTokenizer {
            input,
            pos: 0,
            state: STATE_NULL,
            line: 1,
        }
    }

    /// Return the current line number (1-based).
    pub fn line(&self) -> u32 {
        self.line
    }

    /// Count newlines in a substring of the input.
    fn inc_lines(&mut self, start: usize, end: usize) {
        for b in &self.input.as_bytes()[start..end] {
            if *b == b'\n' {
                self.line += 1;
            }
        }
    }

    /// Consume one token from the input.
    pub fn next_token(&mut self) -> Result<XmlToken, XmlError> {
        let bytes = self.input.as_bytes();
        let len = bytes.len();

        if self.state == STATE_NULL {
            self.line = 1;
            self.state = STATE_TEXT;
        }

        let mut c = self.pos;

        loop {
            if c >= len {
                self.pos = c;
                return Ok(XmlToken::End);
            }

            match self.state {
                STATE_TEXT => {
                    // Find next '<'
                    let mut e = c;
                    while e < len && bytes[e] != b'<' {
                        e += 1;
                    }

                    if e > c {
                        // Text before '<'
                        let text = self.input[c..e].to_string();
                        self.inc_lines(c, e);
                        self.pos = e;
                        self.state = STATE_TEXT;
                        return Ok(XmlToken::Text(text));
                    }

                    // e == c, so bytes[c] == '<'
                    let mut b_pos = c + 1;

                    // Check for comment: <!--
                    if b_pos + 3 <= len
                        && bytes[b_pos] == b'!'
                        && bytes[b_pos + 1] == b'-'
                        && bytes[b_pos + 2] == b'-'
                    {
                        let search_start = b_pos + 3;
                        let end_marker = if let Some(idx) = self.input[search_start..].find("-->") {
                            search_start + idx + 3
                        } else {
                            return Err(XmlError::Invalid);
                        };

                        self.inc_lines(b_pos, end_marker);
                        c = end_marker;
                        continue;
                    }

                    // Processing instruction: <? ... ?>
                    if b_pos < len && bytes[b_pos] == b'?' {
                        let search_start = b_pos + 1;
                        let end_marker = if let Some(idx) = self.input[search_start..].find("?>") {
                            search_start + idx + 2
                        } else {
                            return Err(XmlError::Invalid);
                        };

                        self.inc_lines(b_pos, end_marker);
                        c = end_marker;
                        continue;
                    }

                    // DTD: <! ... >
                    if b_pos < len && bytes[b_pos] == b'!' {
                        let search_start = b_pos + 1;
                        if let Some(idx) = self.input[search_start..].find('>') {
                            let end_marker = search_start + idx + 1;
                            self.inc_lines(b_pos, end_marker);
                            c = end_marker;
                            continue;
                        } else {
                            return Err(XmlError::Invalid);
                        }
                    }

                    // Opening or closing tag
                    let x;
                    if b_pos < len && bytes[b_pos] == b'/' {
                        x = XML_TAG_CLOSE;
                        b_pos += 1;
                    } else {
                        x = XML_TAG_OPEN;
                    }

                    // Find end of tag name: whitespace, '/', or '>'
                    let mut e = b_pos;
                    while e < len
                        && bytes[e] != b' '
                        && bytes[e] != b'\t'
                        && bytes[e] != b'\n'
                        && bytes[e] != b'\r'
                        && bytes[e] != b'/'
                        && bytes[e] != b'>'
                    {
                        e += 1;
                    }

                    if e == b_pos {
                        return Err(XmlError::Invalid);
                    }

                    let name = self.input[b_pos..e].to_string();

                    // Check for self-closing tag with no attributes: <name/>
                    if x == XML_TAG_OPEN && e + 1 < len && bytes[e] == b'/' && bytes[e + 1] == b'>'
                    {
                        self.pos = e + 2;
                        self.state = STATE_TEXT;
                        return Ok(XmlToken::TagCloseEmpty);
                    }

                    self.pos = e;
                    self.state = STATE_TAG;
                    return Ok(if x == XML_TAG_CLOSE {
                        XmlToken::TagClose(name)
                    } else {
                        XmlToken::TagOpen(name)
                    });
                }

                STATE_TAG => {
                    // Skip whitespace
                    let mut b_pos = c;
                    while b_pos < len
                        && (bytes[b_pos] == b' '
                            || bytes[b_pos] == b'\t'
                            || bytes[b_pos] == b'\n'
                            || bytes[b_pos] == b'\r')
                    {
                        b_pos += 1;
                    }

                    if b_pos >= len {
                        return Err(XmlError::Invalid);
                    }

                    self.inc_lines(c, b_pos);

                    // Check if this is an attribute name
                    let mut e = b_pos;
                    while e < len
                        && bytes[e] != b' '
                        && bytes[e] != b'\t'
                        && bytes[e] != b'\n'
                        && bytes[e] != b'\r'
                        && bytes[e] != b'='
                        && bytes[e] != b'/'
                        && bytes[e] != b'>'
                    {
                        e += 1;
                    }

                    if e > b_pos {
                        // An attribute name
                        let name = self.input[b_pos..e].to_string();
                        self.pos = e;
                        self.state = STATE_ATTRIBUTE;
                        return Ok(XmlToken::AttributeName(name));
                    }

                    // Check for "/>"
                    if b_pos + 1 < len && bytes[b_pos] == b'/' && bytes[b_pos + 1] == b'>' {
                        self.pos = b_pos + 2;
                        c = b_pos + 2;
                        self.state = STATE_TEXT;
                        continue;
                    }

                    if bytes[b_pos] != b'>' {
                        return Err(XmlError::Invalid);
                    }

                    c = b_pos + 1;
                    self.state = STATE_TEXT;
                    continue;
                }

                STATE_ATTRIBUTE => {
                    if bytes[c] == b'=' {
                        c += 1;
                        if c >= len {
                            return Err(XmlError::Invalid);
                        }

                        if bytes[c] == b'\'' || bytes[c] == b'"' {
                            // Quoted attribute value
                            let quote = bytes[c];
                            let search_start = c + 1;
                            let end_quote = if let Some(idx) = self.input.as_bytes()[search_start..]
                                .iter()
                                .position(|&b| b == quote)
                            {
                                search_start + idx
                            } else {
                                return Err(XmlError::Invalid);
                            };

                            self.inc_lines(c, end_quote);

                            let value = self.input[c + 1..end_quote].to_string();
                            self.pos = end_quote + 1;
                            self.state = STATE_TAG;
                            return Ok(XmlToken::AttributeValue(value));
                        }

                        // Unquoted attribute value: find whitespace or '>'
                        let mut b_pos = c;
                        while b_pos < len
                            && bytes[b_pos] != b' '
                            && bytes[b_pos] != b'\t'
                            && bytes[b_pos] != b'\n'
                            && bytes[b_pos] != b'\r'
                            && bytes[b_pos] != b'>'
                        {
                            b_pos += 1;
                        }

                        let value = self.input[c..b_pos].to_string();
                        self.pos = b_pos;
                        self.state = STATE_TAG;
                        return Ok(XmlToken::AttributeValue(value));
                    }

                    self.state = STATE_TAG;
                    continue;
                }

                _ => {
                    return Err(XmlError::Invalid);
                }
            }
        }
    }
}

// ── Convenience function ────────────────────────────────────────────────

/// Tokenize an XML string, returning all tokens.
pub fn xml_tokenize_all(input: &str) -> Result<Vec<XmlToken>, XmlError> {
    let mut tokenizer = XmlTokenizer::new(input);
    let mut tokens = Vec::new();
    loop {
        let token = tokenizer.next_token()?;
        if token == XmlToken::End {
            break;
        }
        tokens.push(token);
    }
    Ok(tokens)
}

// ── C ABI facade ──────────────────────────────────────────────────────────

/// A token ready to be published through the C ABI.
///
/// `name`, when present, is an offset range into the input C string. The
/// offsets deliberately describe bytes rather than UTF-8 character positions:
/// `xml_tokenize()` is a byte-oriented C API and must accept non-UTF-8 input.
struct RawXmlToken {
    kind: i32,
    name: Option<(usize, usize)>,
    next: usize,
    state: usize,
    /// The C implementation increments lines only after successfully
    /// allocating text. Other line changes occur while skipping syntax and
    /// are applied directly by [`tokenize_raw_c_bytes`].
    line_after_allocation: Option<(usize, usize)>,
}

fn increment_raw_lines(line: Option<&mut c_uint>, bytes: &[u8]) {
    let Some(line) = line else {
        return;
    };

    for byte in bytes {
        if *byte == b'\n' {
            // C's `unsigned` counter wraps modulo `UINT_MAX + 1`.
            *line = line.wrapping_add(1);
        }
    }
}

fn find_raw_byte(bytes: &[u8], start: usize, needle: u8) -> Option<usize> {
    bytes[start..]
        .iter()
        .position(|byte| *byte == needle)
        .map(|offset| start + offset)
}

fn find_raw_subslice(bytes: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    bytes[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| start + offset + needle.len())
}

fn is_raw_whitespace(byte: u8) -> bool {
    WHITESPACE.contains(&byte)
}

fn is_raw_tag_name_terminator(byte: u8) -> bool {
    is_raw_whitespace(byte) || matches!(byte, b'/' | b'>')
}

fn is_raw_attribute_name_terminator(byte: u8) -> bool {
    is_raw_whitespace(byte) || matches!(byte, b'=' | b'/' | b'>')
}

/// Byte-for-byte implementation of the C `xml_tokenize()` state machine.
///
/// This is intentionally separate from the ergonomic Rust [`XmlTokenizer`]:
/// the public Rust interface requires valid UTF-8, while the C ABI operates
/// on arbitrary NUL-terminated byte strings. It preserves C's deferred state
/// publication: only a returned token updates `*p` and `*state`.
fn tokenize_raw_c_bytes(
    bytes: &[u8],
    initial_state: usize,
    mut line: Option<&mut c_uint>,
) -> std::result::Result<Option<RawXmlToken>, i32> {
    let mut state = initial_state;
    let mut current = 0;

    if state == STATE_NULL {
        if let Some(line) = line.as_deref_mut() {
            *line = 1;
        }
        state = STATE_TEXT;
    }

    loop {
        if current == bytes.len() {
            // Like C, XML_END leaves `*p`, `*name`, and `*state` untouched.
            return Ok(None);
        }

        match state {
            STATE_TEXT => {
                let tag = find_raw_byte(bytes, current, b'<').unwrap_or(bytes.len());
                if tag > current {
                    return Ok(Some(RawXmlToken {
                        kind: XML_TEXT,
                        name: Some((current, tag)),
                        next: tag,
                        state: STATE_TEXT,
                        line_after_allocation: Some((current, tag)),
                    }));
                }

                // `current < bytes.len()` and the scan above stopped on '<'.
                let mut body = current + 1;

                if bytes[body..].starts_with(b"!--") {
                    let Some(after) = find_raw_subslice(bytes, body + 3, b"-->") else {
                        return Err(Errno::EINVAL.to_neg_errno());
                    };
                    increment_raw_lines(line.as_deref_mut(), &bytes[body..after]);
                    current = after;
                    continue;
                }

                if bytes.get(body) == Some(&b'?') {
                    let Some(after) = find_raw_subslice(bytes, body + 1, b"?>") else {
                        return Err(Errno::EINVAL.to_neg_errno());
                    };
                    increment_raw_lines(line.as_deref_mut(), &bytes[body..after]);
                    current = after;
                    continue;
                }

                if bytes.get(body) == Some(&b'!') {
                    let Some(end) = find_raw_byte(bytes, body + 1, b'>') else {
                        return Err(Errno::EINVAL.to_neg_errno());
                    };
                    increment_raw_lines(line.as_deref_mut(), &bytes[body..end + 1]);
                    current = end + 1;
                    continue;
                }

                let kind = if bytes.get(body) == Some(&b'/') {
                    body += 1;
                    XML_TAG_CLOSE
                } else {
                    XML_TAG_OPEN
                };

                let Some(end) = bytes[body..]
                    .iter()
                    .position(|byte| is_raw_tag_name_terminator(*byte))
                    .map(|offset| body + offset)
                else {
                    return Err(Errno::EINVAL.to_neg_errno());
                };

                // C's strndup() accepts an empty tag name, so this must not
                // reject `<>` or `</>` even though callers normally avoid it.
                return Ok(Some(RawXmlToken {
                    kind,
                    name: Some((body, end)),
                    next: end,
                    state: STATE_TAG,
                    line_after_allocation: None,
                }));
            }

            STATE_TAG => {
                let next = current
                    + bytes[current..]
                        .iter()
                        .take_while(|byte| is_raw_whitespace(**byte))
                        .count();
                if next == bytes.len() {
                    return Err(Errno::EINVAL.to_neg_errno());
                }

                increment_raw_lines(line.as_deref_mut(), &bytes[current..next]);

                let end = next
                    + bytes[next..]
                        .iter()
                        .take_while(|byte| !is_raw_attribute_name_terminator(**byte))
                        .count();
                if end > next {
                    return Ok(Some(RawXmlToken {
                        kind: XML_ATTRIBUTE_NAME,
                        name: Some((next, end)),
                        next: end,
                        state: STATE_ATTRIBUTE,
                        line_after_allocation: None,
                    }));
                }

                if bytes[next..].starts_with(b"/>") {
                    return Ok(Some(RawXmlToken {
                        kind: XML_TAG_CLOSE_EMPTY,
                        name: None,
                        next: next + 2,
                        state: STATE_TEXT,
                        line_after_allocation: None,
                    }));
                }

                if bytes[next] != b'>' {
                    return Err(Errno::EINVAL.to_neg_errno());
                }

                current = next + 1;
                state = STATE_TEXT;
            }

            STATE_ATTRIBUTE => {
                if bytes.get(current) == Some(&b'=') {
                    current += 1;

                    if let Some(quote @ (b'\'' | b'"')) = bytes.get(current).copied() {
                        let Some(end) = find_raw_byte(bytes, current + 1, quote) else {
                            return Err(Errno::EINVAL.to_neg_errno());
                        };

                        // C advances the line count before attempting the
                        // strndup() allocation for a quoted value.
                        increment_raw_lines(line.as_deref_mut(), &bytes[current..end]);
                        return Ok(Some(RawXmlToken {
                            kind: XML_ATTRIBUTE_VALUE,
                            name: Some((current + 1, end)),
                            next: end + 1,
                            state: STATE_TAG,
                            line_after_allocation: None,
                        }));
                    }

                    let end = bytes[current..]
                        .iter()
                        .position(|byte| is_raw_whitespace(*byte) || *byte == b'>')
                        .map(|offset| current + offset)
                        // C uses `b = c` when strpbrk() finds no delimiter.
                        .unwrap_or(current);
                    return Ok(Some(RawXmlToken {
                        kind: XML_ATTRIBUTE_VALUE,
                        name: Some((current, end)),
                        next: end,
                        state: STATE_TAG,
                        line_after_allocation: None,
                    }));
                }

                state = STATE_TAG;
            }

            // The C source treats this as unreachable. Returning EINVAL keeps
            // malformed foreign state from turning into undefined behavior.
            _ => return Err(Errno::EINVAL.to_neg_errno()),
        }
    }
}

fn malloc_raw_name(bytes: &[u8]) -> *mut c_char {
    let Some(allocation) = bytes.len().checked_add(1) else {
        return std::ptr::null_mut();
    };

    // SAFETY: malloc accepts any `size_t`; its allocation is deliberately
    // used so C callers may release the result with free(3), as xml.c does.
    let output = unsafe_ffi!(libc::malloc(allocation)).cast::<c_char>();
    if output.is_null() {
        return output;
    }

    if !bytes.is_empty() {
        // SAFETY: `output` has `bytes.len() + 1` writable bytes and the input
        // slice is readable for `bytes.len()` bytes. The ranges cannot overlap
        // because the output is a fresh allocation.
        unsafe_ffi!(std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            output.cast::<u8>(),
            bytes.len()
        ));
    }
    // SAFETY: the final byte is within the just-allocated output buffer.
    unsafe_ffi!(*output.cast::<u8>().add(bytes.len()) = 0);
    output
}

/// C ABI facade for `xml_tokenize()`.
///
/// The tokenizer accepts arbitrary non-NUL bytes, returns a C-allocator
/// string for tokens with a name, and encodes state as the same small pointer
/// values used by the C implementation. The returned name is always suitable
/// for the caller's `free(3)`.
///
/// # Safety
///
/// `p`, `name`, and `state` must be writable, non-null pointer storage. `*p`
/// must point to a live NUL-terminated C byte string for the call. `line`,
/// when non-null, must be writable `unsigned` storage. The input and all
/// pointed-to storage must remain valid and non-aliasing for writes throughout
/// the call. The caller retains ownership of any old `*name`; this function
/// never frees it, so callers must release an old allocation before allowing
/// it to be overwritten. A returned token publishes a fresh allocation (or
/// NULL for `XML_TAG_CLOSE_EMPTY`); `XML_END` and errors leave `*p`, `*name`,
/// and `*state` unchanged. As in C, syntax skipped before an error may still
/// have advanced the optional line counter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_xml_tokenize(
    p: *mut *const c_char,
    name: *mut *mut c_char,
    state: *mut *mut c_void,
    line: *mut c_uint,
) -> i32 {
    if p.is_null() || name.is_null() || state.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the ABI contract guarantees writable outer pointer storage.
    let input = unsafe_ffi!(*p);
    if input.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the ABI contract guarantees a live NUL-terminated C byte
    // string. `CStr` intentionally performs no UTF-8 validation.
    let bytes = unsafe_ffi!(CStr::from_ptr(input)).to_bytes();
    // SAFETY: the ABI contract guarantees writable state storage.
    let initial_state = unsafe_ffi!(*state as usize);
    let mut line = if line.is_null() {
        None
    } else {
        // SAFETY: the ABI contract guarantees writable optional line storage.
        Some(unsafe_ffi!(&mut *line))
    };

    let token = match tokenize_raw_c_bytes(bytes, initial_state, line.as_deref_mut()) {
        Ok(token) => token,
        Err(error) => return error,
    };
    let Some(token) = token else {
        return XML_END;
    };

    let allocated_name = if let Some((start, end)) = token.name {
        let output = malloc_raw_name(&bytes[start..end]);
        if output.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        output
    } else {
        std::ptr::null_mut()
    };

    if let Some((start, end)) = token.line_after_allocation {
        increment_raw_lines(line, &bytes[start..end]);
    }

    // SAFETY: the ABI contract guarantees writable output/state pointer
    // storage. `token.next` is bounded by `bytes`, so this is an in-bounds
    // position in the supplied C string (or its terminating NUL).
    unsafe_ffi!({
        *name = allocated_name;
        *p = input.add(token.next);
        *state = token.state as *mut c_void;
    });
    token.kind
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_sequence() {
        let tokens = xml_tokenize_all(r#"<a b="c">x</a>"#).unwrap();
        assert_eq!(tokens.len(), 5);
        assert_eq!(tokens[0], XmlToken::TagOpen("a".to_string()));
        assert_eq!(tokens[1], XmlToken::AttributeName("b".to_string()));
        assert_eq!(tokens[2], XmlToken::AttributeValue("c".to_string()));
        assert_eq!(tokens[3], XmlToken::Text("x".to_string()));
        assert_eq!(tokens[4], XmlToken::TagClose("a".to_string()));
    }

    #[test]
    fn test_empty_tag() {
        let tokens = xml_tokenize_all("<br/>").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], XmlToken::TagCloseEmpty);
    }

    #[test]
    fn test_comment_skipped() {
        let tokens = xml_tokenize_all("before<!-- comment -->after").unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0], XmlToken::Text("before".to_string()));
        assert_eq!(tokens[1], XmlToken::Text("after".to_string()));
    }

    #[test]
    fn test_processing_instruction_skipped() {
        let tokens = xml_tokenize_all("<?xml version=\"1.0\"?>text").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], XmlToken::Text("text".to_string()));
    }

    #[test]
    fn test_dtd_skipped() {
        let tokens = xml_tokenize_all("<!DOCTYPE html>text").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], XmlToken::Text("text".to_string()));
    }

    #[test]
    fn test_unterminated_comment() {
        let result = xml_tokenize_all("before<!-- no end");
        assert!(matches!(result, Err(XmlError::Invalid)));
    }

    #[test]
    fn test_unterminated_processing_instruction() {
        let result = xml_tokenize_all("<?xml no end");
        assert!(matches!(result, Err(XmlError::Invalid)));
    }

    #[test]
    fn test_unterminated_dtd() {
        let result = xml_tokenize_all("<!DOCTYPE no end");
        assert!(matches!(result, Err(XmlError::Invalid)));
    }

    #[test]
    fn test_unterminated_quoted_attribute() {
        let result = xml_tokenize_all(r#"<a b="x></a>"#);
        assert!(matches!(result, Err(XmlError::Invalid)));
    }

    #[test]
    fn test_single_quoted_attribute() {
        let tokens = xml_tokenize_all("<a b='val'/>").unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], XmlToken::TagOpen("a".to_string()));
        assert_eq!(tokens[1], XmlToken::AttributeName("b".to_string()));
        assert_eq!(tokens[2], XmlToken::AttributeValue("val".to_string()));
    }

    #[test]
    fn test_unquoted_attribute() {
        let tokens = xml_tokenize_all("<a b=val>").unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], XmlToken::TagOpen("a".to_string()));
        assert_eq!(tokens[1], XmlToken::AttributeName("b".to_string()));
        assert_eq!(tokens[2], XmlToken::AttributeValue("val".to_string()));
    }

    #[test]
    fn test_empty_input() {
        let tokens = xml_tokenize_all("").unwrap();
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_text_only() {
        let tokens = xml_tokenize_all("hello world").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], XmlToken::Text("hello world".to_string()));
    }

    #[test]
    fn test_nested_tags() {
        let tokens = xml_tokenize_all("<a><b>x</b></a>").unwrap();
        assert_eq!(tokens.len(), 5);
        assert_eq!(tokens[0], XmlToken::TagOpen("a".to_string()));
        assert_eq!(tokens[1], XmlToken::TagOpen("b".to_string()));
        assert_eq!(tokens[2], XmlToken::Text("x".to_string()));
        assert_eq!(tokens[3], XmlToken::TagClose("b".to_string()));
        assert_eq!(tokens[4], XmlToken::TagClose("a".to_string()));
    }

    #[test]
    fn test_multiple_attributes() {
        let tokens = xml_tokenize_all(r#"<a x="1" y='2' z=3>"#).unwrap();
        assert_eq!(tokens.len(), 7);
        assert_eq!(tokens[0], XmlToken::TagOpen("a".to_string()));
        assert_eq!(tokens[1], XmlToken::AttributeName("x".to_string()));
        assert_eq!(tokens[2], XmlToken::AttributeValue("1".to_string()));
        assert_eq!(tokens[3], XmlToken::AttributeName("y".to_string()));
        assert_eq!(tokens[4], XmlToken::AttributeValue("2".to_string()));
        assert_eq!(tokens[5], XmlToken::AttributeName("z".to_string()));
        assert_eq!(tokens[6], XmlToken::AttributeValue("3".to_string()));
    }

    #[test]
    fn test_line_tracking() {
        let mut tokenizer = XmlTokenizer::new("a\nb\nc<!-- x\ny -->\n<d>");
        let mut results = Vec::new();
        loop {
            let tok = tokenizer.next_token().unwrap();
            results.push((tok.clone(), tokenizer.line()));
            if tok == XmlToken::End {
                break;
            }
        }
        assert_eq!(results[0].1, 3); // after text "a\nb\nc"
        assert_eq!(results[1].1, 5); // after comment with newline
    }

    #[test]
    fn test_token_type_values() {
        assert_eq!(XmlToken::End.token_type(), XML_END);
        assert_eq!(XmlToken::Text("x".into()).token_type(), XML_TEXT);
        assert_eq!(XmlToken::TagOpen("a".into()).token_type(), XML_TAG_OPEN);
        assert_eq!(XmlToken::TagClose("a".into()).token_type(), XML_TAG_CLOSE);
        assert_eq!(XmlToken::TagCloseEmpty.token_type(), XML_TAG_CLOSE_EMPTY);
        assert_eq!(
            XmlToken::AttributeName("a".into()).token_type(),
            XML_ATTRIBUTE_NAME
        );
        assert_eq!(
            XmlToken::AttributeValue("v".into()).token_type(),
            XML_ATTRIBUTE_VALUE
        );
    }

    #[test]
    fn test_boolean_attribute() {
        let tokens = xml_tokenize_all("<input disabled name=val>").unwrap();
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[0], XmlToken::TagOpen("input".to_string()));
        assert_eq!(tokens[1], XmlToken::AttributeName("disabled".to_string()));
        assert_eq!(tokens[2], XmlToken::AttributeName("name".to_string()));
        assert_eq!(tokens[3], XmlToken::AttributeValue("val".to_string()));
    }
}
