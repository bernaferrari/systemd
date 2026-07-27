// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/xml.c
//
// Simplified XML tokenizer. Supports basic XML syntax with HTML5-like
// simplifications (e.g. unquoted attribute values).

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
