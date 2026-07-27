// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/xml.c, src/shared/xml.h

use std::fmt;

use crate::ffi::Errno;

pub type Result<T> = std::result::Result<T, XmlError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XmlState {
    #[default]
    Null,
    Text,
    Tag,
    Attribute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum XmlTokenKind {
    End = 0,
    Text = 1,
    TagOpen = 2,
    TagClose = 3,
    TagCloseEmpty = 4,
    AttributeName = 5,
    AttributeValue = 6,
}

impl XmlTokenKind {
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlToken {
    pub kind: XmlTokenKind,
    pub name: Option<String>,
}

impl XmlToken {
    fn new(kind: XmlTokenKind, name: Option<String>) -> Self {
        Self { kind, name }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlError {
    pub code: i32,
}

impl XmlError {
    pub const fn invalid_argument() -> Self {
        Self {
            code: Errno::EINVAL.to_neg_errno(),
        }
    }
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XML tokenizer error (errno {})", self.code)
    }
}

impl std::error::Error for XmlError {}

#[derive(Debug, Clone)]
pub struct XmlTokenizer<'a> {
    input: &'a str,
    cursor: usize,
    state: XmlState,
    line: u32,
}

impl<'a> XmlTokenizer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            cursor: 0,
            state: XmlState::Null,
            line: 0,
        }
    }

    pub fn next_token(&mut self) -> Result<XmlToken> {
        xml_tokenize(
            self.input,
            &mut self.cursor,
            &mut self.state,
            Some(&mut self.line),
        )
    }

    pub fn line(&self) -> u32 {
        self.line
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn state(&self) -> XmlState {
        self.state
    }
}

pub fn inc_lines(mut line: Option<&mut u32>, s: &str, n: usize) {
    let Some(line) = line.as_deref_mut() else {
        return;
    };

    for byte in s.as_bytes().iter().take(n) {
        if *byte == b'\n' {
            *line += 1;
        }
    }
}

pub fn xml_tokenize(
    input: &str,
    cursor: &mut usize,
    state: &mut XmlState,
    mut line: Option<&mut u32>,
) -> Result<XmlToken> {
    let bytes = input.as_bytes();
    let mut current_state = *state;
    let mut current = *cursor;

    if current_state == XmlState::Null {
        if let Some(line) = line.as_deref_mut() {
            *line = 1;
        }
        current_state = XmlState::Text;
    }

    loop {
        if current >= bytes.len() {
            *cursor = current;
            *state = current_state;
            return Ok(XmlToken::new(XmlTokenKind::End, None));
        }

        match current_state {
            XmlState::Null => return Err(XmlError::invalid_argument()),

            XmlState::Text => {
                let end = find_byte(bytes, current, b'<').unwrap_or(bytes.len());
                if end > current {
                    if input[current..end]
                        .bytes()
                        .all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
                    {
                        current = end;
                        continue;
                    }

                    inc_lines(line.as_deref_mut(), &input[current..end], end - current);

                    *cursor = end;
                    *state = XmlState::Text;
                    return Ok(XmlToken::new(
                        XmlTokenKind::Text,
                        Some(input[current..end].to_owned()),
                    ));
                }

                let mut body = current + 1;

                if starts_with_at(bytes, body, b"!--") {
                    let Some(next) = find_subslice_after(bytes, body + 3, b"-->") else {
                        return Err(XmlError::invalid_argument());
                    };

                    inc_lines(line.as_deref_mut(), &input[body..next], next - body);
                    current = next;
                    continue;
                }

                if byte_at(bytes, body) == Some(b'?') {
                    let Some(next) = find_subslice_after(bytes, body + 1, b"?>") else {
                        return Err(XmlError::invalid_argument());
                    };

                    inc_lines(line.as_deref_mut(), &input[body..next], next - body);
                    current = next;
                    continue;
                }

                if byte_at(bytes, body) == Some(b'!') {
                    let Some(end) = find_byte(bytes, body + 1, b'>') else {
                        return Err(XmlError::invalid_argument());
                    };

                    inc_lines(line.as_deref_mut(), &input[body..end + 1], end + 1 - body);
                    current = end + 1;
                    continue;
                }

                let kind = if byte_at(bytes, body) == Some(b'/') {
                    body += 1;
                    XmlTokenKind::TagClose
                } else {
                    XmlTokenKind::TagOpen
                };

                let Some(end) =
                    find_first_of(bytes, body, |b| is_whitespace(b) || b == b'/' || b == b'>')
                else {
                    return Err(XmlError::invalid_argument());
                };

                *cursor = end;
                *state = XmlState::Tag;
                return Ok(XmlToken::new(kind, Some(input[body..end].to_owned())));
            }

            XmlState::Tag => {
                let next = current + count_while(bytes, current, is_whitespace);
                if next >= bytes.len() {
                    return Err(XmlError::invalid_argument());
                }

                inc_lines(line.as_deref_mut(), &input[current..next], next - current);

                let end = next
                    + count_until(bytes, next, |b| {
                        is_whitespace(b) || b == b'=' || b == b'/' || b == b'>'
                    });
                if end > next {
                    *cursor = end;
                    *state = XmlState::Attribute;
                    return Ok(XmlToken::new(
                        XmlTokenKind::AttributeName,
                        Some(input[next..end].to_owned()),
                    ));
                }

                if starts_with_at(bytes, next, b"/>") {
                    *cursor = next + 2;
                    *state = XmlState::Text;
                    return Ok(XmlToken::new(XmlTokenKind::TagCloseEmpty, None));
                }

                if bytes[next] != b'>' {
                    return Err(XmlError::invalid_argument());
                }

                current = next + 1;
                current_state = XmlState::Text;
            }

            XmlState::Attribute => {
                if byte_at(bytes, current) == Some(b'=') {
                    current += 1;

                    if matches!(byte_at(bytes, current), Some(b'\'' | b'"')) {
                        let quote = bytes[current];
                        let Some(end) = find_byte(bytes, current + 1, quote) else {
                            return Err(XmlError::invalid_argument());
                        };

                        inc_lines(line.as_deref_mut(), &input[current..end], end - current);

                        *cursor = end + 1;
                        *state = XmlState::Tag;
                        return Ok(XmlToken::new(
                            XmlTokenKind::AttributeValue,
                            Some(input[current + 1..end].to_owned()),
                        ));
                    }

                    let end = find_first_of(bytes, current, |b| is_whitespace(b) || b == b'>')
                        .unwrap_or(current);

                    *cursor = end;
                    *state = XmlState::Tag;
                    return Ok(XmlToken::new(
                        XmlTokenKind::AttributeValue,
                        Some(input[current..end].to_owned()),
                    ));
                }

                current_state = XmlState::Tag;
            }
        }
    }
}

const fn is_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn byte_at(bytes: &[u8], index: usize) -> Option<u8> {
    bytes.get(index).copied()
}

fn starts_with_at(bytes: &[u8], index: usize, needle: &[u8]) -> bool {
    bytes.get(index..index + needle.len()) == Some(needle)
}

fn find_byte(bytes: &[u8], start: usize, needle: u8) -> Option<usize> {
    bytes[start..]
        .iter()
        .position(|b| *b == needle)
        .map(|offset| start + offset)
}

fn find_subslice_after(bytes: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(start);
    }

    bytes[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| start + offset + needle.len())
}

fn find_first_of<F>(bytes: &[u8], start: usize, predicate: F) -> Option<usize>
where
    F: Fn(u8) -> bool,
{
    bytes[start..]
        .iter()
        .position(|b| predicate(*b))
        .map(|offset| start + offset)
}

fn count_while<F>(bytes: &[u8], start: usize, predicate: F) -> usize
where
    F: Fn(u8) -> bool,
{
    bytes[start..].iter().take_while(|b| predicate(**b)).count()
}

fn count_until<F>(bytes: &[u8], start: usize, predicate: F) -> usize
where
    F: Fn(u8) -> bool,
{
    bytes[start..]
        .iter()
        .take_while(|b| !predicate(**b))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_tokens(input: &str) -> Result<(Vec<XmlToken>, u32)> {
        let mut tokenizer = XmlTokenizer::new(input);
        let mut tokens = Vec::new();

        loop {
            let token = tokenizer.next_token()?;
            let done = token.kind == XmlTokenKind::End;
            tokens.push(token);
            if done {
                return Ok((tokens, tokenizer.line()));
            }
        }
    }

    #[test]
    fn inc_lines_counts_newlines_in_prefix() {
        let mut line = 5;
        inc_lines(Some(&mut line), "a\nb\nc\nd", 5);
        assert_eq!(line, 7);
    }

    #[test]
    fn empty_input_returns_end_and_initializes_line() {
        let mut tokenizer = XmlTokenizer::new("");
        let token = tokenizer.next_token().unwrap();
        assert_eq!(token.kind, XmlTokenKind::End);
        assert_eq!(token.name, None);
        assert_eq!(tokenizer.line(), 1);
    }

    #[test]
    fn tokenizes_simple_element_sequence() {
        let (tokens, line) = collect_tokens("<a b=\"c\">x</a>").unwrap();
        assert_eq!(line, 1);
        assert_eq!(tokens.len(), 6);
        assert_eq!(
            tokens[0],
            XmlToken::new(XmlTokenKind::TagOpen, Some("a".into()))
        );
        assert_eq!(
            tokens[1],
            XmlToken::new(XmlTokenKind::AttributeName, Some("b".into()))
        );
        assert_eq!(
            tokens[2],
            XmlToken::new(XmlTokenKind::AttributeValue, Some("c".into()))
        );
        assert_eq!(
            tokens[3],
            XmlToken::new(XmlTokenKind::Text, Some("x".into()))
        );
        assert_eq!(
            tokens[4],
            XmlToken::new(XmlTokenKind::TagClose, Some("a".into()))
        );
        assert_eq!(tokens[5], XmlToken::new(XmlTokenKind::End, None));
    }

    #[test]
    fn tokenizes_empty_tag() {
        let (tokens, _) = collect_tokens("<br/>").unwrap();
        assert_eq!(
            tokens[0],
            XmlToken::new(XmlTokenKind::TagOpen, Some("br".into()))
        );
        assert_eq!(tokens[1], XmlToken::new(XmlTokenKind::TagCloseEmpty, None));
        assert_eq!(tokens[2], XmlToken::new(XmlTokenKind::End, None));
    }

    #[test]
    fn tokenizes_boolean_attribute_before_next_attribute() {
        let (tokens, _) = collect_tokens("<input disabled value=ok>").unwrap();
        assert_eq!(
            tokens[0],
            XmlToken::new(XmlTokenKind::TagOpen, Some("input".into()))
        );
        assert_eq!(
            tokens[1],
            XmlToken::new(XmlTokenKind::AttributeName, Some("disabled".into()))
        );
        assert_eq!(
            tokens[2],
            XmlToken::new(XmlTokenKind::AttributeName, Some("value".into()))
        );
        assert_eq!(
            tokens[3],
            XmlToken::new(XmlTokenKind::AttributeValue, Some("ok".into()))
        );
        assert_eq!(tokens[4], XmlToken::new(XmlTokenKind::End, None));
    }

    #[test]
    fn tokenizes_single_quoted_attribute_value() {
        let (tokens, _) = collect_tokens("<a b='c'></a>").unwrap();
        assert_eq!(
            tokens[2],
            XmlToken::new(XmlTokenKind::AttributeValue, Some("c".into()))
        );
    }

    #[test]
    fn tokenizes_unquoted_attribute_value() {
        let (tokens, _) = collect_tokens("<a b=value></a>").unwrap();
        assert_eq!(
            tokens[2],
            XmlToken::new(XmlTokenKind::AttributeValue, Some("value".into()))
        );
    }

    #[test]
    fn preserves_text_before_and_after_tags() {
        let (tokens, _) = collect_tokens("hello<x/>world").unwrap();
        assert_eq!(
            tokens[0],
            XmlToken::new(XmlTokenKind::Text, Some("hello".into()))
        );
        assert_eq!(
            tokens[1],
            XmlToken::new(XmlTokenKind::TagOpen, Some("x".into()))
        );
        assert_eq!(tokens[2], XmlToken::new(XmlTokenKind::TagCloseEmpty, None));
        assert_eq!(
            tokens[3],
            XmlToken::new(XmlTokenKind::Text, Some("world".into()))
        );
        assert_eq!(tokens[4], XmlToken::new(XmlTokenKind::End, None));
    }

    #[test]
    fn skips_comments() {
        let (tokens, _) = collect_tokens("<!-- ignore --><x/>").unwrap();
        assert_eq!(
            tokens[0],
            XmlToken::new(XmlTokenKind::TagOpen, Some("x".into()))
        );
        assert_eq!(tokens[1], XmlToken::new(XmlTokenKind::TagCloseEmpty, None));
        assert_eq!(tokens[2], XmlToken::new(XmlTokenKind::End, None));
    }

    #[test]
    fn skips_processing_instructions() {
        let (tokens, _) = collect_tokens("<?xml version=\"1.0\"?><x/>").unwrap();
        assert_eq!(
            tokens[0],
            XmlToken::new(XmlTokenKind::TagOpen, Some("x".into()))
        );
        assert_eq!(tokens[1], XmlToken::new(XmlTokenKind::TagCloseEmpty, None));
    }

    #[test]
    fn skips_dtd_like_declarations() {
        let (tokens, _) = collect_tokens("<!DOCTYPE test><x/>").unwrap();
        assert_eq!(
            tokens[0],
            XmlToken::new(XmlTokenKind::TagOpen, Some("x".into()))
        );
        assert_eq!(tokens[1], XmlToken::new(XmlTokenKind::TagCloseEmpty, None));
    }

    #[test]
    fn updates_line_numbers_across_skipped_sections() {
        let input = "<!-- one\ntwo -->\n<root\n attr=\"a\nb\">text</root>";
        let (tokens, line) = collect_tokens(input).unwrap();
        assert_eq!(
            tokens[0],
            XmlToken::new(XmlTokenKind::TagOpen, Some("root".into()))
        );
        assert_eq!(
            tokens[1],
            XmlToken::new(XmlTokenKind::AttributeName, Some("attr".into()))
        );
        assert_eq!(
            tokens[2],
            XmlToken::new(XmlTokenKind::AttributeValue, Some("a\nb".into()))
        );
        assert_eq!(line, 4);
    }

    #[test]
    fn tag_whitespace_advances_line_counter_before_attribute() {
        let mut tokenizer = XmlTokenizer::new("<x\n y=\"z\"/>");
        assert_eq!(tokenizer.next_token().unwrap().kind, XmlTokenKind::TagOpen);
        assert_eq!(tokenizer.line(), 1);
        assert_eq!(
            tokenizer.next_token().unwrap().kind,
            XmlTokenKind::AttributeName
        );
        assert_eq!(tokenizer.line(), 2);
    }

    #[test]
    fn rejects_unterminated_comment() {
        let err = collect_tokens("<!-- nope").unwrap_err();
        assert_eq!(err, XmlError::invalid_argument());
    }

    #[test]
    fn rejects_unterminated_processing_instruction() {
        let err = collect_tokens("<?xml").unwrap_err();
        assert_eq!(err, XmlError::invalid_argument());
    }

    #[test]
    fn rejects_unterminated_quoted_attribute() {
        let mut tokenizer = XmlTokenizer::new("<a b=\"x></a>");
        assert_eq!(tokenizer.next_token().unwrap().kind, XmlTokenKind::TagOpen);
        assert_eq!(
            tokenizer.next_token().unwrap().kind,
            XmlTokenKind::AttributeName
        );
        let err = tokenizer.next_token().unwrap_err();
        assert_eq!(err, XmlError::invalid_argument());
    }

    #[test]
    fn rejects_tag_without_name_terminator() {
        let err = collect_tokens("<tag").unwrap_err();
        assert_eq!(err, XmlError::invalid_argument());
    }

    #[test]
    fn exposes_raw_token_values_matching_c_enum() {
        assert_eq!(XmlTokenKind::End.as_raw(), 0);
        assert_eq!(XmlTokenKind::Text.as_raw(), 1);
        assert_eq!(XmlTokenKind::TagOpen.as_raw(), 2);
        assert_eq!(XmlTokenKind::TagClose.as_raw(), 3);
        assert_eq!(XmlTokenKind::TagCloseEmpty.as_raw(), 4);
        assert_eq!(XmlTokenKind::AttributeName.as_raw(), 5);
        assert_eq!(XmlTokenKind::AttributeValue.as_raw(), 6);
    }
}
