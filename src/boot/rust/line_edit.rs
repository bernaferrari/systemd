// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/line-edit.c
//
// EFI console line editor.
//
// Provides a simple line editor for EFI console input with cursor
// movement, word navigation, kill operations, and character
// insertion/deletion. Matches the C implementation's readline-like
// behavior for the systemd-boot menu.

// ── Cursor movement ───────────────────────────────────────────────────────

/// Move the cursor one position to the left.
///
/// If the cursor is at position 0, scroll the first offset left
/// instead (panning the visible window).
pub fn cursor_left(cursor: &mut usize, first: &mut usize) {
    if *cursor > 0 {
        *cursor -= 1;
    } else if *first > 0 {
        *first -= 1;
    }
}

/// Move the cursor one position to the right.
///
/// If the cursor is at the right edge (x_max - 1), scroll the first
/// offset right instead. Will not move past the end of the line.
pub fn cursor_right(cursor: &mut usize, first: &mut usize, x_max: usize, len: usize) {
    if *cursor + *first + 1 >= len {
        return;
    }
    if *cursor + 1 < x_max {
        *cursor += 1;
    } else if *first + *cursor < len {
        *first += 1;
    }
}

// ── Line editing state ────────────────────────────────────────────────────

/// Represents the state of a line being edited.
#[derive(Debug, Clone)]
pub struct LineEdit {
    /// The characters in the line
    pub line: Vec<u16>,
    /// Current cursor position within the visible window
    pub cursor: usize,
    /// First visible character offset (for horizontal scrolling)
    pub first: usize,
    /// Maximum visible width
    pub x_max: usize,
}

impl LineEdit {
    pub fn new(initial: &[u16], x_max: usize) -> Self {
        Self {
            line: initial.to_vec(),
            cursor: 0,
            first: 0,
            x_max,
        }
    }

    pub fn len(&self) -> usize {
        self.line.len()
    }

    pub fn is_empty(&self) -> bool {
        self.line.is_empty()
    }

    /// Position in the full line (first + cursor)
    pub fn pos(&self) -> usize {
        self.first + self.cursor
    }

    /// Move cursor to beginning of line
    pub fn move_home(&mut self) {
        self.cursor = 0;
        self.first = 0;
    }

    /// Move cursor to end of line
    pub fn move_end(&mut self) {
        let len = self.len();
        self.cursor = len - self.first;
        if self.cursor + 1 >= self.x_max {
            self.cursor = self.x_max - 1;
            self.first = len - (self.x_max - 1);
        }
    }

    /// Move cursor left by one character
    pub fn move_left(&mut self) {
        cursor_left(&mut self.cursor, &mut self.first);
    }

    /// Move cursor right by one character
    pub fn move_right(&mut self) {
        let x_max = self.x_max;
        let len = self.len();
        cursor_right(&mut self.cursor, &mut self.first, x_max, len);
    }

    /// Move cursor forward one word (skip spaces, then skip non-spaces)
    pub fn forward_word(&mut self) {
        let len = self.len();
        let pos = self.pos();
        let mut i = pos;

        // Skip spaces
        while i < len && self.line[i] == b' ' as u16 {
            cursor_right(&mut self.cursor, &mut self.first, self.x_max, len);
            i += 1;
        }
        // Skip non-spaces
        while i < len && self.line[i] != b' ' as u16 {
            cursor_right(&mut self.cursor, &mut self.first, self.x_max, len);
            i += 1;
        }
    }

    /// Move cursor backward one word
    pub fn backward_word(&mut self) {
        // Skip non-spaces backward
        let mut p = self.pos();
        while p > 0 && self.line[p - 1] != b' ' as u16 {
            cursor_left(&mut self.cursor, &mut self.first);
            p = self.pos();
        }
        // Skip spaces backward
        p = self.pos();
        while p > 0 && self.line[p - 1] == b' ' as u16 {
            cursor_left(&mut self.cursor, &mut self.first);
            p = self.pos();
        }
        // Skip non-spaces backward (to beginning of previous word)
        p = self.pos();
        while p > 0 && self.line[p - 1] != b' ' as u16 {
            cursor_left(&mut self.cursor, &mut self.first);
            p = self.pos();
        }
    }

    /// Delete character at cursor (forward delete)
    pub fn delete_char(&mut self) -> usize {
        let len = self.len();
        if len == 0 {
            return 0;
        }
        let pos = self.pos();
        if pos == len {
            return 0;
        }
        self.line.remove(pos);
        1
    }

    /// Delete character before cursor (backspace)
    pub fn backspace(&mut self) -> usize {
        let len = self.len();
        if len == 0 {
            return 0;
        }
        if self.first == 0 && self.cursor == 0 {
            return 0;
        }
        let pos = self.pos();
        if pos >= len {
            return 0;
        }
        self.line.remove(pos);
        if self.cursor > 0 {
            self.cursor -= 1;
        }
        1
    }

    /// Kill (delete) from cursor to end of line
    pub fn kill_line(&mut self) -> usize {
        let pos = self.pos();
        let cleared = self.len() - pos;
        self.line.truncate(pos);
        cleared
    }

    /// Kill word forward from cursor
    pub fn kill_word(&mut self) -> usize {
        let len = self.len();
        let pos = self.pos();
        let mut k = pos;

        while k < len && self.line[k] == b' ' as u16 {
            k += 1;
        }
        while k < len && self.line[k] != b' ' as u16 {
            k += 1;
        }

        let clear = k - pos;
        self.line.drain(pos..k);
        clear
    }

    /// Kill word backward from cursor
    pub fn backward_kill_word(&mut self) -> usize {
        let pos = self.pos();
        if pos == 0 {
            return 0;
        }

        let mut clear = 0;
        let mut p = pos;

        if p > 0 && self.line[p - 1] == b' ' as u16 {
            cursor_left(&mut self.cursor, &mut self.first);
            clear += 1;
            p = self.pos();
            while p > 0 && self.line[p] == b' ' as u16 {
                cursor_left(&mut self.cursor, &mut self.first);
                clear += 1;
                p = self.pos();
            }
        }
        while p > 0 && self.line[p - 1] != b' ' as u16 {
            cursor_left(&mut self.cursor, &mut self.first);
            clear += 1;
            p = self.pos();
        }

        let new_pos = self.pos();
        self.line.drain(new_pos..new_pos + clear);
        clear
    }

    /// Insert a character at the cursor position
    pub fn insert_char(&mut self, ch: u16, max_size: usize) -> bool {
        let len = self.len();
        if len + 1 == max_size {
            return false;
        }
        let pos = self.pos();
        self.line.insert(pos, ch);
        cursor_right(&mut self.cursor, &mut self.first, self.x_max, len + 1);
        true
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_str(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn test_cursor_left_basic() {
        let mut cursor = 5usize;
        let mut first = 0usize;
        cursor_left(&mut cursor, &mut first);
        assert_eq!(cursor, 4);
        assert_eq!(first, 0);
    }

    #[test]
    fn test_cursor_left_at_zero_scrolls_first() {
        let mut cursor = 0usize;
        let mut first = 5usize;
        cursor_left(&mut cursor, &mut first);
        assert_eq!(cursor, 0);
        assert_eq!(first, 4);
    }

    #[test]
    fn test_cursor_left_at_zero_no_scroll() {
        let mut cursor = 0usize;
        let mut first = 0usize;
        cursor_left(&mut cursor, &mut first);
        assert_eq!(cursor, 0);
        assert_eq!(first, 0);
    }

    #[test]
    fn test_cursor_right_basic() {
        let mut cursor = 3usize;
        let mut first = 0usize;
        cursor_right(&mut cursor, &mut first, 80, 20);
        assert_eq!(cursor, 4);
    }

    #[test]
    fn test_cursor_right_at_edge_scrolls_first() {
        let mut cursor = 79usize;
        let mut first = 0usize;
        cursor_right(&mut cursor, &mut first, 80, 100);
        assert_eq!(cursor, 79);
        assert_eq!(first, 1);
    }

    #[test]
    fn test_cursor_right_at_end_of_line() {
        let mut cursor = 9usize;
        let mut first = 0usize;
        cursor_right(&mut cursor, &mut first, 80, 10);
        assert_eq!(cursor, 9);
    }

    #[test]
    fn test_line_edit_move_home() {
        let mut le = LineEdit::new(&u16_str("hello world"), 80);
        le.cursor = 5;
        le.first = 3;
        le.move_home();
        assert_eq!(le.cursor, 0);
        assert_eq!(le.first, 0);
    }

    #[test]
    fn test_line_edit_move_end() {
        let line = u16_str("hello world");
        let len = line.len();
        let mut le = LineEdit::new(&line, 80);
        le.move_end();
        assert_eq!(le.pos(), len);
    }

    #[test]
    fn test_line_edit_move_end_small_window() {
        let line = u16_str("hello world this is a longer string");
        let len = line.len();
        let mut le = LineEdit::new(&line, 10);
        le.move_end();
        assert_eq!(le.pos(), len);
        assert!(le.cursor < le.x_max);
    }

    #[test]
    fn test_line_edit_insert_char() {
        let mut le = LineEdit::new(&u16_str("hllo"), 80);
        le.cursor = 1;
        le.insert_char('e' as u16, 100);
        assert_eq!(le.line, u16_str("hello"));
    }

    #[test]
    fn test_line_edit_delete_char() {
        let mut le = LineEdit::new(&u16_str("hello"), 80);
        le.cursor = 1;
        le.delete_char();
        assert_eq!(le.line, u16_str("hllo"));
    }

    #[test]
    fn test_line_edit_backspace() {
        let mut le = LineEdit::new(&u16_str("hello"), 80);
        le.cursor = 2;
        le.backspace();
        assert_eq!(le.line, u16_str("helo"));
        assert_eq!(le.cursor, 1);
    }

    #[test]
    fn test_line_edit_kill_line() {
        let mut le = LineEdit::new(&u16_str("hello world"), 80);
        le.cursor = 5;
        le.kill_line();
        assert_eq!(le.line, u16_str("hello"));
    }

    #[test]
    fn test_line_edit_kill_word() {
        let mut le = LineEdit::new(&u16_str("hello world test"), 80);
        le.cursor = 5;
        le.kill_word();
        assert_eq!(le.line, u16_str("hello test"));
    }

    #[test]
    fn test_line_edit_forward_word() {
        let mut le = LineEdit::new(&u16_str("hello world test"), 80);
        le.forward_word();
        assert_eq!(le.pos(), 5);
    }

    #[test]
    fn test_line_edit_backward_word() {
        let mut le = LineEdit::new(&u16_str("hello world test"), 80);
        le.cursor = 10;
        le.backward_word();
        assert!(le.pos() <= 5);
    }

    #[test]
    fn test_line_edit_backspace_at_start() {
        let mut le = LineEdit::new(&u16_str("hello"), 80);
        assert_eq!(le.backspace(), 0);
        assert_eq!(le.line, u16_str("hello"));
    }

    #[test]
    fn test_line_edit_delete_at_end() {
        let mut le = LineEdit::new(&u16_str("hi"), 80);
        le.cursor = 2;
        assert_eq!(le.delete_char(), 0);
        assert_eq!(le.line, u16_str("hi"));
    }

    #[test]
    fn test_line_edit_insert_at_max() {
        let mut le = LineEdit::new(&u16_str("hello"), 6);
        le.cursor = 5;
        assert!(!le.insert_char('!' as u16, 6));
    }
}
