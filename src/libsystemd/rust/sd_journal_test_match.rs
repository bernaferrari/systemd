// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-match.c

use std::collections::BTreeSet;

pub const SD_JOURNAL_ASSUME_IMMUTABLE: i32 = 1;
pub const EXPECTED_MATCH_STRING: &str = "(((L3=ok OR L3=yes) OR ((L4_2=ok OR L4_2=yes) AND (L4_1=ok OR L4_1=yes))) AND ((TWO=two AND (ONE=two OR ONE=one)) OR (PIFF=paff AND (QUUX=yyyyy OR QUUX=xxxxx OR QUUX=mmmm) AND (HALLO= OR HALLO=WALDO) AND B=C\\000D AND A=\\001\\002)))";

pub type Result<T> = std::result::Result<T, MatchError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchError {
    InvalidField,
    MissingEquals,
    EmptyField,
    EmptyJournal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchItem {
    data: Vec<u8>,
}

impl MatchItem {
    pub fn new(data: impl Into<Vec<u8>>) -> Result<Self> {
        let data = data.into();
        validate_match_bytes(&data)?;
        Ok(Self { data })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn field(&self) -> &[u8] {
        let eq = self
            .data
            .iter()
            .position(|b| *b == b'=')
            .expect("validated match must contain '='");
        &self.data[..eq]
    }

    pub fn render(&self) -> String {
        self.data.iter().map(|b| escape_byte(*b)).collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchClause {
    items: Vec<MatchItem>,
}

impl MatchClause {
    pub fn push(&mut self, item: MatchItem) {
        self.items.push(item);
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn render(&self) -> Result<String> {
        if self.items.is_empty() {
            return Err(MatchError::EmptyJournal);
        }

        let mut field_order: Vec<Vec<u8>> = Vec::new();
        for item in &self.items {
            let field = item.field().to_vec();
            if !field_order.iter().any(|known| known == &field) {
                field_order.push(field);
            }
        }

        let mut terms = Vec::new();
        for field in field_order.into_iter().rev() {
            let mut seen = BTreeSet::new();
            let mut rendered = Vec::new();

            for item in self
                .items
                .iter()
                .filter(|item| item.field() == field.as_slice())
            {
                let text = item.render();
                if seen.insert(text.clone()) {
                    rendered.push(text);
                }
            }

            rendered.reverse();
            terms.push(join_terms(rendered, "OR"));
        }

        Ok(join_terms(terms, "AND"))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchTerm {
    clauses: Vec<MatchClause>,
}

impl MatchTerm {
    fn current_clause_mut(&mut self) -> &mut MatchClause {
        if self.clauses.is_empty() {
            self.clauses.push(MatchClause::default());
        }
        self.clauses.last_mut().expect("clause just inserted")
    }

    pub fn add_match(&mut self, item: MatchItem) {
        self.current_clause_mut().push(item);
    }

    pub fn add_disjunction(&mut self) {
        if self.current_clause_mut().is_empty() {
            return;
        }
        self.clauses.push(MatchClause::default());
    }

    pub fn render(&self) -> Result<String> {
        let rendered: Vec<String> = self
            .clauses
            .iter()
            .filter(|clause| !clause.is_empty())
            .map(MatchClause::render)
            .collect::<Result<_>>()?;

        if rendered.is_empty() {
            return Err(MatchError::EmptyJournal);
        }

        Ok(join_terms(rendered.into_iter().rev().collect(), "OR"))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalMatchExpression {
    terms: Vec<MatchTerm>,
}

impl JournalMatchExpression {
    pub fn new() -> Self {
        Self {
            terms: vec![MatchTerm::default()],
        }
    }

    fn current_term_mut(&mut self) -> &mut MatchTerm {
        if self.terms.is_empty() {
            self.terms.push(MatchTerm::default());
        }
        self.terms.last_mut().expect("term just inserted")
    }

    pub fn add_match_bytes(&mut self, data: impl Into<Vec<u8>>) -> Result<()> {
        let item = MatchItem::new(data)?;
        self.current_term_mut().add_match(item);
        Ok(())
    }

    pub fn add_match_str(&mut self, data: &str) -> Result<()> {
        self.add_match_bytes(data.as_bytes().to_vec())
    }

    pub fn add_disjunction(&mut self) {
        self.current_term_mut().add_disjunction();
    }

    pub fn add_conjunction(&mut self) {
        if self
            .current_term_mut()
            .clauses
            .iter()
            .all(MatchClause::is_empty)
        {
            return;
        }
        self.terms.push(MatchTerm::default());
    }

    pub fn render(&self) -> Result<String> {
        let rendered: Vec<String> = self
            .terms
            .iter()
            .map(MatchTerm::render)
            .collect::<Result<_>>()?;

        Ok(join_terms(rendered.into_iter().rev().collect(), "AND"))
    }
}

pub fn validate_match_bytes(data: &[u8]) -> Result<()> {
    let Some(eq) = data.iter().position(|b| *b == b'=') else {
        return Err(MatchError::MissingEquals);
    };
    if eq == 0 {
        return Err(MatchError::EmptyField);
    }
    if !field_name_is_valid(&data[..eq]) {
        return Err(MatchError::InvalidField);
    }
    Ok(())
}

pub fn field_name_is_valid(field: &[u8]) -> bool {
    !field.is_empty()
        && field[0].is_ascii_uppercase()
        && field
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
}

pub fn escape_byte(byte: u8) -> String {
    match byte {
        0 => "\\000".into(),
        b'\\' => "\\\\".into(),
        byte if byte.is_ascii_graphic() || byte == b' ' => char::from(byte).to_string(),
        byte => format!("\\{:03o}", byte),
    }
}

pub fn build_reference_expression() -> Result<JournalMatchExpression> {
    let mut journal = JournalMatchExpression::new();

    journal.add_match_bytes(vec![b'A', b'=', 1, 2])?;
    journal.add_match_bytes(vec![b'B', b'=', b'C', 0, b'D'])?;
    journal.add_match_str("HALLO=WALDO")?;
    journal.add_match_str("QUUX=mmmm")?;
    journal.add_match_str("QUUX=xxxxx")?;
    journal.add_match_str("HALLO=")?;
    journal.add_match_str("QUUX=xxxxx")?;
    journal.add_match_str("QUUX=yyyyy")?;
    journal.add_match_str("PIFF=paff")?;
    journal.add_disjunction();
    journal.add_match_str("ONE=one")?;
    journal.add_match_str("ONE=two")?;
    journal.add_match_str("TWO=two")?;
    journal.add_conjunction();
    journal.add_match_str("L4_1=yes")?;
    journal.add_match_str("L4_1=ok")?;
    journal.add_match_str("L4_2=yes")?;
    journal.add_match_str("L4_2=ok")?;
    journal.add_disjunction();
    journal.add_match_str("L3=yes")?;
    journal.add_match_str("L3=ok")?;

    Ok(journal)
}

fn join_terms(mut terms: Vec<String>, op: &str) -> String {
    if terms.len() == 1 {
        return terms.pop().expect("single element exists");
    }

    format!("({})", terms.join(&format!(" {op} ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_equals() {
        assert_eq!(
            validate_match_bytes(b"foobar"),
            Err(MatchError::MissingEquals)
        );
    }

    #[test]
    fn rejects_lowercase_field() {
        assert_eq!(
            validate_match_bytes(b"foobar=waldo"),
            Err(MatchError::InvalidField)
        );
    }

    #[test]
    fn rejects_empty_field() {
        assert_eq!(validate_match_bytes(b"="), Err(MatchError::EmptyField));
    }

    #[test]
    fn accepts_binary_payloads() {
        assert!(validate_match_bytes(&[b'A', b'=', 1, 2]).is_ok());
        assert!(validate_match_bytes(&[b'B', b'=', b'C', 0, b'D']).is_ok());
    }

    #[test]
    fn escapes_binary_data_like_c_test() {
        assert_eq!(
            MatchItem::new(vec![b'B', b'=', b'C', 0, b'D'])
                .unwrap()
                .render(),
            "B=C\\000D"
        );
        assert_eq!(
            MatchItem::new(vec![b'A', b'=', 1, 2]).unwrap().render(),
            "A=\\001\\002"
        );
    }

    #[test]
    fn groups_repeated_fields_as_disjunctions() {
        let mut clause = MatchClause::default();
        clause.push(MatchItem::new(b"HALLO=WALDO".to_vec()).unwrap());
        clause.push(MatchItem::new(b"HALLO=".to_vec()).unwrap());
        assert_eq!(clause.render().unwrap(), "(HALLO= OR HALLO=WALDO)");
    }

    #[test]
    fn deduplicates_duplicate_matches() {
        let mut clause = MatchClause::default();
        clause.push(MatchItem::new(b"QUUX=mmmm".to_vec()).unwrap());
        clause.push(MatchItem::new(b"QUUX=xxxxx".to_vec()).unwrap());
        clause.push(MatchItem::new(b"QUUX=xxxxx".to_vec()).unwrap());
        clause.push(MatchItem::new(b"QUUX=yyyyy".to_vec()).unwrap());
        assert_eq!(
            clause.render().unwrap(),
            "(QUUX=yyyyy OR QUUX=xxxxx OR QUUX=mmmm)"
        );
    }

    #[test]
    fn builds_expected_expression() {
        let journal = build_reference_expression().unwrap();
        assert_eq!(journal.render().unwrap(), EXPECTED_MATCH_STRING);
    }

    #[test]
    fn expose_assume_immutable_flag() {
        assert_eq!(SD_JOURNAL_ASSUME_IMMUTABLE, 1);
    }
}
