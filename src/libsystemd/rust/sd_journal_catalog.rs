// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/catalog.c
//

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::id128_util::SdId128;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const NEG_ENOMEM: i32 = -libc::ENOMEM;
pub const CATALOG_SIGNATURE: [u8; 8] = *b"RHHHKSLP";
pub const CATALOG_FILE_DIRS: [&str; 2] = [
    "/usr/local/lib/systemd/catalog/",
    "/usr/lib/systemd/catalog/",
];

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogHeader {
    pub signature: [u8; 8],
    pub compatible_flags: u32,
    pub incompatible_flags: u32,
    pub header_size: u64,
    pub n_items: u64,
    pub catalog_item_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogItem {
    pub id: SdId128,
    pub language: String,
    pub offset: u64,
}

impl Ord for CatalogItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id
            .0
            .cmp(&other.id.0)
            .then_with(|| self.language.cmp(&other.language))
    }
}

impl PartialOrd for CatalogItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn next_header(s: &str) -> Option<&str> {
    let end = s.find('\n')?;
    if end == 0 {
        return None;
    }
    Some(&s[end + 1..])
}

pub fn skip_header(mut s: &str) -> &str {
    while let Some(next) = next_header(s) {
        s = next;
    }
    s
}

pub fn combine_entries(one: &str, two: &str) -> String {
    let body_one = skip_header(one);
    let body_two = skip_header(two);
    let mut combined = String::with_capacity(one.len() + two.len());
    combined.push_str(&one[..one.len() - body_one.len()]);
    combined.push_str(&two[..two.len() - body_two.len()]);
    combined.push_str(if body_one.is_empty() || body_one == "\n" {
        body_two
    } else {
        body_one
    });
    combined
}

pub fn catalog_file_lang(filename: &str) -> Option<String> {
    let end = filename.strip_suffix(".catalog")?;
    let marker = end.rfind(['.', '/'])?;
    if end.as_bytes()[marker] != b'.' || marker + 1 >= end.len() {
        return None;
    }
    let lang = &end[marker + 1..];
    (2..=31).contains(&lang.len()).then(|| lang.to_string())
}

pub fn catalog_entry_lang(lang: &str, default_lang: Option<&str>) -> Result<Option<String>> {
    if !(2..=31).contains(&lang.len()) {
        return Err(NEG_EINVAL);
    }
    if default_lang == Some(lang) {
        return Ok(None);
    }
    Ok(Some(lang.to_string()))
}

pub fn finish_item(
    map: &mut BTreeMap<CatalogItem, String>,
    id: SdId128,
    language: Option<&str>,
    payload: &str,
) -> Result<()> {
    if payload.is_empty() {
        return Err(NEG_EINVAL);
    }

    let item = CatalogItem {
        id,
        language: language.unwrap_or_default().to_string(),
        offset: 0,
    };

    match map.get_mut(&item) {
        Some(existing) => *existing = combine_entries(existing, payload),
        None => {
            map.insert(item, payload.to_string());
        }
    }

    Ok(())
}

pub fn catalog_compare(a: &CatalogItem, b: &CatalogItem) -> Ordering {
    a.cmp(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(fill: u8) -> SdId128 {
        SdId128([fill; 16])
    }

    #[test]
    fn next_header_steps_forward() {
        assert_eq!(next_header("Subject: x\n\nBody"), Some("\nBody"));
    }

    #[test]
    fn skip_header_returns_body() {
        assert_eq!(skip_header("Subject: x\nTitle: y\n\nBody"), "\nBody");
    }

    #[test]
    fn combine_entries_keeps_first_body() {
        let first = "Subject: One\n\nBody one";
        let second = "Title: Two\n\nBody two";
        assert_eq!(
            combine_entries(first, second),
            "Subject: One\nTitle: Two\n\nBody one"
        );
    }

    #[test]
    fn combine_entries_falls_back_to_second_body() {
        let first = "Subject: One\n\n";
        let second = "Title: Two\n\nBody two";
        assert_eq!(
            combine_entries(first, second),
            "Subject: One\nTitle: Two\n\nBody two"
        );
    }

    #[test]
    fn extracts_catalog_language() {
        assert_eq!(
            catalog_file_lang("/tmp/hello.pt_BR.catalog"),
            Some("pt_BR".into())
        );
    }

    #[test]
    fn rejects_invalid_language_length() {
        assert_eq!(catalog_entry_lang("x", None), Err(NEG_EINVAL));
    }

    #[test]
    fn omits_redundant_default_language() {
        assert_eq!(catalog_entry_lang("de", Some("de")), Ok(None));
    }

    #[test]
    fn finish_item_merges_duplicates() {
        let mut map = BTreeMap::new();
        finish_item(&mut map, id(1), Some("en"), "Subject: A\n\nOne").unwrap();
        finish_item(&mut map, id(1), Some("en"), "Title: B\n\nTwo").unwrap();
        assert_eq!(map.values().next().unwrap(), "Subject: A\nTitle: B\n\nOne");
    }

    #[test]
    fn catalog_compare_orders_by_id_then_language() {
        let a = CatalogItem {
            id: id(1),
            language: "en".into(),
            offset: 0,
        };
        let b = CatalogItem {
            id: id(2),
            language: "de".into(),
            offset: 0,
        };
        assert_eq!(catalog_compare(&a, &b), Ordering::Less);
    }
}
