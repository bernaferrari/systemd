// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-catalog.c

use std::collections::BTreeMap;

const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const SD_MESSAGE_COREDUMP: &str = "fc2e22bc6ee647b6b90729ab34a250b1";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatalogDatabase {
    entries: BTreeMap<String, String>,
}

pub fn catalog_file_lang(filename: &str) -> Result<Option<String>, i32> {
    let basename = filename.rsplit('/').next().unwrap_or(filename);
    let Some(rest) = basename.strip_prefix("systemd.") else {
        return Ok(None);
    };
    let Some(lang) = rest.strip_suffix(".catalog") else {
        return Ok(None);
    };
    if lang.is_empty()
        || lang.len() > 30
        || !lang.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Ok(None);
    }
    Ok(Some(lang.to_string()))
}

fn is_valid_id(value: &str) -> bool {
    value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn split_payload(payload: &str) -> (&str, &str) {
    payload.split_once("\n\n").unwrap_or((payload, ""))
}

fn merge_payload(new_payload: &str, old_payload: &str) -> String {
    let (new_headers, new_body) = split_payload(new_payload);
    let (old_headers, old_body) = split_payload(old_payload);
    let body = if new_body.is_empty() {
        old_body
    } else {
        new_body
    };
    if body.is_empty() {
        format!("{new_headers}\n{old_headers}\n")
    } else {
        format!("{new_headers}\n{old_headers}\n\n{body}")
    }
}

pub fn catalog_import_file(contents: &str) -> Result<CatalogDatabase, i32> {
    let mut db = CatalogDatabase::default();
    let blocks = contents.split("-- ").filter(|s| !s.trim().is_empty());

    for block in blocks {
        let mut lines = block.lines();
        let Some(header) = lines.next() else {
            return Err(NEG_EINVAL);
        };
        let mut ids = header.split_whitespace();
        let Some(id) = ids.next() else {
            return Err(NEG_EINVAL);
        };
        let Some(language_id) = ids.next() else {
            return Err(NEG_EINVAL);
        };
        if !is_valid_id(id) || language_id.is_empty() {
            return Err(NEG_EINVAL);
        }
        let payload = lines.collect::<Vec<_>>().join("\n");
        let payload = format!("{payload}\n");
        db.entries
            .entry(id.to_string())
            .and_modify(|old| *old = merge_payload(&payload, old))
            .or_insert(payload);
    }

    Ok(db)
}

pub fn catalog_update(databases: &[CatalogDatabase]) -> Result<CatalogDatabase, i32> {
    let mut merged = CatalogDatabase::default();
    for db in databases {
        for (id, payload) in &db.entries {
            merged.entries.insert(id.clone(), payload.clone());
        }
    }
    Ok(merged)
}

pub fn catalog_list(database: &CatalogDatabase) -> Result<Vec<String>, i32> {
    Ok(database.entries.keys().cloned().collect())
}

pub fn catalog_get(database: &CatalogDatabase, id: &str) -> Result<String, i32> {
    database.entries.get(id).cloned().ok_or(NEG_EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = "-- 0027229ca0644181a76c4e92458afaff dededededededededededededededed\nSubject: message\n\npayload\n";
    const MERGE: &str = "-- 0027229ca0644181a76c4e92458afaff dededededededededededededededed\nSubject: message\nDefined-By: me\n\npayload\n\n-- 0027229ca0644181a76c4e92458afaff dededededededededededededededed\nSubject: override subject\nX-Header: hello\n\noverride payload\n";

    #[test]
    fn language_is_extracted() {
        assert_eq!(
            catalog_file_lang("systemd.de_DE.catalog").unwrap(),
            Some("de_DE".into())
        );
    }

    #[test]
    fn invalid_language_file_returns_none() {
        assert_eq!(catalog_file_lang("systemd..catalog").unwrap(), None);
    }

    #[test]
    fn nested_path_is_supported() {
        assert_eq!(
            catalog_file_lang("/x/y/systemd.ru_RU.catalog").unwrap(),
            Some("ru_RU".into())
        );
    }

    #[test]
    fn invalid_catalog_id_is_rejected() {
        assert_eq!(catalog_import_file("xxx"), Err(NEG_EINVAL));
    }

    #[test]
    fn single_entry_imports_payload() {
        let db = catalog_import_file(ONE).unwrap();
        assert_eq!(
            catalog_get(&db, "0027229ca0644181a76c4e92458afaff").unwrap(),
            "Subject: message\n\npayload\n"
        );
    }

    #[test]
    fn duplicate_ids_are_merged_like_c() {
        let db = catalog_import_file(MERGE).unwrap();
        assert_eq!(catalog_get(&db, "0027229ca0644181a76c4e92458afaff").unwrap(), "Subject: override subject\nX-Header: hello\nSubject: message\nDefined-By: me\n\noverride payload\n");
    }

    #[test]
    fn update_combines_multiple_databases() {
        let a = catalog_import_file(ONE).unwrap();
        let b = catalog_import_file(&format!(
            "-- {SD_MESSAGE_COREDUMP} dededededededededededededededed\nSubject: coredump\n\nbody\n"
        ))
        .unwrap();
        let merged = catalog_update(&[a, b]).unwrap();
        assert_eq!(catalog_list(&merged).unwrap().len(), 2);
    }

    #[test]
    fn get_unknown_entry_fails() {
        assert_eq!(
            catalog_get(&CatalogDatabase::default(), SD_MESSAGE_COREDUMP),
            Err(NEG_EINVAL)
        );
    }
}
