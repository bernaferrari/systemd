// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-dump.c

const NEG_EBADF: i32 = -(libc::EBADF as i32);
const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
pub const HEADER_SIGNATURE: [u8; 8] = *b"LPKSHHRH";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalHeader {
    pub signature: [u8; 8],
    pub state: &'static str,
    pub header_size: u64,
    pub arena_size: u64,
    pub n_objects: u64,
    pub n_entries: u64,
    pub seqnum: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalFile {
    pub path: String,
    pub header: JournalHeader,
}

impl JournalHeader {
    pub fn validate(&self) -> Result<(), i32> {
        if self.signature != HEADER_SIGNATURE || self.header_size == 0 {
            return Err(NEG_EINVAL);
        }
        Ok(())
    }

    pub fn print(&self, path: &str) -> Result<String, i32> {
        self.validate()?;
        Ok(format!(
            "File Path: {path}\nHeader Size: {}\nArena Size: {}\nState: {}\nObjects: {}\nEntries: {}\nSeqnum: {}\n",
            self.header_size, self.arena_size, self.state, self.n_objects, self.n_entries, self.seqnum,
        ))
    }
}

pub fn dump_headers(files: &[JournalFile]) -> Result<String, i32> {
    if files.is_empty() {
        return Err(NEG_EBADF);
    }
    let mut out = Vec::new();
    for file in files {
        out.push(file.header.print(&file.path)?);
    }
    Ok(out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_file(path: &str) -> JournalFile {
        JournalFile {
            path: path.into(),
            header: JournalHeader {
                signature: HEADER_SIGNATURE,
                state: "online",
                header_size: 264,
                arena_size: 4096,
                n_objects: 3,
                n_entries: 2,
                seqnum: 7,
            },
        }
    }

    #[test]
    fn valid_header_passes_validation() {
        assert_eq!(good_file("a").header.validate(), Ok(()));
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let mut file = good_file("a");
        file.header.signature = *b"INVALID!";
        assert_eq!(file.header.validate(), Err(NEG_EINVAL));
    }

    #[test]
    fn zero_sized_header_is_rejected() {
        let mut file = good_file("a");
        file.header.header_size = 0;
        assert_eq!(file.header.validate(), Err(NEG_EINVAL));
    }

    #[test]
    fn print_contains_expected_fields() {
        let rendered = good_file("one.journal")
            .header
            .print("one.journal")
            .unwrap();
        assert!(rendered.contains("File Path: one.journal"));
        assert!(rendered.contains("Entries: 2"));
    }

    #[test]
    fn dump_requires_at_least_one_file() {
        assert_eq!(dump_headers(&[]), Err(NEG_EBADF));
    }

    #[test]
    fn dump_single_file_renders_once() {
        let rendered = dump_headers(&[good_file("one")]).unwrap();
        assert_eq!(rendered.matches("File Path:").count(), 1);
    }

    #[test]
    fn dump_multiple_files_separates_outputs() {
        let rendered = dump_headers(&[good_file("one"), good_file("two")]).unwrap();
        assert_eq!(rendered.matches("File Path:").count(), 2);
    }

    #[test]
    fn dump_propagates_header_errors() {
        let mut file = good_file("broken");
        file.header.signature = [0; 8];
        assert_eq!(dump_headers(&[file]), Err(NEG_EINVAL));
    }
}
