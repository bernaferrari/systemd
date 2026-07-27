// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/vpick/vpick-tool.c

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidPrint(String),
    InvalidResolve(String),
    NoMatch,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrint(v) => write!(f, "invalid print mode: {v}"),
            Self::InvalidResolve(v) => write!(f, "invalid resolve value: {v}"),
            Self::NoMatch => f.write_str("no matching version found"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintMode {
    Path,
    Filename,
    Version,
    Type,
    Architecture,
    Tries,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Filters {
    pub basename: Option<String>,
    pub version: Option<String>,
    pub architecture: Option<String>,
    pub suffix: Option<String>,
    pub resolve: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: String,
    pub version: Option<String>,
    pub entry_type: Option<String>,
    pub architecture: Option<String>,
    pub tries_left: Option<u32>,
    pub tries_done: Option<u32>,
}

pub fn parse_print_mode(value: &str) -> Result<PrintMode> {
    Ok(match value {
        "path" => PrintMode::Path,
        "filename" => PrintMode::Filename,
        "version" => PrintMode::Version,
        "type" => PrintMode::Type,
        "arch" | "architecture" => PrintMode::Architecture,
        "tries" => PrintMode::Tries,
        "all" => PrintMode::All,
        _ => return Err(Error::InvalidPrint(value.into())),
    })
}

pub fn parse_resolve(value: &str) -> Result<bool> {
    match value {
        "1" | "yes" | "true" => Ok(true),
        "0" | "no" | "false" => Ok(false),
        _ => Err(Error::InvalidResolve(value.into())),
    }
}

pub fn select_candidate<'a>(
    candidates: &'a [Candidate],
    filters: &Filters,
) -> Result<&'a Candidate> {
    candidates
        .iter()
        .filter(|c| matches_filters(c, filters))
        .max_by_key(|c| c.version.clone())
        .ok_or(Error::NoMatch)
}

fn matches_filters(candidate: &Candidate, filters: &Filters) -> bool {
    filters.basename.as_ref().is_none_or(|v| {
        candidate
            .path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with(v))
    }) && filters
        .version
        .as_ref()
        .is_none_or(|v| candidate.version.as_ref() == Some(v))
        && filters
            .architecture
            .as_ref()
            .is_none_or(|v| candidate.architecture.as_ref() == Some(v))
        && filters
            .suffix
            .as_ref()
            .is_none_or(|v| candidate.path.ends_with(v))
}

pub fn render(mode: PrintMode, candidate: &Candidate) -> Result<String> {
    Ok(match mode {
        PrintMode::Path => format!("{}\n", candidate.path),
        PrintMode::Filename => format!(
            "{}\n",
            candidate
                .path
                .rsplit('/')
                .next()
                .unwrap_or(candidate.path.as_str())
        ),
        PrintMode::Version => format!("{}\n", candidate.version.clone().ok_or(Error::NoMatch)?),
        PrintMode::Type => format!("{}\n", candidate.entry_type.clone().ok_or(Error::NoMatch)?),
        PrintMode::Architecture => format!(
            "{}\n",
            candidate.architecture.clone().ok_or(Error::NoMatch)?
        ),
        PrintMode::Tries => format!(
            "+{}-{}",
            candidate.tries_left.ok_or(Error::NoMatch)?,
            candidate.tries_done.ok_or(Error::NoMatch)?
        ),
        PrintMode::All => format!(
            "Path: {}\nVersion: {}\n",
            candidate.path,
            candidate.version.clone().unwrap_or_else(|| "n/a".into())
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates() -> Vec<Candidate> {
        vec![
            Candidate {
                path: "/a/foo-1.raw".into(),
                version: Some("1".into()),
                entry_type: Some("regular".into()),
                architecture: Some("x86-64".into()),
                tries_left: Some(2),
                tries_done: Some(1),
            },
            Candidate {
                path: "/a/foo-2.raw".into(),
                version: Some("2".into()),
                entry_type: Some("regular".into()),
                architecture: Some("x86-64".into()),
                tries_left: Some(1),
                tries_done: Some(2),
            },
        ]
    }

    #[test]
    fn parses_arch_print_alias() {
        assert_eq!(parse_print_mode("arch").unwrap(), PrintMode::Architecture);
    }
    #[test]
    fn parses_yes_resolve() {
        assert!(parse_resolve("yes").unwrap());
    }
    #[test]
    fn parses_no_resolve() {
        assert!(!parse_resolve("no").unwrap());
    }
    #[test]
    fn rejects_invalid_print() {
        assert!(matches!(
            parse_print_mode("meta"),
            Err(Error::InvalidPrint(_))
        ));
    }
    #[test]
    fn selects_highest_matching_version() {
        assert_eq!(
            select_candidate(&candidates(), &Filters::default())
                .unwrap()
                .version
                .as_deref(),
            Some("2")
        );
    }
    #[test]
    fn filters_by_architecture() {
        assert_eq!(
            select_candidate(
                &candidates(),
                &Filters {
                    architecture: Some("x86-64".into()),
                    ..Default::default()
                }
            )
            .unwrap()
            .version
            .as_deref(),
            Some("2")
        );
    }
    #[test]
    fn renders_filename() {
        assert_eq!(
            render(PrintMode::Filename, &candidates()[0]).unwrap(),
            "foo-1.raw\n"
        );
    }
    #[test]
    fn renders_tries() {
        assert_eq!(render(PrintMode::Tries, &candidates()[0]).unwrap(), "+2-1");
    }
}
