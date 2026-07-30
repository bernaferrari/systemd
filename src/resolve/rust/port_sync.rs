// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Shared support for resolve/ Rust PORT-SYNC inventories.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSyncFunction {
    pub rust_name: &'static str,
    pub c_name: &'static str,
    pub purpose: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSyncConstant {
    pub name: &'static str,
    pub value: &'static str,
    pub purpose: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSyncModule<'a> {
    pub rust_module: &'static str,
    pub source_path: &'static str,
    pub summary: &'static str,
    pub included_headers: &'a [&'static str],
    pub local_defines: &'a [&'static str],
    pub functions: &'a [PortSyncFunction],
    pub constants: &'a [PortSyncConstant],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSyncError {
    InvalidSourcePath(&'static str),
    EmptySummary(&'static str),
    EmptyHeader(&'static str),
    EmptyDefine(&'static str),
    DuplicateRustName(&'static str),
    DuplicateCName(&'static str),
    DuplicateConstant(&'static str),
    UnknownFunction(String),
    UnknownConstant(String),
}

impl<'a> PortSyncModule<'a> {
    pub fn function(self, rust_name: &str) -> Result<&'a PortSyncFunction, PortSyncError> {
        self.functions
            .iter()
            .find(|function| function.rust_name == rust_name)
            .ok_or_else(|| PortSyncError::UnknownFunction(rust_name.to_owned()))
    }

    pub fn constant(self, name: &str) -> Result<&'a PortSyncConstant, PortSyncError> {
        self.constants
            .iter()
            .find(|constant| constant.name == name)
            .ok_or_else(|| PortSyncError::UnknownConstant(name.to_owned()))
    }

    pub fn validate(self) -> Result<(), PortSyncError> {
        if !self.source_path.starts_with("src/resolve/") || !self.source_path.ends_with(".c") {
            return Err(PortSyncError::InvalidSourcePath(self.source_path));
        }
        if self.summary.trim().is_empty() {
            return Err(PortSyncError::EmptySummary(self.rust_module));
        }
        for header in self.included_headers {
            if header.trim().is_empty() {
                return Err(PortSyncError::EmptyHeader(self.rust_module));
            }
        }
        for define in self.local_defines {
            if define.trim().is_empty() {
                return Err(PortSyncError::EmptyDefine(self.rust_module));
            }
        }
        ensure_unique(
            self.functions.iter().map(|function| function.rust_name),
            PortSyncError::DuplicateRustName,
        )?;
        ensure_unique(
            self.functions.iter().map(|function| function.c_name),
            PortSyncError::DuplicateCName,
        )?;
        ensure_unique(
            self.constants.iter().map(|constant| constant.name),
            PortSyncError::DuplicateConstant,
        )?;
        Ok(())
    }
}

fn ensure_unique<I, F>(items: I, error: F) -> Result<(), PortSyncError>
where
    I: Iterator<Item = &'static str>,
    F: Fn(&'static str) -> PortSyncError,
{
    let mut seen = std::collections::BTreeSet::new();
    for item in items {
        if !seen.insert(item) {
            return Err(error(item));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_module() -> PortSyncModule<'static> {
        const HEADERS: &[&str] = &["sd-event.h", "resolved-manager.h"];
        const DEFINES: &[&str] = &["HOOK_IDLE_CONNECTIONS_MAX"];
        const FUNCTIONS: &[PortSyncFunction] = &[
            PortSyncFunction {
                rust_name: "rs_manager_hook_query",
                c_name: "manager_hook_query",
                purpose: "Tracks hook query dispatch.",
            },
            PortSyncFunction {
                rust_name: "rs_hook_query_free",
                c_name: "hook_query_free",
                purpose: "Tracks hook query destruction.",
            },
        ];
        const CONSTANTS: &[PortSyncConstant] = &[PortSyncConstant {
            name: "HOOK_IDLE_CONNECTIONS_MAX",
            value: "4U",
            purpose: "Maximum number of idle hook connections.",
        }];
        PortSyncModule {
            rust_module: "resolved_hook",
            source_path: "src/resolve/resolved-hook.c",
            summary: "Hook inventory.",
            included_headers: HEADERS,
            local_defines: DEFINES,
            functions: FUNCTIONS,
            constants: CONSTANTS,
        }
    }

    #[test]
    fn validate_accepts_well_formed_module() {
        assert_eq!(sample_module().validate(), Ok(()));
    }

    #[test]
    fn function_lookup_returns_descriptor() {
        let function = sample_module().function("rs_hook_query_free").unwrap();
        assert_eq!(function.c_name, "hook_query_free");
    }

    #[test]
    fn constant_lookup_returns_descriptor() {
        let constant = sample_module()
            .constant("HOOK_IDLE_CONNECTIONS_MAX")
            .unwrap();
        assert_eq!(constant.value, "4U");
    }

    #[test]
    fn validate_rejects_duplicate_rust_names() {
        const FUNCTIONS: &[PortSyncFunction] = &[
            PortSyncFunction {
                rust_name: "dup",
                c_name: "a",
                purpose: "a",
            },
            PortSyncFunction {
                rust_name: "dup",
                c_name: "b",
                purpose: "b",
            },
        ];
        let module = PortSyncModule {
            functions: FUNCTIONS,
            ..sample_module()
        };
        assert_eq!(
            module.validate(),
            Err(PortSyncError::DuplicateRustName("dup"))
        );
    }

    #[test]
    fn validate_rejects_duplicate_c_names() {
        const FUNCTIONS: &[PortSyncFunction] = &[
            PortSyncFunction {
                rust_name: "a",
                c_name: "dup",
                purpose: "a",
            },
            PortSyncFunction {
                rust_name: "b",
                c_name: "dup",
                purpose: "b",
            },
        ];
        let module = PortSyncModule {
            functions: FUNCTIONS,
            ..sample_module()
        };
        assert_eq!(module.validate(), Err(PortSyncError::DuplicateCName("dup")));
    }

    #[test]
    fn validate_rejects_duplicate_constants() {
        const CONSTANTS: &[PortSyncConstant] = &[
            PortSyncConstant {
                name: "dup",
                value: "1",
                purpose: "a",
            },
            PortSyncConstant {
                name: "dup",
                value: "2",
                purpose: "b",
            },
        ];
        let module = PortSyncModule {
            constants: CONSTANTS,
            ..sample_module()
        };
        assert_eq!(
            module.validate(),
            Err(PortSyncError::DuplicateConstant("dup"))
        );
    }

    #[test]
    fn validate_rejects_invalid_source_path() {
        let module = PortSyncModule {
            source_path: "resolved-hook.txt",
            ..sample_module()
        };
        assert_eq!(
            module.validate(),
            Err(PortSyncError::InvalidSourcePath("resolved-hook.txt"))
        );
    }

    #[test]
    fn unknown_lookups_report_requested_name() {
        assert_eq!(
            sample_module().function("missing"),
            Err(PortSyncError::UnknownFunction("missing".to_owned())),
        );
        assert_eq!(
            sample_module().constant("missing"),
            Err(PortSyncError::UnknownConstant("missing".to_owned())),
        );
    }
}
