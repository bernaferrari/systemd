// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/exec-credential.c

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use crate::ffi::Errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    InvalidArgument,
    DuplicateName,
    SizeLimitExceeded,
}

impl CredentialError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::InvalidArgument => Errno::EINVAL.to_neg_errno(),
            Self::DuplicateName => Errno::EEXIST.to_neg_errno(),
            Self::SizeLimitExceeded => Errno::E2BIG.to_neg_errno(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSearchPath {
    Trusted,
    Encrypted,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecImportCredential {
    pub glob: String,
    pub rename: Option<String>,
}

impl ExecImportCredential {
    pub fn new(glob: impl Into<String>, rename: Option<String>) -> Result<Self, CredentialError> {
        let glob = glob.into();
        if glob.is_empty() {
            return Err(CredentialError::InvalidArgument);
        }

        Ok(Self {
            glob,
            rename: rename.and_then(empty_to_none),
        })
    }

    pub fn rename_filename(&self, filename: &str) -> Result<String, CredentialError> {
        if !credential_name_valid(filename) {
            return Err(CredentialError::InvalidArgument);
        }

        match &self.rename {
            None => Ok(filename.to_string()),
            Some(prefix) => {
                let suffix = self.glob_suffix(filename)?;
                Ok(format!("{prefix}{suffix}"))
            }
        }
    }

    fn glob_suffix<'a>(&self, filename: &'a str) -> Result<&'a str, CredentialError> {
        let base = self.glob.strip_suffix('*').unwrap_or(&self.glob);
        filename
            .strip_prefix(base)
            .ok_or(CredentialError::InvalidArgument)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecLoadCredential {
    pub id: String,
    pub path: String,
    pub encrypted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecSetCredential {
    pub id: String,
    pub data: Vec<u8>,
    pub encrypted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecContext {
    pub load_credentials: BTreeMap<String, ExecLoadCredential>,
    pub set_credentials: BTreeMap<String, ExecSetCredential>,
    pub import_credentials: BTreeSet<ExecImportCredential>,
    pub private_devices: bool,
}

impl ExecContext {
    pub fn put_load_credential(
        &mut self,
        id: impl Into<String>,
        path: impl Into<String>,
        encrypted: bool,
    ) -> Result<(), CredentialError> {
        let id = id.into();
        let path = path.into();
        validate_non_empty(&id)?;
        validate_non_empty(&path)?;

        self.load_credentials.insert(
            id.clone(),
            ExecLoadCredential {
                id,
                path,
                encrypted,
            },
        );
        Ok(())
    }

    pub fn put_set_credential(
        &mut self,
        id: impl Into<String>,
        data: Vec<u8>,
        encrypted: bool,
    ) -> Result<(), CredentialError> {
        let id = id.into();
        validate_non_empty(&id)?;

        self.set_credentials.insert(
            id.clone(),
            ExecSetCredential {
                id,
                data,
                encrypted,
            },
        );
        Ok(())
    }

    pub fn put_import_credential(
        &mut self,
        glob: impl Into<String>,
        rename: Option<String>,
    ) -> Result<bool, CredentialError> {
        let import = ExecImportCredential::new(glob, rename)?;
        Ok(self.import_credentials.insert(import))
    }

    pub fn has_credentials(&self) -> bool {
        !(self.load_credentials.is_empty()
            && self.set_credentials.is_empty()
            && self.import_credentials.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecParameters {
    pub flags: u32,
    pub runtime_directory: Option<String>,
    pub unit_id: String,
    pub runtime_scope: RuntimeScope,
    pub received_credentials_directory: Option<String>,
    pub received_encrypted_credentials_directory: Option<String>,
}

impl ExecParameters {
    pub const SETUP_CREDENTIALS: u32 = 1 << 0;
    pub const SETUP_CREDENTIALS_FRESH: u32 = 1 << 1;

    pub const fn need_credentials(&self) -> bool {
        (self.flags & (Self::SETUP_CREDENTIALS | Self::SETUP_CREDENTIALS_FRESH)) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupCredentialsContext<'a> {
    pub scope: RuntimeScope,
    pub exec_context: &'a ExecContext,
    pub runtime_prefix: Option<&'a str>,
    pub received_credentials_directory: Option<&'a str>,
    pub received_encrypted_credentials_directory: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquiredCredential {
    pub id: String,
    pub data: Vec<u8>,
    pub encrypted: bool,
}

pub fn exec_params_need_credentials(params: &ExecParameters) -> bool {
    params.need_credentials()
}

pub fn exec_context_has_credentials(context: &ExecContext) -> bool {
    context.has_credentials()
}

pub fn mount_point_is_credentials(runtime_prefix: &str, path: &str) -> bool {
    let runtime_prefix = normalize_path(runtime_prefix);
    let path = normalize_path(path);

    match path.strip_prefix(&runtime_prefix) {
        Ok(rest) => rest.components().next() == Some(Component::Normal(OsStr::new("credentials"))),
        Err(_) => false,
    }
}

pub fn get_credential_directory(
    runtime_prefix: Option<&str>,
    unit: Option<&str>,
) -> Result<Option<PathBuf>, CredentialError> {
    match (runtime_prefix, unit) {
        (Some(prefix), Some(unit)) if !prefix.is_empty() && !unit.is_empty() => {
            Ok(Some(Path::new(prefix).join("credentials").join(unit)))
        }
        (None, _) | (_, None) => Ok(None),
        _ => Err(CredentialError::InvalidArgument),
    }
}

pub fn exec_context_get_credential_directory(
    context: &ExecContext,
    params: &ExecParameters,
) -> Result<Option<PathBuf>, CredentialError> {
    if !exec_params_need_credentials(params) || !exec_context_has_credentials(context) {
        return Ok(None);
    }

    get_credential_directory(params.runtime_directory.as_deref(), Some(&params.unit_id))
}

pub fn credential_search_path(
    context: &SetupCredentialsContext<'_>,
    kind: CredentialSearchPath,
) -> Result<Vec<PathBuf>, CredentialError> {
    let mut paths = Vec::new();

    if matches!(
        kind,
        CredentialSearchPath::Encrypted | CredentialSearchPath::All
    ) {
        if let Some(path) = context.received_encrypted_credentials_directory {
            paths.push(PathBuf::from(path));
        }

        let store = match context.scope {
            RuntimeScope::System => "/etc/credstore.encrypted",
            RuntimeScope::User => "/run/credstore.encrypted",
        };
        paths.push(PathBuf::from(store));
    }

    if matches!(
        kind,
        CredentialSearchPath::Trusted | CredentialSearchPath::All
    ) {
        if let Some(path) = context.received_credentials_directory {
            paths.push(PathBuf::from(path));
        }

        let store = match context.scope {
            RuntimeScope::System => "/etc/credstore",
            RuntimeScope::User => "/run/credstore",
        };
        paths.push(PathBuf::from(store));
    }

    Ok(paths)
}

pub fn acquire_credentials(
    context: &ExecContext,
    loaded: impl IntoIterator<Item = AcquiredCredential>,
    total_size_limit: usize,
) -> Result<Vec<AcquiredCredential>, CredentialError> {
    let mut merged = BTreeMap::<String, AcquiredCredential>::new();

    for credential in loaded {
        if merged.contains_key(&credential.id) {
            continue;
        }
        validate_non_empty(&credential.id)?;
        merged.insert(credential.id.clone(), credential);
    }

    for credential in context.set_credentials.values() {
        merged
            .entry(credential.id.clone())
            .or_insert_with(|| AcquiredCredential {
                id: credential.id.clone(),
                data: credential.data.clone(),
                encrypted: credential.encrypted,
            });
    }

    let total = merged
        .values()
        .map(|credential| credential.id.len() + credential.data.len())
        .sum::<usize>();
    if total > total_size_limit {
        return Err(CredentialError::SizeLimitExceeded);
    }

    Ok(merged.into_values().collect())
}

pub fn device_nodes_restricted(context: &ExecContext, cgroup_has_device_policy: bool) -> bool {
    context.private_devices || cgroup_has_device_policy
}

fn validate_non_empty(value: &str) -> Result<(), CredentialError> {
    if value.is_empty() {
        Err(CredentialError::InvalidArgument)
    } else {
        Ok(())
    }
}

fn empty_to_none(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn normalize_path(path: &str) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn credential_name_valid(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_credentials_replace_existing_entries() {
        let mut context = ExecContext::default();
        context.put_load_credential("db", "/tmp/a", false).unwrap();
        context.put_load_credential("db", "/tmp/b", true).unwrap();
        let stored = context.load_credentials.get("db").unwrap();
        assert_eq!(stored.path, "/tmp/b");
        assert!(stored.encrypted);
    }

    #[test]
    fn set_credentials_replace_existing_entries() {
        let mut context = ExecContext::default();
        context
            .put_set_credential("api", b"first".to_vec(), false)
            .unwrap();
        context
            .put_set_credential("api", b"second".to_vec(), true)
            .unwrap();
        let stored = context.set_credentials.get("api").unwrap();
        assert_eq!(stored.data, b"second".to_vec());
        assert!(stored.encrypted);
    }

    #[test]
    fn import_credentials_deduplicate_after_empty_rename_normalization() {
        let mut context = ExecContext::default();
        assert!(
            context
                .put_import_credential("foo*", Some(String::new()))
                .unwrap()
        );
        assert!(!context.put_import_credential("foo*", None).unwrap());
    }

    #[test]
    fn params_need_credentials_matches_flag_bits() {
        let params = ExecParameters {
            flags: ExecParameters::SETUP_CREDENTIALS_FRESH,
            runtime_directory: Some("/run/systemd".into()),
            unit_id: "demo.service".into(),
            runtime_scope: RuntimeScope::System,
            received_credentials_directory: None,
            received_encrypted_credentials_directory: None,
        };
        assert!(exec_params_need_credentials(&params));
    }

    #[test]
    fn mount_point_detection_requires_credentials_component() {
        assert!(mount_point_is_credentials(
            "/run/systemd",
            "/run/systemd/credentials/demo.service"
        ));
        assert!(!mount_point_is_credentials(
            "/run/systemd",
            "/run/systemd/other/demo.service"
        ));
    }

    #[test]
    fn credential_directory_is_computed_only_when_needed() {
        let mut context = ExecContext::default();
        context
            .put_set_credential("api", b"secret".to_vec(), false)
            .unwrap();
        let params = ExecParameters {
            flags: ExecParameters::SETUP_CREDENTIALS,
            runtime_directory: Some("/run/systemd".into()),
            unit_id: "demo.service".into(),
            runtime_scope: RuntimeScope::System,
            received_credentials_directory: None,
            received_encrypted_credentials_directory: None,
        };
        assert_eq!(
            exec_context_get_credential_directory(&context, &params).unwrap(),
            Some(
                Path::new("/run/systemd")
                    .join("credentials")
                    .join("demo.service")
            )
        );
    }

    #[test]
    fn search_path_follows_scope_and_kind() {
        let context = ExecContext::default();
        let setup = SetupCredentialsContext {
            scope: RuntimeScope::User,
            exec_context: &context,
            runtime_prefix: Some("/run/user/1000"),
            received_credentials_directory: Some("/tmp/cred"),
            received_encrypted_credentials_directory: Some("/tmp/cred.enc"),
        };
        let paths = credential_search_path(&setup, CredentialSearchPath::All).unwrap();
        assert_eq!(paths[0], PathBuf::from("/tmp/cred.enc"));
        assert_eq!(paths[1], PathBuf::from("/run/credstore.encrypted"));
        assert_eq!(paths[2], PathBuf::from("/tmp/cred"));
        assert_eq!(paths[3], PathBuf::from("/run/credstore"));
    }

    #[test]
    fn acquire_credentials_prefers_preloaded_values_and_enforces_limit() {
        let mut context = ExecContext::default();
        context
            .put_set_credential("api", b"fallback".to_vec(), false)
            .unwrap();
        let loaded = vec![AcquiredCredential {
            id: "api".into(),
            data: b"loaded".to_vec(),
            encrypted: false,
        }];
        let merged = acquire_credentials(&context, loaded.clone(), 64).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].data, b"loaded".to_vec());
        assert_eq!(
            acquire_credentials(&context, loaded, 1).unwrap_err(),
            CredentialError::SizeLimitExceeded
        );
    }

    #[test]
    fn device_nodes_are_restricted_by_private_devices_or_policy() {
        let mut context = ExecContext::default();
        assert!(!device_nodes_restricted(&context, false));
        context.private_devices = true;
        assert!(device_nodes_restricted(&context, false));
        context.private_devices = false;
        assert!(device_nodes_restricted(&context, true));
    }

    #[test]
    fn rename_suffix_follows_c_glob_behavior() {
        let import = ExecImportCredential::new("cred-*", Some("renamed-".into())).unwrap();
        assert_eq!(import.rename_filename("cred-demo").unwrap(), "renamed-demo");
    }
}
