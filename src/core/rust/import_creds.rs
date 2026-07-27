// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/import-creds.c, src/core/import-creds.h

use crate::ffi::Errno;

pub const SYSTEM_CREDENTIALS_DIRECTORY: &str = "/run/credentials/@system";
pub const ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY: &str = "/run/credentials/@encrypted";

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportCredentialsOutcome {
    pub used_existing_env: bool,
    pub imported_boot: bool,
    pub imported_trusted: bool,
    pub import_enabled: bool,
    pub received_creds_dir: Option<String>,
    pub received_encrypted_creds_dir: Option<String>,
}

pub trait CredentialImportBackend {
    fn get_credentials_dir(&self) -> Result<Option<String>>;
    fn get_encrypted_credentials_dir(&self) -> Result<Option<String>>;
    fn symlink_credential_dir(&mut self, envvar: &str, source: &str, target: &str) -> Result<()>;
    fn merge_credentials_trusted(&mut self, received_dir: Option<&str>) -> Result<()>;
    fn proc_cmdline_import_credentials(&self) -> Result<bool>;
    fn import_credentials_boot(&mut self) -> Result<()>;
    fn import_credentials_trusted(&mut self) -> Result<()>;
    fn report_credentials(&mut self);
    fn setenv_notify_socket(&mut self);
}

fn normalize_env_lookup(result: Result<Option<String>>) -> Result<Option<String>> {
    match result {
        Ok(value) => Ok(value),
        Err(Errno::ENXIO) => Ok(None),
        Err(error) => Ok(Some(format!("warning:{error:?}"))),
    }
}

fn ret_gather(slot: &mut Result<()>, next: Result<()>) {
    if slot.is_ok() {
        *slot = next;
    }
}

pub fn import_credentials(
    backend: &mut impl CredentialImportBackend,
) -> Result<ImportCredentialsOutcome> {
    let received_creds_dir = normalize_env_lookup(backend.get_credentials_dir())?;
    let received_encrypted_creds_dir =
        normalize_env_lookup(backend.get_encrypted_credentials_dir())?;

    let envvar_set = received_creds_dir
        .as_deref()
        .is_some_and(|path| !path.starts_with("warning:"))
        || received_encrypted_creds_dir
            .as_deref()
            .is_some_and(|path| !path.starts_with("warning:"));

    let mut gathered = Ok(());
    let mut outcome = ImportCredentialsOutcome {
        used_existing_env: envvar_set,
        imported_boot: false,
        imported_trusted: false,
        import_enabled: true,
        received_creds_dir: received_creds_dir.filter(|path| !path.starts_with("warning:")),
        received_encrypted_creds_dir: received_encrypted_creds_dir
            .filter(|path| !path.starts_with("warning:")),
    };

    if outcome.used_existing_env {
        if let Some(dir) = outcome.received_creds_dir.as_deref() {
            ret_gather(
                &mut gathered,
                backend.symlink_credential_dir(
                    "CREDENTIALS_DIRECTORY",
                    dir,
                    SYSTEM_CREDENTIALS_DIRECTORY,
                ),
            );
        }

        if let Some(dir) = outcome.received_encrypted_creds_dir.as_deref() {
            ret_gather(
                &mut gathered,
                backend.symlink_credential_dir(
                    "ENCRYPTED_CREDENTIALS_DIRECTORY",
                    dir,
                    ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY,
                ),
            );
        }

        ret_gather(
            &mut gathered,
            backend.merge_credentials_trusted(outcome.received_creds_dir.as_deref()),
        );
    } else {
        outcome.import_enabled = backend.proc_cmdline_import_credentials()?;
        if !outcome.import_enabled {
            return Ok(outcome);
        }

        ret_gather(&mut gathered, backend.import_credentials_boot());
        outcome.imported_boot = gathered.is_ok();

        ret_gather(&mut gathered, backend.import_credentials_trusted());
        outcome.imported_trusted = true;
    }

    backend.report_credentials();
    backend.setenv_notify_socket();

    gathered.map(|_| outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeBackend {
        creds_dir: Result<Option<String>>,
        encrypted_dir: Result<Option<String>>,
        import_enabled: Result<bool>,
        boot_result: Result<()>,
        trusted_result: Result<()>,
        symlinks: Vec<(String, String, String)>,
        merged: Vec<Option<String>>,
        reported: usize,
        notify_set: usize,
    }

    impl Default for FakeBackend {
        fn default() -> Self {
            Self {
                creds_dir: Ok(None),
                encrypted_dir: Ok(None),
                import_enabled: Ok(true),
                boot_result: Ok(()),
                trusted_result: Ok(()),
                symlinks: Vec::new(),
                merged: Vec::new(),
                reported: 0,
                notify_set: 0,
            }
        }
    }

    impl CredentialImportBackend for FakeBackend {
        fn get_credentials_dir(&self) -> Result<Option<String>> {
            self.creds_dir.clone()
        }

        fn get_encrypted_credentials_dir(&self) -> Result<Option<String>> {
            self.encrypted_dir.clone()
        }

        fn symlink_credential_dir(
            &mut self,
            envvar: &str,
            source: &str,
            target: &str,
        ) -> Result<()> {
            self.symlinks
                .push((envvar.to_string(), source.to_string(), target.to_string()));
            Ok(())
        }

        fn merge_credentials_trusted(&mut self, received_dir: Option<&str>) -> Result<()> {
            self.merged.push(received_dir.map(ToOwned::to_owned));
            Ok(())
        }

        fn proc_cmdline_import_credentials(&self) -> Result<bool> {
            self.import_enabled
        }

        fn import_credentials_boot(&mut self) -> Result<()> {
            self.boot_result
        }

        fn import_credentials_trusted(&mut self) -> Result<()> {
            self.trusted_result
        }

        fn report_credentials(&mut self) {
            self.reported += 1;
        }

        fn setenv_notify_socket(&mut self) {
            self.notify_set += 1;
        }
    }

    #[test]
    fn existing_environment_short_circuits_import() {
        let mut backend = FakeBackend {
            creds_dir: Ok(Some("/tmp/creds".into())),
            encrypted_dir: Err(Errno::ENXIO),
            import_enabled: Ok(true),
            boot_result: Ok(()),
            trusted_result: Ok(()),
            ..FakeBackend::default()
        };

        let outcome = import_credentials(&mut backend).unwrap();
        assert!(outcome.used_existing_env);
        assert_eq!(backend.symlinks.len(), 1);
        assert_eq!(backend.merged, vec![Some("/tmp/creds".into())]);
        assert_eq!(backend.reported, 1);
        assert_eq!(backend.notify_set, 1);
    }

    #[test]
    fn disabled_import_returns_before_reporting() {
        let mut backend = FakeBackend {
            creds_dir: Err(Errno::ENXIO),
            encrypted_dir: Err(Errno::ENXIO),
            import_enabled: Ok(false),
            boot_result: Ok(()),
            trusted_result: Ok(()),
            ..FakeBackend::default()
        };

        let outcome = import_credentials(&mut backend).unwrap();
        assert!(!outcome.used_existing_env);
        assert!(!outcome.import_enabled);
        assert_eq!(backend.reported, 0);
        assert_eq!(backend.notify_set, 0);
    }
}
