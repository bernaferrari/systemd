// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Ordered `run()` orchestration for systemd-volatile-root.
//
// PORT-SYNC: src/volatile-root/volatile-root.c

use std::io;

use crate::{
    BackingDevice, SysrootState, VOLATILE_ROOT_LINK, VolatileMode, VolatileRootArgs,
    mode_requires_root_transition, validate_path,
};
#[cfg(target_os = "linux")]
use crate::{
    BackingDeviceLinkBackend, LinuxBackingDeviceLinkBackend, LinuxOverlayTransitionBackend,
    LinuxVolatileTransitionBackend, inspect_sysroot, make_overlay_with, make_volatile_with,
};

/// A diagnostic emitted by the ordered, active-mode portion of C's `run()`.
///
/// The C tool reports an already-temporary sysroot as informational and a
/// backing-device symlink failure as a warning. Both conditions continue
/// successfully and therefore cannot be represented by the returned
/// `io::Result` alone. Keeping them typed prevents a future executable
/// boundary from accidentally treating the warning-only symlink as fatal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolatileRootDiagnostic {
    /// `path` already has a temporary filesystem and needs no transition.
    AlreadyTemporary { path: String },
    /// Recording the original backing device failed, but the transition
    /// continues exactly as the C authority does.
    BackingDeviceLinkFailed {
        target: String,
        link: String,
        error_kind: io::ErrorKind,
        /// Retained separately so a systemd logger can render C's `%m`
        /// diagnostic instead of flattening every failure to an error kind.
        error_raw_os_error: Option<i32>,
    },
}

/// The observable completion state of `run_volatile_root_with()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolatileRootRunOutcome {
    /// `no` and `state` do not touch the sysroot in this tool.
    Inactive,
    /// The target was already backed by a temporary filesystem.
    AlreadyTemporary,
    /// A full tmpfs-root replacement was performed by the supplied backend.
    MadeVolatile,
    /// An overlay root was mounted by the supplied backend.
    MadeOverlay,
}

/// Injectable complete active-mode boundary for `volatile-root.c`'s `run()`.
///
/// The trait starts after argument and command-line parsing, but retains the
/// exact C ordering of the remaining work: read-only mount-point preflight,
/// temporary-filesystem early success, backing-device discovery, warning-only
/// symlink creation, and finally the mode-specific transition. The individual
/// transition backends deliberately remain separate; this facade exists only
/// to prove that they are sequenced as one atomic *decision*, not to make the
/// production executable appear ready before its mount namespace is tested.
pub trait VolatileRootRunBackend {
    /// Equivalent to the `path_is_mount_point_full()` and
    /// `path_is_temporary_fs()` preflight pair.
    fn inspect_sysroot(&mut self, path: &str) -> io::Result<SysrootState>;
    /// Equivalent to `get_block_device_harder()`.
    fn backing_device(&mut self, path: &str) -> io::Result<Option<BackingDevice>>;
    /// Equivalent to the warning-only `symlink()` call.
    fn create_backing_device_link(&mut self, target: &str, link: &str) -> io::Result<()>;
    /// Equivalent to `make_volatile()`.
    fn make_volatile(&mut self, path: &str) -> io::Result<()>;
    /// Equivalent to `make_overlay()`.
    fn make_overlay(&mut self, path: &str) -> io::Result<()>;
    /// Report a non-fatal C diagnostic.
    fn report(&mut self, diagnostic: VolatileRootDiagnostic);
}

/// Linux composition of the isolated C-compatible volatile-root operations.
///
/// This joins the already-audited preflight, backing-device, overlay, and
/// fully-volatile backends at the same boundary as C's `run()`, while retaining
/// diagnostics for its caller. It deliberately has no logging policy and is
/// not wired into `main.rs`: invoking it changes a mount namespace and needs
/// an installed-initrd namespace test before it can become the executable's
/// production path.
///
/// Keeping the composition available now is still useful: namespace-scoped
/// tests can exercise the complete ordering through one concrete backend,
/// rather than independently testing pieces that a later integration might
/// accidentally sequence differently.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct LinuxVolatileRootRunBackend {
    diagnostics: Vec<VolatileRootDiagnostic>,
}

#[cfg(target_os = "linux")]
impl LinuxVolatileRootRunBackend {
    /// Construct a backend with no retained diagnostics.
    pub const fn new() -> Self {
        Self {
            diagnostics: Vec::new(),
        }
    }

    /// Diagnostics emitted by the most recent operations, in C ordering.
    pub fn diagnostics(&self) -> &[VolatileRootDiagnostic] {
        &self.diagnostics
    }

    /// Take accumulated non-fatal diagnostics without losing their ordering.
    pub fn take_diagnostics(&mut self) -> Vec<VolatileRootDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }
}

#[cfg(target_os = "linux")]
impl VolatileRootRunBackend for LinuxVolatileRootRunBackend {
    fn inspect_sysroot(&mut self, path: &str) -> io::Result<SysrootState> {
        inspect_sysroot(path)
    }

    fn backing_device(&mut self, path: &str) -> io::Result<Option<BackingDevice>> {
        let mut backend = LinuxBackingDeviceLinkBackend;
        backend.backing_device(path)
    }

    fn create_backing_device_link(&mut self, target: &str, link: &str) -> io::Result<()> {
        let mut backend = LinuxBackingDeviceLinkBackend;
        backend.create_symlink(target, link)
    }

    fn make_volatile(&mut self, path: &str) -> io::Result<()> {
        let mut backend = LinuxVolatileTransitionBackend;
        make_volatile_with(path, &mut backend)
    }

    fn make_overlay(&mut self, path: &str) -> io::Result<()> {
        let mut backend = LinuxOverlayTransitionBackend;
        make_overlay_with(path, &mut backend)
    }

    fn report(&mut self, diagnostic: VolatileRootDiagnostic) {
        self.diagnostics.push(diagnostic);
    }
}

/// Execute the complete mode-specific ordering of C's `run()` through an
/// injectable backend.
///
/// This API is intentionally narrow: it accepts already-resolved arguments,
/// validates their path before *any* backend call, and has no direct mount or
/// logging side effects. The real executable remains fail-closed until a
/// Linux backend is validated in the initrd mount namespace, including C's
/// older-kernel fallback policy.
pub fn run_volatile_root_with(
    args: &VolatileRootArgs,
    backend: &mut impl VolatileRootRunBackend,
) -> io::Result<VolatileRootRunOutcome> {
    // `run()` validates a supplied positional path before checking whether
    // the resolved mode is active. Repeating it here makes the public
    // orchestration boundary safe for callers that construct the args value
    // directly instead of going through `resolve_args_from_cmdline()`.
    validate_path(&args.path).map_err(|errno| io::Error::from_raw_os_error(-errno))?;

    if !mode_requires_root_transition(args.mode) {
        return Ok(VolatileRootRunOutcome::Inactive);
    }

    match backend.inspect_sysroot(&args.path)? {
        SysrootState::AlreadyTemporary => {
            backend.report(VolatileRootDiagnostic::AlreadyTemporary {
                path: args.path.clone(),
            });
            return Ok(VolatileRootRunOutcome::AlreadyTemporary);
        }
        SysrootState::NeedsTransition { .. } => {}
    }

    // Discovery failure is fatal and comes before either link creation or a
    // root transition. In contrast, link creation itself is only an
    // informational aid for post-transition consumers, so C warns and moves
    // on when it fails.
    if let Some(device) = backend.backing_device(&args.path)? {
        let target = device.link_content();
        if let Err(error) = backend.create_backing_device_link(&target, VOLATILE_ROOT_LINK) {
            backend.report(VolatileRootDiagnostic::BackingDeviceLinkFailed {
                target,
                link: VOLATILE_ROOT_LINK.to_owned(),
                error_kind: error.kind(),
                error_raw_os_error: error.raw_os_error(),
            });
        }
    }

    match args.mode {
        VolatileMode::Yes => {
            backend.make_volatile(&args.path)?;
            Ok(VolatileRootRunOutcome::MadeVolatile)
        }
        VolatileMode::Overlay => {
            backend.make_overlay(&args.path)?;
            Ok(VolatileRootRunOutcome::MadeOverlay)
        }
        VolatileMode::No | VolatileMode::State => Ok(VolatileRootRunOutcome::Inactive),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RunCall {
        Inspect(String),
        Discover(String),
        Symlink(String, String),
        MakeVolatile(String),
        MakeOverlay(String),
    }

    struct FakeRunBackend {
        calls: Vec<RunCall>,
        diagnostics: Vec<VolatileRootDiagnostic>,
        preflight: SysrootState,
        preflight_error: Option<i32>,
        device: Option<BackingDevice>,
        discovery_error: Option<i32>,
        symlink_error: Option<i32>,
        volatile_error: Option<i32>,
        overlay_error: Option<i32>,
    }

    impl Default for FakeRunBackend {
        fn default() -> Self {
            Self {
                calls: Vec::new(),
                diagnostics: Vec::new(),
                preflight: SysrootState::NeedsTransition {
                    filesystem_type: "ext4".into(),
                },
                preflight_error: None,
                device: None,
                discovery_error: None,
                symlink_error: None,
                volatile_error: None,
                overlay_error: None,
            }
        }
    }

    impl VolatileRootRunBackend for FakeRunBackend {
        fn inspect_sysroot(&mut self, path: &str) -> io::Result<SysrootState> {
            self.calls.push(RunCall::Inspect(path.into()));
            match self.preflight_error {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => Ok(self.preflight.clone()),
            }
        }

        fn backing_device(&mut self, path: &str) -> io::Result<Option<BackingDevice>> {
            self.calls.push(RunCall::Discover(path.into()));
            match self.discovery_error {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => Ok(self.device),
            }
        }

        fn create_backing_device_link(&mut self, target: &str, link: &str) -> io::Result<()> {
            self.calls
                .push(RunCall::Symlink(target.into(), link.into()));
            match self.symlink_error {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => Ok(()),
            }
        }

        fn make_volatile(&mut self, path: &str) -> io::Result<()> {
            self.calls.push(RunCall::MakeVolatile(path.into()));
            match self.volatile_error {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => Ok(()),
            }
        }

        fn make_overlay(&mut self, path: &str) -> io::Result<()> {
            self.calls.push(RunCall::MakeOverlay(path.into()));
            match self.overlay_error {
                Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                None => Ok(()),
            }
        }

        fn report(&mut self, diagnostic: VolatileRootDiagnostic) {
            self.diagnostics.push(diagnostic);
        }
    }

    #[test]
    fn keeps_inactive_modes_side_effect_free() {
        for mode in [VolatileMode::No, VolatileMode::State] {
            let args = VolatileRootArgs {
                mode,
                path: "/sysroot".into(),
            };
            let mut backend = FakeRunBackend::default();

            assert_eq!(
                run_volatile_root_with(&args, &mut backend).unwrap(),
                VolatileRootRunOutcome::Inactive
            );
            assert!(backend.calls.is_empty());
            assert!(backend.diagnostics.is_empty());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_backend_retains_nonfatal_diagnostics_without_mounting() {
        let mut backend = LinuxVolatileRootRunBackend::new();
        let diagnostic = VolatileRootDiagnostic::AlreadyTemporary {
            path: "/sysroot".into(),
        };

        backend.report(diagnostic.clone());
        assert_eq!(backend.diagnostics(), std::slice::from_ref(&diagnostic));
        assert_eq!(backend.take_diagnostics(), vec![diagnostic]);
        assert!(backend.diagnostics().is_empty());
    }

    #[test]
    fn validates_path_before_all_backend_operations() {
        let args = VolatileRootArgs {
            mode: VolatileMode::Overlay,
            path: "/./".into(),
        };
        let mut backend = FakeRunBackend::default();

        let error = run_volatile_root_with(&args, &mut backend).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        assert!(backend.calls.is_empty());
        assert!(backend.diagnostics.is_empty());
    }

    #[test]
    fn stops_after_preflight_failure() {
        let args = VolatileRootArgs {
            mode: VolatileMode::Yes,
            path: "/sysroot".into(),
        };
        let mut backend = FakeRunBackend {
            preflight_error: Some(libc::ENOTDIR),
            ..FakeRunBackend::default()
        };

        let error = run_volatile_root_with(&args, &mut backend).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR));
        assert_eq!(backend.calls, vec![RunCall::Inspect("/sysroot".into())]);
        assert!(backend.diagnostics.is_empty());
    }

    #[test]
    fn reports_temporary_sysroot_without_recording_or_mounting() {
        let args = VolatileRootArgs {
            mode: VolatileMode::Overlay,
            path: "/sysroot".into(),
        };
        let mut backend = FakeRunBackend {
            preflight: SysrootState::AlreadyTemporary,
            ..FakeRunBackend::default()
        };

        assert_eq!(
            run_volatile_root_with(&args, &mut backend).unwrap(),
            VolatileRootRunOutcome::AlreadyTemporary
        );
        assert_eq!(backend.calls, vec![RunCall::Inspect("/sysroot".into())]);
        assert_eq!(
            backend.diagnostics,
            vec![VolatileRootDiagnostic::AlreadyTemporary {
                path: "/sysroot".into()
            }]
        );
    }

    #[test]
    fn matches_c_yes_order_from_preflight_to_transition() {
        let args = VolatileRootArgs {
            mode: VolatileMode::Yes,
            path: "/sysroot".into(),
        };
        let mut backend = FakeRunBackend {
            device: Some(BackingDevice {
                major: 259,
                minor: 1,
            }),
            ..FakeRunBackend::default()
        };

        assert_eq!(
            run_volatile_root_with(&args, &mut backend).unwrap(),
            VolatileRootRunOutcome::MadeVolatile
        );
        assert_eq!(
            backend.calls,
            vec![
                RunCall::Inspect("/sysroot".into()),
                RunCall::Discover("/sysroot".into()),
                RunCall::Symlink("/dev/block/259:1".into(), VOLATILE_ROOT_LINK.into()),
                RunCall::MakeVolatile("/sysroot".into()),
            ]
        );
        assert!(backend.diagnostics.is_empty());
    }

    #[test]
    fn skips_missing_backing_device_and_dispatches_overlay() {
        let args = VolatileRootArgs {
            mode: VolatileMode::Overlay,
            path: "/sysroot".into(),
        };
        let mut backend = FakeRunBackend::default();

        assert_eq!(
            run_volatile_root_with(&args, &mut backend).unwrap(),
            VolatileRootRunOutcome::MadeOverlay
        );
        assert_eq!(
            backend.calls,
            vec![
                RunCall::Inspect("/sysroot".into()),
                RunCall::Discover("/sysroot".into()),
                RunCall::MakeOverlay("/sysroot".into()),
            ]
        );
        assert!(backend.diagnostics.is_empty());
    }

    #[test]
    fn makes_link_failure_warning_only_before_transition() {
        let args = VolatileRootArgs {
            mode: VolatileMode::Yes,
            path: "/sysroot".into(),
        };
        let mut backend = FakeRunBackend {
            device: Some(BackingDevice { major: 8, minor: 2 }),
            symlink_error: Some(libc::EROFS),
            ..FakeRunBackend::default()
        };

        assert_eq!(
            run_volatile_root_with(&args, &mut backend).unwrap(),
            VolatileRootRunOutcome::MadeVolatile
        );
        assert_eq!(
            backend.calls,
            vec![
                RunCall::Inspect("/sysroot".into()),
                RunCall::Discover("/sysroot".into()),
                RunCall::Symlink("/dev/block/8:2".into(), VOLATILE_ROOT_LINK.into()),
                RunCall::MakeVolatile("/sysroot".into()),
            ]
        );
        assert_eq!(
            backend.diagnostics,
            vec![VolatileRootDiagnostic::BackingDeviceLinkFailed {
                target: "/dev/block/8:2".into(),
                link: VOLATILE_ROOT_LINK.into(),
                error_kind: io::ErrorKind::ReadOnlyFilesystem,
                error_raw_os_error: Some(libc::EROFS),
            }]
        );
    }

    #[test]
    fn stops_before_transition_when_discovery_fails() {
        let args = VolatileRootArgs {
            mode: VolatileMode::Overlay,
            path: "/sysroot".into(),
        };
        let mut backend = FakeRunBackend {
            discovery_error: Some(libc::ENODEV),
            ..FakeRunBackend::default()
        };

        let error = run_volatile_root_with(&args, &mut backend).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENODEV));
        assert_eq!(
            backend.calls,
            vec![
                RunCall::Inspect("/sysroot".into()),
                RunCall::Discover("/sysroot".into()),
            ]
        );
        assert!(backend.diagnostics.is_empty());
    }

    #[test]
    fn preserves_transition_failure_after_warning() {
        let args = VolatileRootArgs {
            mode: VolatileMode::Overlay,
            path: "/sysroot".into(),
        };
        let mut backend = FakeRunBackend {
            device: Some(BackingDevice { major: 8, minor: 3 }),
            symlink_error: Some(libc::EEXIST),
            overlay_error: Some(libc::EOPNOTSUPP),
            ..FakeRunBackend::default()
        };

        let error = run_volatile_root_with(&args, &mut backend).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP));
        assert_eq!(
            backend.calls,
            vec![
                RunCall::Inspect("/sysroot".into()),
                RunCall::Discover("/sysroot".into()),
                RunCall::Symlink("/dev/block/8:3".into(), VOLATILE_ROOT_LINK.into()),
                RunCall::MakeOverlay("/sysroot".into()),
            ]
        );
        assert_eq!(backend.diagnostics.len(), 1);
    }
}
