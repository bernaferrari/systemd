// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/manager.c, src/libsystemd/sd-path/path-lookup.c

//! Typed startup contract for PID 1 generators.
//!
//! C's `manager_startup()` has an ordering dependency that is easy to lose in
//! a partial port: environment generators run first and mutate the transient
//! manager environment; unit generators then receive the resulting generated
//! environment and write the three generated-unit trees that unit loading
//! consumes. This module makes that dependency data-visible. The environment
//! executor now parses and feeds forward C's `gather_environment` protocol,
//! but `main` remains deliberately unwired until the manager startup owner can
//! install the returned transient environment at C's exact lifecycle point.
//! Running only the second half would still be less faithful than leaving the
//! C production path selected.

use crate::generator_runtime::{
    EnvironmentGeneratorExecutionReport, GeneratorExecutionError, GeneratorExecutionOptions,
    GeneratorExecutionReport, execute_system_environment_generators_with_fallback,
    run_system_generator_lifecycle_with_fallback,
};
use crate::generator_setup::{
    GeneratorEnvironmentFacts, GeneratorRunError, GeneratorRunOutcome, GeneratorRuntimeScope,
    LookupPaths, build_generator_environment,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SYSTEM_GENERATOR_PATHS: &[&str] = &[
    "/run/systemd/system-generators",
    "/etc/systemd/system-generators",
    "/usr/local/lib/systemd/system-generators",
    "/usr/lib/systemd/system-generators",
];
const SYSTEM_ENV_GENERATOR_PATHS: &[&str] = &[
    "/run/systemd/system-environment-generators",
    "/etc/systemd/system-environment-generators",
    "/usr/local/lib/systemd/system-environment-generators",
    "/usr/lib/systemd/system-environment-generators",
];

/// Generator search-path category, including its exact C override variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pid1GeneratorKind {
    Environment,
    Unit,
}

impl Pid1GeneratorKind {
    fn override_variable(self) -> &'static str {
        match self {
            Self::Environment => "SYSTEMD_ENVIRONMENT_GENERATOR_PATH",
            Self::Unit => "SYSTEMD_GENERATOR_PATH",
        }
    }

    fn defaults(self) -> &'static [&'static str] {
        match self {
            Self::Environment => SYSTEM_ENV_GENERATOR_PATHS,
            Self::Unit => SYSTEM_GENERATOR_PATHS,
        }
    }
}

/// A PID 1 startup plan has no valid user-manager form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pid1GeneratorPlanError {
    NonSystemScope,
}

impl std::fmt::Display for Pid1GeneratorPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PID 1 generator startup requires system runtime scope")
    }
}

impl std::error::Error for Pid1GeneratorPlanError {}

/// Return the system manager's generator directories with C's override rules.
///
/// An unset variable selects the compiled-in paths. A trailing `:` appends the
/// compiled-in paths after the supplied entries. C converts a relative entry
/// against its current working directory; PID 1 has already chdir'd to `/`, so
/// this makes a relative override rooted rather than silently rejecting a
/// configuration that C accepts.
pub fn system_generator_paths(
    kind: Pid1GeneratorKind,
    environment: &BTreeMap<String, String>,
) -> Vec<PathBuf> {
    let variable = kind.override_variable();
    let Some(value) = environment.get(variable) else {
        return kind.defaults().iter().map(PathBuf::from).collect();
    };

    let append_defaults = value.ends_with(':');
    let mut paths = Vec::new();
    for entry in value.split(':').filter(|entry| !entry.is_empty()) {
        let entry = PathBuf::from(entry);
        paths.push(if entry.is_absolute() {
            entry
        } else {
            Path::new("/").join(entry)
        });
    }
    if append_defaults || paths.is_empty() {
        paths.extend(kind.defaults().iter().map(PathBuf::from));
    }
    paths
}

/// Exact generated-unit output directories for a system manager under `root`.
///
/// Passing `/` selects the live paths.  Tests and a future `--root` startup
/// path can provide an alternate root without allowing `..` to escape it.
pub fn system_generator_lookup_paths(root: &Path) -> LookupPaths {
    let under_root = |absolute: &str| {
        root.join(
            Path::new(absolute)
                .strip_prefix("/")
                .expect("generator output paths are absolute"),
        )
    };
    LookupPaths {
        generator: Some(under_root("/run/systemd/generator")),
        generator_early: Some(under_root("/run/systemd/generator.early")),
        generator_late: Some(under_root("/run/systemd/generator.late")),
        root_dir: (root != Path::new("/")).then(|| root.to_path_buf()),
        ..LookupPaths::default()
    }
}

/// Inputs frozen before startup performs any generator process execution.
///
/// `initial_environment` is the manager transient environment before
/// environment generators.  The only safe transition to `unit_environment`
/// is [`Pid1GeneratorStartupPlan::after_environment_generators`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pid1GeneratorStartupPlan {
    pub environment_generator_paths: Vec<PathBuf>,
    pub unit_generator_paths: Vec<PathBuf>,
    pub lookup_paths: LookupPaths,
    facts: GeneratorEnvironmentFacts,
    initial_environment: BTreeMap<String, String>,
}

impl Pid1GeneratorStartupPlan {
    /// Build a system-PID1 plan without executing untrusted generator code.
    pub fn new(
        root: &Path,
        initial_environment: BTreeMap<String, String>,
        facts: GeneratorEnvironmentFacts,
    ) -> Result<Self, Pid1GeneratorPlanError> {
        if facts.scope != GeneratorRuntimeScope::System {
            return Err(Pid1GeneratorPlanError::NonSystemScope);
        }
        Ok(Self {
            environment_generator_paths: system_generator_paths(
                Pid1GeneratorKind::Environment,
                &initial_environment,
            ),
            unit_generator_paths: system_generator_paths(
                Pid1GeneratorKind::Unit,
                &initial_environment,
            ),
            lookup_paths: system_generator_lookup_paths(root),
            facts,
            initial_environment,
        })
    }

    /// Return the environment given to the first environment generator.
    pub fn initial_environment(&self) -> &BTreeMap<String, String> {
        &self.initial_environment
    }

    /// Run environment generators with C's serial stdout feed-forward
    /// protocol. The returned transient map is the sole valid input to
    /// [`Self::run_unit_generators`].
    ///
    /// This remains an explicit startup seam rather than production `main`
    /// wiring: the eventual manager owner must install the returned map into
    /// its transient-environment state at the same point that C consumes the
    /// executor's serialized result.
    pub fn run_environment_generators(
        &self,
    ) -> Result<EnvironmentGeneratorExecutionReport, GeneratorExecutionError> {
        let options = GeneratorExecutionOptions {
            environment: self.initial_environment.clone(),
            ..GeneratorExecutionOptions::default()
        };
        execute_system_environment_generators_with_fallback(
            &self.environment_generator_paths,
            self.initial_environment.clone(),
            &options,
        )
    }

    /// Build unit-generator execution options only after an environment
    /// executor has returned the serially accumulated transient environment.
    ///
    /// This encodes C's `gather_environment` dependency.  The environment
    /// executor is responsible for accepting valid `VAR=value` output,
    /// rejecting malformed records without accidentally applying them, and
    /// publishing its final map both to PID 1 and to subsequent generators.
    pub fn after_environment_generators(
        &self,
        transient_environment: BTreeMap<String, String>,
    ) -> GeneratorExecutionOptions {
        GeneratorExecutionOptions {
            environment: build_generator_environment(transient_environment, &self.facts),
            ..GeneratorExecutionOptions::default()
        }
    }

    /// Execute unit generators with the C-compatible sandbox fallback.
    ///
    /// Callers must supply the map produced by the completed environment
    /// stage.  A system manager never silently falls back from a setup error:
    /// only the narrow namespace-creation failure accepted by C is retried by
    /// the underlying executor.
    pub fn run_unit_generators(
        &self,
        transient_environment: BTreeMap<String, String>,
    ) -> Result<
        GeneratorRunOutcome<GeneratorExecutionReport>,
        GeneratorRunError<GeneratorExecutionError>,
    > {
        let options = self.after_environment_generators(transient_environment);
        run_system_generator_lifecycle_with_fallback(
            &self.lookup_paths,
            &self.unit_generator_paths,
            &options,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> GeneratorEnvironmentFacts {
        GeneratorEnvironmentFacts {
            scope: GeneratorRuntimeScope::System,
            in_initrd: false,
            soft_reboots_count: 0,
            first_boot: Some(false),
            virtualization: None,
            confidential_virtualization: None,
            architecture: "x86-64".to_string(),
        }
    }

    #[test]
    fn system_paths_match_c_precedence_and_trailing_colon_contract() {
        let env = BTreeMap::from([(
            "SYSTEMD_GENERATOR_PATH".to_string(),
            "/custom/high:/custom/low:".to_string(),
        )]);
        assert_eq!(
            system_generator_paths(Pid1GeneratorKind::Unit, &env),
            vec![
                PathBuf::from("/custom/high"),
                PathBuf::from("/custom/low"),
                PathBuf::from("/run/systemd/system-generators"),
                PathBuf::from("/etc/systemd/system-generators"),
                PathBuf::from("/usr/local/lib/systemd/system-generators"),
                PathBuf::from("/usr/lib/systemd/system-generators"),
            ]
        );
    }

    #[test]
    fn override_without_trailing_colon_hides_compiled_in_paths() {
        let env = BTreeMap::from([(
            "SYSTEMD_ENVIRONMENT_GENERATOR_PATH".to_string(),
            "/only/this".to_string(),
        )]);
        assert_eq!(
            system_generator_paths(Pid1GeneratorKind::Environment, &env),
            vec![PathBuf::from("/only/this")]
        );
    }

    #[test]
    fn pid1_plan_resolves_relative_override_against_the_root_cwd() {
        let env = BTreeMap::from([("SYSTEMD_GENERATOR_PATH".to_string(), "relative".to_string())]);
        let plan = Pid1GeneratorStartupPlan::new(Path::new("/"), env, facts()).unwrap();
        assert_eq!(plan.unit_generator_paths, vec![PathBuf::from("/relative")]);
    }

    #[test]
    fn environment_stage_is_the_only_way_to_build_unit_generator_environment() {
        let plan = Pid1GeneratorStartupPlan::new(
            Path::new("/root-for-test"),
            BTreeMap::from([("ORIGINAL".to_string(), "one".to_string())]),
            facts(),
        )
        .unwrap();
        let unit_options = plan.after_environment_generators(BTreeMap::from([
            ("ORIGINAL".to_string(), "updated".to_string()),
            ("FROM_ENV_GENERATOR".to_string(), "yes".to_string()),
        ]));

        assert_eq!(
            unit_options.environment.get("ORIGINAL"),
            Some(&"updated".to_string())
        );
        assert_eq!(
            unit_options.environment.get("FROM_ENV_GENERATOR"),
            Some(&"yes".to_string())
        );
        assert_eq!(
            unit_options.environment.get("SYSTEMD_SCOPE"),
            Some(&"system".to_string())
        );
        assert_eq!(
            plan.lookup_paths.generator,
            Some(PathBuf::from("/root-for-test/run/systemd/generator"))
        );
    }

    #[test]
    fn pid1_plan_rejects_user_scope_without_panicking() {
        let mut user_facts = facts();
        user_facts.scope = GeneratorRuntimeScope::User;
        assert_eq!(
            Pid1GeneratorStartupPlan::new(Path::new("/"), BTreeMap::new(), user_facts),
            Err(Pid1GeneratorPlanError::NonSystemScope)
        );
    }
}
