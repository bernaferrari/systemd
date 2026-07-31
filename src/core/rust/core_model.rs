// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Ownership-oriented core model for unit/job management.
//
// This is a compiled-but-disconnected model, not a replacement for the live
// `runtime_manager::RuntimeManager` owner. Its manager state uses the shared
// manager vocabulary so it cannot create a competing objective enum.
//
// This module provides ID-based cross-references between units and jobs and
// avoids pointer-sharing patterns.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::manager_tables::{ManagerObjective, ManagerState};
use systemd_shared_rs::unit_file::UnitFile;

pub type EnumMap<K, V> = BTreeMap<K, V>;
pub type Pid = u32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitId(pub u32);

impl fmt::Display for UnitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(pub u32);

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadState {
    Stub,
    Loaded,
    NotFound,
    BadSetting,
    Error,
    Masked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveState {
    Active,
    Reloading,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    Maintenance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    pub kind: String,
    pub parameter: String,
    pub trigger: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecContext;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KillContext;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Dead,
    StartPre,
    Start,
    Running,
    Reload,
    Stop,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceUnit {
    pub state: ServiceState,
    pub main_pid: Option<Pid>,
    pub control_pid: Option<Pid>,
    pub exec_context: ExecContext,
    pub kill_context: KillContext,
}

impl Default for ServiceUnit {
    fn default() -> Self {
        Self {
            state: ServiceState::Dead,
            main_pid: None,
            control_pid: None,
            exec_context: ExecContext,
            kill_context: KillContext,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SocketUnit {
    pub listening: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetUnit {
    pub reached: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountUnit {
    pub mounted: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimerUnit {
    pub waiting: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathUnit {
    pub watching: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SwapUnit {
    pub active: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AutomountUnit {
    pub active: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SliceUnit {
    pub managed: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeUnit {
    pub attached_pids: HashSet<Pid>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceUnit {
    pub available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitData {
    Service(ServiceUnit),
    Socket(SocketUnit),
    Target(TargetUnit),
    Mount(MountUnit),
    Timer(TimerUnit),
    Path(PathUnit),
    Swap(SwapUnit),
    Automount(AutomountUnit),
    Slice(SliceUnit),
    Scope(ScopeUnit),
    Device(DeviceUnit),
}

impl Default for UnitData {
    fn default() -> Self {
        Self::Target(TargetUnit::default())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnitDependency {
    Requires,
    RequiredBy,
    Requisite,
    RequisiteOf,
    Wants,
    WantedBy,
    BindsTo,
    BoundBy,
    PartOf,
    ConsistsOf,
    Upholds,
    UpheldBy,
    Conflicts,
    Before,
    After,
    OnFailure,
    OnFailureOf,
    OnSuccess,
    OnSuccessOf,
    PropagatesReloadTo,
    ReloadPropagatedFrom,
    PropagatesStopTo,
    StopPropagatedFrom,
    JoinsNamespaceOf,
    RequiresMountsFor,
    RequiredMountsBy,
    WantsMountsFor,
    WantedMountsBy,
    InSlice,
    SliceOf,
}

impl UnitDependency {
    pub const fn reverse(self) -> Self {
        match self {
            Self::Requires => Self::RequiredBy,
            Self::RequiredBy => Self::Requires,
            Self::Requisite => Self::RequisiteOf,
            Self::RequisiteOf => Self::Requisite,
            Self::Wants => Self::WantedBy,
            Self::WantedBy => Self::Wants,
            Self::BindsTo => Self::BoundBy,
            Self::BoundBy => Self::BindsTo,
            Self::PartOf => Self::ConsistsOf,
            Self::ConsistsOf => Self::PartOf,
            Self::Upholds => Self::UpheldBy,
            Self::UpheldBy => Self::Upholds,
            Self::Conflicts => Self::Conflicts,
            Self::Before => Self::After,
            Self::After => Self::Before,
            Self::OnFailure => Self::OnFailureOf,
            Self::OnFailureOf => Self::OnFailure,
            Self::OnSuccess => Self::OnSuccessOf,
            Self::OnSuccessOf => Self::OnSuccess,
            Self::PropagatesReloadTo => Self::ReloadPropagatedFrom,
            Self::ReloadPropagatedFrom => Self::PropagatesReloadTo,
            Self::PropagatesStopTo => Self::StopPropagatedFrom,
            Self::StopPropagatedFrom => Self::PropagatesStopTo,
            Self::JoinsNamespaceOf => Self::JoinsNamespaceOf,
            Self::RequiresMountsFor => Self::RequiredMountsBy,
            Self::RequiredMountsBy => Self::RequiresMountsFor,
            Self::WantsMountsFor => Self::WantedMountsBy,
            Self::WantedMountsBy => Self::WantsMountsFor,
            Self::InSlice => Self::SliceOf,
            Self::SliceOf => Self::InSlice,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub id: UnitId,
    pub names: HashSet<String>,
    pub load_state: LoadState,
    pub active_state: ActiveState,
    pub sub_state: String,
    pub data: UnitData,
    pub deps: EnumMap<UnitDependency, HashSet<UnitId>>,
    pub job: Option<JobId>,
    pub nop_job: Option<JobId>,
    pub cgroup_path: Option<PathBuf>,
    pub cgroup_realized: bool,
    pub fragment_path: Option<PathBuf>,
    pub source_path: Option<PathBuf>,
    pub dropin_paths: Vec<PathBuf>,
    pub description: Option<String>,
    pub documentation: Vec<String>,
    pub conditions: Vec<Condition>,
    pub asserts: Vec<Condition>,
    pub refuse_manual_start: bool,
    pub refuse_manual_stop: bool,
    pub default_dependencies: bool,
    pub transient: bool,
}

impl Unit {
    pub fn new(id: UnitId, data: UnitData) -> Self {
        Self {
            id,
            names: HashSet::new(),
            load_state: LoadState::Stub,
            active_state: ActiveState::Inactive,
            sub_state: String::new(),
            data,
            deps: EnumMap::new(),
            job: None,
            nop_job: None,
            cgroup_path: None,
            cgroup_realized: false,
            fragment_path: None,
            source_path: None,
            dropin_paths: Vec::new(),
            description: None,
            documentation: Vec::new(),
            conditions: Vec::new(),
            asserts: Vec::new(),
            refuse_manual_start: false,
            refuse_manual_stop: false,
            default_dependencies: true,
            transient: false,
        }
    }

    fn insert_dep(&mut self, dep: UnitDependency, id: UnitId) {
        self.deps.entry(dep).or_default().insert(id);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: JobId,
    pub unit: UnitId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manager {
    pub units: HashMap<UnitId, Unit>,
    pub units_by_name: HashMap<String, UnitId>,
    pub jobs: HashMap<JobId, Job>,
    pub state: ManagerState,
    pub objective: ManagerObjective,
    pub cgroup_root: PathBuf,
    pub default_target: String,
    pub environment: Vec<String>,
    pub unit_path: Vec<PathBuf>,
    pub next_unit_id: UnitId,
    pub next_job_id: JobId,
}

impl Default for Manager {
    fn default() -> Self {
        Self {
            units: HashMap::new(),
            units_by_name: HashMap::new(),
            jobs: HashMap::new(),
            state: ManagerState::Initializing,
            objective: ManagerObjective::Ok,
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            default_target: "default.target".to_string(),
            environment: Vec::new(),
            unit_path: Vec::new(),
            next_unit_id: UnitId(1),
            next_job_id: JobId(1),
        }
    }
}

impl Manager {
    pub fn alloc_unit_id(&mut self) -> UnitId {
        let current = self.next_unit_id;
        self.next_unit_id = UnitId(self.next_unit_id.0.saturating_add(1));
        current
    }

    pub fn alloc_job_id(&mut self) -> JobId {
        let current = self.next_job_id;
        self.next_job_id = JobId(self.next_job_id.0.saturating_add(1));
        current
    }

    pub fn add_unit(&mut self, mut unit: Unit) {
        let id = unit.id;
        for name in &unit.names {
            self.units_by_name.insert(name.clone(), id);
        }
        unit.id = id;
        self.units.insert(id, unit);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyError {
    UnknownFromUnit(UnitId),
    UnknownToUnit(UnitId),
}

#[derive(Debug)]
pub enum UnitLoadError {
    UnknownUnitName(String),
    NotFound(String),
    Io(std::io::Error),
    Parse(systemd_shared_rs::unit_file::UnitFileParseError),
}

impl fmt::Display for UnitLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownUnitName(name) => write!(f, "unknown unit name: {name}"),
            Self::NotFound(name) => write!(f, "unit fragment not found: {name}"),
            Self::Io(err) => write!(f, "I/O error while loading unit fragment: {err}"),
            Self::Parse(err) => write!(f, "failed to parse unit fragment: {err}"),
        }
    }
}

impl std::error::Error for UnitLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Parse(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for UnitLoadError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<systemd_shared_rs::unit_file::UnitFileParseError> for UnitLoadError {
    fn from(value: systemd_shared_rs::unit_file::UnitFileParseError) -> Self {
        Self::Parse(value)
    }
}

pub fn unit_add_dependency(
    manager: &mut Manager,
    from: UnitId,
    dep: UnitDependency,
    to: UnitId,
) -> Result<(), DependencyError> {
    if !manager.units.contains_key(&from) {
        return Err(DependencyError::UnknownFromUnit(from));
    }
    if !manager.units.contains_key(&to) {
        return Err(DependencyError::UnknownToUnit(to));
    }

    let reverse = dep.reverse();

    {
        let from_unit = manager
            .units
            .get_mut(&from)
            .ok_or(DependencyError::UnknownFromUnit(from))?;
        from_unit.insert_dep(dep, to);
    }

    {
        let to_unit = manager
            .units
            .get_mut(&to)
            .ok_or(DependencyError::UnknownToUnit(to))?;
        to_unit.insert_dep(reverse, from);
    }

    Ok(())
}

fn default_unit_paths() -> Vec<PathBuf> {
    // This disconnected model must not grow a second, stale unit-path
    // policy. The runtime manager owns the compiled default order; both
    // models retain an explicit `Manager::unit_path` override for tests.
    crate::runtime_manager::unit_file::default_unit_search_paths()
}

fn unit_candidate_names(name: &str) -> Vec<String> {
    let mut candidates = vec![name.to_string()];

    if let Some((stem, suffix)) = name.rsplit_once('.')
        && let Some((prefix, instance)) = stem.split_once('@')
        && !instance.is_empty()
    {
        candidates.push(format!("{prefix}@.{suffix}"));
    }

    candidates
}

fn parse_fragment(path: &Path) -> Result<(), UnitLoadError> {
    let file = File::open(path)?;
    let _ = UnitFile::parse_reader_strict_systemd(file)?;
    Ok(())
}

fn canonical_unit_name(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
}

pub fn unit_find_fragment(manager: &mut Manager, name: &str) -> Result<PathBuf, UnitLoadError> {
    let unit_id = manager
        .units_by_name
        .get(name)
        .copied()
        .ok_or_else(|| UnitLoadError::UnknownUnitName(name.to_string()))?;

    let search_paths = if manager.unit_path.is_empty() {
        default_unit_paths()
    } else {
        manager.unit_path.clone()
    };

    for candidate_name in unit_candidate_names(name) {
        for search_path in &search_paths {
            let source_path = search_path.join(&candidate_name);
            if !source_path.exists() {
                continue;
            }

            let fragment_path = source_path
                .canonicalize()
                .unwrap_or_else(|_| source_path.clone());
            parse_fragment(&fragment_path)?;

            let resolved_name = canonical_unit_name(&fragment_path);
            let unit = manager
                .units
                .get_mut(&unit_id)
                .ok_or_else(|| UnitLoadError::UnknownUnitName(name.to_string()))?;
            unit.fragment_path = Some(fragment_path.clone());
            unit.source_path = (source_path != fragment_path).then_some(source_path.clone());
            unit.load_state = LoadState::Loaded;

            if let Some(resolved_name) = resolved_name {
                unit.names.insert(resolved_name.clone());
                manager
                    .units_by_name
                    .entry(resolved_name)
                    .or_insert(unit_id);
            }

            return Ok(fragment_path);
        }
    }

    if let Some(unit) = manager.units.get_mut(&unit_id) {
        unit.fragment_path = None;
        unit.source_path = None;
        unit.load_state = LoadState::NotFound;
    }
    Err(UnitLoadError::NotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unit(id: u32, name: &str) -> Unit {
        let mut u = Unit::new(UnitId(id), UnitData::Service(ServiceUnit::default()));
        u.names.insert(name.to_string());
        u
    }

    #[test]
    fn id_newtypes_are_hashable_and_displayable() {
        let mut units = HashSet::new();
        units.insert(UnitId(7));
        assert!(units.contains(&UnitId(7)));
        assert_eq!(UnitId(12).to_string(), "12");
        assert_eq!(JobId(33).to_string(), "33");
    }

    #[test]
    fn disconnected_model_uses_runtime_unit_search_defaults() {
        assert_eq!(
            default_unit_paths(),
            crate::runtime_manager::unit_file::default_unit_search_paths()
        );
    }

    #[test]
    fn unit_data_has_all_expected_variants() {
        let variants = [
            UnitData::Service(ServiceUnit::default()),
            UnitData::Socket(SocketUnit::default()),
            UnitData::Target(TargetUnit::default()),
            UnitData::Mount(MountUnit::default()),
            UnitData::Timer(TimerUnit::default()),
            UnitData::Path(PathUnit::default()),
            UnitData::Swap(SwapUnit::default()),
            UnitData::Automount(AutomountUnit::default()),
            UnitData::Slice(SliceUnit::default()),
            UnitData::Scope(ScopeUnit::default()),
            UnitData::Device(DeviceUnit::default()),
        ];
        assert_eq!(variants.len(), 11);
    }

    #[test]
    fn manager_owns_units_jobs_and_metadata() {
        let mut manager = Manager::default();
        let mut alpha = unit(1, "alpha.service");
        alpha.job = Some(JobId(9));
        manager.add_unit(alpha);
        manager.jobs.insert(
            JobId(9),
            Job {
                id: JobId(9),
                unit: UnitId(1),
            },
        );

        assert_eq!(
            manager.units_by_name.get("alpha.service").copied(),
            Some(UnitId(1))
        );
        assert_eq!(manager.jobs.get(&JobId(9)).map(|j| j.unit), Some(UnitId(1)));
    }

    #[test]
    fn dependency_reverse_pairs_match_expected() {
        assert_eq!(
            UnitDependency::Requires.reverse(),
            UnitDependency::RequiredBy
        );
        assert_eq!(UnitDependency::Before.reverse(), UnitDependency::After);
        assert_eq!(UnitDependency::InSlice.reverse(), UnitDependency::SliceOf);
        assert_eq!(
            UnitDependency::PropagatesStopTo.reverse(),
            UnitDependency::StopPropagatedFrom
        );
    }

    #[test]
    fn unit_add_dependency_registers_both_directions() {
        let mut manager = Manager::default();
        manager.add_unit(unit(1, "alpha.service"));
        manager.add_unit(unit(2, "beta.service"));

        unit_add_dependency(&mut manager, UnitId(1), UnitDependency::Requires, UnitId(2)).unwrap();

        assert!(manager.units[&UnitId(1)].deps[&UnitDependency::Requires].contains(&UnitId(2)));
        assert!(manager.units[&UnitId(2)].deps[&UnitDependency::RequiredBy].contains(&UnitId(1)));
    }

    #[test]
    fn unit_add_dependency_is_atomic_on_missing_units() {
        let mut manager = Manager::default();
        manager.add_unit(unit(1, "alpha.service"));

        let error = unit_add_dependency(
            &mut manager,
            UnitId(1),
            UnitDependency::Requires,
            UnitId(999),
        )
        .unwrap_err();
        assert_eq!(error, DependencyError::UnknownToUnit(UnitId(999)));
        assert!(
            !manager.units[&UnitId(1)]
                .deps
                .contains_key(&UnitDependency::Requires)
        );
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{stamp}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn unit_find_fragment_loads_direct_file() {
        let root = unique_temp_dir("core-model-fragment-direct");
        let path = root.join("demo.service");
        fs::write(&path, "[Unit]\nDescription=Demo\n").unwrap();
        let canonical = path.canonicalize().unwrap();

        let mut manager = Manager {
            unit_path: vec![root.clone()],
            ..Default::default()
        };
        manager.add_unit(unit(1, "demo.service"));

        let loaded = unit_find_fragment(&mut manager, "demo.service").unwrap();
        assert_eq!(loaded, canonical);
        assert_eq!(manager.units[&UnitId(1)].load_state, LoadState::Loaded);
        assert_eq!(manager.units[&UnitId(1)].fragment_path, Some(canonical));
    }

    #[test]
    fn unit_find_fragment_uses_template_fallback_for_instance() {
        let root = unique_temp_dir("core-model-fragment-template");
        let template = root.join("demo@.service");
        fs::write(&template, "[Unit]\nDescription=Template\n").unwrap();
        let canonical = template.canonicalize().unwrap();

        let mut manager = Manager {
            unit_path: vec![root.clone()],
            ..Default::default()
        };
        manager.add_unit(unit(1, "demo@prod.service"));

        let loaded = unit_find_fragment(&mut manager, "demo@prod.service").unwrap();
        assert_eq!(loaded, canonical);
        assert_eq!(manager.units[&UnitId(1)].load_state, LoadState::Loaded);
    }

    #[cfg(unix)]
    #[test]
    fn unit_find_fragment_tracks_alias_source_path_for_symlink() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("core-model-fragment-alias");
        let canonical = root.join("real.service");
        let alias = root.join("alias.service");

        fs::write(&canonical, "[Unit]\nDescription=Real\n").unwrap();
        symlink(&canonical, &alias).unwrap();
        let canonical_path = canonical.canonicalize().unwrap();

        let mut manager = Manager {
            unit_path: vec![root],
            ..Default::default()
        };
        manager.add_unit(unit(1, "alias.service"));

        let loaded = unit_find_fragment(&mut manager, "alias.service").unwrap();
        let unit = &manager.units[&UnitId(1)];
        assert_eq!(loaded, canonical_path);
        assert_eq!(unit.source_path, Some(alias));
        assert!(unit.names.contains("real.service"));
        assert_eq!(
            manager.units_by_name.get("real.service").copied(),
            Some(UnitId(1))
        );
    }

    #[test]
    fn unit_find_fragment_marks_not_found_when_missing() {
        let root = unique_temp_dir("core-model-fragment-missing");

        let mut manager = Manager {
            unit_path: vec![root],
            ..Default::default()
        };
        manager.add_unit(unit(1, "missing.service"));

        let error = unit_find_fragment(&mut manager, "missing.service").unwrap_err();
        assert_eq!(
            error.to_string(),
            "unit fragment not found: missing.service"
        );
        assert_eq!(manager.units[&UnitId(1)].load_state, LoadState::NotFound);
    }

    #[test]
    fn unit_find_fragment_fails_on_invalid_syntax() {
        let root = unique_temp_dir("core-model-fragment-invalid");
        let invalid = root.join("broken.service");
        fs::write(&invalid, "[Unit\nDescription=Broken\n").unwrap();

        let mut manager = Manager {
            unit_path: vec![root],
            ..Default::default()
        };
        manager.add_unit(unit(1, "broken.service"));

        let err = unit_find_fragment(&mut manager, "broken.service").unwrap_err();
        assert!(matches!(err, UnitLoadError::Parse(_)));
        assert_eq!(manager.units[&UnitId(1)].load_state, LoadState::Stub);
    }
}
