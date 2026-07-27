// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/slice.c
//
use std::collections::BTreeMap;

pub const SOURCE_PATH: &str = "src/core/slice.c";
pub const SPECIAL_ROOT_SLICE: &str = "-.slice";
pub const SPECIAL_SYSTEM_SLICE: &str = "system.slice";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    Stub,
    Loaded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceState {
    Dead,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Inactive,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SliceError {
    InvalidName(String),
    InvalidLoadState,
    LocatedOutsideParent,
    UnsupportedFreezerAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceUnit {
    pub id: String,
    pub load_state: LoadState,
    pub ignore_on_isolate: bool,
    pub default_dependencies: bool,
    pub description: Option<String>,
    pub documentation: Vec<String>,
    pub perpetual: bool,
    pub parent_slice: Option<String>,
    pub before_shutdown: bool,
    pub conflicts_shutdown: bool,
    pub manager_is_system: bool,
    pub manager_test_ignore_dependencies: bool,
}

impl SliceUnit {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            load_state: LoadState::Stub,
            ignore_on_isolate: false,
            default_dependencies: true,
            description: None,
            documentation: Vec::new(),
            perpetual: false,
            parent_slice: None,
            before_shutdown: false,
            conflicts_shutdown: false,
            manager_is_system: false,
            manager_test_ignore_dependencies: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slice {
    pub unit: SliceUnit,
    pub state: SliceState,
    pub deserialized_state: SliceState,
    pub concurrency_hard_max: u32,
    pub concurrency_soft_max: u32,
    pub pending_change_signal: bool,
    pub state_log: Vec<(SliceState, SliceState)>,
}

impl Slice {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            unit: SliceUnit::new(id),
            state: SliceState::Dead,
            deserialized_state: SliceState::Dead,
            concurrency_hard_max: u32::MAX,
            concurrency_soft_max: u32::MAX,
            pending_change_signal: false,
            state_log: Vec::new(),
        }
    }

    pub fn init(&mut self) -> Result<(), SliceError> {
        if self.unit.load_state != LoadState::Stub {
            return Err(SliceError::InvalidLoadState);
        }

        self.unit.ignore_on_isolate = true;
        self.concurrency_hard_max = u32::MAX;
        self.concurrency_soft_max = u32::MAX;
        Ok(())
    }

    pub fn set_state(&mut self, state: SliceState) {
        let old_state = self.state;
        if old_state != state {
            self.pending_change_signal = true;
            self.state = state;
            self.state_log.push((old_state, state));
        }
    }

    pub fn add_parent_slice(&mut self) -> Result<Option<String>, SliceError> {
        if self.unit.parent_slice.is_some() {
            return Ok(None);
        }

        let parent = build_parent_slice(&self.unit.id)?;
        self.unit.parent_slice = parent.clone();
        Ok(parent)
    }

    pub fn add_default_dependencies(&mut self) {
        if self.unit.default_dependencies {
            self.unit.before_shutdown = true;
            self.unit.conflicts_shutdown = true;
        }
    }

    pub fn verify(&self) -> Result<(), SliceError> {
        if self.unit.load_state != LoadState::Loaded {
            return Err(SliceError::InvalidLoadState);
        }
        if !slice_name_is_valid(&self.unit.id) {
            return Err(SliceError::InvalidName(self.unit.id.clone()));
        }
        if self.unit.manager_test_ignore_dependencies {
            return Ok(());
        }

        let expected_parent = build_parent_slice(&self.unit.id)?;
        if expected_parent != self.unit.parent_slice {
            return Err(SliceError::LocatedOutsideParent);
        }

        Ok(())
    }

    pub fn load_root_slice(&mut self) -> bool {
        if self.unit.id != SPECIAL_ROOT_SLICE {
            return false;
        }

        self.unit.perpetual = true;
        self.unit.default_dependencies = false;
        self.unit
            .description
            .get_or_insert_with(|| "Root Slice".into());
        if self.unit.documentation.is_empty() {
            self.unit
                .documentation
                .push("man:systemd.special(7)".into());
        }
        true
    }

    pub fn load_system_slice(&mut self) -> bool {
        if !self.unit.manager_is_system || self.unit.id != SPECIAL_SYSTEM_SLICE {
            return false;
        }

        self.unit.perpetual = true;
        self.unit.default_dependencies = false;
        self.unit
            .description
            .get_or_insert_with(|| "System Slice".into());
        if self.unit.documentation.is_empty() {
            self.unit
                .documentation
                .push("man:systemd.special(7)".into());
        }
        true
    }

    pub fn load(&mut self) -> Result<(), SliceError> {
        if self.unit.load_state != LoadState::Stub {
            return Err(SliceError::InvalidLoadState);
        }

        self.load_root_slice();
        self.load_system_slice();
        self.unit.load_state = LoadState::Loaded;
        self.add_parent_slice()?;
        self.add_default_dependencies();
        if self.unit.description.is_none() {
            self.unit.description =
                Some(format!("Slice {}", self.unit.id.trim_end_matches(".slice")));
        }
        self.verify()
    }

    pub fn coldplug(&mut self) {
        if self.deserialized_state != self.state {
            self.set_state(self.deserialized_state);
        }
    }

    pub fn start(&mut self) -> Result<bool, SliceError> {
        if self.state != SliceState::Dead {
            return Err(SliceError::InvalidLoadState);
        }
        self.set_state(SliceState::Active);
        Ok(true)
    }

    pub fn stop(&mut self) -> Result<bool, SliceError> {
        if self.state != SliceState::Active {
            return Err(SliceError::InvalidLoadState);
        }
        self.set_state(SliceState::Dead);
        Ok(true)
    }

    pub fn serialize(&self) -> BTreeMap<String, String> {
        BTreeMap::from([("state".into(), self.sub_state_to_string().into())])
    }

    pub fn deserialize_item(&mut self, key: &str, value: &str) {
        if key == "state" {
            self.deserialized_state = if value == "active" {
                SliceState::Active
            } else {
                SliceState::Dead
            };
        }
    }

    pub fn active_state(&self) -> UnitActiveState {
        match self.state {
            SliceState::Dead => UnitActiveState::Inactive,
            SliceState::Active => UnitActiveState::Active,
        }
    }

    pub fn sub_state_to_string(&self) -> &'static str {
        match self.state {
            SliceState::Dead => "dead",
            SliceState::Active => "active",
        }
    }

    pub fn make_perpetual(id: impl Into<String>) -> Self {
        let mut slice = Self::new(id);
        slice.unit.perpetual = true;
        slice.deserialized_state = SliceState::Active;
        slice
    }

    pub fn can_freeze(&self) -> bool {
        false
    }

    pub fn freezer_action(&self) -> Result<(), SliceError> {
        Err(SliceError::UnsupportedFreezerAction)
    }
}

pub fn enumerate_perpetual(names: &[&str]) -> Vec<Slice> {
    names
        .iter()
        .map(|name| Slice::make_perpetual(*name))
        .collect()
}

fn slice_name_is_valid(name: &str) -> bool {
    name.ends_with(".slice") && !name.is_empty()
}

fn build_parent_slice(name: &str) -> Result<Option<String>, SliceError> {
    if name == SPECIAL_ROOT_SLICE {
        return Ok(None);
    }
    if !slice_name_is_valid(name) {
        return Err(SliceError::InvalidName(name.into()));
    }

    let stem = name.trim_end_matches(".slice");
    if let Some((prefix, _)) = stem.rsplit_once('-') {
        Ok(Some(format!("{prefix}.slice")))
    } else {
        Ok(Some(SPECIAL_ROOT_SLICE.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_matches_stub_defaults() {
        let mut slice = Slice::new("demo.slice");
        slice.init().unwrap();
        assert!(slice.unit.ignore_on_isolate);
        assert_eq!(slice.concurrency_hard_max, u32::MAX);
    }

    #[test]
    fn parent_slice_is_derived_from_unit_name() {
        let mut slice = Slice::new("system-demo.slice");
        assert_eq!(
            slice.add_parent_slice().unwrap(),
            Some("system.slice".into())
        );
    }

    #[test]
    fn root_slice_is_synthesized_without_parent() {
        let mut slice = Slice::new(SPECIAL_ROOT_SLICE);
        assert!(slice.load_root_slice());
        assert!(slice.unit.perpetual);
        assert_eq!(build_parent_slice(SPECIAL_ROOT_SLICE).unwrap(), None);
    }

    #[test]
    fn load_and_verify_accept_valid_slice() {
        let mut slice = Slice::new("system-demo.slice");
        slice.load().unwrap();
        assert_eq!(slice.unit.load_state, LoadState::Loaded);
        assert_eq!(slice.unit.parent_slice, Some("system.slice".into()));
    }

    #[test]
    fn coldplug_replays_deserialized_state() {
        let mut slice = Slice::new("demo.slice");
        slice.deserialized_state = SliceState::Active;
        slice.coldplug();
        assert_eq!(slice.state, SliceState::Active);
    }

    #[test]
    fn start_and_stop_update_active_state() {
        let mut slice = Slice::new("demo.slice");
        slice.start().unwrap();
        assert_eq!(slice.active_state(), UnitActiveState::Active);
        slice.stop().unwrap();
        assert_eq!(slice.active_state(), UnitActiveState::Inactive);
    }
}
