// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/target.c, src/core/target.h
//

use std::collections::BTreeSet;

use crate::ffi::Errno;

pub const SOURCE_PATHS: &[&str] = &["src/core/target.c", "src/core/target.h"];
pub const SPECIAL_SHUTDOWN_TARGET: &str = "shutdown.target";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    Dead,
    Active,
}

impl TargetState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dead => "dead",
            Self::Active => "active",
        }
    }

    pub fn parse(value: &str) -> Result<Self, Errno> {
        match value {
            "dead" => Ok(Self::Dead),
            "active" => Ok(Self::Active),
            _ => Err(Errno::EINVAL),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitActiveState {
    Inactive,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    Stub,
    Loaded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateChange {
    pub old_state: TargetState,
    pub new_state: TargetState,
    pub old_active_state: UnitActiveState,
    pub new_active_state: UnitActiveState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetDependencyPlan {
    pub dependencies_to_add: Vec<String>,
    pub add_shutdown_conflict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    names: BTreeSet<String>,
    pub default_dependencies: bool,
    pub state: TargetState,
    pub deserialized_state: TargetState,
    pub invocation_id: Option<String>,
    queued_default_target_dependencies: Vec<String>,
}

impl Default for Target {
    fn default() -> Self {
        Self {
            names: BTreeSet::new(),
            default_dependencies: true,
            state: TargetState::Dead,
            deserialized_state: TargetState::Dead,
            invocation_id: None,
            queued_default_target_dependencies: Vec::new(),
        }
    }
}

impl Target {
    pub fn with_name(name: impl Into<String>) -> Self {
        let mut target = Self::default();
        target.names.insert(name.into());
        target
    }

    pub fn add_name(&mut self, name: impl Into<String>) {
        self.names.insert(name.into());
    }

    pub fn queue_default_target_dependency(&mut self, unit: impl Into<String>) {
        self.queued_default_target_dependencies.push(unit.into());
    }

    pub const fn active_state(&self) -> UnitActiveState {
        match self.state {
            TargetState::Dead => UnitActiveState::Inactive,
            TargetState::Active => UnitActiveState::Active,
        }
    }

    pub const fn sub_state_to_string(&self) -> &'static str {
        self.state.as_str()
    }

    pub fn set_state(&mut self, new_state: TargetState) -> StateChange {
        let old_state = self.state;
        self.state = new_state;

        StateChange {
            old_state,
            new_state,
            old_active_state: translate_state(old_state),
            new_active_state: translate_state(new_state),
        }
    }

    pub fn add_default_dependencies(&self) -> Result<TargetDependencyPlan, Errno> {
        if !self.default_dependencies {
            return Ok(TargetDependencyPlan {
                dependencies_to_add: Vec::new(),
                add_shutdown_conflict: false,
            });
        }

        let snapshot = self.queued_default_target_dependencies.clone();
        Ok(TargetDependencyPlan {
            dependencies_to_add: snapshot,
            add_shutdown_conflict: !self.names.contains(SPECIAL_SHUTDOWN_TARGET),
        })
    }

    pub fn load(&self, load_state: LoadState) -> Result<Option<TargetDependencyPlan>, Errno> {
        if load_state != LoadState::Loaded {
            return Ok(None);
        }

        self.add_default_dependencies().map(Some)
    }

    pub fn coldplug(&mut self) -> Result<Option<StateChange>, Errno> {
        if self.state != TargetState::Dead {
            return Err(Errno::EINVAL);
        }

        if self.deserialized_state == self.state {
            return Ok(None);
        }

        Ok(Some(self.set_state(self.deserialized_state)))
    }

    pub fn dump(&self, prefix: &str) -> Result<String, Errno> {
        if prefix.is_empty() {
            return Err(Errno::EINVAL);
        }

        Ok(format!("{prefix}Target State: {}\n", self.state.as_str()))
    }

    pub fn start(&mut self, invocation_id: impl Into<String>) -> Result<StateChange, Errno> {
        if self.state != TargetState::Dead {
            return Err(Errno::EINVAL);
        }

        self.invocation_id = Some(invocation_id.into());
        Ok(self.set_state(TargetState::Active))
    }

    pub fn stop(&mut self) -> Result<StateChange, Errno> {
        if self.state != TargetState::Active {
            return Err(Errno::EINVAL);
        }

        Ok(self.set_state(TargetState::Dead))
    }

    pub fn serialize(&self) -> Vec<(String, String)> {
        vec![("state".into(), self.state.as_str().into())]
    }

    pub fn deserialize_item(&mut self, key: &str, value: &str) -> Result<bool, Errno> {
        if key == "state" {
            self.deserialized_state = TargetState::parse(value)?;
            return Ok(true);
        }

        Ok(false)
    }
}

pub const fn translate_state(state: TargetState) -> UnitActiveState {
    match state {
        TargetState::Dead => UnitActiveState::Inactive,
        TargetState::Active => UnitActiveState::Active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_state_roundtrip() {
        assert_eq!(TargetState::parse("dead"), Ok(TargetState::Dead));
        assert_eq!(TargetState::parse("active"), Ok(TargetState::Active));
        assert_eq!(TargetState::Dead.as_str(), "dead");
    }

    #[test]
    fn translation_matches_c_table() {
        assert_eq!(
            translate_state(TargetState::Dead),
            UnitActiveState::Inactive
        );
        assert_eq!(
            translate_state(TargetState::Active),
            UnitActiveState::Active
        );
    }

    #[test]
    fn default_dependencies_snapshot_is_preserved() {
        let mut target = Target::with_name("multi-user.target");
        target.queue_default_target_dependency("basic.target");
        target.queue_default_target_dependency("sysinit.target");

        let plan = target.add_default_dependencies().unwrap();
        assert_eq!(
            plan.dependencies_to_add,
            vec!["basic.target", "sysinit.target"]
        );
        assert!(plan.add_shutdown_conflict);
    }

    #[test]
    fn shutdown_target_skips_shutdown_dependency() {
        let target = Target::with_name(SPECIAL_SHUTDOWN_TARGET);
        let plan = target.add_default_dependencies().unwrap();
        assert!(!plan.add_shutdown_conflict);
    }

    #[test]
    fn coldplug_applies_deserialized_state() {
        let mut target = Target::default();
        target.deserialized_state = TargetState::Active;
        let change = target.coldplug().unwrap().unwrap();
        assert_eq!(change.old_state, TargetState::Dead);
        assert_eq!(change.new_state, TargetState::Active);
    }

    #[test]
    fn start_and_stop_follow_c_state_machine() {
        let mut target = Target::default();
        target.start("invocation-1").unwrap();
        assert_eq!(target.state, TargetState::Active);
        assert_eq!(target.invocation_id.as_deref(), Some("invocation-1"));
        target.stop().unwrap();
        assert_eq!(target.state, TargetState::Dead);
    }

    #[test]
    fn serialize_and_deserialize_state() {
        let mut target = Target::default();
        target.deserialize_item("state", "active").unwrap();
        assert_eq!(target.deserialized_state, TargetState::Active);
        assert_eq!(target.serialize(), vec![("state".into(), "dead".into())]);
    }

    #[test]
    fn dump_matches_c_format() {
        let target = Target::default();
        assert_eq!(target.dump("  ").unwrap(), "  Target State: dead\n");
    }
}
