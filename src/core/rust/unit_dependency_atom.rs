// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit-dependency-atom.c
//
use std::fmt;

pub type UnitDependencyAtom = u64;

pub const UNIT_ATOM_PULL_IN_START: UnitDependencyAtom = 1 << 0;
pub const UNIT_ATOM_RETROACTIVE_START_REPLACE: UnitDependencyAtom = 1 << 1;
pub const UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE: UnitDependencyAtom = 1 << 2;
pub const UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE: UnitDependencyAtom = 1 << 3;
pub const UNIT_ATOM_PULL_IN_VERIFY: UnitDependencyAtom = 1 << 4;
pub const UNIT_ATOM_PULL_IN_START_IGNORED: UnitDependencyAtom = 1 << 5;
pub const UNIT_ATOM_RETROACTIVE_START_FAIL: UnitDependencyAtom = 1 << 6;
pub const UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT: UnitDependencyAtom = 1 << 7;
pub const UNIT_ATOM_ADD_START_WHEN_UPHELD_QUEUE: UnitDependencyAtom = 1 << 8;
pub const UNIT_ATOM_PROPAGATE_STOP: UnitDependencyAtom = 1 << 9;
pub const UNIT_ATOM_PROPAGATE_START_FAILURE: UnitDependencyAtom = 1 << 10;
pub const UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED: UnitDependencyAtom = 1 << 11;
pub const UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES: UnitDependencyAtom = 1 << 12;
pub const UNIT_ATOM_PROPAGATE_INACTIVE_START_AS_FAILURE: UnitDependencyAtom = 1 << 13;
pub const UNIT_ATOM_RETROACTIVE_STOP_ON_STOP: UnitDependencyAtom = 1 << 14;
pub const UNIT_ATOM_ADD_CANNOT_BE_ACTIVE_WITHOUT_QUEUE: UnitDependencyAtom = 1 << 15;
pub const UNIT_ATOM_START_STEADILY: UnitDependencyAtom = 1 << 16;
pub const UNIT_ATOM_PULL_IN_STOP: UnitDependencyAtom = 1 << 17;
pub const UNIT_ATOM_RETROACTIVE_STOP_ON_START: UnitDependencyAtom = 1 << 18;
pub const UNIT_ATOM_PULL_IN_STOP_IGNORED: UnitDependencyAtom = 1 << 19;
pub const UNIT_ATOM_PROPAGATE_STOP_FAILURE: UnitDependencyAtom = 1 << 20;
pub const UNIT_ATOM_PROPAGATE_STOP_GRACEFUL: UnitDependencyAtom = 1 << 21;
pub const UNIT_ATOM_ON_FAILURE: UnitDependencyAtom = 1 << 22;
pub const UNIT_ATOM_ON_SUCCESS: UnitDependencyAtom = 1 << 23;
pub const UNIT_ATOM_ON_FAILURE_OF: UnitDependencyAtom = 1 << 24;
pub const UNIT_ATOM_ON_SUCCESS_OF: UnitDependencyAtom = 1 << 25;
pub const UNIT_ATOM_BEFORE: UnitDependencyAtom = 1 << 26;
pub const UNIT_ATOM_AFTER: UnitDependencyAtom = 1 << 27;
pub const UNIT_ATOM_TRIGGERS: UnitDependencyAtom = 1 << 28;
pub const UNIT_ATOM_TRIGGERED_BY: UnitDependencyAtom = 1 << 29;
pub const UNIT_ATOM_PROPAGATES_RELOAD_TO: UnitDependencyAtom = 1 << 30;
pub const UNIT_ATOM_JOINS_NAMESPACE_OF: UnitDependencyAtom = 1 << 31;
pub const UNIT_ATOM_REFERENCES: UnitDependencyAtom = 1 << 32;
pub const UNIT_ATOM_REFERENCED_BY: UnitDependencyAtom = 1 << 33;
pub const UNIT_ATOM_IN_SLICE: UnitDependencyAtom = 1 << 34;
pub const UNIT_ATOM_SLICE_OF: UnitDependencyAtom = 1 << 35;
pub const _UNIT_DEPENDENCY_ATOM_INVALID: UnitDependencyAtom = u64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    InvalidDependency(i32),
    UnknownUniqueAtom(UnitDependencyAtom),
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDependency(v) => write!(f, "invalid dependency {v}"),
            Self::UnknownUniqueAtom(v) => write!(f, "unknown or ambiguous atom mask {v:#x}"),
        }
    }
}

impl std::error::Error for PortError {}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitDependency {
    Requires = 0,
    Requisite,
    Wants,
    BindsTo,
    Upholds,
    RequiredBy,
    RequisiteOf,
    WantedBy,
    BoundBy,
    UpheldBy,
    Conflicts,
    ConflictedBy,
    PropagatesStopTo,
    OnFailure,
    OnSuccess,
    OnFailureOf,
    OnSuccessOf,
    Before,
    After,
    PartOf,
    ConsistsOf,
    Triggers,
    TriggeredBy,
    PropagatesReloadTo,
    JoinsNamespaceOf,
    References,
    ReferencedBy,
    InSlice,
    SliceOf,
    ReloadPropagatedFrom,
    StopPropagatedFrom,
}

impl UnitDependency {
    pub fn from_raw(value: i32) -> Result<Self, PortError> {
        use UnitDependency::*;
        Ok(match value {
            0 => Requires,
            1 => Requisite,
            2 => Wants,
            3 => BindsTo,
            4 => Upholds,
            5 => RequiredBy,
            6 => RequisiteOf,
            7 => WantedBy,
            8 => BoundBy,
            9 => UpheldBy,
            10 => Conflicts,
            11 => ConflictedBy,
            12 => PropagatesStopTo,
            13 => OnFailure,
            14 => OnSuccess,
            15 => OnFailureOf,
            16 => OnSuccessOf,
            17 => Before,
            18 => After,
            19 => PartOf,
            20 => ConsistsOf,
            21 => Triggers,
            22 => TriggeredBy,
            23 => PropagatesReloadTo,
            24 => JoinsNamespaceOf,
            25 => References,
            26 => ReferencedBy,
            27 => InSlice,
            28 => SliceOf,
            29 => ReloadPropagatedFrom,
            30 => StopPropagatedFrom,
            v => return Err(PortError::InvalidDependency(v)),
        })
    }
}

const ATOM_MAP: &[(UnitDependency, UnitDependencyAtom)] = &[
    (
        UnitDependency::Requires,
        UNIT_ATOM_PULL_IN_START
            | UNIT_ATOM_RETROACTIVE_START_REPLACE
            | UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE
            | UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,
    ),
    (
        UnitDependency::Requisite,
        UNIT_ATOM_PULL_IN_VERIFY
            | UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE
            | UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,
    ),
    (
        UnitDependency::Wants,
        UNIT_ATOM_PULL_IN_START_IGNORED
            | UNIT_ATOM_RETROACTIVE_START_FAIL
            | UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE
            | UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,
    ),
    (
        UnitDependency::BindsTo,
        UNIT_ATOM_PULL_IN_START
            | UNIT_ATOM_RETROACTIVE_START_REPLACE
            | UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT
            | UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE
            | UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,
    ),
    (
        UnitDependency::Upholds,
        UNIT_ATOM_PULL_IN_START_IGNORED
            | UNIT_ATOM_RETROACTIVE_START_REPLACE
            | UNIT_ATOM_ADD_START_WHEN_UPHELD_QUEUE
            | UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE
            | UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,
    ),
    (
        UnitDependency::RequiredBy,
        UNIT_ATOM_PROPAGATE_STOP
            | UNIT_ATOM_PROPAGATE_START_FAILURE
            | UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED
            | UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES,
    ),
    (
        UnitDependency::RequisiteOf,
        UNIT_ATOM_PROPAGATE_STOP
            | UNIT_ATOM_PROPAGATE_START_FAILURE
            | UNIT_ATOM_PROPAGATE_INACTIVE_START_AS_FAILURE
            | UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED
            | UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES,
    ),
    (
        UnitDependency::WantedBy,
        UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES | UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED,
    ),
    (
        UnitDependency::BoundBy,
        UNIT_ATOM_RETROACTIVE_STOP_ON_STOP
            | UNIT_ATOM_PROPAGATE_STOP
            | UNIT_ATOM_PROPAGATE_START_FAILURE
            | UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED
            | UNIT_ATOM_ADD_CANNOT_BE_ACTIVE_WITHOUT_QUEUE
            | UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES,
    ),
    (
        UnitDependency::UpheldBy,
        UNIT_ATOM_START_STEADILY
            | UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES
            | UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED,
    ),
    (
        UnitDependency::Conflicts,
        UNIT_ATOM_PULL_IN_STOP | UNIT_ATOM_RETROACTIVE_STOP_ON_START,
    ),
    (
        UnitDependency::ConflictedBy,
        UNIT_ATOM_PULL_IN_STOP_IGNORED
            | UNIT_ATOM_RETROACTIVE_STOP_ON_START
            | UNIT_ATOM_PROPAGATE_STOP_FAILURE,
    ),
    (
        UnitDependency::PropagatesStopTo,
        UNIT_ATOM_RETROACTIVE_STOP_ON_STOP | UNIT_ATOM_PROPAGATE_STOP_GRACEFUL,
    ),
    (UnitDependency::OnFailure, UNIT_ATOM_ON_FAILURE),
    (UnitDependency::OnSuccess, UNIT_ATOM_ON_SUCCESS),
    (UnitDependency::OnFailureOf, UNIT_ATOM_ON_FAILURE_OF),
    (UnitDependency::OnSuccessOf, UNIT_ATOM_ON_SUCCESS_OF),
    (UnitDependency::Before, UNIT_ATOM_BEFORE),
    (UnitDependency::After, UNIT_ATOM_AFTER),
    (
        UnitDependency::PartOf,
        UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,
    ),
    (UnitDependency::ConsistsOf, UNIT_ATOM_PROPAGATE_STOP),
    (UnitDependency::Triggers, UNIT_ATOM_TRIGGERS),
    (UnitDependency::TriggeredBy, UNIT_ATOM_TRIGGERED_BY),
    (
        UnitDependency::PropagatesReloadTo,
        UNIT_ATOM_PROPAGATES_RELOAD_TO,
    ),
    (
        UnitDependency::JoinsNamespaceOf,
        UNIT_ATOM_JOINS_NAMESPACE_OF,
    ),
    (UnitDependency::References, UNIT_ATOM_REFERENCES),
    (UnitDependency::ReferencedBy, UNIT_ATOM_REFERENCED_BY),
    (UnitDependency::InSlice, UNIT_ATOM_IN_SLICE),
    (UnitDependency::SliceOf, UNIT_ATOM_SLICE_OF),
    (UnitDependency::ReloadPropagatedFrom, 0),
    (UnitDependency::StopPropagatedFrom, 0),
];

pub fn unit_dependency_to_atom(dependency: UnitDependency) -> UnitDependencyAtom {
    ATOM_MAP
        .iter()
        .find(|(candidate, _)| *candidate == dependency)
        .map(|(_, atom)| *atom)
        .expect("dependency table is exhaustive")
}

pub fn unit_dependency_to_atom_raw(raw: i32) -> Result<UnitDependencyAtom, PortError> {
    Ok(unit_dependency_to_atom(UnitDependency::from_raw(raw)?))
}

pub fn unit_dependency_from_unique_atom(
    atom: UnitDependencyAtom,
) -> Result<UnitDependency, PortError> {
    use UnitDependency::*;
    match atom {
        x if x == UNIT_ATOM_PULL_IN_VERIFY
            || x == (UNIT_ATOM_PULL_IN_VERIFY
                | UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE
                | UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE) =>
        {
            Ok(Requisite)
        }
        x if x == UNIT_ATOM_RETROACTIVE_START_FAIL
            || x == (UNIT_ATOM_PULL_IN_START_IGNORED
                | UNIT_ATOM_RETROACTIVE_START_FAIL
                | UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE
                | UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE) =>
        {
            Ok(Wants)
        }
        x if x == UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT
            || x == (UNIT_ATOM_PULL_IN_START
                | UNIT_ATOM_RETROACTIVE_START_REPLACE
                | UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT
                | UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE
                | UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE) =>
        {
            Ok(BindsTo)
        }
        x if x == UNIT_ATOM_ADD_START_WHEN_UPHELD_QUEUE
            || x == (UNIT_ATOM_PULL_IN_START_IGNORED
                | UNIT_ATOM_RETROACTIVE_START_REPLACE
                | UNIT_ATOM_ADD_START_WHEN_UPHELD_QUEUE
                | UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE
                | UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE) =>
        {
            Ok(Upholds)
        }
        x if x == UNIT_ATOM_PROPAGATE_INACTIVE_START_AS_FAILURE
            || x == (UNIT_ATOM_PROPAGATE_STOP
                | UNIT_ATOM_PROPAGATE_START_FAILURE
                | UNIT_ATOM_PROPAGATE_INACTIVE_START_AS_FAILURE
                | UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED
                | UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES) =>
        {
            Ok(RequisiteOf)
        }
        x if x == UNIT_ATOM_ADD_CANNOT_BE_ACTIVE_WITHOUT_QUEUE
            || x == (UNIT_ATOM_RETROACTIVE_STOP_ON_STOP
                | UNIT_ATOM_PROPAGATE_STOP
                | UNIT_ATOM_PROPAGATE_START_FAILURE
                | UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED
                | UNIT_ATOM_ADD_CANNOT_BE_ACTIVE_WITHOUT_QUEUE
                | UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES) =>
        {
            Ok(BoundBy)
        }
        x if x == UNIT_ATOM_START_STEADILY
            || x == (UNIT_ATOM_START_STEADILY
                | UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES
                | UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED) =>
        {
            Ok(UpheldBy)
        }
        x if x == UNIT_ATOM_PULL_IN_STOP
            || x == (UNIT_ATOM_PULL_IN_STOP | UNIT_ATOM_RETROACTIVE_STOP_ON_START) =>
        {
            Ok(Conflicts)
        }
        x if x == UNIT_ATOM_PULL_IN_STOP_IGNORED
            || x == UNIT_ATOM_PROPAGATE_STOP_FAILURE
            || x == (UNIT_ATOM_PULL_IN_STOP_IGNORED
                | UNIT_ATOM_RETROACTIVE_STOP_ON_START
                | UNIT_ATOM_PROPAGATE_STOP_FAILURE) =>
        {
            Ok(ConflictedBy)
        }
        x if x == UNIT_ATOM_PROPAGATE_STOP_GRACEFUL
            || x == (UNIT_ATOM_RETROACTIVE_STOP_ON_STOP | UNIT_ATOM_PROPAGATE_STOP_GRACEFUL) =>
        {
            Ok(PropagatesStopTo)
        }
        UNIT_ATOM_ON_FAILURE => Ok(OnFailure),
        UNIT_ATOM_ON_SUCCESS => Ok(OnSuccess),
        UNIT_ATOM_ON_SUCCESS_OF => Ok(OnSuccessOf),
        UNIT_ATOM_ON_FAILURE_OF => Ok(OnFailureOf),
        UNIT_ATOM_BEFORE => Ok(Before),
        UNIT_ATOM_AFTER => Ok(After),
        UNIT_ATOM_TRIGGERS => Ok(Triggers),
        UNIT_ATOM_TRIGGERED_BY => Ok(TriggeredBy),
        UNIT_ATOM_PROPAGATES_RELOAD_TO => Ok(PropagatesReloadTo),
        UNIT_ATOM_JOINS_NAMESPACE_OF => Ok(JoinsNamespaceOf),
        UNIT_ATOM_REFERENCES => Ok(References),
        UNIT_ATOM_REFERENCED_BY => Ok(ReferencedBy),
        UNIT_ATOM_IN_SLICE => Ok(InSlice),
        UNIT_ATOM_SLICE_OF => Ok(SliceOf),
        other => Err(PortError::UnknownUniqueAtom(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_maps_to_expected_mask() {
        let atom = unit_dependency_to_atom(UnitDependency::Requires);
        assert_eq!(
            atom,
            UNIT_ATOM_PULL_IN_START
                | UNIT_ATOM_RETROACTIVE_START_REPLACE
                | UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE
                | UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE
        );
    }

    #[test]
    fn reload_propagated_from_has_no_atoms() {
        assert_eq!(
            unit_dependency_to_atom(UnitDependency::ReloadPropagatedFrom),
            0
        );
    }

    #[test]
    fn raw_conversion_rejects_negative_values() {
        assert_eq!(
            unit_dependency_to_atom_raw(-1),
            Err(PortError::InvalidDependency(-1))
        );
    }

    #[test]
    fn raw_conversion_accepts_last_dependency() {
        assert_eq!(
            unit_dependency_to_atom_raw(UnitDependency::StopPropagatedFrom as i32),
            Ok(0)
        );
    }

    #[test]
    fn best_effort_reverse_maps_unique_subset() {
        assert_eq!(
            unit_dependency_from_unique_atom(UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT),
            Ok(UnitDependency::BindsTo)
        );
    }

    #[test]
    fn best_effort_reverse_maps_full_mask() {
        assert_eq!(
            unit_dependency_from_unique_atom(unit_dependency_to_atom(UnitDependency::Conflicts)),
            Ok(UnitDependency::Conflicts)
        );
    }

    #[test]
    fn ambiguous_requires_mask_is_rejected() {
        assert_eq!(
            unit_dependency_from_unique_atom(unit_dependency_to_atom(UnitDependency::Requires)),
            Err(PortError::UnknownUniqueAtom(unit_dependency_to_atom(
                UnitDependency::Requires
            )))
        );
    }

    #[test]
    fn unknown_atom_is_rejected() {
        assert_eq!(
            unit_dependency_from_unique_atom(1 << 60),
            Err(PortError::UnknownUniqueAtom(1 << 60))
        );
    }

    #[test]
    fn simple_atom_round_trips() {
        assert_eq!(
            unit_dependency_from_unique_atom(UNIT_ATOM_AFTER),
            Ok(UnitDependency::After)
        );
    }
}
