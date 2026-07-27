// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-slice.c
//

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbusSliceError {
    InvalidProperty,
    InvalidValue,
    CgroupFailure,
    RealizeFailure,
}

pub type Result<T> = std::result::Result<T, DbusSliceError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    Stub,
    Loaded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitWriteFlags(u32);

impl UnitWriteFlags {
    pub const NONE: Self = Self(0);
    pub const PRIVATE: Self = Self(1 << 0);

    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn with_private(self) -> Self {
        Self(self.0 | Self::PRIVATE.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unit {
    pub transient: bool,
    pub load_state: LoadState,
    pub realized_cgroup: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slice {
    pub concurrency_hard_max: u32,
    pub concurrency_soft_max: u32,
    pub currently_active: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceUnit {
    pub unit: Unit,
    pub slice: Slice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyValue {
    Unsigned(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertySetResult {
    Applied,
    Ignored,
}

pub fn property_get_currently_active(slice: &Slice) -> Result<u32> {
    Ok(slice.currently_active)
}

pub fn bus_slice_set_transient_property(
    slice: &mut Slice,
    name: &str,
    value: PropertyValue,
    flags: UnitWriteFlags,
) -> Result<PropertySetResult> {
    let _flags = flags.with_private();

    match (name, value) {
        ("ConcurrencyHardMax", PropertyValue::Unsigned(v)) => {
            slice.concurrency_hard_max = v;
            Ok(PropertySetResult::Applied)
        }
        ("ConcurrencySoftMax", PropertyValue::Unsigned(v)) => {
            slice.concurrency_soft_max = v;
            Ok(PropertySetResult::Applied)
        }
        _ => Ok(PropertySetResult::Ignored),
    }
}

pub fn bus_slice_set_property<F>(
    slice_unit: &mut SliceUnit,
    name: &str,
    value: PropertyValue,
    flags: UnitWriteFlags,
    mut bus_cgroup_set_property: F,
) -> Result<PropertySetResult>
where
    F: FnMut(&mut Unit, &str, PropertyValue, UnitWriteFlags) -> Result<PropertySetResult>,
{
    let cgroup_result = bus_cgroup_set_property(&mut slice_unit.unit, name, value, flags)?;
    if cgroup_result == PropertySetResult::Applied {
        return Ok(cgroup_result);
    }

    if slice_unit.unit.transient && slice_unit.unit.load_state == LoadState::Stub {
        return bus_slice_set_transient_property(&mut slice_unit.slice, name, value, flags);
    }

    Ok(PropertySetResult::Ignored)
}

pub fn bus_slice_commit_properties<F>(unit: &mut Unit, mut realize_cgroup: F) -> Result<()>
where
    F: FnMut(&mut Unit) -> Result<()>,
{
    realize_cgroup(unit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_slice_unit() -> SliceUnit {
        SliceUnit {
            unit: Unit {
                transient: true,
                load_state: LoadState::Stub,
                realized_cgroup: false,
            },
            slice: Slice {
                concurrency_hard_max: 10,
                concurrency_soft_max: 5,
                currently_active: 3,
            },
        }
    }

    #[test]
    fn property_get_currently_active_returns_current_count() {
        assert_eq!(
            property_get_currently_active(&sample_slice_unit().slice),
            Ok(3)
        );
    }

    #[test]
    fn transient_property_updates_hard_limit() {
        let mut slice = sample_slice_unit().slice;
        let result = bus_slice_set_transient_property(
            &mut slice,
            "ConcurrencyHardMax",
            PropertyValue::Unsigned(99),
            UnitWriteFlags::NONE,
        );

        assert_eq!(result, Ok(PropertySetResult::Applied));
        assert_eq!(slice.concurrency_hard_max, 99);
    }

    #[test]
    fn transient_property_updates_soft_limit() {
        let mut slice = sample_slice_unit().slice;
        let result = bus_slice_set_transient_property(
            &mut slice,
            "ConcurrencySoftMax",
            PropertyValue::Unsigned(77),
            UnitWriteFlags::NONE,
        );

        assert_eq!(result, Ok(PropertySetResult::Applied));
        assert_eq!(slice.concurrency_soft_max, 77);
    }

    #[test]
    fn transient_property_ignores_unknown_names() {
        let mut slice = sample_slice_unit().slice;
        let result = bus_slice_set_transient_property(
            &mut slice,
            "MemoryMax",
            PropertyValue::Unsigned(77),
            UnitWriteFlags::NONE,
        );

        assert_eq!(result, Ok(PropertySetResult::Ignored));
        assert_eq!(slice.concurrency_hard_max, 10);
        assert_eq!(slice.concurrency_soft_max, 5);
    }

    #[test]
    fn set_property_returns_cgroup_result_when_handled() {
        let mut slice_unit = sample_slice_unit();
        let result = bus_slice_set_property(
            &mut slice_unit,
            "CPUWeight",
            PropertyValue::Unsigned(50),
            UnitWriteFlags::NONE,
            |_unit, name, value, _flags| {
                assert_eq!(name, "CPUWeight");
                assert_eq!(value, PropertyValue::Unsigned(50));
                Ok(PropertySetResult::Applied)
            },
        );

        assert_eq!(result, Ok(PropertySetResult::Applied));
        assert_eq!(slice_unit.slice.concurrency_hard_max, 10);
    }

    #[test]
    fn set_property_uses_transient_path_for_stub_units() {
        let mut slice_unit = sample_slice_unit();
        let result = bus_slice_set_property(
            &mut slice_unit,
            "ConcurrencyHardMax",
            PropertyValue::Unsigned(42),
            UnitWriteFlags::NONE,
            |_unit, _name, _value, _flags| Ok(PropertySetResult::Ignored),
        );

        assert_eq!(result, Ok(PropertySetResult::Applied));
        assert_eq!(slice_unit.slice.concurrency_hard_max, 42);
    }

    #[test]
    fn set_property_skips_transient_path_for_non_stub_units() {
        let mut slice_unit = sample_slice_unit();
        slice_unit.unit.load_state = LoadState::Loaded;

        let result = bus_slice_set_property(
            &mut slice_unit,
            "ConcurrencyHardMax",
            PropertyValue::Unsigned(42),
            UnitWriteFlags::NONE,
            |_unit, _name, _value, _flags| Ok(PropertySetResult::Ignored),
        );

        assert_eq!(result, Ok(PropertySetResult::Ignored));
        assert_eq!(slice_unit.slice.concurrency_hard_max, 10);
    }

    #[test]
    fn commit_properties_realizes_cgroup() {
        let mut unit = sample_slice_unit().unit;
        let result = bus_slice_commit_properties(&mut unit, |unit| {
            unit.realized_cgroup = true;
            Ok(())
        });

        assert_eq!(result, Ok(()));
        assert!(unit.realized_cgroup);
    }

    #[test]
    fn commit_properties_propagates_errors() {
        let mut unit = sample_slice_unit().unit;
        let result =
            bus_slice_commit_properties(&mut unit, |_unit| Err(DbusSliceError::RealizeFailure));

        assert_eq!(result, Err(DbusSliceError::RealizeFailure));
        assert!(!unit.realized_cgroup);
    }
}
