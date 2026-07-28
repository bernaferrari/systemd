// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c
//
use std::sync::Mutex;

use super::model::{
    DependencyKind, DependencyMask, Result, UNIT_PATH, Unit, UnitError, is_valid_unit_name,
    sanitize_bus_path_fragment,
};

pub fn unit_add_dependency(
    unit: &mut Unit,
    dependency: DependencyKind,
    other: &str,
    _add_reference: bool,
    _mask: DependencyMask,
) -> Result<()> {
    if !is_valid_unit_name(other) {
        return Err(UnitError::Invalid);
    }
    unit.dependency_set_mut(dependency)
        .insert(other.to_string());
    Ok(())
}

pub fn unit_add_two_dependencies(
    unit: &mut Unit,
    first: DependencyKind,
    second: DependencyKind,
    other: &str,
    add_reference: bool,
    mask: DependencyMask,
) -> Result<()> {
    unit_add_dependency(unit, first, other, add_reference, mask)?;
    unit_add_dependency(unit, second, other, add_reference, mask)
}

pub fn unit_add_dependency_by_name(
    unit: &mut Unit,
    dependency: DependencyKind,
    name: &str,
    add_reference: bool,
    mask: DependencyMask,
) -> Result<()> {
    unit.manager.known_units.insert(name.to_string());
    unit_add_dependency(unit, dependency, name, add_reference, mask)
}

pub fn unit_add_two_dependencies_by_name(
    unit: &mut Unit,
    first: DependencyKind,
    second: DependencyKind,
    name: &str,
    add_reference: bool,
    mask: DependencyMask,
) -> Result<()> {
    unit_add_two_dependencies(unit, first, second, name, add_reference, mask)
}

/// Set the process-wide unit search path and update the Rust-side cache.
///
/// # Safety
///
/// The caller must ensure that no other thread reads or mutates the process
/// environment for the duration of this call.
pub unsafe fn setenv_unit_path(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        return Err(UnitError::Invalid);
    }
    // SAFETY: upheld by the caller as required by this function's contract.
    unsafe { std::env::set_var("SYSTEMD_UNIT_PATH", path) };
    *UNIT_PATH
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| UnitError::Busy)? = Some(path.into());
    Ok(())
}

pub fn unit_dbus_path(unit: &Unit) -> Result<String> {
    Ok(format!(
        "/org/freedesktop/systemd1/unit/{}",
        sanitize_bus_path_fragment(unit.id.as_deref().ok_or(UnitError::Missing)?)
    ))
}

pub fn unit_dbus_path_invocation_id(unit: &Unit) -> Result<String> {
    let id = unit.invocation_id.ok_or(UnitError::Missing)?;
    Ok(format!(
        "/org/freedesktop/systemd1/unit/{}/invocation/{:02x?}",
        sanitize_bus_path_fragment(unit.id.as_deref().ok_or(UnitError::Missing)?),
        id
    ))
}

pub fn unit_set_invocation_id(unit: &mut Unit, id: [u8; 16]) {
    unit.invocation_id = Some(id);
}

pub fn unit_set_slice(unit: &mut Unit, slice: &str) -> Result<()> {
    if !slice.ends_with(".slice") {
        return Err(UnitError::Invalid);
    }
    unit.slice = Some(slice.to_string());
    Ok(())
}

pub fn unit_set_default_slice(unit: &mut Unit) -> Result<()> {
    unit_set_slice(
        unit,
        if unit.manager.user_mode {
            "app.slice"
        } else {
            "system.slice"
        },
    )
}

pub fn unit_slice_name(unit: &Unit) -> Option<&str> {
    unit.slice.as_deref()
}

pub fn unit_load_related_unit(unit: &Unit, suffix: &str) -> Result<String> {
    let base = unit
        .id
        .as_deref()
        .ok_or(UnitError::Missing)?
        .split('.')
        .next()
        .unwrap_or_default();
    Ok(format!("{base}.{suffix}"))
}

pub fn unit_install_bus_match(unit: &mut Unit, name: &str) -> Result<()> {
    unit_watch_bus_name(unit, name)
}

pub fn unit_watch_bus_name(unit: &mut Unit, name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(UnitError::Invalid);
    }
    unit.bus_names.insert(name.into());
    Ok(())
}

pub fn unit_unwatch_bus_name(unit: &mut Unit, name: &str) {
    unit.bus_names.remove(name);
}

pub fn unit_add_node_dependency(
    unit: &mut Unit,
    what: &str,
    dependency: DependencyKind,
    mask: DependencyMask,
) -> Result<()> {
    unit_add_dependency(
        unit,
        dependency,
        &format!(
            "dev-{}.device",
            what.trim_start_matches('/').replace('/', "-")
        ),
        true,
        mask,
    )
}

pub fn unit_add_blockdev_dependency(
    unit: &mut Unit,
    what: &str,
    mask: DependencyMask,
) -> Result<()> {
    unit_add_node_dependency(unit, what, DependencyKind::Requires, mask)
}
