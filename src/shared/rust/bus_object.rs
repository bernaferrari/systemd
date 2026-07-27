// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-object.c, src/shared/bus-object.h
//
// D-Bus object registration and introspection helpers.
//
// Provides structures and functions for describing D-Bus object
// implementations, finding implementations by path or interface,
// listing registered paths, and generating introspection data.

// ── Error types ─────────────────────────────────────────────────────────────

/// Errors that can occur during bus object operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusObjectError {
    /// The requested pattern was not found among implementations.
    NotFound { kind: NotFoundKind, pattern: String },
    /// A required field is missing or invalid.
    InvalidField { field: &'static str, reason: String },
}

/// Distinguishes whether a search was for an object path or an interface name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotFoundKind {
    Interface,
    ObjectPath,
}

impl std::fmt::Display for BusObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BusObjectError::NotFound { kind, pattern } => {
                let label = match kind {
                    NotFoundKind::Interface => "Interface",
                    NotFoundKind::ObjectPath => "Object path",
                };
                write!(f, "{} {} not found", label, pattern)
            }
            BusObjectError::InvalidField { field, reason } => {
                write!(f, "Invalid {}: {}", field, reason)
            }
        }
    }
}

impl std::error::Error for BusObjectError {}

// ── Data structures ─────────────────────────────────────────────────────────

/// A vtable paired with an object_find callback for fallback registration.
///
/// Fallback vtables are used when the D-Bus object path may not exist yet;
/// the `object_find` callback is invoked to locate or create the object
/// dynamically at dispatch time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusObjectVtablePair {
    /// Identifier for the vtable (typically the interface name).
    pub vtable_id: String,
    /// Identifier for the object_find callback.
    pub object_find_id: String,
}

impl BusObjectVtablePair {
    /// Create a new fallback vtable pair.
    pub fn new(vtable_id: impl Into<String>, object_find_id: impl Into<String>) -> Self {
        Self {
            vtable_id: vtable_id.into(),
            object_find_id: object_find_id.into(),
        }
    }
}

/// Sentinel value: a fallback vtable pair with empty strings acts as the
/// terminator in C arrays (`BUS_FALLBACK_VTABLES(...)`) — in Rust, the
/// `Vec` length handles termination, but this constant supports migration.
pub const FALLBACK_VTABLE_SENTINEL: BusObjectVtablePair = BusObjectVtablePair {
    vtable_id: String::new(),
    object_find_id: String::new(),
};

/// Describes a D-Bus object implementation with its path, interface,
/// vtables, and optional child implementations.
///
/// Mirrors the C `BusObjectImplementation` struct but owns all data
/// and uses idiomatic Rust collections instead of null-terminated arrays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusObjectImplementation {
    /// D-Bus object path (e.g. "/org/freedesktop/systemd1").
    pub path: String,
    /// D-Bus interface name (e.g. "org.freedesktop.systemd1.Manager").
    pub interface: String,
    /// Regular vtable identifiers registered for this path+interface.
    pub vtables: Vec<String>,
    /// Fallback vtable pairs registered for dynamic object lookup.
    pub fallback_vtables: Vec<BusObjectVtablePair>,
    /// Optional node enumerator callback identifier.
    pub node_enumerator: Option<String>,
    /// Whether this path exports an object manager.
    pub manager: bool,
    /// Child implementations registered under sub-paths.
    pub children: Vec<BusObjectImplementation>,
}

impl BusObjectImplementation {
    /// Create a new implementation with the given path and interface.
    pub fn new(path: impl Into<String>, interface: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            interface: interface.into(),
            vtables: Vec::new(),
            fallback_vtables: Vec::new(),
            node_enumerator: None,
            manager: false,
            children: Vec::new(),
        }
    }

    /// Builder-style: add a regular vtable identifier.
    pub fn with_vtable(mut self, vtable: impl Into<String>) -> Self {
        self.vtables.push(vtable.into());
        self
    }

    /// Builder-style: add a fallback vtable pair.
    pub fn with_fallback_vtable(mut self, pair: BusObjectVtablePair) -> Self {
        self.fallback_vtables.push(pair);
        self
    }

    /// Builder-style: set the node enumerator identifier.
    pub fn with_node_enumerator(mut self, id: impl Into<String>) -> Self {
        self.node_enumerator = Some(id.into());
        self
    }

    /// Builder-style: set whether this is an object manager.
    pub fn with_manager(mut self, manager: bool) -> Self {
        self.manager = manager;
        self
    }

    /// Builder-style: add a child implementation.
    pub fn with_child(mut self, child: BusObjectImplementation) -> Self {
        self.children.push(child);
        self
    }

    /// Returns `true` if this implementation has any registered interfaces
    /// (regular or fallback vtables).
    pub fn has_interfaces(&self) -> bool {
        !self.vtables.is_empty() || !self.fallback_vtables.is_empty()
    }

    /// Validate this implementation, returning an error if required fields
    /// are missing or malformed.
    pub fn validate(&self) -> Result<(), BusObjectError> {
        if self.path.is_empty() {
            return Err(BusObjectError::InvalidField {
                field: "path",
                reason: "must not be empty".into(),
            });
        }
        if self.interface.is_empty() {
            return Err(BusObjectError::InvalidField {
                field: "interface",
                reason: "must not be empty".into(),
            });
        }
        if !is_valid_object_path(&self.path) {
            return Err(BusObjectError::InvalidField {
                field: "path",
                reason: format!("'{}' is not a valid D-Bus object path", self.path),
            });
        }
        if !is_valid_interface_name(&self.interface) {
            return Err(BusObjectError::InvalidField {
                field: "interface",
                reason: format!("'{}' is not a valid D-Bus interface name", self.interface),
            });
        }
        Ok(())
    }
}

// ── Validation helpers ──────────────────────────────────────────────────────

/// Check whether a string is a valid D-Bus interface name.
///
/// Interface names must contain at least two dot-separated elements.
/// Each element starts with a lowercase ASCII letter and contains only
/// lowercase ASCII letters, digits, and underscores.
pub fn is_valid_interface_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().all(|part| {
        if part.is_empty() || part.len() > 255 {
            return false;
        }
        let mut chars = part.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Check whether a string is a valid D-Bus object path.
///
/// Paths must start with '/' and consist of '/'-separated elements,
/// each containing only ASCII alphanumeric characters or underscores.
pub fn is_valid_object_path(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') {
        return false;
    }
    if path == "/" {
        return true;
    }
    let parts: Vec<&str> = path.split('/').collect();
    // path starts with '/' so split gives "" as first element
    if parts.len() < 2 || !parts[0].is_empty() {
        return false;
    }
    parts[1..]
        .iter()
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

// ── Lookup functions ────────────────────────────────────────────────────────

/// Classify a pattern as an interface name or object path.
///
/// Used to format descriptive error messages when a pattern is not found.
pub fn classify_pattern(pattern: &str) -> NotFoundKind {
    if is_valid_interface_name(pattern) {
        NotFoundKind::Interface
    } else {
        NotFoundKind::ObjectPath
    }
}

/// Recursively search for an implementation matching `pattern`.
///
/// Matches against both the `path` and `interface` fields. Searches
/// top-level implementations first, then recurses into children depth-first.
pub fn find_implementation<'a>(
    pattern: &str,
    bus_objects: &'a [BusObjectImplementation],
) -> Option<&'a BusObjectImplementation> {
    for impl_obj in bus_objects {
        if impl_obj.path == pattern || impl_obj.interface == pattern {
            return Some(impl_obj);
        }
        if let Some(found) = find_implementation(pattern, &impl_obj.children) {
            return Some(found);
        }
    }
    None
}

/// Recursively search for a mutable implementation matching `pattern`.
pub fn find_implementation_mut<'a>(
    pattern: &str,
    bus_objects: &'a mut [BusObjectImplementation],
) -> Option<&'a mut BusObjectImplementation> {
    for impl_obj in bus_objects.iter_mut() {
        if impl_obj.path == pattern || impl_obj.interface == pattern {
            return Some(impl_obj);
        }
        if let Some(found) = find_implementation_mut(pattern, &mut impl_obj.children) {
            return Some(found);
        }
    }
    None
}

/// Count the total number of implementations in the tree (including children).
pub fn count_implementations(bus_objects: &[BusObjectImplementation]) -> usize {
    let mut count = 0;
    count_impls(bus_objects, &mut count);
    count
}

fn count_impls(bus_objects: &[BusObjectImplementation], count: &mut usize) {
    for impl_obj in bus_objects {
        *count += 1;
        count_impls(&impl_obj.children, count);
    }
}

// ── Path listing ────────────────────────────────────────────────────────────

/// Collect all `(path, interface)` pairs from the implementation tree,
/// returned depth-first.
pub fn list_paths(bus_objects: &[BusObjectImplementation]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    collect_paths(bus_objects, &mut result);
    result
}

fn collect_paths(bus_objects: &[BusObjectImplementation], result: &mut Vec<(String, String)>) {
    for impl_obj in bus_objects {
        result.push((impl_obj.path.clone(), impl_obj.interface.clone()));
        collect_paths(&impl_obj.children, result);
    }
}

// ── Introspection ───────────────────────────────────────────────────────────

/// Introspection data generated for a single D-Bus object implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectionData {
    /// Interface names contributed by regular vtables.
    pub interfaces: Vec<String>,
    /// Interface names contributed by fallback vtables.
    pub fallback_interfaces: Vec<String>,
    /// Child node paths directly under this object.
    pub child_nodes: Vec<String>,
    /// Whether this node exports an `org.freedesktop.DBus.ObjectManager`.
    pub has_manager: bool,
}

impl IntrospectionData {
    /// Total number of interfaces (regular + fallback).
    pub fn total_interfaces(&self) -> usize {
        self.interfaces.len() + self.fallback_interfaces.len()
    }
}

/// The result of an introspection query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntrospectionResult {
    /// A full path listing (pattern was `"list"`).
    PathList(Vec<(String, String)>),
    /// Introspection data for a specific implementation.
    Introspection(IntrospectionData),
}

/// Generate introspection data for implementations matching `pattern`.
///
/// If `pattern` is `"list"`, returns a [`IntrospectionResult::PathList`]
/// containing all registered `(path, interface)` pairs.
///
/// Otherwise, finds the implementation matching `pattern` (by path or
/// interface) and returns [`IntrospectionResult::Introspection`] with
/// its interface and child-node information.
///
/// # Errors
///
/// Returns [`BusObjectError::NotFound`] if no implementation matches.
pub fn bus_introspect_implementations(
    pattern: &str,
    bus_objects: &[BusObjectImplementation],
) -> Result<IntrospectionResult, BusObjectError> {
    if pattern == "list" {
        return Ok(IntrospectionResult::PathList(list_paths(bus_objects)));
    }

    let impl_obj =
        find_implementation(pattern, bus_objects).ok_or_else(|| BusObjectError::NotFound {
            kind: classify_pattern(pattern),
            pattern: pattern.to_owned(),
        })?;

    let mut interfaces: Vec<String> = Vec::new();
    let mut fallback_interfaces: Vec<String> = Vec::new();

    // When the matched implementation has fallback vtables and the pattern
    // is an interface name, look for a non-fallback implementation at the
    // same path. This handles cases like systemd units where e.g.
    // "org.freedesktop.systemd1.Service" is a fallback vtable for
    // "/org/freedesktop/systemd1/unit", and we also want to emit
    // "org.freedesktop.systemd1.Unit" from the non-fallback impl.
    let main_impl = if !impl_obj.fallback_vtables.is_empty() && is_valid_interface_name(pattern) {
        find_implementation(&impl_obj.path, bus_objects)
    } else {
        None
    };

    // Emit the main (non-fallback) implementation's interfaces first
    if let Some(main) = &main_impl {
        if !std::ptr::eq(*main, impl_obj) {
            interfaces.extend(main.vtables.iter().cloned());
        }
    }

    // Emit the matched implementation's interfaces (skip if it was already
    // emitted as main_impl)
    if main_impl
        .as_ref()
        .map_or(true, |m| !std::ptr::eq(*m, impl_obj))
    {
        interfaces.extend(impl_obj.vtables.iter().cloned());
        for pair in &impl_obj.fallback_vtables {
            fallback_interfaces.push(pair.vtable_id.clone());
        }
    }

    // Collect child node paths
    let child_nodes: Vec<String> = impl_obj.children.iter().map(|c| c.path.clone()).collect();

    Ok(IntrospectionResult::Introspection(IntrospectionData {
        interfaces,
        fallback_interfaces,
        child_nodes,
        has_manager: impl_obj.manager,
    }))
}

// ── Registration helpers ────────────────────────────────────────────────────

/// Describes the actions that would be taken when registering an
/// implementation tree with a D-Bus connection.
///
/// This is a pure-data representation; the actual sd-bus calls happen
/// in the C layer. The Rust side validates and collects the registration
/// plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationPlan {
    /// `(path, interface)` pairs for regular vtable registration.
    pub vtable_registrations: Vec<(String, String, String)>,
    /// `(path, interface, vtable_id, object_find_id)` for fallback vtables.
    pub fallback_registrations: Vec<(String, String, String, String)>,
    /// `(path, enumerator_id)` for node enumerators.
    pub node_enumerators: Vec<(String, String)>,
    /// Paths where an object manager should be added.
    pub object_managers: Vec<String>,
}

/// Build a registration plan for an entire implementation tree.
///
/// Walks the tree recursively, collecting all vtable, fallback,
/// node-enumerator, and object-manager registrations that the C layer
/// would issue.
///
/// # Errors
///
/// Returns [`BusObjectError::InvalidField`] if any implementation fails
/// validation.
pub fn build_registration_plan(
    bus_objects: &[BusObjectImplementation],
) -> Result<RegistrationPlan, BusObjectError> {
    let mut plan = RegistrationPlan {
        vtable_registrations: Vec::new(),
        fallback_registrations: Vec::new(),
        node_enumerators: Vec::new(),
        object_managers: Vec::new(),
    };
    collect_registration_plan(bus_objects, &mut plan)?;
    Ok(plan)
}

fn collect_registration_plan(
    bus_objects: &[BusObjectImplementation],
    plan: &mut RegistrationPlan,
) -> Result<(), BusObjectError> {
    for impl_obj in bus_objects {
        impl_obj.validate()?;

        for vtable in &impl_obj.vtables {
            plan.vtable_registrations.push((
                impl_obj.path.clone(),
                impl_obj.interface.clone(),
                vtable.clone(),
            ));
        }

        for pair in &impl_obj.fallback_vtables {
            plan.fallback_registrations.push((
                impl_obj.path.clone(),
                impl_obj.interface.clone(),
                pair.vtable_id.clone(),
                pair.object_find_id.clone(),
            ));
        }

        if let Some(ref enumerator) = impl_obj.node_enumerator {
            plan.node_enumerators
                .push((impl_obj.path.clone(), enumerator.clone()));
        }

        if impl_obj.manager {
            plan.object_managers.push(impl_obj.path.clone());
        }

        collect_registration_plan(&impl_obj.children, plan)?;
    }
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixtures ────────────────────────────────────────────────────────

    fn sample_implementations() -> Vec<BusObjectImplementation> {
        vec![BusObjectImplementation::new(
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .with_vtable("vtable_manager")
        .with_manager(true)
        .with_node_enumerator("enum_units")
        .with_child(
            BusObjectImplementation::new(
                "/org/freedesktop/systemd1/unit",
                "org.freedesktop.systemd1.Unit",
            )
            .with_vtable("vtable_unit"),
        )
        .with_child(
            BusObjectImplementation::new(
                "/org/freedesktop/systemd1/job",
                "org.freedesktop.systemd1.Job",
            )
            .with_vtable("vtable_job"),
        )]
    }

    fn fallback_implementations() -> Vec<BusObjectImplementation> {
        vec![
            BusObjectImplementation::new(
                "/org/freedesktop/systemd1/unit",
                "org.freedesktop.systemd1.Unit",
            )
            .with_vtable("vtable_unit"),
            BusObjectImplementation::new(
                "/org/freedesktop/systemd1/unit",
                "org.freedesktop.systemd1.Service",
            )
            .with_fallback_vtable(BusObjectVtablePair::new(
                "vtable_service",
                "unit_object_find",
            )),
        ]
    }

    // ── Validation tests ────────────────────────────────────────────────

    #[test]
    fn test_is_valid_interface_name_valid() {
        assert!(is_valid_interface_name("org.freedesktop.DBus"));
        assert!(is_valid_interface_name("org.freedesktop.systemd1.Manager"));
        assert!(is_valid_interface_name("a.b"));
        assert!(is_valid_interface_name("com.example.foo_bar.baz2"));
    }

    #[test]
    fn test_is_valid_interface_name_invalid() {
        assert!(!is_valid_interface_name(""));
        assert!(!is_valid_interface_name("SingleElement"));
        assert!(!is_valid_interface_name(".leading.dot"));
        assert!(!is_valid_interface_name("trailing.dot."));
        assert!(!is_valid_interface_name("1digit.start"));
        assert!(!is_valid_interface_name("has-dash"));
        assert!(!is_valid_interface_name("a"));
    }

    #[test]
    fn test_is_valid_object_path_valid() {
        assert!(is_valid_object_path("/"));
        assert!(is_valid_object_path("/org/freedesktop/systemd1"));
        assert!(is_valid_object_path("/org/freedesktop/systemd1/unit"));
        assert!(is_valid_object_path("/_underscore"));
        assert!(is_valid_object_path("/org/Aa1"));
    }

    #[test]
    fn test_is_valid_object_path_invalid() {
        assert!(!is_valid_object_path(""));
        assert!(!is_valid_object_path("no_slash"));
        assert!(!is_valid_object_path("/double//slash"));
        assert!(!is_valid_object_path("/has-dash"));
        assert!(!is_valid_object_path("/trailing/"));
    }

    #[test]
    fn test_classify_pattern() {
        assert_eq!(
            classify_pattern("org.freedesktop.systemd1.Manager"),
            NotFoundKind::Interface
        );
        assert_eq!(
            classify_pattern("/org/freedesktop/systemd1"),
            NotFoundKind::ObjectPath
        );
        assert_eq!(
            classify_pattern("not_a_valid_interface"),
            NotFoundKind::ObjectPath
        );
    }

    // ── Implementation construction ─────────────────────────────────────

    #[test]
    fn test_implementation_builder() {
        let impl_obj = BusObjectImplementation::new("/path", "if.name")
            .with_vtable("vt1")
            .with_vtable("vt2")
            .with_fallback_vtable(BusObjectVtablePair::new("fvt", "find"))
            .with_node_enumerator("enum")
            .with_manager(true);

        assert_eq!(impl_obj.path, "/path");
        assert_eq!(impl_obj.interface, "if.name");
        assert_eq!(impl_obj.vtables, vec!["vt1", "vt2"]);
        assert_eq!(impl_obj.fallback_vtables.len(), 1);
        assert_eq!(impl_obj.node_enumerator.as_deref(), Some("enum"));
        assert!(impl_obj.manager);
        assert!(impl_obj.has_interfaces());
    }

    #[test]
    fn test_implementation_validate_ok() {
        let impl_obj = BusObjectImplementation::new("/org/example/Foo", "org.example.Foo");
        assert!(impl_obj.validate().is_ok());
    }

    #[test]
    fn test_implementation_validate_empty_path() {
        let impl_obj = BusObjectImplementation::new("", "org.example.Foo");
        let err = impl_obj.validate().unwrap_err();
        assert_eq!(
            err,
            BusObjectError::InvalidField {
                field: "path",
                reason: "must not be empty".into(),
            }
        );
    }

    #[test]
    fn test_implementation_validate_invalid_path() {
        let impl_obj = BusObjectImplementation::new("no_slash", "a.b");
        let err = impl_obj.validate().unwrap_err();
        assert!(matches!(
            err,
            BusObjectError::InvalidField { field: "path", .. }
        ));
    }

    // ── Find implementation ─────────────────────────────────────────────

    #[test]
    fn test_find_implementation_by_path() {
        let impls = sample_implementations();
        let found = find_implementation("/org/freedesktop/systemd1", &impls);
        assert!(found.is_some());
        assert_eq!(found.unwrap().interface, "org.freedesktop.systemd1.Manager");
    }

    #[test]
    fn test_find_implementation_by_interface() {
        let impls = sample_implementations();
        let found = find_implementation("org.freedesktop.systemd1.Job", &impls);
        assert!(found.is_some());
        assert_eq!(found.unwrap().path, "/org/freedesktop/systemd1/job");
    }

    #[test]
    fn test_find_implementation_in_children() {
        let impls = sample_implementations();
        let found = find_implementation("/org/freedesktop/systemd1/unit", &impls);
        assert!(found.is_some());
        assert_eq!(found.unwrap().interface, "org.freedesktop.systemd1.Unit");
    }

    #[test]
    fn test_find_implementation_not_found() {
        let impls = sample_implementations();
        assert!(find_implementation("/nonexistent", &impls).is_none());
    }

    #[test]
    fn test_find_implementation_mut() {
        let mut impls = sample_implementations();
        let found = find_implementation_mut("org.freedesktop.systemd1.Job", &mut impls);
        assert!(found.is_some());
        found.unwrap().manager = true;
        // Verify mutation took effect
        let found = find_implementation("org.freedesktop.systemd1.Job", &impls);
        assert!(found.unwrap().manager);
    }

    // ── Count implementations ───────────────────────────────────────────

    #[test]
    fn test_count_implementations() {
        let impls = sample_implementations();
        assert_eq!(count_implementations(&impls), 3); // Manager + Unit + Job
    }

    #[test]
    fn test_count_implementations_empty() {
        assert_eq!(count_implementations(&[]), 0);
    }

    // ── List paths ──────────────────────────────────────────────────────

    #[test]
    fn test_list_paths() {
        let impls = sample_implementations();
        let paths = list_paths(&impls);
        assert_eq!(paths.len(), 3);
        assert_eq!(
            paths[0],
            (
                "/org/freedesktop/systemd1".to_string(),
                "org.freedesktop.systemd1.Manager".to_string()
            )
        );
        assert_eq!(
            paths[1],
            (
                "/org/freedesktop/systemd1/unit".to_string(),
                "org.freedesktop.systemd1.Unit".to_string()
            )
        );
    }

    #[test]
    fn test_list_paths_empty() {
        assert!(list_paths(&[]).is_empty());
    }

    // ── Introspection ───────────────────────────────────────────────────

    #[test]
    fn test_introspect_list() {
        let impls = sample_implementations();
        let result = bus_introspect_implementations("list", &impls).unwrap();
        match result {
            IntrospectionResult::PathList(paths) => assert_eq!(paths.len(), 3),
            IntrospectionResult::Introspection(_) => panic!("expected PathList"),
        }
    }

    #[test]
    fn test_introspect_by_path() {
        let impls = sample_implementations();
        let result = bus_introspect_implementations("/org/freedesktop/systemd1", &impls).unwrap();
        match result {
            IntrospectionResult::Introspection(data) => {
                assert!(data.has_manager);
                assert_eq!(data.interfaces, vec!["vtable_manager"]);
                assert_eq!(data.child_nodes.len(), 2);
            }
            IntrospectionResult::PathList(_) => panic!("expected Introspection"),
        }
    }

    #[test]
    fn test_introspect_by_interface() {
        let impls = sample_implementations();
        let result =
            bus_introspect_implementations("org.freedesktop.systemd1.Unit", &impls).unwrap();
        match result {
            IntrospectionResult::Introspection(data) => {
                assert_eq!(data.interfaces, vec!["vtable_unit"]);
                assert!(!data.has_manager);
            }
            IntrospectionResult::PathList(_) => panic!("expected Introspection"),
        }
    }

    #[test]
    fn test_introspect_not_found() {
        let impls = sample_implementations();
        let err = bus_introspect_implementations("/org/nonexistent/Path", &impls).unwrap_err();
        assert_eq!(
            err,
            BusObjectError::NotFound {
                kind: NotFoundKind::ObjectPath,
                pattern: "/org/nonexistent/Path".into()
            }
        );
    }

    #[test]
    fn test_introspect_fallback_with_main() {
        // When a fallback impl is matched by interface, the main (non-fallback)
        // impl at the same path should also be emitted.
        let impls = fallback_implementations();
        let result =
            bus_introspect_implementations("org.freedesktop.systemd1.Service", &impls).unwrap();
        match result {
            IntrospectionResult::Introspection(data) => {
                // Main impl's vtable should appear first
                assert!(data.interfaces.contains(&"vtable_unit".to_string()));
                // Fallback interface should appear too
                assert!(data
                    .fallback_interfaces
                    .contains(&"vtable_service".to_string()));
                assert_eq!(data.total_interfaces(), 2);
            }
            IntrospectionResult::PathList(_) => panic!("expected Introspection"),
        }
    }

    #[test]
    fn test_introspect_fallback_by_path_no_main_emit() {
        // When matched by path (not interface), fallback vtables are emitted
        // without the main-impl lookup.
        let impls = fallback_implementations();
        let result =
            bus_introspect_implementations("/org/freedesktop/systemd1/unit", &impls).unwrap();
        match result {
            IntrospectionResult::Introspection(data) => {
                // Path match returns the first impl at that path (Unit)
                assert!(data.interfaces.contains(&"vtable_unit".to_string()));
            }
            IntrospectionResult::PathList(_) => panic!("expected Introspection"),
        }
    }

    // ── Registration plan ───────────────────────────────────────────────

    #[test]
    fn test_build_registration_plan() {
        let impls = sample_implementations();
        let plan = build_registration_plan(&impls).unwrap();

        // Manager has 1 vtable
        assert_eq!(plan.vtable_registrations.len(), 3); // manager + unit + job
        assert_eq!(plan.object_managers, vec!["/org/freedesktop/systemd1"]);
        assert_eq!(
            plan.node_enumerators,
            vec![(
                "/org/freedesktop/systemd1".to_string(),
                "enum_units".to_string()
            )]
        );
    }

    #[test]
    fn test_build_registration_plan_with_fallback() {
        let impls = fallback_implementations();
        let plan = build_registration_plan(&impls).unwrap();

        assert_eq!(plan.vtable_registrations.len(), 1);
        assert_eq!(plan.fallback_registrations.len(), 1);
        assert_eq!(plan.fallback_registrations[0].2, "vtable_service");
        assert_eq!(plan.fallback_registrations[0].3, "unit_object_find");
    }

    #[test]
    fn test_build_registration_plan_invalid() {
        let impls = vec![BusObjectImplementation::new("", "a.b")];
        let err = build_registration_plan(&impls).unwrap_err();
        assert!(matches!(err, BusObjectError::InvalidField { .. }));
    }

    #[test]
    fn test_build_registration_plan_empty() {
        let plan = build_registration_plan(&[]).unwrap();
        assert!(plan.vtable_registrations.is_empty());
        assert!(plan.fallback_registrations.is_empty());
        assert!(plan.node_enumerators.is_empty());
        assert!(plan.object_managers.is_empty());
    }

    // ── Error display ───────────────────────────────────────────────────

    #[test]
    fn test_error_display_not_found() {
        let err = BusObjectError::NotFound {
            kind: NotFoundKind::Interface,
            pattern: "org.example.Foo".into(),
        };
        assert_eq!(format!("{err}"), "Interface org.example.Foo not found");

        let err = BusObjectError::NotFound {
            kind: NotFoundKind::ObjectPath,
            pattern: "/org/example".into(),
        };
        assert_eq!(format!("{err}"), "Object path /org/example not found");
    }

    #[test]
    fn test_error_display_invalid_field() {
        let err = BusObjectError::InvalidField {
            field: "path",
            reason: "must not be empty".into(),
        };
        assert_eq!(format!("{err}"), "Invalid path: must not be empty");
    }

    // ── Sentinel / edge cases ───────────────────────────────────────────

    #[test]
    fn test_fallback_vtable_sentinel() {
        assert!(FALLBACK_VTABLE_SENTINEL.vtable_id.is_empty());
        assert!(FALLBACK_VTABLE_SENTINEL.object_find_id.is_empty());
    }

    #[test]
    fn test_has_interfaces_empty() {
        let impl_obj = BusObjectImplementation::new("/a", "b.c");
        assert!(!impl_obj.has_interfaces());
    }

    #[test]
    fn test_vtable_pair_new() {
        let pair = BusObjectVtablePair::new("vt", "find_fn");
        assert_eq!(pair.vtable_id, "vt");
        assert_eq!(pair.object_find_id, "find_fn");
    }

    #[test]
    fn test_introspection_data_total_interfaces() {
        let data = IntrospectionData {
            interfaces: vec!["a".into(), "b".into()],
            fallback_interfaces: vec!["c".into()],
            child_nodes: vec![],
            has_manager: false,
        };
        assert_eq!(data.total_interfaces(), 3);
    }

    #[test]
    fn test_deep_nesting() {
        let impls = vec![BusObjectImplementation::new("/a", "a.b").with_child(
            BusObjectImplementation::new("/a/b", "a.b.c").with_child(
                BusObjectImplementation::new("/a/b/c", "a.b.c.d").with_vtable("deep_vt"),
            ),
        )];

        assert_eq!(count_implementations(&impls), 3);
        let found = find_implementation("/a/b/c", &impls);
        assert!(found.is_some());
        assert_eq!(found.unwrap().vtables, vec!["deep_vt"]);

        let paths = list_paths(&impls);
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[2].0, "/a/b/c");
    }
}
