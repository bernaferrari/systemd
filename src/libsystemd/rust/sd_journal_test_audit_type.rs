// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-audit-type.c

pub const AUDIT_KERNEL: u32 = 2000;
const NEG_EINVAL: i32 = -(libc::EINVAL as i32);

const KNOWN_TYPES: &[(u32, &str)] = &[
    (0, "AUDIT_GET"),
    (1, "AUDIT_SET"),
    (2, "AUDIT_LIST"),
    (1000, "AUDIT_USER"),
    (1107, "AUDIT_AVC"),
    (1327, "AUDIT_MAC_POLICY_LOAD"),
    (1334, "AUDIT_INTEGRITY_DATA"),
    (2000, "AUDIT_KERNEL"),
];

pub fn audit_type_to_string(value: u32) -> &'static str {
    KNOWN_TYPES
        .iter()
        .find_map(|(k, v)| (*k == value).then_some(*v))
        .unwrap_or("UNKNOWN")
}

pub fn audit_type_name(value: u32) -> String {
    match audit_type_to_string(value) {
        "UNKNOWN" => format!("AUDIT_TYPE_{value}"),
        known => known.to_string(),
    }
}

pub fn render_audit_label(value: u32) -> Result<String, i32> {
    if value > AUDIT_KERNEL {
        return Err(NEG_EINVAL);
    }

    Ok(format!(
        "{value} → {} → {}",
        audit_type_to_string(value),
        audit_type_name(value)
    ))
}

pub fn render_all_audit_labels() -> Result<Vec<String>, i32> {
    (0..=AUDIT_KERNEL).map(render_audit_label).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_type_uses_canonical_name() {
        assert_eq!(audit_type_to_string(1000), "AUDIT_USER");
    }

    #[test]
    fn unknown_type_falls_back_to_unknown() {
        assert_eq!(audit_type_to_string(42), "UNKNOWN");
    }

    #[test]
    fn name_for_known_type_matches_symbol() {
        assert_eq!(audit_type_name(2000), "AUDIT_KERNEL");
    }

    #[test]
    fn name_for_unknown_type_is_formatted() {
        assert_eq!(audit_type_name(42), "AUDIT_TYPE_42");
    }

    #[test]
    fn rendered_label_matches_c_test_shape() {
        assert_eq!(
            render_audit_label(1000).unwrap(),
            "1000 → AUDIT_USER → AUDIT_USER"
        );
    }

    #[test]
    fn rendering_rejects_out_of_range_values() {
        assert_eq!(render_audit_label(AUDIT_KERNEL + 1), Err(NEG_EINVAL));
    }

    #[test]
    fn render_all_covers_full_closed_range() {
        let labels = render_all_audit_labels().unwrap();
        assert_eq!(labels.len(), AUDIT_KERNEL as usize + 1);
    }

    #[test]
    fn render_all_starts_and_ends_at_expected_values() {
        let labels = render_all_audit_labels().unwrap();
        assert_eq!(labels.first().unwrap(), "0 → AUDIT_GET → AUDIT_GET");
        assert_eq!(labels.last().unwrap(), "2000 → AUDIT_KERNEL → AUDIT_KERNEL");
    }
}
