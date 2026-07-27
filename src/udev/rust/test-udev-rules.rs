// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/test-udev-rules.c
//
// Rule matcher tests.

pub fn rule_matches(action: &str, expected: &str) -> bool {
    action == expected
}

pub fn env_rule_matches(key: &str, value: &str, env: &std::collections::BTreeMap<String, String>) -> bool {
    env.get(key).is_some_and(|stored| stored == value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn action_match_is_exact() { assert!(rule_matches("add", "add")); assert!(!rule_matches("change", "add")); }
    #[test] fn env_match_reads_map() { let env = std::collections::BTreeMap::from([("ID".to_string(), "42".to_string())]); assert!(env_rule_matches("ID", "42", &env)); assert!(!env_rule_matches("ID", "43", &env)); }
}
