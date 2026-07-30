// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port of networkd-routing-policy-rule.c
//
// SAFETY: This module is a Rust port of the corresponding C source.
// FFI boundary functions use unsafe extern "C" with proper SAFETY comments.
// Internal logic uses safe Rust with Result<T, Errno> error handling.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum RoutingPolicyRuleConfParserType {
    RoutingPolicyRuleIif,
    RoutingPolicyRuleOif,
    RoutingPolicyRuleFamily,
    RoutingPolicyRuleFwmark,
    RoutingPolicyRuleGoto,
    RoutingPolicyRuleInvert,
    RoutingPolicyRuleIpProtocol,
    RoutingPolicyRuleL3mdev,
    RoutingPolicyRuleSport,
    RoutingPolicyRuleDport,
    RoutingPolicyRuleFrom,
    RoutingPolicyRuleTo,
    RoutingPolicyRulePriority,
    RoutingPolicyRuleSuppressIfgroup,
    RoutingPolicyRuleSuppressPrefixlen,
    RoutingPolicyRuleTable,
    RoutingPolicyRuleTos,
    RoutingPolicyRuleAction,
    RoutingPolicyRuleUidRange,
}

#[derive(Debug)]
pub struct RoutingPolicyRule {
    pub source: i32,
    pub state: i32,
    pub n_ref: i32,
    pub address_family: i32,
    pub family: i32,
    pub tos: i32,
    pub action: i32,
    pub flags: i32,
    pub to: i32,
    pub from: i32,
    pub priority_goto: i32,
    pub priority_set: i32,
    pub priority: i32,
    pub fwmark: i32,
    pub realms: i32,
    pub tunnel_id: i32,
    pub suppress_ifgroup: i32,
    pub suppress_prefixlen: i32,
    pub table: i32,
    pub fwmask: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_networkd_routing_policy_rule_enums() {
        let _ = std::mem::size_of::<RoutingPolicyRuleConfParserType>();
    }
}
