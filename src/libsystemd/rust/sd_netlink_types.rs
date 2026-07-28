// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-types.c

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EOPNOTSUPP: i32 = -(libc::EOPNOTSUPP as i32);
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;

#[repr(C)]
struct NlMsgErrHeader {
    error: i32,
    msg_len: u32,
    msg_type: u16,
    msg_flags: u16,
    msg_seq: u32,
    msg_pid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NlaType {
    Unspec,
    Binary,
    Flag,
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    String,
    Bitfield32,
    Reject,
    InAddr,
    EtherAddr,
    CacheInfo,
    SockAddr,
    Nested,
    NestedUnionByString,
    NestedUnionByFamily,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NlaPolicy {
    pub kind: NlaType,
    pub size: usize,
    pub nested: Option<PolicyTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyTarget {
    Set(Box<NlaPolicySet>),
    Union(Box<NlaPolicySetUnion>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NlaPolicySet {
    pub policies: Vec<Option<NlaPolicy>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NlaPolicySetUnion {
    pub match_attribute: u16,
    pub string_keys: Vec<(String, NlaPolicySet)>,
    pub family_keys: Vec<(i32, NlaPolicySet)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetlinkProtocol {
    Route,
    Netfilter,
    Generic,
    SockDiag,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetlinkMessageDescription {
    pub protocol: NetlinkProtocol,
    pub header_policy: Option<NlaPolicy>,
}

impl NlaPolicy {
    pub fn simple(kind: NlaType) -> Self {
        Self {
            kind,
            size: 0,
            nested: None,
        }
    }

    pub fn sized(kind: NlaType, size: usize) -> Self {
        Self {
            kind,
            size,
            nested: None,
        }
    }

    pub fn nested(set: NlaPolicySet) -> Self {
        Self {
            kind: NlaType::Nested,
            size: 0,
            nested: Some(PolicyTarget::Set(Box::new(set))),
        }
    }

    pub fn nested_with_size(set: NlaPolicySet, size: usize) -> Self {
        Self {
            kind: NlaType::Nested,
            size,
            nested: Some(PolicyTarget::Set(Box::new(set))),
        }
    }

    pub fn nested_union_by_string(union: NlaPolicySetUnion) -> Self {
        Self {
            kind: NlaType::NestedUnionByString,
            size: 0,
            nested: Some(PolicyTarget::Union(Box::new(union))),
        }
    }

    pub fn nested_union_by_family(union: NlaPolicySetUnion) -> Self {
        Self {
            kind: NlaType::NestedUnionByFamily,
            size: 0,
            nested: Some(PolicyTarget::Union(Box::new(union))),
        }
    }
}

impl NlaPolicySet {
    pub fn empty() -> Self {
        Self {
            policies: vec![None],
        }
    }

    pub fn error() -> Self {
        let mut policies = vec![None; 3];
        policies[1] = Some(NlaPolicy::simple(NlaType::String));
        policies[2] = Some(NlaPolicy::simple(NlaType::U32));
        Self { policies }
    }

    pub fn basic() -> Self {
        let mut policies = vec![None; 4];
        policies[2] = Some(NlaPolicy::nested(Self::empty()));
        policies[3] = Some(NlaPolicy::nested_with_size(
            Self::error(),
            std::mem::size_of::<NlMsgErrHeader>(),
        ));
        Self { policies }
    }

    pub fn get_policy(&self, attr_type: u16) -> Option<&NlaPolicy> {
        self.policies
            .get(attr_type as usize)
            .and_then(|p| p.as_ref())
    }

    pub fn get_policy_set(&self, attr_type: u16) -> Option<&NlaPolicySet> {
        match self.get_policy(attr_type)?.nested.as_ref()? {
            PolicyTarget::Set(set) => Some(set),
            PolicyTarget::Union(_) => None,
        }
    }

    pub fn get_policy_set_union(&self, attr_type: u16) -> Option<&NlaPolicySetUnion> {
        match self.get_policy(attr_type)?.nested.as_ref()? {
            PolicyTarget::Union(union) => Some(union),
            PolicyTarget::Set(_) => None,
        }
    }
}

impl NlaPolicySetUnion {
    pub fn get_match_attribute(&self) -> u16 {
        self.match_attribute
    }

    pub fn get_policy_set_by_string(&self, string: &str) -> Option<&NlaPolicySet> {
        self.string_keys
            .iter()
            .find(|(key, _)| key == string)
            .map(|(_, set)| set)
    }

    pub fn get_policy_set_by_family(&self, family: i32) -> Option<&NlaPolicySet> {
        self.family_keys
            .iter()
            .find(|(key, _)| *key == family)
            .map(|(_, set)| set)
    }
}

pub fn policy_get_type(policy: &NlaPolicy) -> NlaType {
    policy.kind
}

pub fn policy_get_size(policy: &NlaPolicy) -> usize {
    policy.size
}

pub fn policy_get_policy_set(policy: &NlaPolicy) -> Option<&NlaPolicySet> {
    match policy.nested.as_ref()? {
        PolicyTarget::Set(set) => Some(set),
        PolicyTarget::Union(_) => None,
    }
}

pub fn policy_get_policy_set_union(policy: &NlaPolicy) -> Option<&NlaPolicySetUnion> {
    match policy.nested.as_ref()? {
        PolicyTarget::Union(union) => Some(union),
        PolicyTarget::Set(_) => None,
    }
}

pub fn netlink_get_policy_set_and_header_size(
    message: &NetlinkMessageDescription,
    msg_type: u16,
) -> Result<(NlaPolicySet, usize)> {
    let policy = if msg_type == NLMSG_DONE {
        NlaPolicySet::basic().get_policy(2).cloned()
    } else if msg_type == NLMSG_ERROR {
        NlaPolicySet::basic().get_policy(3).cloned()
    } else {
        message.header_policy.clone()
    }
    .ok_or(NEG_EOPNOTSUPP)?;

    if policy.kind != NlaType::Nested {
        return Err(NEG_EOPNOTSUPP);
    }
    let set = policy_get_policy_set(&policy)
        .ok_or(NEG_EOPNOTSUPP)?
        .clone();
    Ok((set, policy.size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_policy_contains_message_and_offset() {
        let set = NlaPolicySet::error();
        assert_eq!(set.get_policy(1).unwrap().kind, NlaType::String);
        assert_eq!(set.get_policy(2).unwrap().kind, NlaType::U32);
    }

    #[test]
    fn basic_policy_contains_nested_sets() {
        let set = NlaPolicySet::basic();
        assert_eq!(set.get_policy(2).unwrap().kind, NlaType::Nested);
        assert_eq!(
            set.get_policy(3).unwrap().size,
            std::mem::size_of::<NlMsgErrHeader>()
        );
    }

    #[test]
    fn lookup_missing_policy_returns_none() {
        assert!(NlaPolicySet::empty().get_policy(10).is_none());
    }

    #[test]
    fn nested_policy_exposes_policy_set() {
        let policy = NlaPolicy::nested(NlaPolicySet::empty());
        assert!(policy_get_policy_set(&policy).is_some());
    }

    #[test]
    fn union_policy_exposes_string_lookup() {
        let union = NlaPolicySetUnion {
            match_attribute: 5,
            string_keys: vec![("bridge".into(), NlaPolicySet::empty())],
            family_keys: vec![],
        };
        let policy = NlaPolicy::nested_union_by_string(union);
        assert!(
            policy_get_policy_set_union(&policy)
                .unwrap()
                .get_policy_set_by_string("bridge")
                .is_some()
        );
    }

    #[test]
    fn union_policy_exposes_family_lookup() {
        let union = NlaPolicySetUnion {
            match_attribute: 7,
            string_keys: vec![],
            family_keys: vec![(libc::AF_INET, NlaPolicySet::empty())],
        };
        assert!(union.get_policy_set_by_family(libc::AF_INET).is_some());
    }

    #[test]
    fn returns_policy_set_for_builtin_done_message() {
        let message = NetlinkMessageDescription {
            protocol: NetlinkProtocol::Route,
            header_policy: None,
        };
        let (set, _) = netlink_get_policy_set_and_header_size(&message, NLMSG_DONE).unwrap();
        assert_eq!(set.policies.len(), 1);
    }

    #[test]
    fn returns_policy_set_for_custom_nested_message() {
        let message = NetlinkMessageDescription {
            protocol: NetlinkProtocol::Generic,
            header_policy: Some(NlaPolicy::nested_with_size(NlaPolicySet::error(), 12)),
        };
        let (_, size) = netlink_get_policy_set_and_header_size(&message, 42).unwrap();
        assert_eq!(size, 12);
    }

    #[test]
    fn rejects_non_nested_header_policies() {
        let message = NetlinkMessageDescription {
            protocol: NetlinkProtocol::SockDiag,
            header_policy: Some(NlaPolicy::simple(NlaType::U32)),
        };
        assert_eq!(
            netlink_get_policy_set_and_header_size(&message, 99),
            Err(NEG_EOPNOTSUPP)
        );
    }

    #[test]
    fn reports_match_attribute() {
        let union = NlaPolicySetUnion {
            match_attribute: 9,
            string_keys: vec![],
            family_keys: vec![],
        };
        assert_eq!(union.get_match_attribute(), 9);
    }
}
