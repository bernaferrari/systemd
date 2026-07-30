// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-synthesize.c
//
// DNS answer synthesis: synthesize responses for localhost, local DNS stub,
// local DNS proxy, reverse lookups, and hostname-based answers.

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_AAAA: u16 = 28;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const AF_UNSPEC: i32 = 0;

const DNS_PROTOCOL_DNS: u32 = 0;
const DNS_PROTOCOL_LLMNR: u32 = 1;
const DNS_PROTOCOL_MDNS: u32 = 2;

const LOCALHOST_IPV4: u32 = 0x7f000001_u32.to_be();
const LOCAL_DNS_STUB_IPV4: u32 = 0x7f000035_u32.to_be();
const LOCAL_DNS_PROXY_IPV4: u32 = 0x7f000036_u32.to_be();

// ── Protocol / family helpers ───────────────────────────────────────────────

fn dns_synthesize_family(flags: u32) -> i32 {
    let protocol = (flags >> 8) & 0xFF;
    match protocol {
        0 => AF_UNSPEC,
        _ => (flags & 0xFF) as i32,
    }
}

fn dns_synthesize_protocol(flags: u32) -> u32 {
    (flags >> 8) & 0xFF
}

fn make_flags(protocol: u32, family: i32, _confidential: bool, _synthetic: bool) -> u32 {
    ((protocol & 0xFF) << 8) | ((family as u32) & 0xFF)
}

// ── Resource key / question ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DnsResourceKey {
    class: u16,
    rtype: u16,
    name: String,
}

impl DnsResourceKey {
    fn new(class: u16, rtype: u16, name: &str) -> Self {
        Self {
            class,
            rtype,
            name: name.to_string(),
        }
    }
}

struct DnsQuestion {
    keys: Vec<DnsResourceKey>,
}

impl DnsQuestion {
    fn new() -> Self {
        Self { keys: Vec::new() }
    }

    fn add(&mut self, key: DnsResourceKey) {
        self.keys.push(key);
    }
}

// ── Resource record / answer ────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DnsResourceRecord {
    key: DnsResourceKey,
    a_addr: Option<u32>,
    ptr_name: Option<String>,
}

impl DnsResourceRecord {
    fn new(class: u16, rtype: u16, name: &str) -> Self {
        Self {
            key: DnsResourceKey::new(class, rtype, name),
            a_addr: None,
            ptr_name: None,
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.key.class == other.key.class
            && self.key.rtype == other.key.rtype
            && self.key.name.eq_ignore_ascii_case(&other.key.name)
    }
}

struct DnsAnswer {
    records: Vec<DnsResourceRecord>,
}

impl DnsAnswer {
    fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn contains(&self, rr: &DnsResourceRecord) -> bool {
        self.records.iter().any(|r| r.matches(rr))
    }

    fn match_key(&self, key: &DnsResourceKey) -> bool {
        self.records.iter().any(|r| {
            r.key.class == key.class
                && r.key.rtype == key.rtype
                && r.key.name.eq_ignore_ascii_case(&key.name)
        })
    }
}

// ── Manager ─────────────────────────────────────────────────────────────────

struct Manager {
    full_hostname: Option<String>,
    llmnr_hostname: Option<String>,
    mdns_hostname: Option<String>,
}

impl Manager {
    fn new() -> Self {
        Self {
            full_hostname: None,
            llmnr_hostname: None,
            mdns_hostname: None,
        }
    }
}

// ── Synthesis logic ─────────────────────────────────────────────────────────

fn dns_synthesize_answer(
    mgr: &Manager,
    question: &DnsQuestion,
    answer: &mut DnsAnswer,
) -> Result<bool, i32> {
    let mut found = false;

    for key in &question.keys {
        let name_lower = key.name.to_ascii_lowercase();

        if key.rtype == DNS_TYPE_A {
            if name_lower == "localhost" {
                let mut rr = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, "localhost");
                rr.a_addr = Some(LOCALHOST_IPV4);
                answer.records.push(rr);
                found = true;
            } else if name_lower == "_localdnsstub" {
                let mut rr = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, "_localdnsstub");
                rr.a_addr = Some(LOCAL_DNS_STUB_IPV4);
                answer.records.push(rr);
                found = true;
            } else if name_lower == "_localdnsproxy" {
                let mut rr = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, "_localdnsproxy");
                rr.a_addr = Some(LOCAL_DNS_PROXY_IPV4);
                answer.records.push(rr);
                found = true;
            } else if let Some(ref hostname) = mgr.full_hostname
                && name_lower == hostname.to_ascii_lowercase()
            {
                let mut rr = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, hostname);
                rr.a_addr = Some(LOCALHOST_IPV4);
                answer.records.push(rr);
                found = true;
            }
        }

        if key.rtype == DNS_TYPE_PTR {
            if name_lower == "1.0.0.127.in-addr.arpa" {
                let mut rr =
                    DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_PTR, "1.0.0.127.in-addr.arpa");
                rr.ptr_name = Some("localhost".to_string());
                answer.records.push(rr);
                found = true;
            } else if name_lower == "53.0.0.127.in-addr.arpa" {
                let mut rr =
                    DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_PTR, "53.0.0.127.in-addr.arpa");
                rr.ptr_name = Some("_localdnsstub".to_string());
                answer.records.push(rr);
                found = true;
            } else if name_lower == "54.0.0.127.in-addr.arpa" {
                let mut rr =
                    DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_PTR, "54.0.0.127.in-addr.arpa");
                rr.ptr_name = Some("_localdnsproxy".to_string());
                answer.records.push(rr);
                found = true;
            } else if name_lower == "2.0.0.127.in-addr.arpa" {
                let ptr_names: Vec<String> = vec![
                    mgr.full_hostname.clone().unwrap_or_default(),
                    mgr.llmnr_hostname.clone().unwrap_or_default(),
                    mgr.mdns_hostname.clone().unwrap_or_default(),
                    "localhost".to_string(),
                ];
                for pn in ptr_names {
                    if !pn.is_empty() {
                        let mut rr = DnsResourceRecord::new(
                            DNS_CLASS_IN,
                            DNS_TYPE_PTR,
                            "2.0.0.127.in-addr.arpa",
                        );
                        rr.ptr_name = Some(pn);
                        answer.records.push(rr);
                        found = true;
                    }
                }
            } else if name_lower.ends_with(".in-addr.arpa") {
                let octets_str = name_lower.strip_suffix(".in-addr.arpa").unwrap();
                let octets: Vec<&str> = octets_str.split('.').collect();
                if octets.len() == 4 && mgr.full_hostname.is_some() {
                    let ip_bytes: Vec<u8> =
                        octets.iter().filter_map(|o| o.parse::<u8>().ok()).collect();
                    if ip_bytes.len() == 4 {
                        let ip = u32::from_be_bytes([
                            ip_bytes[0],
                            ip_bytes[1],
                            ip_bytes[2],
                            ip_bytes[3],
                        ]);
                        if ip == 0x7f000002_u32.to_be() {
                            // handled by 2.0.0.127 above
                        } else if ip == 0x7f000000_u32.to_be() {
                            return Err(-6);
                        }
                    }
                }
            }
        }

        if name_lower.ends_with(".in-addr.arpa") && !found {
            // non-matching reverse lookup
        }
    }

    Ok(found)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthesize_family_and_protocol() {
        let flags = make_flags(DNS_PROTOCOL_DNS, AF_INET, false, false);
        assert_eq!(dns_synthesize_family(flags), AF_UNSPEC);
        assert_eq!(dns_synthesize_protocol(flags), DNS_PROTOCOL_DNS);

        let flags = make_flags(DNS_PROTOCOL_LLMNR, AF_INET6, false, false);
        assert_eq!(dns_synthesize_family(flags), AF_INET6);
        assert_eq!(dns_synthesize_protocol(flags), DNS_PROTOCOL_LLMNR);

        let flags = make_flags(DNS_PROTOCOL_MDNS, AF_INET, false, false);
        assert_eq!(dns_synthesize_family(flags), AF_INET);
        assert_eq!(dns_synthesize_protocol(flags), DNS_PROTOCOL_MDNS);
    }

    #[test]
    fn test_synthesize_answer_empty() {
        let mgr = Manager::new();
        let mut question = DnsQuestion::new();
        question.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ));
        let mut answer = DnsAnswer::new();

        let result = dns_synthesize_answer(&mgr, &question, &mut answer).unwrap();
        assert!(!result);
        assert!(answer.is_empty());
    }

    #[test]
    fn test_synthesize_answer_localhost() {
        let mgr = Manager::new();
        let mut question = DnsQuestion::new();
        question.add(DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "localhost"));
        let mut answer = DnsAnswer::new();

        let result = dns_synthesize_answer(&mgr, &question, &mut answer).unwrap();
        assert!(result);

        let mut expected = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, "localhost");
        expected.a_addr = Some(LOCALHOST_IPV4);
        assert!(answer.contains(&expected));
    }

    #[test]
    fn test_synthesize_answer_own_hostname() {
        let mut mgr = Manager::new();
        mgr.full_hostname = Some("resolver.local".to_string());
        let mut question = DnsQuestion::new();
        question.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "resolver.local",
        ));
        let mut answer = DnsAnswer::new();

        let result = dns_synthesize_answer(&mgr, &question, &mut answer).unwrap();
        assert!(result);

        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "resolver.local");
        assert!(answer.match_key(&key));
    }

    #[test]
    fn test_synthesize_answer_stub() {
        let mgr = Manager::new();
        let mut question = DnsQuestion::new();
        question.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "_localdnsstub",
        ));
        let mut answer = DnsAnswer::new();

        let result = dns_synthesize_answer(&mgr, &question, &mut answer).unwrap();
        assert!(result);

        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "_localdnsstub");
        assert!(answer.match_key(&key));
    }

    #[test]
    fn test_synthesize_answer_localhost_ptr() {
        let mgr = Manager::new();
        let mut question = DnsQuestion::new();
        question.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_PTR,
            "1.0.0.127.in-addr.arpa",
        ));
        let mut answer = DnsAnswer::new();

        let result = dns_synthesize_answer(&mgr, &question, &mut answer).unwrap();
        assert!(result);

        let mut expected =
            DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_PTR, "1.0.0.127.in-addr.arpa");
        expected.ptr_name = Some("localhost".to_string());
        assert!(answer.contains(&expected));
    }

    #[test]
    fn test_synthesize_answer_address_not_matching() {
        let mut mgr = Manager::new();
        mgr.full_hostname = Some("resolver.local".to_string());
        mgr.llmnr_hostname = Some("llmnr.resolver.local".to_string());
        mgr.mdns_hostname = Some("mdns.resolver.local".to_string());
        let mut question = DnsQuestion::new();
        question.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_PTR,
            "0.1.254.169.in-addr.arpa",
        ));
        let mut answer = DnsAnswer::new();

        let result = dns_synthesize_answer(&mgr, &question, &mut answer).unwrap();
        assert!(!result);
        assert!(answer.is_empty());
    }

    #[test]
    fn test_synthesize_answer_local_hostname_ptr() {
        let mut mgr = Manager::new();
        mgr.full_hostname = Some("resolver.local".to_string());
        mgr.llmnr_hostname = Some("llmnr.resolver.local".to_string());
        mgr.mdns_hostname = Some("mdns.resolver.local".to_string());
        let mut question = DnsQuestion::new();
        question.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_PTR,
            "2.0.0.127.in-addr.arpa",
        ));
        let mut answer = DnsAnswer::new();

        let result = dns_synthesize_answer(&mgr, &question, &mut answer).unwrap();
        assert!(result);

        let mut rr1 = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        rr1.ptr_name = Some("resolver.local".to_string());
        assert!(answer.contains(&rr1));

        let mut rr2 = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        rr2.ptr_name = Some("llmnr.resolver.local".to_string());
        assert!(answer.contains(&rr2));

        let mut rr3 = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        rr3.ptr_name = Some("mdns.resolver.local".to_string());
        assert!(answer.contains(&rr3));

        let mut rr4 = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_PTR, "2.0.0.127.in-addr.arpa");
        rr4.ptr_name = Some("localhost".to_string());
        assert!(answer.contains(&rr4));
    }

    #[test]
    fn test_synthesize_answer_local_dns_stub_ptr() {
        let mut mgr = Manager::new();
        mgr.full_hostname = Some("resolver.local".to_string());
        mgr.llmnr_hostname = Some("llmnr.resolver.local".to_string());
        mgr.mdns_hostname = Some("mdns.resolver.local".to_string());
        let mut question = DnsQuestion::new();
        question.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_PTR,
            "53.0.0.127.in-addr.arpa",
        ));
        let mut answer = DnsAnswer::new();

        let result = dns_synthesize_answer(&mgr, &question, &mut answer).unwrap();
        assert!(result);

        let mut expected =
            DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_PTR, "53.0.0.127.in-addr.arpa");
        expected.ptr_name = Some("_localdnsstub".to_string());
        assert!(answer.contains(&expected));
    }

    #[test]
    fn test_synthesize_answer_local_dns_proxy_ptr() {
        let mut mgr = Manager::new();
        mgr.full_hostname = Some("resolver.local".to_string());
        mgr.llmnr_hostname = Some("llmnr.resolver.local".to_string());
        mgr.mdns_hostname = Some("mdns.resolver.local".to_string());
        let mut question = DnsQuestion::new();
        question.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_PTR,
            "54.0.0.127.in-addr.arpa",
        ));
        let mut answer = DnsAnswer::new();

        let result = dns_synthesize_answer(&mgr, &question, &mut answer).unwrap();
        assert!(result);

        let mut expected =
            DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_PTR, "54.0.0.127.in-addr.arpa");
        expected.ptr_name = Some("_localdnsproxy".to_string());
        assert!(answer.contains(&expected));
    }
}
