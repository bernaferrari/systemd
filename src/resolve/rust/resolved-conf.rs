// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-conf.c
//
// resolved configuration parsing: DNS servers, search domains,
// DNS stub listener configuration, credential reading, kernel
// command line parsing, and record type set management.

use std::collections::HashSet;
use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────

pub const DNS_SERVER_SYSTEM: i32 = 0;
pub const DNS_SERVER_FALLBACK: i32 = 1;

pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_TYPE_A: u16 = 1;

// ── Enums ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsStubListenerMode {
    No,
    UdpOnly,
    TcpOnly,
    Yes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOverTlsMode {
    No,
    Opportunistic,
    Yes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecMode {
    No,
    AllowDowngrade,
    Yes,
}

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    InvalidServer(String),
    InvalidDomain(String),
    InvalidAddress(String),
    InvalidStubListener(String),
    InvalidRecordType(String),
    CredentialReadFailed(String),
    CmdlineParseFailed(String),
    ConfigFileFailed(String),
    DnssecNotAvailable,
    DnsOverTlsNotAvailable,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidServer(s) => write!(f, "Invalid DNS server: {}", s),
            ConfigError::InvalidDomain(s) => write!(f, "Invalid search domain: {}", s),
            ConfigError::InvalidAddress(s) => write!(f, "Invalid address: {}", s),
            ConfigError::InvalidStubListener(s) => {
                write!(f, "Invalid stub listener: {}", s)
            }
            ConfigError::InvalidRecordType(s) => {
                write!(f, "Invalid DNS record type: {}", s)
            }
            ConfigError::CredentialReadFailed(s) => {
                write!(f, "Credential read failed: {}", s)
            }
            ConfigError::CmdlineParseFailed(s) => {
                write!(f, "Kernel cmdline parse failed: {}", s)
            }
            ConfigError::ConfigFileFailed(s) => {
                write!(f, "Config file parse failed: {}", s)
            }
            ConfigError::DnssecNotAvailable => {
                write!(f, "DNSSEC not available")
            }
            ConfigError::DnsOverTlsNotAvailable => {
                write!(f, "DNS-over-TLS not available")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

// ── Stub listener extra ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsStubListenerExtra {
    pub mode: DnsStubListenerMode,
    pub address: String,
    pub port: u16,
}

impl DnsStubListenerExtra {
    pub fn parse(rvalue: &str) -> Result<Self, ConfigError> {
        if rvalue.trim().is_empty() {
            return Err(ConfigError::InvalidStubListener("empty value".to_string()));
        }

        let (mode_str, addr_str) = if let Some(p) = rvalue.strip_prefix("udp:") {
            (DnsStubListenerMode::UdpOnly, p)
        } else if let Some(p) = rvalue.strip_prefix("tcp:") {
            (DnsStubListenerMode::TcpOnly, p)
        } else {
            (DnsStubListenerMode::Yes, rvalue)
        };

        let (address, port) = parse_addr_port(addr_str)?;

        Ok(DnsStubListenerExtra {
            mode: mode_str,
            address,
            port,
        })
    }
}

fn parse_addr_port(input: &str) -> Result<(String, u16), ConfigError> {
    if let Some(colon_pos) = input.rfind(':') {
        let addr = &input[..colon_pos];
        let port_str = &input[colon_pos + 1..];
        let port: u16 = port_str
            .parse()
            .map_err(|_| ConfigError::InvalidAddress(input.to_string()))?;
        Ok((addr.to_string(), port))
    } else {
        Ok((input.to_string(), 53))
    }
}

// ── Configuration state ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub dns_servers: Vec<String>,
    pub fallback_servers: Vec<String>,
    pub search_domains: Vec<String>,
    pub stub_listener_mode: DnsStubListenerMode,
    pub extra_stub_listeners: Vec<DnsStubListenerExtra>,
    pub dns_over_tls_mode: DnsOverTlsMode,
    pub dnssec_mode: DnssecMode,
    pub negative_trust_anchors: HashSet<String>,
    pub read_resolv_conf: bool,
    pub need_builtin_fallbacks: bool,
    pub record_types: HashSet<u16>,
}

impl Default for ResolvedConfig {
    fn default() -> Self {
        ResolvedConfig {
            dns_servers: Vec::new(),
            fallback_servers: Vec::new(),
            search_domains: Vec::new(),
            stub_listener_mode: DnsStubListenerMode::Yes,
            extra_stub_listeners: Vec::new(),
            dns_over_tls_mode: DnsOverTlsMode::No,
            dnssec_mode: DnssecMode::No,
            negative_trust_anchors: HashSet::new(),
            read_resolv_conf: true,
            need_builtin_fallbacks: true,
            record_types: HashSet::new(),
        }
    }
}

impl ResolvedConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse_dns_servers(&mut self, server_type: i32, value: &str) -> Result<(), ConfigError> {
        if value.trim().is_empty() {
            match server_type {
                DNS_SERVER_SYSTEM => self.dns_servers.clear(),
                DNS_SERVER_FALLBACK => self.fallback_servers.clear(),
                _ => {}
            }
            return Ok(());
        }

        let servers = parse_server_string(value);
        match server_type {
            DNS_SERVER_SYSTEM => {
                self.dns_servers.extend(servers);
                self.read_resolv_conf = false;
            }
            DNS_SERVER_FALLBACK => {
                self.fallback_servers.extend(servers);
                self.need_builtin_fallbacks = false;
            }
            _ => {}
        }

        Ok(())
    }

    pub fn parse_search_domains(&mut self, value: &str) -> Result<(), ConfigError> {
        if value.trim().is_empty() {
            self.search_domains.clear();
            return Ok(());
        }

        let domains = parse_domain_string(value);
        self.search_domains.extend(domains);
        self.read_resolv_conf = false;
        Ok(())
    }

    pub fn parse_stub_listener_extra(&mut self, value: &str) -> Result<(), ConfigError> {
        if value.trim().is_empty() {
            self.extra_stub_listeners.clear();
            return Ok(());
        }

        let stub = DnsStubListenerExtra::parse(value)?;
        self.extra_stub_listeners.push(stub);
        Ok(())
    }

    pub fn parse_record_types(&mut self, value: &str) -> Result<(), ConfigError> {
        if value.trim().is_empty() {
            self.record_types.clear();
            return Ok(());
        }

        for word in value.split_whitespace() {
            let rr_type = dns_type_from_string(word);
            if rr_type == 0 && word.to_uppercase() != "ANY" {
                return Err(ConfigError::InvalidRecordType(word.to_string()));
            }
            self.record_types.insert(rr_type);
        }
        Ok(())
    }

    pub fn read_credentials(&mut self, dns: Option<&str>, domains: Option<&str>) {
        if !self.read_resolv_conf {
            return;
        }

        if let Some(dns) = dns {
            let servers = parse_server_string(dns);
            self.dns_servers.extend(servers);
            self.read_resolv_conf = false;
        }

        if let Some(domains) = domains {
            let domain_list = parse_domain_string(domains);
            self.search_domains.extend(domain_list);
            self.read_resolv_conf = false;
        }
    }

    pub fn parse_proc_cmdline(
        &mut self,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), ConfigError> {
        let val = match value {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(()),
        };

        match key {
            "nameserver" => {
                let servers = parse_server_string(val);
                self.dns_servers.clear();
                self.dns_servers.extend(servers);
                self.read_resolv_conf = false;
            }
            "domain" => {
                let domains = parse_domain_string(val);
                self.search_domains.clear();
                self.search_domains.extend(domains);
                self.read_resolv_conf = false;
            }
            _ => {}
        }

        Ok(())
    }

    pub fn finalize(
        &mut self,
        have_openssl: bool,
        have_dns_over_tls: bool,
    ) -> Result<(), ConfigError> {
        if !have_openssl && self.dnssec_mode != DnssecMode::No {
            self.dnssec_mode = DnssecMode::No;
        }

        if !have_dns_over_tls && self.dns_over_tls_mode != DnsOverTlsMode::No {
            self.dns_over_tls_mode = DnsOverTlsMode::No;
        }

        if self.need_builtin_fallbacks {
            self.fallback_servers
                .extend(parse_server_string("91.239.100.100 2000::8"));
        }

        Ok(())
    }
}

// ── DNS type parsing ───────────────────────────────────────────────────────

pub fn dns_type_from_string(s: &str) -> u16 {
    match s.to_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "TLSA" => 52,
        "ANY" => 255,
        _ => 0,
    }
}

// ── String parsing helpers ─────────────────────────────────────────────────

fn parse_server_string(value: &str) -> Vec<String> {
    value.split_whitespace().map(|s| s.to_string()).collect()
}

fn parse_domain_string(value: &str) -> Vec<String> {
    value.split_whitespace().map(|s| s.to_string()).collect()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ResolvedConfig::new();
        assert!(config.dns_servers.is_empty());
        assert!(config.search_domains.is_empty());
        assert!(config.read_resolv_conf);
        assert!(config.need_builtin_fallbacks);
        assert_eq!(config.stub_listener_mode, DnsStubListenerMode::Yes);
    }

    #[test]
    fn test_parse_dns_servers_system() {
        let mut config = ResolvedConfig::new();
        config
            .parse_dns_servers(DNS_SERVER_SYSTEM, "8.8.8.8 8.8.4.4")
            .unwrap();
        assert_eq!(config.dns_servers, vec!["8.8.8.8", "8.8.4.4"]);
        assert!(!config.read_resolv_conf);
    }

    #[test]
    fn test_parse_dns_servers_fallback() {
        let mut config = ResolvedConfig::new();
        config
            .parse_dns_servers(DNS_SERVER_FALLBACK, "1.1.1.1")
            .unwrap();
        assert_eq!(config.fallback_servers, vec!["1.1.1.1"]);
        assert!(!config.need_builtin_fallbacks);
    }

    #[test]
    fn test_parse_dns_servers_empty_clears() {
        let mut config = ResolvedConfig::new();
        config.dns_servers.push("8.8.8.8".to_string());
        config.parse_dns_servers(DNS_SERVER_SYSTEM, "").unwrap();
        assert!(config.dns_servers.is_empty());
    }

    #[test]
    fn test_parse_search_domains() {
        let mut config = ResolvedConfig::new();
        config.parse_search_domains("example.com test.com").unwrap();
        assert_eq!(config.search_domains, vec!["example.com", "test.com"]);
        assert!(!config.read_resolv_conf);
    }

    #[test]
    fn test_parse_search_domains_empty_clears() {
        let mut config = ResolvedConfig::new();
        config.search_domains.push("x.com".to_string());
        config.parse_search_domains("").unwrap();
        assert!(config.search_domains.is_empty());
    }

    #[test]
    fn test_stub_listener_extra_parse_udp() {
        let stub = DnsStubListenerExtra::parse("udp:127.0.0.1:5353").unwrap();
        assert_eq!(stub.mode, DnsStubListenerMode::UdpOnly);
        assert_eq!(stub.address, "127.0.0.1");
        assert_eq!(stub.port, 5353);
    }

    #[test]
    fn test_stub_listener_extra_parse_tcp() {
        let stub = DnsStubListenerExtra::parse("tcp:127.0.0.1:5353").unwrap();
        assert_eq!(stub.mode, DnsStubListenerMode::TcpOnly);
    }

    #[test]
    fn test_stub_listener_extra_parse_default() {
        let stub = DnsStubListenerExtra::parse("127.0.0.1:5353").unwrap();
        assert_eq!(stub.mode, DnsStubListenerMode::Yes);
    }

    #[test]
    fn test_stub_listener_extra_parse_default_port() {
        let stub = DnsStubListenerExtra::parse("127.0.0.1").unwrap();
        assert_eq!(stub.port, 53);
    }

    #[test]
    fn test_stub_listener_extra_empty_clears() {
        let mut config = ResolvedConfig::new();
        config
            .extra_stub_listeners
            .push(DnsStubListenerExtra::parse("127.0.0.1").unwrap());
        config.parse_stub_listener_extra("").unwrap();
        assert!(config.extra_stub_listeners.is_empty());
    }

    #[test]
    fn test_parse_record_types() {
        let mut config = ResolvedConfig::new();
        config.parse_record_types("A AAAA MX").unwrap();
        assert!(config.record_types.contains(&1));
        assert!(config.record_types.contains(&28));
        assert!(config.record_types.contains(&15));
    }

    #[test]
    fn test_parse_record_types_empty_clears() {
        let mut config = ResolvedConfig::new();
        config.record_types.insert(1);
        config.parse_record_types("").unwrap();
        assert!(config.record_types.is_empty());
    }

    #[test]
    fn test_read_credentials_dns() {
        let mut config = ResolvedConfig::new();
        config.read_credentials(Some("8.8.8.8"), None);
        assert_eq!(config.dns_servers, vec!["8.8.8.8"]);
        assert!(!config.read_resolv_conf);
    }

    #[test]
    fn test_read_credentials_skipped_when_disabled() {
        let mut config = ResolvedConfig::new();
        config.read_resolv_conf = false;
        config.read_credentials(Some("8.8.8.8"), None);
        assert!(config.dns_servers.is_empty());
    }

    #[test]
    fn test_parse_proc_cmdline_nameserver() {
        let mut config = ResolvedConfig::new();
        config
            .parse_proc_cmdline("nameserver", Some("1.1.1.1"))
            .unwrap();
        assert_eq!(config.dns_servers, vec!["1.1.1.1"]);
        assert!(!config.read_resolv_conf);
    }

    #[test]
    fn test_parse_proc_cmdline_domain() {
        let mut config = ResolvedConfig::new();
        config
            .parse_proc_cmdline("domain", Some("example.com"))
            .unwrap();
        assert_eq!(config.search_domains, vec!["example.com"]);
    }

    #[test]
    fn test_parse_proc_cmdline_empty_value() {
        let mut config = ResolvedConfig::new();
        config.parse_proc_cmdline("nameserver", None).unwrap();
        assert!(config.dns_servers.is_empty());
    }

    #[test]
    fn test_finalize_no_openssl() {
        let mut config = ResolvedConfig::new();
        config.dnssec_mode = DnssecMode::Yes;
        config.finalize(false, true).unwrap();
        assert_eq!(config.dnssec_mode, DnssecMode::No);
    }

    #[test]
    fn test_finalize_no_dotls() {
        let mut config = ResolvedConfig::new();
        config.dns_over_tls_mode = DnsOverTlsMode::Yes;
        config.finalize(true, false).unwrap();
        assert_eq!(config.dns_over_tls_mode, DnsOverTlsMode::No);
    }

    #[test]
    fn test_dns_type_from_string() {
        assert_eq!(dns_type_from_string("A"), 1);
        assert_eq!(dns_type_from_string("AAAA"), 28);
        assert_eq!(dns_type_from_string("SRV"), 33);
        assert_eq!(dns_type_from_string("unknown"), 0);
    }
}
