// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/libsystemd-network/dhcp-message.c, src/libsystemd-network/dhcp-protocol.c

use crate::{EINVAL, Errno};
use std::fmt;
use std::sync::Arc;

const ENOBUFS: Errno = errno(105);
const ENOENT: Errno = errno(2);
const ENOMSG: Errno = errno(42);
const ENOMEM: Errno = errno(12);

pub const DHCP_MESSAGE_SIZE: usize = 240;
pub const DHCP_FILE_LEN: usize = 128;
pub const DHCP_SNAME_LEN: usize = 64;

pub const DHCP_OVERLOAD_FILE: u8 = 1;
pub const DHCP_OVERLOAD_SNAME: u8 = 2;

pub const SD_DHCP_RELAY_AGENT_CIRCUIT_ID: u8 = 1;
pub const SD_DHCP_RELAY_AGENT_REMOTE_ID: u8 = 2;

const fn errno(code: i32) -> Errno {
    match Errno::new(code) {
        Some(errno) => errno,
        None => panic!("errno must be non-zero"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DhcpOptionCode(pub u8);

impl DhcpOptionCode {
    pub const PAD: Self = Self(0);
    pub const SUBNET_MASK: Self = Self(1);
    pub const TIME_OFFSET: Self = Self(2);
    pub const ROUTER: Self = Self(3);
    pub const TIME_SERVER: Self = Self(4);
    pub const NAME_SERVER: Self = Self(5);
    pub const DOMAIN_NAME_SERVER: Self = Self(6);
    pub const LOG_SERVER: Self = Self(7);
    pub const QUOTES_SERVER: Self = Self(8);
    pub const LPR_SERVER: Self = Self(9);
    pub const IMPRESS_SERVER: Self = Self(10);
    pub const RLP_SERVER: Self = Self(11);
    pub const HOST_NAME: Self = Self(12);
    pub const BOOT_FILE_SIZE: Self = Self(13);
    pub const MERIT_DUMP_FILE: Self = Self(14);
    pub const DOMAIN_NAME: Self = Self(15);
    pub const SWAP_SERVER: Self = Self(16);
    pub const ROOT_PATH: Self = Self(17);
    pub const EXTENSION_FILE: Self = Self(18);
    pub const FORWARD: Self = Self(19);
    pub const SOURCE_ROUTE: Self = Self(20);
    pub const POLICY_FILTER: Self = Self(21);
    pub const MAX_DATAGRAM_ASSEMBLY: Self = Self(22);
    pub const DEFAULT_IP_TTL: Self = Self(23);
    pub const MTU_TIMEOUT: Self = Self(24);
    pub const MTU_PLATEAU: Self = Self(25);
    pub const MTU_INTERFACE: Self = Self(26);
    pub const MTU_SUBNET: Self = Self(27);
    pub const BROADCAST: Self = Self(28);
    pub const MASK_DISCOVERY: Self = Self(29);
    pub const MASK_SUPPLIER: Self = Self(30);
    pub const ROUTER_DISCOVERY: Self = Self(31);
    pub const ROUTER_REQUEST: Self = Self(32);
    pub const STATIC_ROUTE: Self = Self(33);
    pub const TRAILERS: Self = Self(34);
    pub const ARP_TIMEOUT: Self = Self(35);
    pub const ETHERNET: Self = Self(36);
    pub const DEFAULT_TCP_TTL: Self = Self(37);
    pub const KEEPALIVE_TIME: Self = Self(38);
    pub const KEEPALIVE_DATA: Self = Self(39);
    pub const NIS_DOMAIN: Self = Self(40);
    pub const NIS_SERVER: Self = Self(41);
    pub const NTP_SERVER: Self = Self(42);
    pub const VENDOR_SPECIFIC: Self = Self(43);
    pub const NETBIOS_NAME_SERVER: Self = Self(44);
    pub const NETBIOS_DIST_SERVER: Self = Self(45);
    pub const NETBIOS_NODE_TYPE: Self = Self(46);
    pub const NETBIOS_SCOPE: Self = Self(47);
    pub const X_WINDOW_FONT: Self = Self(48);
    pub const X_WINDOW_MANAGER: Self = Self(49);
    pub const REQUESTED_IP_ADDRESS: Self = Self(50);
    pub const IP_ADDRESS_LEASE_TIME: Self = Self(51);
    pub const OVERLOAD: Self = Self(52);
    pub const MESSAGE_TYPE: Self = Self(53);
    pub const SERVER_IDENTIFIER: Self = Self(54);
    pub const PARAMETER_REQUEST_LIST: Self = Self(55);
    pub const ERROR_MESSAGE: Self = Self(56);
    pub const MAXIMUM_MESSAGE_SIZE: Self = Self(57);
    pub const RENEWAL_TIME: Self = Self(58);
    pub const REBINDING_TIME: Self = Self(59);
    pub const VENDOR_CLASS_IDENTIFIER: Self = Self(60);
    pub const CLIENT_IDENTIFIER: Self = Self(61);
    pub const NETWARE_IP_DOMAIN: Self = Self(62);
    pub const NETWARE_IP_OPTION: Self = Self(63);
    pub const NIS_DOMAIN_NAME: Self = Self(64);
    pub const NIS_SERVER_ADDR: Self = Self(65);
    pub const BOOT_SERVER_NAME: Self = Self(66);
    pub const BOOT_FILENAME: Self = Self(67);
    pub const HOME_AGENT_ADDRESSES: Self = Self(68);
    pub const SMTP_SERVER: Self = Self(69);
    pub const POP3_SERVER: Self = Self(70);
    pub const NNTP_SERVER: Self = Self(71);
    pub const WWW_SERVER: Self = Self(72);
    pub const FINGER_SERVER: Self = Self(73);
    pub const IRC_SERVER: Self = Self(74);
    pub const STREETTALK_SERVER: Self = Self(75);
    pub const STDA_SERVER: Self = Self(76);
    pub const USER_CLASS: Self = Self(77);
    pub const DIRECTORY_AGENT: Self = Self(78);
    pub const SERVICE_SCOPE: Self = Self(79);
    pub const RAPID_COMMIT: Self = Self(80);
    pub const FQDN: Self = Self(81);
    pub const RELAY_AGENT_INFORMATION: Self = Self(82);
    pub const ISNS: Self = Self(83);
    pub const NDS_SERVER: Self = Self(85);
    pub const NDS_TREE_NAME: Self = Self(86);
    pub const NDS_CONTEXT: Self = Self(87);
    pub const BCMCS_CONTROLLER_DOMAIN_NAME: Self = Self(88);
    pub const BCMCS_CONTROLLER_ADDRESS: Self = Self(89);
    pub const AUTHENTICATION: Self = Self(90);
    pub const CLIENT_LAST_TRANSACTION_TIME: Self = Self(91);
    pub const ASSOCIATED_IP: Self = Self(92);
    pub const CLIENT_SYSTEM: Self = Self(93);
    pub const CLIENT_NDI: Self = Self(94);
    pub const LDAP: Self = Self(95);
    pub const UUID: Self = Self(97);
    pub const USER_AUTHENTICATION: Self = Self(98);
    pub const GEOCONF_CIVIC: Self = Self(99);
    pub const POSIX_TIMEZONE: Self = Self(100);
    pub const TZDB_TIMEZONE: Self = Self(101);
    pub const IPV6_ONLY_PREFERRED: Self = Self(108);
    pub const DHCP4O6_SOURCE_ADDRESS: Self = Self(109);
    pub const NETINFO_ADDRESS: Self = Self(112);
    pub const NETINFO_TAG: Self = Self(113);
    pub const DHCP_CAPTIVE_PORTAL: Self = Self(114);
    pub const AUTO_CONFIG: Self = Self(116);
    pub const NAME_SERVICE_SEARCH: Self = Self(117);
    pub const SUBNET_SELECTION: Self = Self(118);
    pub const DOMAIN_SEARCH: Self = Self(119);
    pub const SIP_SERVER: Self = Self(120);
    pub const CLASSLESS_STATIC_ROUTE: Self = Self(121);
    pub const CABLELABS_CLIENT_CONFIGURATION: Self = Self(122);
    pub const GEOCONF: Self = Self(123);
    pub const VENDOR_CLASS: Self = Self(124);
    pub const VENDOR_SPECIFIC_INFORMATION: Self = Self(125);
    pub const PANA_AGENT: Self = Self(136);
    pub const LOST_SERVER_FQDN: Self = Self(137);
    pub const CAPWAP_AC_ADDRESS: Self = Self(138);
    pub const MOS_ADDRESS: Self = Self(139);
    pub const MOS_FQDN: Self = Self(140);
    pub const SIP_SERVICE_DOMAIN: Self = Self(141);
    pub const ANDSF_ADDRESS: Self = Self(142);
    pub const SZTP_REDIRECT: Self = Self(143);
    pub const GEOLOC: Self = Self(144);
    pub const FORCERENEW_NONCE_CAPABLE: Self = Self(145);
    pub const RDNSS_SELECTION: Self = Self(146);
    pub const DOTS_RI: Self = Self(147);
    pub const DOTS_ADDRESS: Self = Self(148);
    pub const TFTP_SERVER_ADDRESS: Self = Self(150);
    pub const STATUS_CODE: Self = Self(151);
    pub const BASE_TIME: Self = Self(152);
    pub const START_TIME_OF_STATE: Self = Self(153);
    pub const QUERY_START_TIME: Self = Self(154);
    pub const QUERY_END_TIME: Self = Self(155);
    pub const DHCP_STATE: Self = Self(156);
    pub const DATA_SOURCE: Self = Self(157);
    pub const PCP_SERVER: Self = Self(158);
    pub const PORT_PARAMS: Self = Self(159);
    pub const MUD_URL: Self = Self(161);
    pub const V4_DNR: Self = Self(162);
    pub const PXELINUX_MAGIC: Self = Self(208);
    pub const CONFIGURATION_FILE: Self = Self(209);
    pub const PATH_PREFIX: Self = Self(210);
    pub const REBOOT_TIME: Self = Self(211);
    pub const SIX_RD: Self = Self(212);
    pub const ACCESS_DOMAIN: Self = Self(213);
    pub const SUBNET_ALLOCATION: Self = Self(220);
    pub const VIRTUAL_SUBNET_SELECTION: Self = Self(221);
    pub const PRIVATE_BASE: Self = Self(224);
    pub const PRIVATE_CLASSLESS_STATIC_ROUTE: Self = Self(249);
    pub const PRIVATE_PROXY_AUTODISCOVERY: Self = Self(252);
    pub const PRIVATE_LAST: Self = Self(254);
    pub const END: Self = Self(255);

    pub const fn name(self) -> &'static str {
        match self.0 {
            0 => "pad",
            1 => "subnet-mask",
            3 => "router",
            6 => "domain-name-server",
            12 => "host-name",
            15 => "domain-name",
            43 => "vendor-specific",
            52 => "overload",
            53 => "message-type",
            56 => "error-message",
            77 => "user-class",
            82 => "relay-agent-information",
            120 => "sip-server",
            255 => "end",
            _ => "option",
        }
    }
}

impl fmt::Display for DhcpOptionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.name() == "option" {
            write!(f, "option-{}", self.0)
        } else {
            write!(f, "{}", self.name())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
    ForceRenew = 9,
    LeaseQuery = 10,
    LeaseUnassigned = 11,
    LeaseUnknown = 12,
    LeaseActive = 13,
    BulkLeaseQuery = 14,
    LeaseQueryDone = 15,
    ActiveLeaseQuery = 16,
    LeaseQueryStatus = 17,
    Tls = 18,
}

impl DhcpMessageType {
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            9 => Some(Self::ForceRenew),
            10 => Some(Self::LeaseQuery),
            11 => Some(Self::LeaseUnassigned),
            12 => Some(Self::LeaseUnknown),
            13 => Some(Self::LeaseActive),
            14 => Some(Self::BulkLeaseQuery),
            15 => Some(Self::LeaseQueryDone),
            16 => Some(Self::ActiveLeaseQuery),
            17 => Some(Self::LeaseQueryStatus),
            18 => Some(Self::Tls),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "DHCPDISCOVER",
            Self::Offer => "DHCPOFFER",
            Self::Request => "DHCPREQUEST",
            Self::Decline => "DHCPDECLINE",
            Self::Ack => "DHCPACK",
            Self::Nak => "DHCPNAK",
            Self::Release => "DHCPRELEASE",
            Self::Inform => "DHCPINFORM",
            Self::ForceRenew => "DHCPFORCERENEW",
            Self::LeaseQuery => "DHCPLEASEQUERY",
            Self::LeaseUnassigned => "DHCPLEASEUNASSIGNED",
            Self::LeaseUnknown => "DHCPLEASEUNKNOWN",
            Self::LeaseActive => "DHCPLEASEACTIVE",
            Self::BulkLeaseQuery => "DHCPBULKLEASEQUERY",
            Self::LeaseQueryDone => "DHCPLEASEQUERYDONE",
            Self::ActiveLeaseQuery => "DHCPACTIVELEASEQUERY",
            Self::LeaseQueryStatus => "DHCPLEASEQUERYSTATUS",
            Self::Tls => "DHCPTLS",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdDhcpOption {
    pub option: DhcpOptionCode,
    pub data: Arc<[u8]>,
}

impl SdDhcpOption {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpRelayAgentInfo {
    pub circuit_id: Option<String>,
    pub remote_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    pub sname: [u8; DHCP_SNAME_LEN],
    pub file: [u8; DHCP_FILE_LEN],
    pub options: Vec<u8>,
}

impl DhcpMessage {
    pub fn new(options_len: usize) -> Self {
        Self {
            sname: [0; DHCP_SNAME_LEN],
            file: [0; DHCP_FILE_LEN],
            options: vec![0; options_len],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpParseResult {
    pub message_type: u8,
    pub error_message: Option<String>,
}

impl DhcpParseResult {
    pub fn message_type_enum(&self) -> Option<DhcpMessageType> {
        DhcpMessageType::from_u8(self.message_type)
    }
}

pub enum DhcpOptionValue<'a> {
    None,
    Raw(&'a [u8]),
    UserClass(&'a [&'a str]),
    VendorSpecific(&'a [SdDhcpOption]),
    RelayAgentInformation(&'a DhcpRelayAgentInfo),
}

pub type DhcpOptionCallback<'a> = dyn FnMut(DhcpOptionCode, &[u8]) -> Result<(), Errno> + 'a;

pub fn sd_dhcp_option_new(option: u8, data: &[u8]) -> Result<SdDhcpOption, Errno> {
    let owned = data.to_vec();
    if owned.len() != data.len() {
        return Err(ENOMEM);
    }

    Ok(SdDhcpOption {
        option: DhcpOptionCode(option),
        data: Arc::from(owned),
    })
}

pub fn dhcp_option_find_option(
    options: &[u8],
    length: usize,
    code: u8,
) -> Result<(usize, usize), Errno> {
    if length > options.len() {
        return Err(ENOBUFS);
    }

    let mut offset = 0;
    while offset < length {
        let r = option_length(options, length, offset)?;
        if options[offset] == code {
            return Ok((offset, r));
        }
        offset += r;
    }

    Err(ENOENT)
}

pub fn dhcp_option_remove_option(
    options: &mut [u8],
    length: usize,
    option_code: u8,
) -> Result<usize, Errno> {
    let (offset, consumed) = dhcp_option_find_option(options, length, option_code)?;
    options.copy_within(offset + consumed..length, offset);
    Ok(length - consumed)
}

pub fn dhcp_option_append(
    message: &mut DhcpMessage,
    size: usize,
    offset: &mut usize,
    overload: u8,
    code: DhcpOptionCode,
    value: DhcpOptionValue<'_>,
) -> Result<(), Errno> {
    let use_file = overload & DHCP_OVERLOAD_FILE != 0;
    let use_sname = overload & DHCP_OVERLOAD_SNAME != 0;

    if *offset < size {
        match option_append(&mut message.options, size, offset, code, &value) {
            Ok(()) => return Ok(()),
            Err(err) if err == ENOBUFS && (use_file || use_sname) => {
                option_append(
                    &mut message.options,
                    size,
                    offset,
                    DhcpOptionCode::END,
                    &DhcpOptionValue::None,
                )?;
                *offset = size;
            }
            Err(err) => return Err(err),
        }
    }

    if use_file {
        let mut file_offset = offset.saturating_sub(size);
        if file_offset < DHCP_FILE_LEN {
            match option_append_array(&mut message.file, &mut file_offset, code, &value) {
                Ok(()) => {
                    *offset = size + file_offset;
                    return Ok(());
                }
                Err(err) if err == ENOBUFS && use_sname => {
                    option_append_array(
                        &mut message.file,
                        &mut file_offset,
                        DhcpOptionCode::END,
                        &DhcpOptionValue::None,
                    )?;
                    *offset = size + DHCP_FILE_LEN;
                }
                Err(err) => return Err(err),
            }
        }
    }

    if use_sname {
        let mut sname_offset =
            offset.saturating_sub(size + if use_file { DHCP_FILE_LEN } else { 0 });
        if sname_offset < DHCP_SNAME_LEN {
            option_append_array(&mut message.sname, &mut sname_offset, code, &value)?;
            *offset = size + if use_file { DHCP_FILE_LEN } else { 0 } + sname_offset;
            return Ok(());
        }
    }

    Err(ENOBUFS)
}

pub fn dhcp_option_parse(
    message: &DhcpMessage,
    len: usize,
    mut cb: Option<&mut DhcpOptionCallback<'_>>,
) -> Result<DhcpParseResult, Errno> {
    if len < DHCP_MESSAGE_SIZE {
        return Err(EINVAL);
    }

    let options_len = len - DHCP_MESSAGE_SIZE;
    if options_len > message.options.len() {
        return Err(EINVAL);
    }

    let mut overload = 0u8;
    let mut message_type = 0u8;
    let mut error_message = None;

    parse_options(
        &message.options[..options_len],
        Some(&mut overload),
        Some(&mut message_type),
        Some(&mut error_message),
        cb.as_deref_mut(),
    )?;

    if overload & DHCP_OVERLOAD_FILE != 0 {
        parse_options(
            &message.file,
            None,
            Some(&mut message_type),
            Some(&mut error_message),
            cb.as_deref_mut(),
        )?;
    }

    if overload & DHCP_OVERLOAD_SNAME != 0 {
        parse_options(
            &message.sname,
            None,
            Some(&mut message_type),
            Some(&mut error_message),
            cb,
        )?;
    }

    if message_type == 0 {
        return Err(ENOMSG);
    }

    let error_message = match DhcpMessageType::from_u8(message_type) {
        Some(DhcpMessageType::Nak | DhcpMessageType::Decline) => error_message,
        _ => None,
    };

    Ok(DhcpParseResult {
        message_type,
        error_message,
    })
}

pub fn dhcp_option_parse_string(option: &[u8]) -> Result<Option<String>, Errno> {
    if option.is_empty() {
        return Ok(None);
    }

    let bytes = match option.strip_suffix(&[0]) {
        Some(stripped) => stripped,
        None => option,
    };

    if bytes.contains(&0) {
        return Err(EINVAL);
    }

    let string = std::str::from_utf8(bytes).map_err(|_| EINVAL)?;
    if !string.chars().all(|ch| !ch.is_control()) {
        return Err(EINVAL);
    }

    Ok(Some(string.to_owned()))
}

pub fn dhcp_option_parse_hostname(option: &[u8]) -> Result<Option<String>, Errno> {
    let hostname = match dhcp_option_parse_string(option)? {
        Some(hostname) => hostname,
        None => return Ok(None),
    };

    if !is_valid_hostname(&hostname) {
        return Err(EINVAL);
    }

    Ok(Some(hostname))
}

pub fn dhcp_option_to_string(code: DhcpOptionCode, data: &[u8]) -> Result<String, Errno> {
    match code {
        DhcpOptionCode::HOST_NAME | DhcpOptionCode::DOMAIN_NAME | DhcpOptionCode::ERROR_MESSAGE => {
            dhcp_option_parse_string(data)?.ok_or(EINVAL)
        }
        DhcpOptionCode::MESSAGE_TYPE => {
            let value = *data.first().ok_or(EINVAL)?;
            let ty = DhcpMessageType::from_u8(value).ok_or(EINVAL)?;
            Ok(ty.as_str().to_owned())
        }
        _ => Ok(data
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("")),
    }
}

fn parse_options(
    options: &[u8],
    mut overload: Option<&mut u8>,
    mut message_type: Option<&mut u8>,
    mut error_message: Option<&mut Option<String>>,
    mut cb: Option<&mut DhcpOptionCallback<'_>>,
) -> Result<(), Errno> {
    let mut offset = 0;

    while offset < options.len() {
        let code = options[offset];
        offset += 1;

        match code {
            0 => continue,
            255 => return Ok(()),
            _ => {}
        }

        if options.len() < offset + 1 {
            return Err(ENOBUFS);
        }

        let len = options[offset] as usize;
        offset += 1;

        if options.len() < offset + len {
            return Err(EINVAL);
        }

        let option = &options[offset..offset + len];
        match code {
            53 => {
                if len != 1 {
                    return Err(EINVAL);
                }
                if let Some(slot) = message_type.as_deref_mut() {
                    *slot = option[0];
                }
            }
            56 => {
                if len == 0 {
                    return Err(EINVAL);
                }
                if let Some(slot) = error_message.as_deref_mut() {
                    let string = option_string_ascii(option)?;
                    *slot = Some(string);
                }
            }
            52 => {
                if len != 1 {
                    return Err(EINVAL);
                }
                if let Some(slot) = overload.as_deref_mut() {
                    *slot = option[0];
                }
            }
            _ => {
                if let Some(callback) = cb.as_deref_mut() {
                    callback(DhcpOptionCode(code), option)?;
                }
            }
        }

        offset += len;
    }

    Ok(())
}

fn option_append(
    options: &mut [u8],
    size: usize,
    offset: &mut usize,
    code: DhcpOptionCode,
    value: &DhcpOptionValue<'_>,
) -> Result<(), Errno> {
    let len = options.len();
    let Some(slice) = options.get_mut(..size.min(len)) else {
        return Err(ENOBUFS);
    };
    option_append_slice(slice, offset, code, value)
}

fn option_append_array<const N: usize>(
    options: &mut [u8; N],
    offset: &mut usize,
    code: DhcpOptionCode,
    value: &DhcpOptionValue<'_>,
) -> Result<(), Errno> {
    option_append_slice(options, offset, code, value)
}

fn option_append_slice(
    options: &mut [u8],
    offset: &mut usize,
    code: DhcpOptionCode,
    value: &DhcpOptionValue<'_>,
) -> Result<(), Errno> {
    if options.is_empty() || *offset > options.len() {
        return Err(ENOBUFS);
    }

    let limit = if code != DhcpOptionCode::END {
        options.len().saturating_sub(1)
    } else {
        options.len()
    };

    match code {
        DhcpOptionCode::PAD | DhcpOptionCode::END => {
            if *offset + 1 > limit {
                return Err(ENOBUFS);
            }
            options[*offset] = code.0;
            *offset += 1;
            Ok(())
        }
        DhcpOptionCode::USER_CLASS => match value {
            DhcpOptionValue::Raw(data) if !data.is_empty() => {
                dhcp_option_append_tlv(options, limit, offset, code, data)
            }
            DhcpOptionValue::UserClass(strings) => {
                if strings.is_empty() {
                    return Err(EINVAL);
                }

                let mut total = 0usize;
                for s in *strings {
                    let len = s.len();
                    if len == 0 || len > u8::MAX as usize {
                        return Err(EINVAL);
                    }
                    total += len + 1;
                }

                if total > u8::MAX as usize || *offset + 2 + total > limit {
                    return Err(ENOBUFS);
                }

                options[*offset] = code.0;
                options[*offset + 1] = total as u8;
                *offset += 2;

                for s in *strings {
                    let len = s.len();
                    options[*offset] = len as u8;
                    options[*offset + 1..*offset + 1 + len].copy_from_slice(s.as_bytes());
                    *offset += 1 + len;
                }
                Ok(())
            }
            DhcpOptionValue::Raw(_) => Err(EINVAL),
            _ => Err(EINVAL),
        },
        DhcpOptionCode::SIP_SERVER => {
            let data = match value {
                DhcpOptionValue::Raw(data) => *data,
                _ => return Err(EINVAL),
            };

            if data.len() > u8::MAX as usize - 1 || *offset + 3 + data.len() > limit {
                return Err(ENOBUFS);
            }

            options[*offset] = code.0;
            options[*offset + 1] = (data.len() + 1) as u8;
            options[*offset + 2] = 1;
            options[*offset + 3..*offset + 3 + data.len()].copy_from_slice(data);
            *offset += 3 + data.len();
            Ok(())
        }
        DhcpOptionCode::VENDOR_SPECIFIC => match value {
            DhcpOptionValue::Raw(data) if !data.is_empty() => {
                dhcp_option_append_tlv(options, limit, offset, code, data)
            }
            DhcpOptionValue::VendorSpecific(entries) => {
                let total = entries.iter().try_fold(0usize, |acc, entry| {
                    let len = entry.len();
                    if len > u8::MAX as usize {
                        return Err(EINVAL);
                    }
                    acc.checked_add(len + 2).ok_or(EINVAL)
                })?;

                if total > u8::MAX as usize || *offset + 2 + total > limit {
                    return Err(ENOBUFS);
                }

                options[*offset] = code.0;
                options[*offset + 1] = total as u8;
                *offset += 2;

                for entry in *entries {
                    dhcp_option_append_tlv(
                        options,
                        options.len(),
                        offset,
                        entry.option,
                        &entry.data,
                    )?;
                }
                Ok(())
            }
            DhcpOptionValue::Raw(_) => Err(EINVAL),
            _ => Err(EINVAL),
        },
        DhcpOptionCode::RELAY_AGENT_INFORMATION => match value {
            DhcpOptionValue::Raw(data) if !data.is_empty() => {
                dhcp_option_append_tlv(options, limit, offset, code, data)
            }
            DhcpOptionValue::RelayAgentInformation(info) => {
                if *offset + 2 > limit {
                    return Err(ENOBUFS);
                }

                let start = *offset;
                let mut current = start + 2;
                if let Some(circuit_id) = info.circuit_id.as_deref() {
                    dhcp_option_append_tlv(
                        options,
                        options.len(),
                        &mut current,
                        DhcpOptionCode(SD_DHCP_RELAY_AGENT_CIRCUIT_ID),
                        circuit_id.as_bytes(),
                    )?;
                }
                if let Some(remote_id) = info.remote_id.as_deref() {
                    dhcp_option_append_tlv(
                        options,
                        options.len(),
                        &mut current,
                        DhcpOptionCode(SD_DHCP_RELAY_AGENT_REMOTE_ID),
                        remote_id.as_bytes(),
                    )?;
                }

                let payload_len = current - start - 2;
                if payload_len > u8::MAX as usize {
                    return Err(EINVAL);
                }

                options[start] = code.0;
                options[start + 1] = payload_len as u8;
                *offset = current;
                Ok(())
            }
            DhcpOptionValue::Raw(_) => Err(EINVAL),
            _ => Err(EINVAL),
        },
        _ => {
            let data = match value {
                DhcpOptionValue::None => &[][..],
                DhcpOptionValue::Raw(data) => *data,
                _ => return Err(EINVAL),
            };
            dhcp_option_append_tlv(options, limit, offset, code, data)
        }
    }
}

fn dhcp_option_append_tlv(
    options: &mut [u8],
    size: usize,
    offset: &mut usize,
    code: DhcpOptionCode,
    optval: &[u8],
) -> Result<(), Errno> {
    if optval.len() > u8::MAX as usize || *offset >= size || *offset + 2 + optval.len() > size {
        return Err(ENOBUFS);
    }

    options[*offset] = code.0;
    options[*offset + 1] = optval.len() as u8;
    options[*offset + 2..*offset + 2 + optval.len()].copy_from_slice(optval);
    *offset += 2 + optval.len();
    Ok(())
}

fn option_length(options: &[u8], length: usize, offset: usize) -> Result<usize, Errno> {
    if offset >= length || length > options.len() {
        return Err(ENOBUFS);
    }

    if matches!(options[offset], 0 | 255) {
        return Ok(1);
    }
    if length < offset + 2 {
        return Err(ENOBUFS);
    }

    let total = 2 + options[offset + 1] as usize;
    if length < offset + total {
        return Err(ENOBUFS);
    }

    Ok(total)
}

fn option_string_ascii(option: &[u8]) -> Result<String, Errno> {
    let text = dhcp_option_parse_string(option)?.ok_or(EINVAL)?;
    if !text.is_ascii() {
        return Err(EINVAL);
    }
    Ok(text)
}

fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 255 {
        return false;
    }

    hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(options: &[u8], file: &[u8], sname: &[u8]) -> DhcpMessage {
        let mut msg = DhcpMessage::new(options.len());
        msg.options.copy_from_slice(options);
        msg.file[..file.len()].copy_from_slice(file);
        msg.sname[..sname.len()].copy_from_slice(sname);
        msg
    }

    #[test]
    fn parse_requires_full_message_header() {
        let msg = DhcpMessage::new(0);
        assert_eq!(dhcp_option_parse(&msg, 0, None).unwrap_err(), EINVAL);
        assert_eq!(
            dhcp_option_parse(&msg, DHCP_MESSAGE_SIZE - 1, None).unwrap_err(),
            EINVAL
        );
    }

    #[test]
    fn parse_returns_enomsg_without_message_type() {
        let msg = message(&[], &[], &[]);
        assert_eq!(
            dhcp_option_parse(&msg, DHCP_MESSAGE_SIZE, None).unwrap_err(),
            ENOMSG
        );
    }

    #[test]
    fn parse_accepts_padding_and_extracts_message_type() {
        let opts = [42, 5, 65, 66, 67, 68, 69, 0, 0, 53, 1, 5];
        let mut seen = Vec::new();
        let mut cb = |code: DhcpOptionCode, data: &[u8]| {
            seen.push((code.0, data.to_vec()));
            Ok(())
        };

        let result = dhcp_option_parse(
            &message(&opts, &[], &[]),
            DHCP_MESSAGE_SIZE + opts.len(),
            Some(&mut cb),
        )
        .unwrap();
        assert_eq!(result.message_type_enum(), Some(DhcpMessageType::Ack));
        assert_eq!(seen, vec![(42, b"ABCDE".to_vec())]);
    }

    #[test]
    fn parse_rejects_truncated_option_length() {
        let opts = [42, 2, 1, 2, 44];
        assert_eq!(
            dhcp_option_parse(
                &message(&opts, &[], &[]),
                DHCP_MESSAGE_SIZE + opts.len(),
                None
            )
            .unwrap_err(),
            ENOBUFS
        );
    }

    #[test]
    fn parse_rejects_invalid_payload_length() {
        let opts = [8, 255, 70, 71, 72];
        assert_eq!(
            dhcp_option_parse(
                &message(&opts, &[], &[]),
                DHCP_MESSAGE_SIZE + opts.len(),
                None
            )
            .unwrap_err(),
            EINVAL
        );
    }

    #[test]
    fn parse_honors_overload_file_and_sname() {
        let opts = [52, 1, DHCP_OVERLOAD_FILE | DHCP_OVERLOAD_SNAME];
        let file = [222, 3, 1, 2, 3];
        let sname = [1, 4, 1, 2, 3, 4, 53, 1, 5];
        let mut seen = Vec::new();
        let mut cb = |code: DhcpOptionCode, data: &[u8]| {
            seen.push((code.0, data.to_vec()));
            Ok(())
        };

        let result = dhcp_option_parse(
            &message(&opts, &file, &sname),
            DHCP_MESSAGE_SIZE + opts.len(),
            Some(&mut cb),
        )
        .unwrap();
        assert_eq!(result.message_type_enum(), Some(DhcpMessageType::Ack));
        assert_eq!(seen, vec![(222, vec![1, 2, 3]), (1, vec![1, 2, 3, 4])]);
    }

    #[test]
    fn parse_collects_error_message_only_for_nak_and_decline() {
        let opts = [53, 1, 6, 56, 4, b't', b'e', b's', b't'];
        let result = dhcp_option_parse(
            &message(&opts, &[], &[]),
            DHCP_MESSAGE_SIZE + opts.len(),
            None,
        )
        .unwrap();
        assert_eq!(result.error_message.as_deref(), Some("test"));

        let opts = [53, 1, 5, 56, 4, b't', b'e', b's', b't'];
        let result = dhcp_option_parse(
            &message(&opts, &[], &[]),
            DHCP_MESSAGE_SIZE + opts.len(),
            None,
        )
        .unwrap();
        assert_eq!(result.error_message, None);
    }

    #[test]
    fn parse_string_allows_single_trailing_nul() {
        assert_eq!(
            dhcp_option_parse_string(b"host\0").unwrap().as_deref(),
            Some("host")
        );
        assert_eq!(dhcp_option_parse_string(b"").unwrap(), None);
        assert_eq!(dhcp_option_parse_string(b"ho\0st").unwrap_err(), EINVAL);
    }

    #[test]
    fn parse_hostname_validates_dns_hostname() {
        assert_eq!(
            dhcp_option_parse_hostname(b"host.example")
                .unwrap()
                .as_deref(),
            Some("host.example")
        );
        assert_eq!(dhcp_option_parse_hostname(b"bad_host").unwrap_err(), EINVAL);
    }

    #[test]
    fn sd_dhcp_option_new_copies_data() {
        let option = sd_dhcp_option_new(43, &[1, 2, 3]).unwrap();
        assert_eq!(option.option, DhcpOptionCode::VENDOR_SPECIFIC);
        assert_eq!(&*option.data, &[1, 2, 3]);
    }

    #[test]
    fn find_and_remove_option_match_c_behavior() {
        let mut opts = vec![53, 1, 5, 1, 4, 255, 255, 255, 0, 255];
        let (offset, consumed) = dhcp_option_find_option(&opts, opts.len(), 53).unwrap();
        assert_eq!((offset, consumed), (0, 3));

        let len = opts.len();
        let new_len = dhcp_option_remove_option(&mut opts, len, 53).unwrap();
        assert_eq!(&opts[..new_len], &[1, 4, 255, 255, 255, 0, 255]);
    }

    #[test]
    fn append_matches_option_overflow_behavior() {
        let mut msg = DhcpMessage::new(11);
        msg.options[..4].copy_from_slice(b"ABCD");

        let mut offset = 0;
        assert_eq!(
            dhcp_option_append(
                &mut msg,
                0,
                &mut offset,
                0,
                DhcpOptionCode::PAD,
                DhcpOptionValue::None
            )
            .unwrap_err(),
            ENOBUFS
        );
        assert_eq!(offset, 0);

        offset = 4;
        assert_eq!(
            dhcp_option_append(
                &mut msg,
                5,
                &mut offset,
                0,
                DhcpOptionCode::PAD,
                DhcpOptionValue::None
            )
            .unwrap_err(),
            ENOBUFS
        );
        assert_eq!(
            dhcp_option_append(
                &mut msg,
                6,
                &mut offset,
                0,
                DhcpOptionCode::PAD,
                DhcpOptionValue::None
            ),
            Ok(())
        );
        assert_eq!(offset, 5);
    }

    #[test]
    fn append_spills_from_options_into_sname() {
        let mut msg = DhcpMessage::new(11);
        msg.options[..4].copy_from_slice(b"ABCD");
        let sequence = [
            160,
            2,
            0x11,
            0x12,
            0,
            DhcpOptionCode(31).0,
            8,
            0x31,
            0x32,
            0x33,
            0x34,
            0x35,
            0x36,
            0x37,
            0x38,
            0,
            55,
            3,
            0x51,
            0x52,
            0x53,
            17,
            7,
            0x71,
            0x72,
            0x73,
            0x74,
            0x75,
            0x76,
            0x77,
            255,
        ];

        let mut offset = 4usize;
        let mut pos = 0usize;
        while sequence[pos] != 255 {
            let code = DhcpOptionCode(sequence[pos]);
            if code == DhcpOptionCode::PAD {
                dhcp_option_append(
                    &mut msg,
                    11,
                    &mut offset,
                    DHCP_OVERLOAD_SNAME,
                    code,
                    DhcpOptionValue::None,
                )
                .unwrap();
                pos += 1;
            } else {
                let len = sequence[pos + 1] as usize;
                let data = &sequence[pos + 2..pos + 2 + len];
                dhcp_option_append(
                    &mut msg,
                    11,
                    &mut offset,
                    DHCP_OVERLOAD_SNAME,
                    code,
                    DhcpOptionValue::Raw(data),
                )
                .unwrap();
                pos += 2 + len;
            }
        }

        assert_eq!(
            &msg.options[..9],
            &[b'A', b'B', b'C', b'D', 160, 2, 0x11, 0x12, 0]
        );
        assert_eq!(msg.options[9], 255);
        assert_eq!(msg.options[10], 0);
        assert_eq!(
            &msg.sname[..pos - 5],
            &[
                31, 8, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0, 55, 3, 0x51, 0x52, 0x53,
                17, 7, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77
            ]
        );
    }

    #[test]
    fn append_user_class_vendor_and_relay_options() {
        let mut msg = DhcpMessage::new(64);
        let mut offset = 0;
        let vendor = [
            sd_dhcp_option_new(1, b"A").unwrap(),
            sd_dhcp_option_new(2, b"BC").unwrap(),
        ];
        let relay = DhcpRelayAgentInfo {
            circuit_id: Some("circuit".into()),
            remote_id: Some("remote".into()),
        };

        dhcp_option_append(
            &mut msg,
            64,
            &mut offset,
            0,
            DhcpOptionCode::USER_CLASS,
            DhcpOptionValue::UserClass(&["one", "two"]),
        )
        .unwrap();
        dhcp_option_append(
            &mut msg,
            64,
            &mut offset,
            0,
            DhcpOptionCode::VENDOR_SPECIFIC,
            DhcpOptionValue::VendorSpecific(&vendor),
        )
        .unwrap();
        dhcp_option_append(
            &mut msg,
            64,
            &mut offset,
            0,
            DhcpOptionCode::RELAY_AGENT_INFORMATION,
            DhcpOptionValue::RelayAgentInformation(&relay),
        )
        .unwrap();

        assert_eq!(
            &msg.options[..offset],
            &[
                77, 8, 3, b'o', b'n', b'e', 3, b't', b'w', b'o', 43, 7, 1, 1, b'A', 2, 2, b'B',
                b'C', 82, 17, 1, 7, b'c', b'i', b'r', b'c', b'u', b'i', b't', 2, 6, b'r', b'e',
                b'm', b'o', b't', b'e',
            ]
        );
    }

    #[test]
    fn option_to_string_formats_known_values() {
        assert_eq!(
            dhcp_option_to_string(DhcpOptionCode::MESSAGE_TYPE, &[5]).unwrap(),
            "DHCPACK"
        );
        assert_eq!(
            dhcp_option_to_string(DhcpOptionCode::HOST_NAME, b"host").unwrap(),
            "host"
        );
        assert_eq!(
            dhcp_option_to_string(DhcpOptionCode(200), &[0xaa, 0xbb]).unwrap(),
            "aabb"
        );
    }
}
