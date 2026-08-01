// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/wifi-util.c, src/shared/wifi-util.h

use crate::ffi::*;
use std::ffi::c_void;
use std::fmt;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

pub const NL80211_GENL_NAME: &str = "nl80211";

const AF_NETLINK: i32 = 16;
const NETLINK_GENERIC: i32 = 16;
const SOL_SOCKET: i32 = 1;
const SO_RCVTIMEO: i32 = 20;
const SO_SNDTIMEO: i32 = 21;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
const NLM_F_MULTI: u16 = 0x0002;

const NLMSG_ERROR: u16 = 0x0002;
const NLMSG_DONE: u16 = 0x0003;

const GENL_ID_CTRL: u16 = 0x0010;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_GET_STATION: u8 = 17;

const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_SSID: u16 = 52;

const NLMSG_ALIGNTO: usize = 4;
const NLA_ALIGNTO: usize = 4;
const NETLINK_BUFFER_SIZE: usize = 32 * 1024;

static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nl80211Iftype {
    AdHoc,
    Station,
    Ap,
    ApVlan,
    Wds,
    Monitor,
    MeshPoint,
    P2pClient,
    P2pGo,
    P2pDevice,
    Ocb,
    Nan,
    Other(u32),
}

impl Nl80211Iftype {
    pub const fn from_raw(raw: u32) -> Self {
        match raw {
            1 => Self::AdHoc,
            2 => Self::Station,
            3 => Self::Ap,
            4 => Self::ApVlan,
            5 => Self::Wds,
            6 => Self::Monitor,
            7 => Self::MeshPoint,
            8 => Self::P2pClient,
            9 => Self::P2pGo,
            10 => Self::P2pDevice,
            11 => Self::Ocb,
            12 => Self::Nan,
            other => Self::Other(other),
        }
    }

    pub const fn raw(self) -> u32 {
        match self {
            Self::AdHoc => 1,
            Self::Station => 2,
            Self::Ap => 3,
            Self::ApVlan => 4,
            Self::Wds => 5,
            Self::Monitor => 6,
            Self::MeshPoint => 7,
            Self::P2pClient => 8,
            Self::P2pGo => 9,
            Self::P2pDevice => 10,
            Self::Ocb => 11,
            Self::Nan => 12,
            Self::Other(raw) => raw,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiSsid(Vec<u8>);

impl WifiSsid {
    pub fn new(bytes: Vec<u8>) -> Result<Self, i32> {
        if bytes.is_empty() || bytes.contains(&0) {
            return Err(-libc::EINVAL);
        }

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

impl fmt::Display for WifiSsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_lossy())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiInterfaceInfo {
    pub iftype: Nl80211Iftype,
    pub ssid: Option<WifiSsid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct GenlMsgHdr {
    cmd: u8,
    version: u8,
    reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NlAttr {
    nla_len: u16,
    nla_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgErr {
    error: i32,
    _msg: NlMsgHdr,
}

#[derive(Debug, Clone, Copy)]
struct NetlinkMessage<'a> {
    msg_type: u16,
    flags: u16,
    payload: &'a [u8],
}

pub fn wifi_get_interface(ifindex: i32) -> Result<Option<WifiInterfaceInfo>, i32> {
    if ifindex <= 0 {
        return Err(-libc::EINVAL);
    }

    let mut socket = GenericNetlinkSocket::open()?;
    let family_id = socket.resolve_family_id(NL80211_GENL_NAME)?;
    let reply = socket.send_and_receive(
        family_id,
        NL80211_CMD_GET_INTERFACE,
        NLM_F_REQUEST | NLM_F_ACK,
        &[(NL80211_ATTR_IFINDEX, &(ifindex as u32).to_ne_bytes())],
    );

    match reply {
        Ok(messages) => Ok(parse_interface_messages(&messages, family_id)),
        Err(err) if err == -libc::ENODEV => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn wifi_get_station(ifindex: i32) -> Result<Option<MacAddress>, i32> {
    if ifindex <= 0 {
        return Err(-libc::EINVAL);
    }

    let mut socket = GenericNetlinkSocket::open()?;
    let family_id = socket.resolve_family_id(NL80211_GENL_NAME)?;
    let messages = socket.send_and_receive(
        family_id,
        NL80211_CMD_GET_STATION,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP,
        &[(NL80211_ATTR_IFINDEX, &(ifindex as u32).to_ne_bytes())],
    )?;

    Ok(parse_station_messages(&messages, family_id))
}

pub fn nl80211_iftype_to_string(iftype: Nl80211Iftype) -> Option<&'static str> {
    match iftype {
        Nl80211Iftype::AdHoc => Some("ad-hoc"),
        Nl80211Iftype::Station => Some("station"),
        Nl80211Iftype::Ap => Some("ap"),
        Nl80211Iftype::ApVlan => Some("ap-vlan"),
        Nl80211Iftype::Wds => Some("wds"),
        Nl80211Iftype::Monitor => Some("monitor"),
        Nl80211Iftype::MeshPoint => Some("mesh-point"),
        Nl80211Iftype::P2pClient => Some("p2p-client"),
        Nl80211Iftype::P2pGo => Some("p2p-go"),
        Nl80211Iftype::P2pDevice => Some("p2p-device"),
        Nl80211Iftype::Ocb => Some("ocb"),
        Nl80211Iftype::Nan => Some("nan"),
        Nl80211Iftype::Other(_) => None,
    }
}

pub fn nl80211_iftype_from_string(name: &str) -> Option<Nl80211Iftype> {
    match name {
        "ad-hoc" => Some(Nl80211Iftype::AdHoc),
        "station" => Some(Nl80211Iftype::Station),
        "ap" => Some(Nl80211Iftype::Ap),
        "ap-vlan" => Some(Nl80211Iftype::ApVlan),
        "wds" => Some(Nl80211Iftype::Wds),
        "monitor" => Some(Nl80211Iftype::Monitor),
        "mesh-point" => Some(Nl80211Iftype::MeshPoint),
        "p2p-client" => Some(Nl80211Iftype::P2pClient),
        "p2p-go" => Some(Nl80211Iftype::P2pGo),
        "p2p-device" => Some(Nl80211Iftype::P2pDevice),
        "ocb" => Some(Nl80211Iftype::Ocb),
        "nan" => Some(Nl80211Iftype::Nan),
        _ => None,
    }
}

static NL80211_CMD_TABLE: &[Option<&str>] = &[
    None,
    Some("get_wiphy"),
    Some("set_wiphy"),
    Some("new_wiphy"),
    Some("del_wiphy"),
    Some("get_interface"),
    Some("set_interface"),
    Some("new_interface"),
    Some("del_interface"),
    Some("get_key"),
    Some("set_key"),
    Some("new_key"),
    Some("del_key"),
    Some("get_beacon"),
    Some("set_beacon"),
    Some("start_ap"),
    Some("stop_ap"),
    Some("get_station"),
    Some("set_station"),
    Some("new_station"),
    Some("del_station"),
    Some("get_mpath"),
    Some("set_mpath"),
    Some("new_mpath"),
    Some("del_mpath"),
    Some("set_bss"),
    Some("set_reg"),
    Some("req_set_reg"),
    Some("get_mesh_config"),
    Some("set_mesh_config"),
    Some("set_mgmt_extra_ie"),
    Some("get_reg"),
    Some("get_scan"),
    Some("trigger_scan"),
    Some("new_scan_results"),
    Some("scan_aborted"),
    Some("reg_change"),
    Some("authenticate"),
    Some("associate"),
    Some("deauthenticate"),
    Some("disassociate"),
    Some("michael_mic_failure"),
    Some("reg_beacon_hint"),
    Some("join_ibss"),
    Some("leave_ibss"),
    Some("testmode"),
    Some("connect"),
    Some("roam"),
    Some("disconnect"),
    Some("set_wiphy_netns"),
    Some("get_survey"),
    Some("new_survey_results"),
    Some("set_pmksa"),
    Some("del_pmksa"),
    Some("flush_pmksa"),
    Some("remain_on_channel"),
    Some("cancel_remain_on_channel"),
    Some("set_tx_bitrate_mask"),
    Some("register_frame"),
    Some("frame"),
    Some("frame_tx_status"),
    Some("set_power_save"),
    Some("get_power_save"),
    Some("set_cqm"),
    Some("notify_cqm"),
    Some("set_channel"),
    Some("set_wds_peer"),
    Some("frame_wait_cancel"),
    Some("join_mesh"),
    Some("leave_mesh"),
    Some("unprot_deauthenticate"),
    Some("unprot_disassociate"),
    Some("new_peer_candidate"),
    Some("get_wowlan"),
    Some("set_wowlan"),
    Some("start_sched_scan"),
    Some("stop_sched_scan"),
    Some("sched_scan_results"),
    Some("sched_scan_stopped"),
    Some("set_rekey_offload"),
    Some("pmksa_candidate"),
    Some("tdls_oper"),
    Some("tdls_mgmt"),
    Some("unexpected_frame"),
    Some("probe_client"),
    Some("register_beacons"),
    Some("unexpected_4addr_frame"),
    Some("set_noack_map"),
    Some("ch_switch_notify"),
    Some("start_p2p_device"),
    Some("stop_p2p_device"),
    Some("conn_failed"),
    Some("set_mcast_rate"),
    Some("set_mac_acl"),
    Some("radar_detect"),
    Some("get_protocol_features"),
    Some("update_ft_ies"),
    Some("ft_event"),
    Some("crit_protocol_start"),
    Some("crit_protocol_stop"),
    Some("get_coalesce"),
    Some("set_coalesce"),
    Some("channel_switch"),
    Some("vendor"),
    Some("set_qos_map"),
    Some("add_tx_ts"),
    Some("del_tx_ts"),
    Some("get_mpp"),
    Some("join_ocb"),
    Some("leave_ocb"),
    Some("ch_switch_started_notify"),
    Some("tdls_channel_switch"),
    Some("tdls_cancel_channel_switch"),
    Some("wiphy_reg_change"),
    Some("abort_scan"),
    Some("start_nan"),
    Some("stop_nan"),
    Some("add_nan_function"),
    Some("del_nan_function"),
    Some("change_nan_config"),
    Some("nan_match"),
    Some("set_multicast_to_unicast"),
    Some("update_connect_params"),
    Some("set_pmk"),
    Some("del_pmk"),
    Some("port_authorized"),
    Some("reload_regdb"),
    Some("external_auth"),
    Some("sta_opmode_changed"),
    Some("control_port_frame"),
    Some("get_ftm_responder_stats"),
    Some("peer_measurement_start"),
    Some("peer_measurement_result"),
    Some("peer_measurement_complete"),
    Some("notify_radar"),
    Some("update_owe_info"),
    Some("probe_mesh_link"),
    Some("set_tid_config"),
    Some("unprot_beacon"),
    Some("control_port_frame_tx_status"),
    Some("set_sar_specs"),
    Some("obss_color_collision"),
    Some("color_change_request"),
    Some("color_change_started"),
    Some("color_change_aborted"),
    Some("color_change_completed"),
];

pub fn nl80211_cmd_to_string(cmd: i32) -> Option<&'static str> {
    usize::try_from(cmd)
        .ok()
        .and_then(|index| NL80211_CMD_TABLE.get(index))
        .copied()
        .flatten()
}

struct GenericNetlinkSocket {
    fd: RawFd,
}

impl GenericNetlinkSocket {
    fn open() -> Result<Self, i32> {
        // SAFETY: socket() takes only scalar arguments and returns an owned descriptor on success.
        let fd = unsafe_ffi!(libc::socket(AF_NETLINK, libc::SOCK_RAW, NETLINK_GENERIC));
        if fd < 0 {
            return Err(last_errno());
        }

        let socket = Self { fd };
        if let Err(err) = socket.bind() {
            drop(socket);
            return Err(err);
        }
        if let Err(err) = socket.set_timeouts() {
            drop(socket);
            return Err(err);
        }
        Ok(socket)
    }

    fn bind(&self) -> Result<(), i32> {
        let addr = SockAddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };

        // SAFETY: self.fd is owned, and addr is a valid SockAddrNl for the duration of bind().
        let r = unsafe_ffi!({
            libc::bind(
                self.fd,
                (&addr as *const SockAddrNl).cast::<libc::sockaddr>(),
                size_of::<SockAddrNl>() as libc::socklen_t,
            )
        });
        if r < 0 {
            return Err(last_errno());
        }
        Ok(())
    }

    fn set_timeouts(&self) -> Result<(), i32> {
        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };

        for name in [SO_RCVTIMEO, SO_SNDTIMEO] {
            // SAFETY: self.fd is owned and timeout is valid initialized storage of the supplied size.
            let r = unsafe_ffi!({
                libc::setsockopt(
                    self.fd,
                    SOL_SOCKET,
                    name,
                    (&timeout as *const libc::timeval).cast::<c_void>(),
                    size_of::<libc::timeval>() as libc::socklen_t,
                )
            });
            if r < 0 {
                return Err(last_errno());
            }
        }

        Ok(())
    }

    fn resolve_family_id(&mut self, family_name: &str) -> Result<u16, i32> {
        let responses = self.send_and_receive(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            NLM_F_REQUEST | NLM_F_ACK,
            &[(CTRL_ATTR_FAMILY_NAME, family_name.as_bytes())],
        )?;

        for message in responses {
            if message.msg_type != GENL_ID_CTRL {
                continue;
            }

            let Some((_, payload)) = split_genl_payload(message.payload) else {
                continue;
            };

            for (attr_type, data) in parse_attributes(payload) {
                if attr_type == CTRL_ATTR_FAMILY_ID {
                    if let Some(family_id) = read_u16(data) {
                        return Ok(family_id);
                    }
                }
            }
        }

        Err(-libc::ENODATA)
    }

    fn send_and_receive(
        &mut self,
        msg_type: u16,
        cmd: u8,
        flags: u16,
        attrs: &[(u16, &[u8])],
    ) -> Result<Vec<NetlinkMessage<'static>>, i32> {
        let seq = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let request = build_genl_request(msg_type, cmd, flags, seq, attrs);
        self.send(&request)?;
        self.receive(seq)
    }

    fn send(&self, request: &[u8]) -> Result<(), i32> {
        let kernel = SockAddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };

        // SAFETY: self.fd is owned; request and addr remain valid for the duration of sendto().
        let r = unsafe_ffi!({
            libc::sendto(
                self.fd,
                request.as_ptr().cast::<c_void>(),
                request.len(),
                0,
                (&kernel as *const SockAddrNl).cast::<libc::sockaddr>(),
                size_of::<SockAddrNl>() as libc::socklen_t,
            )
        });
        if r < 0 {
            return Err(last_errno());
        }
        Ok(())
    }

    fn receive(&self, seq: u32) -> Result<Vec<NetlinkMessage<'static>>, i32> {
        let mut messages = Vec::new();

        loop {
            let mut buffer = vec![0u8; NETLINK_BUFFER_SIZE];
            // SAFETY: self.fd is owned and buffer provides writable storage for its stated length.
            let received = unsafe_ffi!({
                libc::recv(
                    self.fd,
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer.len(),
                    0,
                )
            });
            if received < 0 {
                return Err(last_errno());
            }

            buffer.truncate(received as usize);
            let packet = parse_netlink_packet(&buffer, seq)?;
            let mut done = false;

            for message in packet {
                if message.msg_type == NLMSG_DONE {
                    done = true;
                    continue;
                }

                if message.msg_type == NLMSG_ERROR {
                    return Err(parse_nlmsg_error(message.payload));
                }

                let is_multi = message.flags & NLM_F_MULTI != 0;
                messages.push(NetlinkMessage {
                    msg_type: message.msg_type,
                    flags: message.flags,
                    payload: std::boxed::Box::leak(message.payload.to_vec().into_boxed_slice()),
                });

                if !is_multi {
                    done = true;
                }
            }

            if done {
                return Ok(messages);
            }
        }
    }
}

impl Drop for GenericNetlinkSocket {
    fn drop(&mut self) {
        // SAFETY: self.fd is the descriptor owned by this socket and is closed exactly once here.
        unsafe_ffi!({
            libc::close(self.fd);
        })
    }
}

fn build_genl_request(
    msg_type: u16,
    cmd: u8,
    flags: u16,
    seq: u32,
    attrs: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut buffer = vec![0u8; size_of::<NlMsgHdr>()];
    append_genl_header(
        &mut buffer,
        GenlMsgHdr {
            cmd,
            version: 0,
            reserved: 0,
        },
    );

    for &(attr_type, attr_data) in attrs {
        append_attribute(&mut buffer, attr_type, attr_data);
    }

    let header = NlMsgHdr {
        nlmsg_len: buffer.len() as u32,
        nlmsg_type: msg_type,
        nlmsg_flags: flags,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    };
    write_nlmsg_header(&mut buffer[..size_of::<NlMsgHdr>()], header);
    buffer
}

fn append_genl_header(buffer: &mut Vec<u8>, header: GenlMsgHdr) {
    buffer.push(header.cmd);
    buffer.push(header.version);
    buffer.extend_from_slice(&header.reserved.to_ne_bytes());
}

fn append_attribute(buffer: &mut Vec<u8>, attr_type: u16, data: &[u8]) {
    let attr_len = (size_of::<NlAttr>() + data.len()) as u16;
    buffer.extend_from_slice(&attr_len.to_ne_bytes());
    buffer.extend_from_slice(&attr_type.to_ne_bytes());
    buffer.extend_from_slice(data);
    pad_to_alignment(buffer, NLA_ALIGNTO);
}

fn write_nlmsg_header(dst: &mut [u8], header: NlMsgHdr) {
    dst[0..4].copy_from_slice(&header.nlmsg_len.to_ne_bytes());
    dst[4..6].copy_from_slice(&header.nlmsg_type.to_ne_bytes());
    dst[6..8].copy_from_slice(&header.nlmsg_flags.to_ne_bytes());
    dst[8..12].copy_from_slice(&header.nlmsg_seq.to_ne_bytes());
    dst[12..16].copy_from_slice(&header.nlmsg_pid.to_ne_bytes());
}

fn pad_to_alignment(buffer: &mut Vec<u8>, alignment: usize) {
    let new_len = align(buffer.len(), alignment);
    buffer.resize(new_len, 0);
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn parse_netlink_packet(packet: &[u8], expected_seq: u32) -> Result<Vec<NetlinkMessage<'_>>, i32> {
    let mut offset = 0;
    let mut messages = Vec::new();

    while offset + size_of::<NlMsgHdr>() <= packet.len() {
        let header = read_nlmsg_header(&packet[offset..offset + size_of::<NlMsgHdr>()])?;
        if header.nlmsg_len < size_of::<NlMsgHdr>() as u32 {
            return Err(-libc::EBADMSG);
        }

        let end = offset + header.nlmsg_len as usize;
        if end > packet.len() {
            return Err(-libc::EBADMSG);
        }

        if header.nlmsg_seq != expected_seq {
            offset = align(end, NLMSG_ALIGNTO);
            continue;
        }

        messages.push(NetlinkMessage {
            msg_type: header.nlmsg_type,
            flags: header.nlmsg_flags,
            payload: &packet[offset + size_of::<NlMsgHdr>()..end],
        });
        offset = align(end, NLMSG_ALIGNTO);
    }

    Ok(messages)
}

fn read_nlmsg_header(bytes: &[u8]) -> Result<NlMsgHdr, i32> {
    if bytes.len() < size_of::<NlMsgHdr>() {
        return Err(-libc::EBADMSG);
    }

    Ok(NlMsgHdr {
        nlmsg_len: u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
        nlmsg_type: u16::from_ne_bytes(bytes[4..6].try_into().unwrap()),
        nlmsg_flags: u16::from_ne_bytes(bytes[6..8].try_into().unwrap()),
        nlmsg_seq: u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
        nlmsg_pid: u32::from_ne_bytes(bytes[12..16].try_into().unwrap()),
    })
}

fn parse_nlmsg_error(payload: &[u8]) -> i32 {
    if payload.len() < size_of::<NlMsgErr>() {
        return -libc::EBADMSG;
    }

    let error = i32::from_ne_bytes(payload[0..4].try_into().unwrap());
    if error == 0 { -libc::ENODATA } else { error }
}

fn split_genl_payload(payload: &[u8]) -> Option<(GenlMsgHdr, &[u8])> {
    if payload.len() < size_of::<GenlMsgHdr>() {
        return None;
    }

    Some((
        GenlMsgHdr {
            cmd: payload[0],
            version: payload[1],
            reserved: u16::from_ne_bytes(payload[2..4].try_into().ok()?),
        },
        &payload[4..],
    ))
}

fn parse_attributes(mut payload: &[u8]) -> Vec<(u16, &[u8])> {
    let mut attrs = Vec::new();

    while payload.len() >= size_of::<NlAttr>() {
        let nla_len = u16::from_ne_bytes([payload[0], payload[1]]) as usize;
        let nla_type = u16::from_ne_bytes([payload[2], payload[3]]);
        if nla_len < size_of::<NlAttr>() || nla_len > payload.len() {
            break;
        }

        attrs.push((nla_type, &payload[size_of::<NlAttr>()..nla_len]));
        let next = align(nla_len, NLA_ALIGNTO);
        if next > payload.len() {
            break;
        }
        payload = &payload[next..];
    }

    attrs
}

fn parse_interface_messages(
    messages: &[NetlinkMessage<'_>],
    family_id: u16,
) -> Option<WifiInterfaceInfo> {
    messages
        .iter()
        .find_map(|message| parse_interface_message(*message, family_id))
}

fn parse_interface_message(
    message: NetlinkMessage<'_>,
    family_id: u16,
) -> Option<WifiInterfaceInfo> {
    if message.msg_type != family_id {
        return None;
    }

    let (_, payload) = split_genl_payload(message.payload)?;
    let attrs = parse_attributes(payload);

    let iftype = attrs.iter().find_map(|(kind, data)| {
        (*kind == NL80211_ATTR_IFTYPE)
            .then(|| read_u32(data))
            .flatten()
    })?;

    let ssid = attrs.iter().find_map(|(kind, data)| {
        (*kind == NL80211_ATTR_SSID)
            .then(|| WifiSsid::new(data.to_vec()).ok())
            .flatten()
    });

    Some(WifiInterfaceInfo {
        iftype: Nl80211Iftype::from_raw(iftype),
        ssid,
    })
}

fn parse_station_messages(messages: &[NetlinkMessage<'_>], family_id: u16) -> Option<MacAddress> {
    messages
        .iter()
        .find_map(|message| parse_station_message(*message, family_id))
}

fn parse_station_message(message: NetlinkMessage<'_>, family_id: u16) -> Option<MacAddress> {
    if message.msg_type != family_id {
        return None;
    }

    let (_, payload) = split_genl_payload(message.payload)?;
    for (attr_type, data) in parse_attributes(payload) {
        if attr_type == NL80211_ATTR_MAC && data.len() == 6 {
            return Some(MacAddress(data.try_into().ok()?));
        }
    }

    None
}

fn read_u16(data: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes(data.get(0..2)?.try_into().ok()?))
}

fn read_u32(data: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(data.get(0..4)?.try_into().ok()?))
}

fn last_errno() -> i32 {
    -io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genl_payload(cmd: u8, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut payload = Vec::new();
        append_genl_header(
            &mut payload,
            GenlMsgHdr {
                cmd,
                version: 0,
                reserved: 0,
            },
        );
        for &(kind, data) in attrs {
            append_attribute(&mut payload, kind, data);
        }
        payload
    }

    #[test]
    fn iftype_roundtrip() {
        let variants = [
            Nl80211Iftype::AdHoc,
            Nl80211Iftype::Station,
            Nl80211Iftype::Ap,
            Nl80211Iftype::Nan,
        ];

        for variant in variants {
            assert_eq!(Nl80211Iftype::from_raw(variant.raw()), variant);
        }
    }

    #[test]
    fn iftype_unknown_is_preserved() {
        assert_eq!(Nl80211Iftype::from_raw(999), Nl80211Iftype::Other(999));
        assert_eq!(Nl80211Iftype::Other(999).raw(), 999);
    }

    #[test]
    fn iftype_string_lookups_match_c_table() {
        assert_eq!(
            nl80211_iftype_to_string(Nl80211Iftype::Station),
            Some("station")
        );
        assert_eq!(
            nl80211_iftype_from_string("mesh-point"),
            Some(Nl80211Iftype::MeshPoint)
        );
        assert_eq!(nl80211_iftype_to_string(Nl80211Iftype::Other(42)), None);
        assert_eq!(nl80211_iftype_from_string("bogus"), None);
    }

    #[test]
    fn command_string_lookup_matches_known_entries() {
        assert_eq!(nl80211_cmd_to_string(1), Some("get_wiphy"));
        assert_eq!(nl80211_cmd_to_string(17), Some("get_station"));
        assert_eq!(nl80211_cmd_to_string(143), Some("color_change_started"));
        assert_eq!(nl80211_cmd_to_string(0), None);
        assert_eq!(nl80211_cmd_to_string(999), None);
    }

    #[test]
    fn ssid_accepts_non_utf8_without_nul() {
        let ssid = WifiSsid::new(vec![0xff, b'a']).unwrap();
        assert_eq!(ssid.as_bytes(), &[0xff, b'a']);
    }

    #[test]
    fn ssid_rejects_empty_and_nul_bytes() {
        assert_eq!(WifiSsid::new(Vec::new()), Err(-libc::EINVAL));
        assert_eq!(WifiSsid::new(vec![b'a', 0, b'b']), Err(-libc::EINVAL));
    }

    #[test]
    fn parse_attributes_handles_aligned_entries() {
        let mut buffer = Vec::new();
        append_attribute(&mut buffer, 1, &[1, 2, 3, 4]);
        append_attribute(&mut buffer, 2, &[9]);

        let attrs = parse_attributes(&buffer);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0], (1, &[1, 2, 3, 4][..]));
        assert_eq!(attrs[1], (2, &[9][..]));
    }

    #[test]
    fn parse_interface_message_extracts_iftype_and_ssid() {
        let iftype = 2u32.to_ne_bytes();
        let payload = genl_payload(
            NL80211_CMD_GET_INTERFACE,
            &[
                (NL80211_ATTR_IFTYPE, &iftype),
                (NL80211_ATTR_SSID, b"home-wifi"),
            ],
        );
        let info = parse_interface_message(
            NetlinkMessage {
                msg_type: 42,
                flags: 0,
                payload: &payload,
            },
            42,
        )
        .unwrap();

        assert_eq!(info.iftype, Nl80211Iftype::Station);
        assert_eq!(info.ssid.unwrap().as_bytes(), b"home-wifi");
    }

    #[test]
    fn parse_interface_message_ignores_invalid_ssid() {
        let iftype = 3u32.to_ne_bytes();
        let payload = genl_payload(
            NL80211_CMD_GET_INTERFACE,
            &[(NL80211_ATTR_IFTYPE, &iftype), (NL80211_ATTR_SSID, b"a\0b")],
        );
        let info = parse_interface_message(
            NetlinkMessage {
                msg_type: 7,
                flags: 0,
                payload: &payload,
            },
            7,
        )
        .unwrap();

        assert_eq!(info.iftype, Nl80211Iftype::Ap);
        assert!(info.ssid.is_none());
    }

    #[test]
    fn parse_interface_message_requires_iftype() {
        let payload = genl_payload(NL80211_CMD_GET_INTERFACE, &[(NL80211_ATTR_SSID, b"wifi")]);
        assert!(
            parse_interface_message(
                NetlinkMessage {
                    msg_type: 7,
                    flags: 0,
                    payload: &payload,
                },
                7,
            )
            .is_none()
        );
    }

    #[test]
    fn parse_interface_messages_ignores_wrong_family() {
        let iftype = 2u32.to_ne_bytes();
        let payload = genl_payload(NL80211_CMD_GET_INTERFACE, &[(NL80211_ATTR_IFTYPE, &iftype)]);
        let messages = [NetlinkMessage {
            msg_type: 99,
            flags: 0,
            payload: &payload,
        }];

        assert!(parse_interface_messages(&messages, 42).is_none());
    }

    #[test]
    fn parse_station_message_extracts_mac() {
        let payload = genl_payload(
            NL80211_CMD_GET_STATION,
            &[(NL80211_ATTR_MAC, &[0, 1, 2, 3, 4, 5])],
        );
        let mac = parse_station_message(
            NetlinkMessage {
                msg_type: 23,
                flags: 0,
                payload: &payload,
            },
            23,
        )
        .unwrap();

        assert_eq!(mac.0, [0, 1, 2, 3, 4, 5]);
        assert_eq!(mac.to_string(), "00:01:02:03:04:05");
    }

    #[test]
    fn parse_station_messages_returns_first_match() {
        let first = genl_payload(
            NL80211_CMD_GET_STATION,
            &[(NL80211_ATTR_MAC, &[1, 1, 1, 1, 1, 1])],
        );
        let second = genl_payload(
            NL80211_CMD_GET_STATION,
            &[(NL80211_ATTR_MAC, &[2, 2, 2, 2, 2, 2])],
        );
        let messages = [
            NetlinkMessage {
                msg_type: 11,
                flags: 0,
                payload: &first,
            },
            NetlinkMessage {
                msg_type: 11,
                flags: 0,
                payload: &second,
            },
        ];

        assert_eq!(
            parse_station_messages(&messages, 11).unwrap().0,
            [1, 1, 1, 1, 1, 1]
        );
    }

    #[test]
    fn netlink_error_parsing_preserves_kernel_errno() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(-libc::ENODEV).to_ne_bytes());
        payload.resize(size_of::<NlMsgErr>(), 0);
        assert_eq!(parse_nlmsg_error(&payload), -libc::ENODEV);
    }

    #[test]
    fn request_builder_sets_header_length_and_alignment() {
        let request = build_genl_request(
            77,
            9,
            NLM_F_REQUEST,
            55,
            &[(3, &[1, 2, 3]), (4, &[9, 8, 7, 6])],
        );

        let header = read_nlmsg_header(&request[..size_of::<NlMsgHdr>()]).unwrap();
        assert_eq!(header.nlmsg_len as usize, request.len());
        assert_eq!(header.nlmsg_type, 77);
        assert_eq!(header.nlmsg_seq, 55);
        assert_eq!(request.len() % 4, 0);
    }
}
