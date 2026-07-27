// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// systemd-network Rust crate
//
// Safe Rust port of the systemd network management subsystem.

//! # systemd-network
//!
//! Rust port of systemd's network management daemon (networkd),
//! networkctl, netdev, traffic control, and related components.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod fuzz_netdev_parser;
pub mod fuzz_network_parser;
pub mod networkctl;
pub mod networkctl_address_label;
pub mod networkctl_config_file;
pub mod networkctl_description;
pub mod networkctl_dump_util;
pub mod networkctl_journal;
pub mod networkctl_link_info;
pub mod networkctl_list;
pub mod networkctl_lldp;
pub mod networkctl_misc;
pub mod networkctl_status_link;
pub mod networkctl_status_system;
pub mod networkctl_util;
pub mod networkd;
pub mod networkd_address;
pub mod networkd_address_generation;
pub mod networkd_address_label;
pub mod networkd_address_pool;
pub mod networkd_bridge_fdb;
pub mod networkd_bridge_mdb;
pub mod networkd_bridge_vlan;
pub mod networkd_can;
pub mod networkd_conf;
pub mod networkd_dhcp4;
pub mod networkd_dhcp4_bus;
pub mod networkd_dhcp6;
pub mod networkd_dhcp6_bus;
pub mod networkd_dhcp_common;
pub mod networkd_dhcp_prefix_delegation;
pub mod networkd_dhcp_server;
pub mod networkd_dhcp_server_bus;
pub mod networkd_dhcp_server_static_lease;
pub mod networkd_dns;
pub mod networkd_ipv4acd;
pub mod networkd_ipv4ll;
pub mod networkd_ipv6_proxy_ndp;
pub mod networkd_ipv6ll;
pub mod networkd_json;
pub mod networkd_link;
pub mod networkd_link_bus;
pub mod networkd_link_varlink;
pub mod networkd_lldp_rx;
pub mod networkd_lldp_tx;
pub mod networkd_manager;
pub mod networkd_manager_bus;
pub mod networkd_manager_varlink;
pub mod networkd_ndisc;
pub mod networkd_neighbor;
pub mod networkd_netlabel;
pub mod networkd_network;
pub mod networkd_network_bus;
pub mod networkd_nexthop;
pub mod networkd_ntp;
pub mod networkd_queue;
pub mod networkd_radv;
pub mod networkd_resolve_hook;
pub mod networkd_route;
pub mod networkd_route_metric;
pub mod networkd_route_nexthop;
pub mod networkd_route_util;
pub mod networkd_routing_policy_rule;
pub mod networkd_runtime;
pub mod networkd_serialize;
pub mod networkd_setlink;
pub mod networkd_speed_meter;
pub mod networkd_sriov;
pub mod networkd_state_file;
pub mod networkd_sysctl;
pub mod networkd_util;
pub mod networkd_varlink_metrics;
pub mod networkd_wifi;
pub mod networkd_wiphy;
pub mod networkd_wwan;
pub mod networkd_wwan_bus;
pub mod test_network;
pub mod test_network_tables;
pub mod test_networkd_address;
pub mod test_networkd_conf;
pub mod test_networkd_util;

pub mod bpf_sysctl_monitor {
    pub mod sysctl_monitor_bpf;
}

pub mod generator {
    pub mod network_generator;
    pub mod network_generator_main;
    pub mod test_network_generator;
}

pub mod netdev {
    pub mod bareudp;
    pub mod batadv;
    pub mod bond;
    pub mod bridge;
    pub mod dummy;
    pub mod fou_tunnel;
    pub mod geneve;
    pub mod hsr;
    pub mod ifb;
    pub mod ipoib;
    pub mod ipvlan;
    pub mod l2tp_tunnel;
    pub mod macsec;
    pub mod macvlan;
    pub mod netdev;
    pub mod netdev_util;
    pub mod nlmon;
    pub mod tunnel;
    pub mod tuntap;
    pub mod vcan;
    pub mod veth;
    pub mod vlan;
    pub mod vrf;
    pub mod vxcan;
    pub mod vxlan;
    pub mod wireguard;
    pub mod wlan;
    pub mod xfrm;
}

pub mod tc {
    pub mod cake;
    pub mod codel;
    pub mod drr;
    pub mod ets;
    pub mod fifo;
    pub mod fq;
    pub mod fq_codel;
    pub mod fq_pie;
    pub mod gred;
    pub mod hhf;
    pub mod htb;
    pub mod mq;
    pub mod multiq;
    pub mod netem;
    pub mod pie;
    pub mod qdisc;
    pub mod qfq;
    pub mod sfb;
    pub mod sfq;
    pub mod tbf;
    pub mod tc;
    pub mod tc_util;
    pub mod tclass;
    pub mod teql;
}

pub mod wait_online {
    pub mod wait_online;
    pub mod wait_online_link;
    pub mod wait_online_manager;
}

pub use netdev::netdev::NetDev;
pub use networkd_link::Link;
pub use networkd_manager::Manager;
pub use networkd_util::NetworkConfigSource;
