// SPDX-License-Identifier: LGPL-2.1-or-later
//
// systemd-shared-rs: conservative Rust shadow modules for src/shared/
//
// This crate intentionally starts small. The Meson input list below mirrors the
// module declarations here so the shadow port stays mechanically trackable.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![deny(improper_ctypes_definitions)]
#![deny(clippy::missing_safety_doc)]
#![deny(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::comparison_chain)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::missing_transmute_annotations)]
#![allow(clippy::manual_is_ascii_check)]
#![allow(clippy::manual_range_contains)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::manual_c_str_literals)]
#![allow(clippy::ptr_eq)]
#![allow(clippy::needless_return)]
#![allow(clippy::duplicated_attributes)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::needless_late_init)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::from_over_into)]
#![allow(clippy::unnecessary_literal_unwrap)]
#![allow(clippy::single_match)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::redundant_closure)]
#![allow(dead_code)]
#![allow(private_interfaces)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(clippy::needless_question_mark)]
#![allow(clippy::redundant_slicing)]
#![allow(clippy::manual_contains)]
#![allow(clippy::needless_bool)]
#![allow(clippy::nonminimal_bool)]

pub mod acpi_fpdt;
pub mod barrier;
pub mod bitmap;
pub mod bond_util;
pub mod boot_entry;
pub mod boot_timestamps;
pub mod bootspec;
pub mod bpf_dlopen;
pub mod bpf_program;
pub mod bus_get_properties;
pub mod bus_locator;
pub mod bus_log_control_api;
pub mod bus_map_properties;
pub mod bus_message_util;
pub mod bus_object;
pub mod bus_polkit;
pub mod bus_print_properties;
pub mod bus_unit_procs;
pub mod bus_unit_util;
pub mod bus_util;
pub mod bus_wait_for_jobs;
pub mod bus_wait_for_units;
pub mod calendarspec;
pub mod cgroup_setup;
pub mod cgroup_show;
pub mod chown_recursive;
pub mod clean_ipc;
pub mod clock_util;
pub mod compare_operator;
pub mod condition;
pub mod conf_parser;
pub mod copy;
pub mod coredump_util;
pub mod cpu_set_util;
pub mod creds_util;
pub mod dev_setup;
pub mod device_enumerator;
pub mod device_util;
pub mod dhcp_identifier;
pub mod discover_image;
pub mod dissect_image;
pub mod dns_answer;
pub mod dns_configuration;
pub mod dns_domain;
pub mod dns_packet;
pub mod dns_question;
pub mod dns_rr;
pub mod dns_type;
pub mod efi_api;
pub mod efivars;
pub mod env_file_label;
pub mod ethtool_util;
pub mod exec_util;
pub mod exit_status;
pub mod fdset;
pub mod ffi;
pub mod fileio_label;
pub mod firewall_util;
pub mod format_table;
pub mod fstab_util;
pub mod fuzz_calendarspec;
pub mod group_record;
pub mod id128_print;
pub mod in_addr_prefix_util;
pub mod ipvlan_util;
pub mod journal_field;
pub mod journal_file_util;
pub mod journal_importer;
pub mod journal_util;
pub mod label_util;
pub mod local_addresses;
pub mod locale_setup;
pub mod log_assert_critical;
pub mod lsm_util;
pub mod machine_bind_user;
pub mod machine_credential;
pub mod machine_id_setup;
pub mod macvlan_util;
pub mod mkdir_label;
pub mod mount_setup;
pub mod mount_util;
pub mod net_condition;
pub mod netif_naming_scheme;
pub mod netif_sriov;
pub mod netif_util;
pub mod nsflags;
pub mod numa_util;
pub mod openssl_util;
pub mod output_mode;
pub mod pam_util;
pub mod printk_util;
pub mod resolve_hook_util;
pub mod resolve_util;
pub mod rm_rf;
pub mod seccomp_util;
pub mod secret_bytes;
pub mod securebits_util;
pub mod sleep_config;
pub mod switch_root;
pub mod tmpfile_util_label;
pub mod tomoyo_util;
pub mod user_record;
pub mod user_record_nss;
pub mod user_record_show;
pub mod userdb_dropin;
pub mod varlink_journal;
pub mod varlink_journal_access;
pub mod varlink_managed_oom;
pub mod varlink_mute_console;
pub mod varlink_oom;
pub mod varlink_oom_prekill;
pub mod varlink_pcr_lock;
pub mod vlan_util;
pub mod volatile_util;
pub mod wifi_util;
// Meson enables UTMP only with glibc. Keep unsupported libc targets from
// compiling a facade whose void updwtmpx() API cannot report unavailability.
pub mod acl_util;
pub mod ask_password_agent;
pub mod ask_password_api;
pub mod r#async;
pub mod bpf_link;
pub mod btrfs_util;
pub mod daemon_util;
pub mod data_fd_util;
pub mod dropin;
pub mod edit_util;
pub mod efi_loader;
pub mod elf_util;
pub mod extension_util;
pub mod factory_reset;
pub mod find_esp;
pub mod fork_notify;
pub mod generator;
pub mod gpt;
pub mod hibernate_util;
pub mod hostname_setup;
pub mod hwdb_util;
pub mod image_policy;
pub mod import_util;
pub mod install;
pub mod install_file;
pub mod install_printf;
pub mod kbd_util;
pub mod kernel_config;
pub mod kernel_image;
pub mod killall;
pub mod libaudit_util;
pub mod loop_util;
pub mod loopback_setup;
pub mod main_func;
pub mod metrics;
pub mod mkfs_util;
pub mod module_util;
pub mod mstack;
pub mod notify_recv;
pub mod nsresource;
pub mod open_file;
pub mod options;
pub mod osc_context;
pub mod pager;
pub mod parse_argument;
pub mod parse_helpers;
pub mod password_quality_util_passwdqc;
pub mod password_quality_util_pwquality;
pub mod pcre2_util;
pub mod pe_binary;
pub mod plymouth_util;
pub mod polkit_agent;
pub mod portable_util;
pub mod pretty_print;
pub mod prompt_util;
pub mod ptyfwd;
pub mod quota_util;
pub mod reboot_util;
pub mod recovery_key;
pub mod reread_partition_table;
pub mod resize_fs;
pub mod selinux_util;
pub mod serialize;
pub mod service_util;
pub mod shift_uid;
pub mod smack_util;
pub mod smbios11;
pub mod snapshot_util;
pub mod socket_forward;
pub mod socket_label;
pub mod socket_netlink;
pub mod specifier;
pub mod tar_util;
pub mod tests;
pub mod udev_util;
pub mod unit_file;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub mod utmp_wtmp;
pub mod varlink_idl_common;
pub mod varlink_io_systemd_AskPassword;
pub mod varlink_io_systemd_BootControl;
pub mod varlink_io_systemd_Credentials;
pub mod varlink_io_systemd_FactoryReset;
pub mod varlink_io_systemd_Hostname;
pub mod varlink_io_systemd_Import;
pub mod varlink_io_systemd_InstanceMetadata;
pub mod varlink_io_systemd_Journal;
pub mod varlink_io_systemd_JournalAccess;
pub mod varlink_io_systemd_Login;
pub mod varlink_io_systemd_Machine;
pub mod varlink_io_systemd_MachineImage;
pub mod varlink_io_systemd_ManagedOOM;
pub mod varlink_io_systemd_Manager;
pub mod varlink_io_systemd_Metrics;
pub mod varlink_io_systemd_MountFileSystem;
pub mod varlink_io_systemd_MuteConsole;
pub mod varlink_io_systemd_NamespaceResource;
pub mod varlink_io_systemd_Network;
pub mod varlink_io_systemd_Network_Link;
pub mod varlink_io_systemd_PCRExtend;
pub mod varlink_io_systemd_PCRLock;
pub mod varlink_io_systemd_Repart;
pub mod varlink_io_systemd_Resolve;
pub mod varlink_io_systemd_Resolve_Hook;
pub mod varlink_io_systemd_Resolve_Monitor;
pub mod varlink_io_systemd_Udev;
pub mod varlink_io_systemd_Unit;
pub mod varlink_io_systemd_UserDatabase;
pub mod varlink_io_systemd_oom;
pub mod varlink_io_systemd_oom_Prekill;
pub mod varlink_io_systemd_service;
pub mod varlink_io_systemd_sysext;
pub mod varlink_serialize;
pub mod vconsole_util;
pub mod verb_log_control;
pub mod verbs;
pub mod vpick;
pub mod wall;
pub mod watchdog;
pub mod web_util;
pub mod xml;

pub use ffi::Errno;
