#!/usr/bin/env python3
"""Static current-C parity check for the Rust string-table facade.

No compilation or VM is involved. The named C arrays are authoritative for
their Rust counterparts; nl80211 additionally resolves the installed Linux
UAPI enum so platform-header drift cannot silently rebind a string.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WIFI_C = ROOT / "src/shared/wifi-util.c"
WIFI_RUST = ROOT / "src/basic/rust/netdev_str_tables/tpm_bpf_wifi.rs"
UAPI = Path("/usr/include/linux/nl80211.h")

# C source, C array, Rust source, Rust array. This is deliberately explicit:
# adding a table requires naming the precise C authority beside it.
TABLES = (
    ("src/shared/bond-util.c", "bond_mode_table", "src/basic/rust/netdev_str_tables/network_link.rs", "BOND_MODE_TABLE"),
    ("src/shared/bond-util.c", "bond_xmit_hash_policy_table", "src/basic/rust/netdev_str_tables/network_link.rs", "BOND_XMIT_HASH_POLICY_TABLE"),
    ("src/shared/bond-util.c", "bond_lacp_rate_table", "src/basic/rust/netdev_str_tables/network_link.rs", "BOND_LACP_RATE_TABLE"),
    ("src/shared/bond-util.c", "bond_ad_select_table", "src/basic/rust/netdev_str_tables/network_link.rs", "BOND_AD_SELECT_TABLE"),
    ("src/shared/bond-util.c", "bond_fail_over_mac_table", "src/basic/rust/netdev_str_tables/network_link.rs", "BOND_FAIL_OVER_MAC_TABLE"),
    ("src/shared/bond-util.c", "bond_arp_validate_table", "src/basic/rust/netdev_str_tables/network_link.rs", "BOND_ARP_VALIDATE_TABLE"),
    ("src/shared/bond-util.c", "bond_arp_all_targets_table", "src/basic/rust/netdev_str_tables/network_link.rs", "BOND_ARP_ALL_TARGETS_TABLE"),
    ("src/shared/bond-util.c", "bond_primary_reselect_table", "src/basic/rust/netdev_str_tables/network_link.rs", "BOND_PRIMARY_RESELECT_TABLE"),
    ("src/shared/bridge-util.c", "bridge_state_table", "src/basic/rust/netdev_str_tables/network_link.rs", "BRIDGE_STATE_TABLE"),
    ("src/shared/ethtool-util.c", "port_table", "src/basic/rust/netdev_str_tables/network_link.rs", "PORT_TABLE"),
    ("src/shared/ethtool-util.c", "mdi_table", "src/basic/rust/netdev_str_tables/network_link.rs", "MDI_TABLE"),
    ("src/shared/macvlan-util.c", "macvlan_mode_table", "src/basic/rust/netdev_str_tables/network_virtual.rs", "MACVLAN_MODE_TABLE"),
    ("src/shared/ipvlan-util.c", "ipvlan_mode_table", "src/basic/rust/netdev_str_tables/network_virtual.rs", "IPVLAN_MODE_TABLE"),
    ("src/shared/ipvlan-util.c", "ipvlan_flags_table", "src/basic/rust/netdev_str_tables/network_virtual.rs", "IPVLAN_FLAGS_TABLE"),
    ("src/shared/geneve-util.c", "geneve_df_table", "src/basic/rust/netdev_str_tables/network_virtual.rs", "GENEVE_DF_TABLE"),
    ("src/shared/boot-entry.c", "boot_entry_token_type_table", "src/basic/rust/netdev_str_tables/boot_import.rs", "BOOT_ENTRY_TOKEN_TYPE_TABLE"),
    ("src/shared/import-util.c", "import_type_table", "src/basic/rust/netdev_str_tables/boot_import.rs", "IMPORT_TYPE_TABLE"),
    ("src/shared/import-util.c", "import_verify_table", "src/basic/rust/netdev_str_tables/boot_import.rs", "IMPORT_VERIFY_TABLE"),
    ("src/shared/resolve-util.c", "resolve_support_table", "src/basic/rust/netdev_str_tables/resolve_modes.rs", "RESOLVE_SUPPORT_TABLE"),
    ("src/shared/resolve-util.c", "dnssec_mode_table", "src/basic/rust/netdev_str_tables/resolve_modes.rs", "DNSSEC_MODE_TABLE"),
    ("src/shared/resolve-util.c", "dns_over_tls_mode_table", "src/basic/rust/netdev_str_tables/resolve_modes.rs", "DNS_OVER_TLS_MODE_TABLE"),
    ("src/shared/resolve-util.c", "dns_cache_mode_table", "src/basic/rust/netdev_str_tables/resolve_modes.rs", "DNS_CACHE_MODE_TABLE"),
    ("src/shared/dns-packet.c", "dns_rcode_table", "src/basic/rust/netdev_str_tables/dns_security.rs", "DNS_RCODE_TABLE"),
    ("src/shared/dns-packet.c", "dns_protocol_table", "src/basic/rust/netdev_str_tables/dns_security.rs", "DNS_PROTOCOL_TABLE"),
    ("src/shared/dns-packet.c", "dns_svc_param_key_table", "src/basic/rust/netdev_str_tables/dns_security.rs", "DNS_SVC_PARAM_KEY_TABLE"),
    ("src/shared/dns-packet.c", "dns_ede_rcode_table", "src/basic/rust/netdev_str_tables/dns_security.rs", "DNS_EDE_RCODE_TABLE"),
    ("src/shared/dns-rr.c", "dnssec_algorithm_table", "src/basic/rust/netdev_str_tables/dns_security.rs", "DNSSEC_ALGORITHM_TABLE"),
    ("src/shared/dns-rr.c", "dnssec_digest_table", "src/basic/rust/netdev_str_tables/dns_security.rs", "DNSSEC_DIGEST_TABLE"),
    ("src/shared/dns-rr.c", "sshfp_algorithm_table", "src/basic/rust/netdev_str_tables/dns_security.rs", "SSHFP_ALGORITHM_TABLE"),
    ("src/shared/dns-rr.c", "sshfp_key_type_table", "src/basic/rust/netdev_str_tables/dns_security.rs", "SSHFP_KEY_TYPE_TABLE"),
    ("src/shared/netif-sriov.c", "sr_iov_attribute_table", "src/basic/rust/netdev_str_tables/tpm_bpf_wifi.rs", "SR_IOV_ATTRIBUTE_TABLE"),
    ("src/shared/bpf-program.c", "bpf_cgroup_attach_type_table", "src/basic/rust/netdev_str_tables/tpm_bpf_wifi.rs", "BPF_CGROUP_ATTACH_TYPE_TABLE"),
    ("src/shared/tpm2-util.c", "tpm2_userspace_event_type_table", "src/basic/rust/netdev_str_tables/tpm_bpf_wifi.rs", "TPM2_USERSPACE_EVENT_TYPE_TABLE"),
    ("src/shared/tpm2-util.c", "tpm2_pcr_index_table", "src/basic/rust/netdev_str_tables/tpm_bpf_wifi.rs", "TPM2_PCR_INDEX_TABLE"),
    ("src/shared/wifi-util.c", "nl80211_iftype_table", "src/basic/rust/netdev_str_tables/tpm_bpf_wifi.rs", "NL80211_IFTYPE_TABLE"),
    ("src/shared/wifi-util.c", "nl80211_cmd_table", "src/basic/rust/netdev_str_tables/tpm_bpf_wifi.rs", "NL80211_CMD_TABLE"),
    ("src/shared/coredump-util.c", "coredump_filter_table", "src/basic/rust/netdev_str_tables.rs", "COREDUMP_FILTER_TABLE"),
    ("src/shared/sleep-config.c", "sleep_operation_table", "src/basic/rust/netdev_str_tables.rs", "SLEEP_OPERATION_TABLE"),
    ("src/shared/factory-reset.c", "factory_reset_mode_table", "src/basic/rust/netdev_str_tables.rs", "FACTORY_RESET_MODE_TABLE"),
    ("src/shared/hostname-setup.c", "hostname_source_table", "src/basic/rust/netdev_str_tables.rs", "HOSTNAME_SOURCE_TABLE"),
    ("src/shared/numa-util.c", "mpol_table", "src/basic/rust/netdev_str_tables.rs", "MPOL_TABLE"),
    ("src/shared/output-mode.c", "output_mode_table", "src/basic/rust/netdev_str_tables.rs", "OUTPUT_MODE_TABLE"),
    ("src/shared/volatile-util.c", "volatile_mode_table", "src/basic/rust/netdev_str_tables.rs", "VOLATILE_MODE_TABLE"),
    ("src/shared/install.c", "unit_file_state_table", "src/basic/rust/netdev_str_tables.rs", "UNIT_FILE_STATE_TABLE"),
    ("src/shared/install.c", "preset_action_past_tense_table", "src/basic/rust/netdev_str_tables.rs", "PRESET_ACTION_PAST_TENSE_TABLE"),
    ("src/shared/install.c", "install_change_type_table", "src/basic/rust/netdev_str_tables.rs", "INSTALL_CHANGE_TYPE_TABLE"),
    ("src/shared/install.c", "unit_file_preset_mode_table", "src/basic/rust/netdev_str_tables.rs", "UNIT_FILE_PRESET_MODE_TABLE"),
    ("src/shared/discover-image.c", "image_type_table", "src/basic/rust/netdev_str_tables.rs", "IMAGE_TYPE_TABLE"),
    ("src/shared/kernel-image.c", "kernel_image_type_table", "src/basic/rust/netdev_str_tables.rs", "KERNEL_IMAGE_TYPE_TABLE"),
    ("src/shared/open-file.c", "open_file_flags_table", "src/basic/rust/netdev_str_tables.rs", "OPEN_FILE_FLAGS_TABLE"),
    ("src/shared/socket-label.c", "socket_address_bind_ipv6_only_table", "src/basic/rust/netdev_str_tables.rs", "SOCKET_ADDRESS_BIND_IPV6_ONLY_TABLE"),
    ("src/shared/metrics.c", "metric_family_type_table", "src/basic/rust/netdev_str_tables.rs", "METRIC_FAMILY_TYPE_TABLE"),
    ("src/shared/mstack.c", "mstack_mount_type_table", "src/basic/rust/netdev_str_tables.rs", "MSTACK_MOUNT_TYPE_TABLE"),
    ("src/shared/bus-util.c", "bus_transport_table", "src/basic/rust/netdev_str_tables.rs", "BUS_TRANSPORT_TABLE"),
    ("src/shared/user-record.c", "user_storage_table", "src/basic/rust/netdev_str_tables.rs", "USER_STORAGE_TABLE"),
    ("src/shared/user-record.c", "user_disposition_table", "src/basic/rust/netdev_str_tables.rs", "USER_DISPOSITION_TABLE"),
    ("src/shared/user-record.c", "auto_resize_mode_table", "src/basic/rust/netdev_str_tables.rs", "AUTO_RESIZE_MODE_TABLE"),
    ("src/shared/gpt.c", "partition_designator_table", "src/basic/rust/netdev_str_tables.rs", "PARTITION_DESIGNATOR_TABLE"),
    ("src/shared/netif-naming-scheme.c", "name_policy_table", "src/basic/rust/netdev_str_tables.rs", "NAME_POLICY_TABLE"),
    ("src/shared/netif-naming-scheme.c", "alternative_names_policy_table", "src/basic/rust/netdev_str_tables.rs", "ALTERNATIVE_NAMES_POLICY_TABLE"),
    ("src/shared/condition.c", "condition_result_table", "src/basic/rust/netdev_str_tables.rs", "CONDITION_RESULT_TABLE"),
    ("src/shared/firewall-util.c", "nfproto_table", "src/basic/rust/netdev_str_tables.rs", "NFPROTO_TABLE"),
    ("src/shared/firewall-util.c", "nft_set_source_table", "src/basic/rust/netdev_str_tables.rs", "NFT_SET_SOURCE_TABLE"),
    ("src/shared/bootspec.c", "boot_entry_type_table", "src/basic/rust/netdev_str_tables.rs", "BOOT_ENTRY_TYPE_TABLE"),
    ("src/shared/bootspec.c", "boot_entry_type_description_table", "src/basic/rust/netdev_str_tables.rs", "BOOT_ENTRY_TYPE_DESCRIPTION_TABLE"),
    ("src/shared/bootspec.c", "boot_entry_source_table", "src/basic/rust/netdev_str_tables.rs", "BOOT_ENTRY_SOURCE_TABLE"),
    ("src/shared/bootspec.c", "boot_entry_source_description_table", "src/basic/rust/netdev_str_tables.rs", "BOOT_ENTRY_SOURCE_DESCRIPTION_TABLE"),
    ("src/shared/ioprio-util.c", "ioprio_class_table", "src/basic/rust/netdev_str_tables.rs", "IOPRIO_CLASS_TABLE"),
)


def block(text: str, start: int, open_: str, close: str) -> str:
    depth = 0
    for end in range(start, len(text)):
        depth += text[end] == open_
        depth -= text[end] == close
        if depth == 0:
            return text[start : end + 1]
    raise ValueError("unterminated declaration")


def c_entries(source: Path, table: str) -> list[bytes]:
    text = source.read_text()
    match = re.search(rf"\b{re.escape(table)}\s*(?:\[[^]]*\])?\s*=\s*\{{", text)
    if not match:
        raise ValueError(f"{source}: missing C table {table}")
    contents = block(text, text.index("{", match.start()), "{", "}")
    return [ast.literal_eval(f'b"{s}"') for s in re.findall(r'\[[^]]+\]\s*=\s*"((?:\\.|[^"\\])*)"', contents)]


def rust_entries(source: Path, table: str) -> list[bytes]:
    text = source.read_text()
    match = re.search(rf"\bstatic\s+{re.escape(table)}\b[^=]*=\s*&\s*\[", text)
    if not match:
        raise ValueError(f"{source}: missing Rust table {table}")
    contents = block(text, text.index("[", match.end() - 1), "[", "]")
    return [ast.literal_eval(f'b"{s}"').removesuffix(b"\0") for s in re.findall(r'b"((?:\\.|[^"\\])*)"', contents)]


def uapi_values(enum_name: str) -> dict[str, int]:
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", UAPI.read_text(), flags=re.DOTALL)
    match = re.search(rf"enum\s+{enum_name}\s*\{{", text)
    if not match:
        raise ValueError(f"{UAPI}: missing enum {enum_name}")
    values, next_value = {}, 0
    for symbol, value in re.findall(r"\b(NL80211_(?:CMD|IFTYPE)_[A-Z0-9_]+)\b\s*(?:=\s*([^,]+))?\s*,", block(text, text.index("{", match.start()), "{", "}")):
        # `*_MAX = __... - 1` is a sentinel, never a table designator.
        # Keeping it out avoids accepting a partial expression evaluator.
        if symbol.endswith("_MAX"):
            continue
        if value:
            next_value = enum_expression(value.strip(), values)
        values[symbol], next_value = next_value, next_value + 1
    return values


def enum_expression(expression: str, values: dict[str, int]) -> int:
    """Resolve the deliberately small integer-expression subset used by nl80211.

    UAPI command names are occasionally kept as aliases while their preferred
    spelling changes.  Enum initializers may therefore refer to an earlier
    enumerator.  Parse those references instead of evaluating header text; a
    reference to an unknown (or forward) symbol remains a hard failure.
    """
    try:
        node = ast.parse(expression, mode="eval").body
    except SyntaxError as error:
        raise ValueError(f"{UAPI}: unsupported enum expression {expression!r}") from error

    def resolve(node: ast.expr) -> int:
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name):
            try:
                return values[node.id]
            except KeyError as error:
                raise ValueError(
                    f"{UAPI}: unknown or forward enum symbol {node.id!r} in {expression!r}"
                ) from error
        if isinstance(node, ast.UnaryOp):
            operand = resolve(node.operand)
            if isinstance(node.op, ast.UAdd):
                return operand
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.Invert):
                return ~operand
        if isinstance(node, ast.BinOp):
            left, right = resolve(node.left), resolve(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.LShift):
                return left << right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitAnd):
                return left & right
        raise ValueError(f"{UAPI}: unsupported enum expression {expression!r}")

    return resolve(node)


def platform_entries(c_table: str, rust_table: str, enum_name: str) -> tuple[dict[int, bytes], dict[int, bytes]]:
    values = uapi_values(enum_name)
    c_text = WIFI_C.read_text()
    c_match = re.search(rf"\b{c_table}\s*(?:\[[^]]*\])?\s*=\s*\{{", c_text)
    c_block = block(c_text, c_text.index("{", c_match.start()), "{", "}")
    expected = {values[k]: ast.literal_eval(f'b"{v}"') for k, v in re.findall(r'\[(NL80211_(?:CMD|IFTYPE)_[A-Z0-9_]+)\]\s*=\s*"((?:\\.|[^"\\])*)"', c_block)}
    r_text = WIFI_RUST.read_text()
    r_match = re.search(rf"\bstatic\s+{rust_table}\b[^=]*=\s*&\s*\[", r_text)
    r_block = block(r_text, r_text.index("[", r_match.end() - 1), "[", "]")
    actual = {int(k): ast.literal_eval(f'b"{v}"').removesuffix(b"\0") for k, v in re.findall(r'\(\s*(\d+)\s*,\s*b"((?:\\.|[^"\\])*)"\s*\)', r_block)}
    return expected, actual


def main() -> int:
    errors, entries = [], 0
    platform_checked = 0
    for c_source, c_table, rust_source, rust_table in TABLES:
        try:
            expected, actual = c_entries(ROOT / c_source, c_table), rust_entries(ROOT / rust_source, rust_table)
            entries += len(expected)
            if expected != actual:
                errors.append(f"{rust_table} differs from {c_source}:{c_table}: C={expected!r}, Rust={actual!r}")
        except (ValueError, SyntaxError) as error:
            errors.append(str(error))
    try:
        if UAPI.is_file():
            for enum, c_table, rust_table in (("nl80211_commands", "nl80211_cmd_table", "NL80211_CMD_TABLE"), ("nl80211_iftype", "nl80211_iftype_table", "NL80211_IFTYPE_TABLE")):
                expected, actual = platform_entries(c_table, rust_table, enum)
                entries += len(expected)
                platform_checked += 1
                if expected != actual:
                    errors.append(f"{rust_table} differs from current C + Linux UAPI: C={expected!r}, Rust={actual!r}")
    except (ValueError, SyntaxError, AttributeError) as error:
        errors.append(str(error))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"string-table source parity: tables={len(TABLES)} entries={entries} platform_tables={platform_checked}/2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
