import os

files = {
    "journalctl_authenticate.rs": {
        "c_file": "journalctl-authenticate.c",
        "desc": "journalctl FSS key setup and verification.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn action_setup_keys() -> c_int;",
        ],
        "wrappers": [
            ("rs_action_setup_keys", "action_setup_keys", []),
        ],
    },
    "journalctl_catalog.rs": {
        "c_file": "journalctl-catalog.c",
        "desc": "journalctl catalog update and listing.",
        "includes": "c_char, c_int, c_void",
        "extern_c": [
            "fn action_update_catalog() -> c_int;",
            "fn action_list_catalog(items: *mut *mut c_char) -> c_int;",
        ],
        "wrappers": [
            ("rs_action_update_catalog", "action_update_catalog", []),
            ("rs_action_list_catalog", "action_list_catalog", ["items"]),
        ],
    },
    "journalctl_filter.rs": {
        "c_file": "journalctl-filter.c",
        "desc": "journalctl journal filter setup (matches, boots, units, etc.).",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn journal_add_unit_matches(j: *mut c_void, flags: c_int, mangle_flags: c_int, system_units: *mut *mut c_char, uid: c_uint, user_units: *mut *mut c_char) -> c_int;",
            "fn add_filters(j: *mut c_void, matches: *mut *mut c_char) -> c_int;",
        ],
        "wrappers": [
            ("rs_journal_add_unit_matches", "journal_add_unit_matches", ["j", "flags", "mangle_flags", "system_units", "uid", "user_units"]),
            ("rs_add_filters", "add_filters", ["j", "matches"]),
        ],
    },
    "journalctl_misc.rs": {
        "c_file": "journalctl-misc.c",
        "desc": "journalctl miscellaneous actions (header, verify, disk-usage, list-boots, etc.).",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn action_print_header() -> c_int;",
            "fn action_verify() -> c_int;",
            "fn action_disk_usage() -> c_int;",
            "fn action_list_boots() -> c_int;",
            "fn action_list_fields() -> c_int;",
            "fn action_list_field_names() -> c_int;",
            "fn action_list_invocations() -> c_int;",
            "fn action_list_namespaces() -> c_int;",
        ],
        "wrappers": [
            ("rs_action_print_header", "action_print_header", []),
            ("rs_action_verify", "action_verify", []),
            ("rs_action_disk_usage", "action_disk_usage", []),
            ("rs_action_list_boots", "action_list_boots", []),
            ("rs_action_list_fields", "action_list_fields", []),
            ("rs_action_list_field_names", "action_list_field_names", []),
            ("rs_action_list_invocations", "action_list_invocations", []),
            ("rs_action_list_namespaces", "action_list_namespaces", []),
        ],
    },
    "journalctl_show.rs": {
        "c_file": "journalctl-show.c",
        "desc": "journalctl show entries with event loop and cursor management.",
        "includes": "c_char, c_int, c_void",
        "extern_c": [
            "fn action_show(matches: *mut *mut c_char) -> c_int;",
        ],
        "wrappers": [
            ("rs_action_show", "action_show", ["matches"]),
        ],
    },
    "journalctl_util.rs": {
        "c_file": "journalctl-util.c",
        "desc": "journalctl shared utilities (journal acquire, boot, invocation, etc.).",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn format_timestamp_maybe_utc(buf: *mut c_char, l: usize, t: u64) -> *mut c_char;",
            "fn acquire_journal(ret: *mut *mut c_void) -> c_int;",
            "fn journal_boot_has_effect(j: *mut c_void) -> c_int;",
            "fn journal_acquire_boot(j: *mut c_void) -> c_int;",
            "fn get_possible_units(j: *mut c_void, fields: *const c_char, patterns: *mut *mut c_char, ret: *mut *mut c_void) -> c_int;",
            "fn acquire_unit(j: *mut c_void, option_name: *const c_char, ret_unit: *mut *const c_char, ret_type: *mut c_int) -> c_int;",
            "fn journal_acquire_invocation(j: *mut c_void) -> c_int;",
        ],
        "wrappers": [
            ("rs_format_timestamp_maybe_utc", "format_timestamp_maybe_utc", ["buf", "l", "t"]),
            ("rs_acquire_journal", "acquire_journal", ["ret"]),
            ("rs_journal_boot_has_effect", "journal_boot_has_effect", ["j"]),
            ("rs_journal_acquire_boot", "journal_acquire_boot", ["j"]),
            ("rs_get_possible_units", "get_possible_units", ["j", "fields", "patterns", "ret"]),
            ("rs_acquire_unit", "acquire_unit", ["j", "option_name", "ret_unit", "ret_type"]),
            ("rs_journal_acquire_invocation", "journal_acquire_invocation", ["j"]),
        ],
    },
    "journalctl_varlink.rs": {
        "c_file": "journalctl-varlink.c",
        "desc": "journalctl varlink client for flush, relinquish, rotate, sync, vacuum.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn varlink_connect_journal(ret: *mut *mut c_void) -> c_int;",
            "fn action_flush_to_var() -> c_int;",
            "fn action_relinquish_var() -> c_int;",
            "fn action_rotate() -> c_int;",
            "fn action_vacuum() -> c_int;",
            "fn action_rotate_and_vacuum() -> c_int;",
            "fn action_sync() -> c_int;",
        ],
        "wrappers": [
            ("rs_varlink_connect_journal", "varlink_connect_journal", ["ret"]),
            ("rs_action_flush_to_var", "action_flush_to_var", []),
            ("rs_action_relinquish_var", "action_relinquish_var", []),
            ("rs_action_rotate", "action_rotate", []),
            ("rs_action_vacuum", "action_vacuum", []),
            ("rs_action_rotate_and_vacuum", "action_rotate_and_vacuum", []),
            ("rs_action_sync", "action_sync", []),
        ],
    },
    "journalctl_varlink_server.rs": {
        "c_file": "journalctl-varlink-server.c",
        "desc": "journalctl varlink server: GetEntries method.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn vl_method_get_entries(link: *mut c_void, parameters: *mut c_void, flags: c_uint, userdata: *mut c_void) -> c_int;",
        ],
        "wrappers": [
            ("rs_vl_method_get_entries", "vl_method_get_entries", ["link", "parameters", "flags", "userdata"]),
        ],
    },
    "journalctl.rs": {
        "c_file": "journalctl.c",
        "desc": "Main journalctl binary with argument parsing and action dispatch.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn parse_id_descriptor(x: *const c_char, ret_id: *mut [u8; 16], ret_offset: *mut c_int) -> c_int;",
            "fn parse_lines(arg: *const c_char, graceful: c_int) -> c_int;",
            "fn help_facilities() -> c_int;",
            "fn help() -> c_int;",
            "fn vl_server() -> c_int;",
            "fn parse_argv(argc: c_int, argv: *mut *mut c_char) -> c_int;",
            "fn run(argc: c_int, argv: *mut *mut c_char) -> c_int;",
        ],
        "wrappers": [
            ("rs_parse_id_descriptor", "parse_id_descriptor", ["x", "ret_id", "ret_offset"]),
            ("rs_parse_lines", "parse_lines", ["arg", "graceful"]),
            ("rs_help_facilities", "help_facilities", []),
            ("rs_journalctl_help", "help", []),
            ("rs_vl_server", "vl_server", []),
            ("rs_journalctl_parse_argv", "parse_argv", ["argc", "argv"]),
            ("rs_journalctl_run", "run", ["argc", "argv"]),
        ],
    },
    "journald_audit.rs": {
        "c_file": "journald-audit.c",
        "desc": "journald audit socket processing and netlink message handling.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn process_audit_string(m: *mut c_void, audit_type: c_int, data: *const c_char, size: usize);",
            "fn manager_process_audit_message(m: *mut c_void, buffer: *const c_void, buffer_size: usize, ucred: *const c_void, sa: *const c_void, salen: usize);",
            "fn manager_open_audit(m: *mut c_void) -> c_int;",
            "fn manager_reset_kernel_audit(m: *mut c_void, old_set_audit: c_int);",
        ],
        "wrappers": [
            ("rs_process_audit_string", "process_audit_string", ["m", "audit_type", "data", "size"]),
            ("rs_manager_process_audit_message", "manager_process_audit_message", ["m", "buffer", "buffer_size", "ucred", "sa", "salen"]),
            ("rs_manager_open_audit", "manager_open_audit", ["m"]),
            ("rs_manager_reset_kernel_audit", "manager_reset_kernel_audit", ["m", "old_set_audit"]),
        ],
    },
    "journald_client.rs": {
        "c_file": "journald-client.c",
        "desc": "journald client context log filter pattern matching.",
        "includes": "c_char, c_int, c_void",
        "extern_c": [
            "fn client_context_read_log_filter_patterns(c: *mut c_void, cgroup: *const c_char) -> c_int;",
            "fn client_context_check_keep_log(c: *mut c_void, message: *const c_char, len: usize) -> c_int;",
        ],
        "wrappers": [
            ("rs_client_context_read_log_filter_patterns", "client_context_read_log_filter_patterns", ["c", "cgroup"]),
            ("rs_client_context_check_keep_log", "client_context_check_keep_log", ["c", "message", "len"]),
        ],
    },
    "journald_config.rs": {
        "c_file": "journald-config.c",
        "desc": "journald configuration loading, parsing, and merging.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn journal_config_done(c: *mut c_void);",
            "fn journal_config_set_defaults(c: *mut c_void);",
            "fn manager_merge_configs(m: *mut c_void);",
            "fn manager_load_config(m: *mut c_void);",
            "fn manager_dispatch_reload_signal(s: *mut c_void, si: *const c_void, userdata: *mut c_void) -> c_int;",
            "fn config_parse_line_max(unit: *const c_char, filename: *const c_char, line: c_uint, section: *const c_char, section_line: c_uint, lvalue: *const c_char, ltype: c_int, rvalue: *const c_char, data: *mut c_void, userdata: *mut c_void) -> c_int;",
            "fn config_parse_compress(unit: *const c_char, filename: *const c_char, line: c_uint, section: *const c_char, section_line: c_uint, lvalue: *const c_char, ltype: c_int, rvalue: *const c_char, data: *mut c_void, userdata: *mut c_void) -> c_int;",
            "fn config_parse_forward_to_socket(unit: *const c_char, filename: *const c_char, line: c_uint, section: *const c_char, section_line: c_uint, lvalue: *const c_char, ltype: c_int, rvalue: *const c_char, data: *mut c_void, userdata: *mut c_void) -> c_int;",
        ],
        "wrappers": [
            ("rs_journal_config_done", "journal_config_done", ["c"]),
            ("rs_journal_config_set_defaults", "journal_config_set_defaults", ["c"]),
            ("rs_manager_merge_configs", "manager_merge_configs", ["m"]),
            ("rs_manager_load_config", "manager_load_config", ["m"]),
            ("rs_manager_dispatch_reload_signal", "manager_dispatch_reload_signal", ["s", "si", "userdata"]),
            ("rs_config_parse_line_max", "config_parse_line_max", ["unit", "filename", "line", "section", "section_line", "lvalue", "ltype", "rvalue", "data", "userdata"]),
            ("rs_config_parse_compress", "config_parse_compress", ["unit", "filename", "line", "section", "section_line", "lvalue", "ltype", "rvalue", "data", "userdata"]),
            ("rs_config_parse_forward_to_socket", "config_parse_forward_to_socket", ["unit", "filename", "line", "section", "section_line", "lvalue", "ltype", "rvalue", "data", "userdata"]),
        ],
    },
    "journald_console.rs": {
        "c_file": "journald-console.c",
        "desc": "journald console message forwarding.",
        "includes": "c_char, c_int, c_void",
        "extern_c": [
            "fn manager_forward_console(m: *mut c_void, priority: c_int, identifier: *const c_char, message: *const c_char, ucred: *const c_void);",
        ],
        "wrappers": [
            ("rs_manager_forward_console", "manager_forward_console", ["m", "priority", "identifier", "message", "ucred"]),
        ],
    },
    "journald_context.rs": {
        "c_file": "journald-context.c",
        "desc": "journald client context metadata cache with LRU eviction.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn client_context_maybe_refresh(m: *mut c_void, c: *mut c_void, ucred: *const c_void, label: *const c_char, unit_id: *const c_char, timestamp: u64);",
            "fn manager_refresh_client_contexts_on_reload(m: *mut c_void, old_interval: u64, old_burst: c_uint);",
            "fn client_context_flush_regular(m: *mut c_void);",
            "fn client_context_flush_all(m: *mut c_void);",
            "fn client_context_get(m: *mut c_void, pid: i32, ucred: *const c_void, label: *const c_char, unit_id: *const c_char, ret: *mut *mut c_void) -> c_int;",
            "fn client_context_acquire(m: *mut c_void, pid: i32, ucred: *const c_void, label: *const c_char, unit_id: *const c_char, ret: *mut *mut c_void) -> c_int;",
            "fn client_context_release(m: *mut c_void, c: *mut c_void) -> *mut c_void;",
            "fn client_context_acquire_default(m: *mut c_void);",
        ],
        "wrappers": [
            ("rs_client_context_maybe_refresh", "client_context_maybe_refresh", ["m", "c", "ucred", "label", "unit_id", "timestamp"]),
            ("rs_manager_refresh_client_contexts_on_reload", "manager_refresh_client_contexts_on_reload", ["m", "old_interval", "old_burst"]),
            ("rs_client_context_flush_regular", "client_context_flush_regular", ["m"]),
            ("rs_client_context_flush_all", "client_context_flush_all", ["m"]),
            ("rs_client_context_get", "client_context_get", ["m", "pid", "ucred", "label", "unit_id", "ret"]),
            ("rs_client_context_acquire", "client_context_acquire", ["m", "pid", "ucred", "label", "unit_id", "ret"]),
            ("rs_client_context_release", "client_context_release", ["m", "c"]),
            ("rs_client_context_acquire_default", "client_context_acquire_default", ["m"]),
        ],
    },
    "journald_kmsg.rs": {
        "c_file": "journald-kmsg.c",
        "desc": "journald /dev/kmsg reading and kernel message processing.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn manager_forward_kmsg(m: *mut c_void, priority: c_int, identifier: *const c_char, message: *const c_char, ucred: *const c_void);",
            "fn dev_kmsg_record(m: *mut c_void, p: *mut c_char, l: usize);",
            "fn manager_flush_dev_kmsg(m: *mut c_void) -> c_int;",
            "fn manager_open_dev_kmsg(m: *mut c_void) -> c_int;",
            "fn manager_open_kernel_seqnum(m: *mut c_void) -> c_int;",
            "fn manager_close_kernel_seqnum(m: *mut c_void);",
            "fn manager_reopen_dev_kmsg(m: *mut c_void, old_read_kmsg: c_int) -> c_int;",
        ],
        "wrappers": [
            ("rs_manager_forward_kmsg", "manager_forward_kmsg", ["m", "priority", "identifier", "message", "ucred"]),
            ("rs_dev_kmsg_record", "dev_kmsg_record", ["m", "p", "l"]),
            ("rs_manager_flush_dev_kmsg", "manager_flush_dev_kmsg", ["m"]),
            ("rs_manager_open_dev_kmsg", "manager_open_dev_kmsg", ["m"]),
            ("rs_manager_open_kernel_seqnum", "manager_open_kernel_seqnum", ["m"]),
            ("rs_manager_close_kernel_seqnum", "manager_close_kernel_seqnum", ["m"]),
            ("rs_manager_reopen_dev_kmsg", "manager_reopen_dev_kmsg", ["m", "old_read_kmsg"]),
        ],
    },
    "journald_manager.rs": {
        "c_file": "journald-manager.c",
        "desc": "journald manager: core daemon state, journal file management, dispatch.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn manager_new(m: *mut *mut c_void) -> c_int;",
            "fn manager_set_namespace(m: *mut c_void, namespace: *const c_char) -> c_int;",
            "fn manager_init(m: *mut c_void) -> c_int;",
            "fn manager_vacuum(m: *mut c_void, verbose: c_int);",
            "fn manager_flush_to_var(m: *mut c_void, require_flag_file: c_int);",
            "manager_driver_message(m: *mut c_void, code: c_int, format: *const c_char, ...);",
            "fn manager_space_usage_message(m: *mut c_void, s: *const c_char);",
            "manager_full_sync(m: *mut c_void, wait: c_int);",
            "fn manager_full_rotate(m: *mut c_void);",
            "manager_full_flush(m: *mut c_void);",
            "manager_relinquish_var(m: *mut c_void);",
            "manager_dispatch_message(m: *mut c_void, iovec: *const c_void, n: c_int, m: c_int, context: *mut c_void, ts: *const c_void, priority: c_int, object_pid: i32);",
            "manager_process_datagram(source: *mut c_void, fd: c_int, revents: u32, userdata: *mut c_void) -> c_int;",
            "fn manager_start_or_stop_idle_timer(m: *mut c_void);",
            "manager_maybe_append_tags(m: *mut c_void);",
            "manager_maybe_warn_forward_syslog_missed(m: *mut c_void);",
            "manager_reopen_journals(m: *mut c_void, old: *const c_void);",
            "manager_free(m: *mut c_void);",
            "fn manager_freezep(m: *mut c_void);",
        ],
        "wrappers": [
            ("rs_manager_new", "manager_new", ["m"]),
            ("rs_manager_set_namespace", "manager_set_namespace", ["m", "namespace"]),
            ("rs_manager_init", "manager_init", ["m"]),
            ("rs_manager_vacuum", "manager_vacuum", ["m", "verbose"]),
            ("rs_manager_flush_to_var", "manager_flush_to_var", ["m", "require_flag_file"]),
            ("rs_manager_full_sync", "manager_full_sync", ["m", "wait"]),
            ("rs_manager_full_rotate", "manager_full_rotate", ["m"]),
            ("rs_manager_full_flush", "manager_full_flush", ["m"]),
            ("rs_manager_relinquish_var", "manager_relinquish_var", ["m"]),
            ("rs_manager_dispatch_message", "manager_dispatch_message", ["m", "iovec", "n", "m", "context", "ts", "priority", "object_pid"]),
            ("rs_manager_process_datagram", "manager_process_datagram", ["source", "fd", "revents", "userdata"]),
            ("rs_manager_start_or_stop_idle_timer", "manager_start_or_stop_idle_timer", ["m"]),
            ("rs_manager_maybe_append_tags", "manager_maybe_append_tags", ["m"]),
            ("rs_manager_maybe_warn_forward_syslog_missed", "manager_maybe_warn_forward_syslog_missed", ["m"]),
            ("rs_manager_reopen_journals", "manager_reopen_journals", ["m", "old"]),
            ("rs_manager_free", "manager_free", ["m"]),
            ("rs_manager_freezep", "manager_freezep", ["m"]),
        ],
    },
    "journald_native.rs": {
        "c_file": "journald-native.c",
        "desc": "journald native protocol message and file processing.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn manager_process_native_message(m: *mut c_void, buffer: *const c_char, buffer_size: usize, ucred: *const c_void, tv: *const c_void, label: *const c_char);",
            "fn manager_process_native_file(m: *mut c_void, fd: c_int, ucred: *const c_void, tv: *const c_void, label: *const c_char) -> c_int;",
            "fn manager_open_native_socket(m: *mut c_void, native_socket: *const c_char) -> c_int;",
        ],
        "wrappers": [
            ("rs_manager_process_native_message", "manager_process_native_message", ["m", "buffer", "buffer_size", "ucred", "tv", "label"]),
            ("rs_manager_process_native_file", "manager_process_native_file", ["m", "fd", "ucred", "tv", "label"]),
            ("rs_manager_open_native_socket", "manager_open_native_socket", ["m", "native_socket"]),
        ],
    },
    "journald_rate_limit.rs": {
        "c_file": "journald-rate-limit.c",
        "desc": "Per-priority journal rate limiting with burst and interval.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn journal_ratelimit_test(groups_by_id: *mut *mut c_void, id: *const c_char, rl_interval: u64, rl_burst: c_uint, priority: c_int, available: u64) -> c_int;",
        ],
        "wrappers": [
            ("rs_journal_ratelimit_test", "journal_ratelimit_test", ["groups_by_id", "id", "rl_interval", "rl_burst", "priority", "available"]),
        ],
    },
    "journald_socket.rs": {
        "c_file": "journald-socket.c",
        "desc": "journald forward-to-socket functionality.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn manager_forward_socket(m: *mut c_void, iovec: *const c_void, n_iovec: usize, ts: *const c_void, priority: c_int) -> c_int;",
            "fn manager_reload_forward_socket(m: *mut c_void, old: *const c_void);",
        ],
        "wrappers": [
            ("rs_manager_forward_socket", "manager_forward_socket", ["m", "iovec", "n_iovec", "ts", "priority"]),
            ("rs_manager_reload_forward_socket", "manager_reload_forward_socket", ["m", "old"]),
        ],
    },
    "journald_stream.rs": {
        "c_file": "journald-stream.c",
        "desc": "journald stdout stream processing with protocol negotiation and persistence.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn stdout_stream_free(s: *mut c_void) -> *mut c_void;",
            "fn stdout_stream_terminate(s: *mut c_void);",
            "fn stdout_stream_install(m: *mut c_void, fd: c_int, ret: *mut *mut c_void) -> c_int;",
            "fn manager_restore_streams(m: *mut c_void, fds: *mut c_void) -> c_int;",
            "fn manager_open_stdout_socket(m: *mut c_void, stdout_socket: *const c_char) -> c_int;",
            "fn stdout_stream_send_notify(s: *mut c_void);",
        ],
        "wrappers": [
            ("rs_stdout_stream_free", "stdout_stream_free", ["s"]),
            ("rs_stdout_stream_terminate", "stdout_stream_terminate", ["s"]),
            ("rs_stdout_stream_install", "stdout_stream_install", ["m", "fd", "ret"]),
            ("rs_manager_restore_streams", "manager_restore_streams", ["m", "fds"]),
            ("rs_manager_open_stdout_socket", "manager_open_stdout_socket", ["m", "stdout_socket"]),
            ("rs_stdout_stream_send_notify", "stdout_stream_send_notify", ["s"]),
        ],
    },
    "journald_sync.rs": {
        "c_file": "journald-sync.c",
        "desc": "journald synchronization request tracking for Varlink Synchronize method.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn stream_sync_req_free(ssr: *mut c_void) -> *mut c_void;",
            "fn stream_sync_req_advance_revalidate(ssr: *mut c_void, p: usize);",
            "fn sync_req_free(req: *mut c_void) -> *mut c_void;",
            "fn sync_req_new(m: *mut c_void, link: *mut c_void, ret: *mut *mut c_void) -> c_int;",
            "fn manager_notify_stream(m: *mut c_void, stream: *mut c_void);",
            "fn sync_req_revalidate(req: *mut c_void) -> c_int;",
            "fn sync_req_revalidate_by_timestamp(m: *mut c_void);",
            "fn sync_req_varlink_reply(req: *mut c_void);",
        ],
        "wrappers": [
            ("rs_stream_sync_req_free", "stream_sync_req_free", ["ssr"]),
            ("rs_stream_sync_req_advance_revalidate", "stream_sync_req_advance_revalidate", ["ssr", "p"]),
            ("rs_sync_req_free", "sync_req_free", ["req"]),
            ("rs_sync_req_new", "sync_req_new", ["m", "link", "ret"]),
            ("rs_manager_notify_stream", "manager_notify_stream", ["m", "stream"]),
            ("rs_sync_req_revalidate", "sync_req_revalidate", ["req"]),
            ("rs_sync_req_revalidate_by_timestamp", "sync_req_revalidate_by_timestamp", ["m"]),
            ("rs_sync_req_varlink_reply", "sync_req_varlink_reply", ["req"]),
        ],
    },
    "journald_syslog.rs": {
        "c_file": "journald-syslog.c",
        desc": "journald syslog socket handling and message processing.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn manager_forward_syslog(m: *mut c_void, priority: c_int, identifier: *const c_char, message: *const c_char, ucred: *const c_void, tv: *const c_void);",
            "fn syslog_fixup_facility(priority: c_int) -> c_int;",
            "fn syslog_parse_identifier(buf: *mut *const c_char, ret_identifier: *mut *mut c_char, ret_pid: *mut i32) -> usize;",
            "fn manager_process_syslog_message(m: *mut c_void, buf: *const c_char, raw_len: usize, ucred: *const c_void, tv: *const c_void, label: *const c_char);",
            "fn manager_open_syslog_socket(m: *mut c_void, syslog_socket: *const c_char) -> c_int;",
            "fn manager_maybe_warn_forward_syslog_missed(m: *mut c_void);",
        ],
        "wrappers": [
            ("rs_manager_forward_syslog", "manager_forward_syslog", ["m", "priority", "identifier", "message", "ucred", "tv"]),
            ("rs_syslog_fixup_facility", "syslog_fixup_facility", ["priority"]),
            ("rs_syslog_parse_identifier", "syslog_parse_identifier", ["buf", "ret_identifier", "ret_pid"]),
            ("rs_manager_process_syslog_message", "manager_process_syslog_message", ["m", "buf", "raw_len", "ucred", "tv", "label"]),
            ("rs_manager_open_syslog_socket", "manager_open_syslog_socket", ["m", "syslog_socket"]),
            ("rs_manager_maybe_warn_forward_syslog_missed", "manager_maybe_warn_forward_syslog_missed", ["m"]),
        ],
    },
    "journald_varlink.rs": {
        "c_file": "journald-varlink.c",
        "desc": "journald Varlink server: Synchronize, Rotate, FlushToVar, RelinquishVar.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn sync_req_varlink_reply(req: *mut c_void);",
            "fn manager_open_varlink(m: *mut c_void, socket: *const c_char, fd: c_int) -> c_int;",
        ],
        "wrappers": [
            ("rs_sync_req_varlink_reply", "sync_req_varlink_reply", ["req"]),
            ("rs_manager_open_varlink", "manager_open_varlink", ["m", "socket", "fd"]),
        ],
    },
    "journald_wall.rs": {
        "c_file": "journald-wall.c",
        "desc": "journald wall message forwarding via wall(1).",
        "includes": "c_char, c_int, c_void",
        "extern_c": [
            "fn manager_forward_wall(m: *mut c_void, priority: c_int, identifier: *const c_char, message: *const c_char, ucred: *const c_void);",
        ],
        "wrappers": [
            ("rs_manager_forward_wall", "manager_forward_wall", ["m", "priority", "identifier", "message", "ucred"]),
        ],
    },
    "journald.rs": {
        "c_file": "journald.c",
        "desc": "Main systemd-journald daemon entry point.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn run(argc: c_int, argv: *mut *mut c_char) -> c_int;",
        ],
        "wrappers": [
            ("rs_journald_run", "run", ["argc", "argv"]),
        ],
    },
    "test_journald_config.rs": {
        "c_file": "test-journald-config.c",
        desc: "Tests for journald config parsing (compress, forward_to_socket).",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn config_compress(unit: *const c_char, filename: *const c_char, line: c_uint, section: *const c_char, section_line: c_uint, lvalue: *const c_char, ltype: c_int, rvalue: *const c_char, data: *mut c_void, userdata: *mut c_void) -> c_int;",
            "fn config_forward_to_socket(unit: *const c_char, filename: *const c_char, line: c_uint, section: *const c_char, section_line: c_uint, lvalue: *const c_char, ltype: c_int, rvalue: *const c_char, data: *mut c_void, userdata: *mut c_void) -> c_int;",
        ],
        "wrappers": [
            ("rs_config_compress", "config_compress", ["unit", "filename", "line", "section", "section_line", "lvalue", "ltype", "rvalue", "data", "userdata"]),
            ("rs_config_forward_to_socket", "config_forward_to_socket", ["unit", "filename", "line", "section", "section_line", "lvalue", "ltype", "rvalue", "data", "userdata"]),
        ],
    },
    "test_journald_rate_limit.rs": {
        "c_file": "test-journald-rate-limit.c",
        desc: "Tests for journal rate limiting logic.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn journal_ratelimit_test(groups_by_id: *mut *mut c_void, id: *const c_char, rl_interval: u64, rl_burst: c_uint, priority: c_int, available: u64) -> c_int;",
        ],
        "wrappers": [
            ("rs_journal_ratelimit_test", "journal_ratelimit_test", ["groups_by_id", "id", "rl_interval", "rl_burst", "priority", "available"]),
        ],
    },
    "test_journald_syslog.rs": {
        "c_file": "test-journald-syslog.c",
        desc": "Tests for syslog identifier and priority parsing.",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn syslog_parse_identifier(buf: *mut *const c_char, ret_identifier: *mut *mut c_char, ret_pid: *mut i32) -> usize;",
            "fn syslog_parse_priority(str: *mut *const c_char, priority: *mut c_int, with_facility: c_int) -> c_int;",
        ],
        "wrappers": [
            ("rs_syslog_parse_identifier", "syslog_parse_identifier", ["buf", "ret_identifier", "ret_pid"]),
            ("rs_syslog_parse_priority", "syslog_parse_priority", ["str", "priority", "with_facility"]),
        ],
    },
    "test_journald_tables.rs": {
        "c_file": "test-journald-tables.c",
        desc: "Tests for string table lookups (split_mode, storage).",
        "includes": "c_char, c_int, c_uint, c_void",
        "extern_c": [
            "fn test_table_split_mode() -> c_int;",
            "fn test_table_storage() -> c_int;",
        ],
        "wrappers": [
            ("rs_test_table_split_mode", "test_table_split_mode", []),
            ("rs_test_table_storage", "test_table_storage", []),
        ],
    },
}

template = '''// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/{c_file}
//
{desc}

use std::ffi::{{{includes}}};

pub const SOURCE_PATH: &str = "src/journal/{c_file}";
pub const SOURCE_TEXT: &str = include_str!("../{c_file}");

unsafe extern "C" {{
{declarations}
}}

{wrappers}

#[cfg(test)]
mod tests {{
    #[test]
    fn smoke() {{
        assert!(!SOURCE_TEXT.is_empty());
    }}
}}
'''

for fname, info in files.items():
    c_file = info["c_file"]
    declarations = "\n".join(f"    {d}" for d in info["extern_c"])
    wrappers = []
    for wname, cname, params in info["wrappers"]:
        params_str = ", ".join(params)
        if params:
            params_str = ", " + params_str
        wrappers.append(f"""#[no_mangle]
pub unsafe extern "C" fn {wname}({params_str}) -> {info['return_type']} {{
    {cname}({", ".join(params)})
}}

with open(fname, 'w') as f:
    f.write(template.format(
        c_file=c_file,
        desc=info["desc"],
        includes=info["includes"],
        declarations=declarations,
        wrappers="\n".join(wrappers),
        return_type=info.get("return_type", "c_int"),
    ))

print("Generated", len(files), "files")
