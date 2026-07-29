# SPDX-License-Identifier: LGPL-2.1-or-later

basic_sources = files(
        'MurmurHash2.c',
        'af-list.c',
        'alloc-util.c',
        'ansi-color.c',
        'architecture.c',
        'argv-util.c',
        'arphrd-util.c',
        'assert-util.c',
        'audit-util.c',
        'btrfs-util.c',
        'build.c',
        'build-path.c',
        'bus-label.c',
        'capability-list.c',
        'capability-util.c',
        'capsule-util.c',
        'cgroup-util.c',
        'chase.c',
        'chattr-util.c',
        'compress.c',
        'conf-files.c',
        'confidential-virt.c',
        'device-nodes.c',
        'devnum-util.c',
        'dirent-util.c',
        'dlfcn-util.c',
        'efivars.c',
        'env-file.c',
        'env-util.c',
        'errno-list.c',
        'errno-util.c',
        'escape.c',
        'ether-addr-util.c',
        'extract-word.c',
        'fd-util.c',
        'fiber-ops.c',
        'fileio.c',
        'filesystems.c',
        'format-ifname.c',
        'format-util.c',
        'fs-util.c',
        'glob-util.c',
        'glyph-util.c',
        'gunicode.c',
        'hash-funcs.c',
        'hashmap.c',
        'hexdecoct.c',
        'hmac.c',
        'hostname-util.c',
        'in-addr-util.c',
        'initrd-util.c',
        'inotify-util.c',
        'io-util.c',
        'iovec-util.c',
        'iovec-wrapper.c',
        'keyring-util.c',
        'label-util.c',
        'limits-util.c',
        'locale-util.c',
        'lock-util.c',
        'log.c',
        'log-context.c',
        'login-util.c',
        'math-util.c',
        'memfd-util.c',
        'memory-util.c',
        'mempool.c',
        'memstream-util.c',
        'mkdir.c',
        'mountpoint-util.c',
        'namespace-util.c',
        'nulstr-util.c',
        'ordered-set.c',
        'os-util.c',
        'parse-util.c',
        'path-util.c',
        'percent-util.c',
        'pidfd-util.c',
        'pidref.c',
        'prioq.c',
        'proc-cmdline.c',
        'process-util.c',
        'procfs-util.c',
        'psi-util.c',
        'random-util.c',
        'ratelimit.c',
        'raw-clone.c',
        'recurse-dir.c',
        'replace-var.c',
        'rlimit-util.c',
        'runtime-scope.c',
        'sha256.c',
        'sigbus.c',
        'signal-util.c',
        'siphash24.c',
        'socket-util.c',
        'sort-util.c',
        'stat-util.c',
        'static-destruct.c',
        'stdio-util.c',
        'strbuf.c',
        'string-table.c',
        'string-util.c',
        'strv.c',
        'strxcpyx.c',
        'sync-util.c',
        'sysctl-util.c',
        'syslog-util.c',
        'terminal-util.c',
        'time-util.c',
        'tmpfile-util.c',
        'uid-classification.c',
        'uid-range.c',
        'unit-def.c',
        'unit-name.c',
        'user-util.c',
        'utf8.c',
        'virt.c',
        'xattr-util.c',
)

sources += basic_sources

generated_gperf_headers = []
errno_list_txt = []
foreach item : [
        # name,             source,             prefix,    headers
        ['af',              af_sources,         '',        ['<sys/socket.h>'],       ],
        ['arphrd',          arphrd_sources,     'ARPHRD_', ['<linux/if_arp.h>'],     ],
        ['capability',      capability_sources, '',        ['<linux/capability.h>'], ],
        ['errno',           [],                 '',        ['<errno.h>'],            ],
        ['statx-mask',      statx_sources                                            ],
        ['statx-attribute', statx_sources                                            ],
]

        generate_list = files('generate-@0@-list.sh'.format(item[0]))
        list_txt = custom_target(
                input : [generate_list, item[1]],
                output : '@0@-list.txt'.format(item[0]),
                command : [env, 'bash', generate_list, cpp, system_include_args],
                capture : true)

        if item[0] == 'errno'
                errno_list_txt = list_txt
        endif

        awkscript = '@0@-to-name.awk'.format(item[0])
        target = custom_target(
                input : [awkscript, list_txt],
                output : '@0@-to-name.inc'.format(item[0]),
                command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
                capture : true)

        generated_gperf_headers += [target]

        if item.length() > 2
                gperf_file = custom_target(
                        input : list_txt,
                        output : '@0@-from-name.gperf'.format(item[0]),
                        command : [generate_gperfs, item[0], item[2], '@INPUT@'] + item[3],
                        capture : true)

                target = custom_target(
                        input : gperf_file,
                        output : '@0@-from-name.inc'.format(item[0]),
                        command : [gperf,
                                '-L', 'ANSI-C', '-t', '--ignore-case',
                                '-N', 'lookup_@0@'.format(item[0]),
                                '-H', 'hash_@0@_name'.format(item[0]),
                                '-p', '-C',
                                '@INPUT@'],
                        capture : true)

                generated_gperf_headers += [target]
        endif
endforeach

generated_sources += generated_gperf_headers
basic_sources += generated_gperf_headers

errno_to_name_rust = custom_target(
        input : [files('generate-errno-rust.py'), errno_list_txt],
        output : 'errno-to-name-rust.rs',
        command : [python, '@INPUT0@', '@INPUT1@', '@OUTPUT@', cpp, system_include_args])

############################################################

filesystem_sets_py = files('filesystem-sets.py')
filesystem_sets_c = custom_target(
        output : 'filesystem-sets.c',
        command : [filesystem_sets_py,
                   'fs-type-to-string',
                   'filesystem-sets',
                   'fs-in-group'],
        capture : true)

filesystems_gperf_gperf = custom_target(
        output : 'filesystems-gperf.gperf',
        command : [filesystem_sets_py,
                   'gperf'],
        capture : true)

filesystems_gperf_h = custom_target(
        input : filesystems_gperf_gperf,
        output : 'filesystems-gperf.h',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += [filesystem_sets_c, filesystems_gperf_gperf, filesystems_gperf_h]
basic_sources += [filesystem_sets_c, filesystems_gperf_h]

test('kernel-filesystem-magics',
     filesystem_sets_py,
     args : ['check'],
     env : ['CPP=@0@'.format(cpp)])

# ── Rust shadow modules (optional) ─────────────────────────────────────────
# The Rust code builds as a standalone staticlib. It is NOT merged into
# libbasic — instead, shadow tests link against it explicitly.
# Rust functions use rs_ prefix to avoid symbol conflicts with C.
rust_staticlib = []
if get_option('rust').enabled()
        cargo = find_program('cargo', required : true)
        rust_sources = files(
                'rust/Cargo.toml',
                'rust/lib.rs',
                'rust/ffi.rs',
                'rust/ffi_string_table.rs',
                'rust/alloc_util.rs',
                'rust/argv_util.rs',
                'rust/ansi_color.rs',
                'rust/bus_label.rs',
                'rust/escape.rs',
                'rust/escape/allocating.rs',
                'rust/escape/core_abi.rs',
                'rust/escape/full_abi.rs',
                'rust/ether_addr_util.rs',
                'rust/extract_word.rs',
                'rust/format_util.rs',
                'rust/hexdecoct.rs',
                'rust/glyph_util.rs',
                'rust/gunicode.rs',
                'rust/header_inline_abi.rs',
                'rust/hostname_util.rs',
                'rust/in_addr_util.rs',
                'rust/devnum_util.rs',
                'rust/device_nodes.rs',
                'rust/env_util.rs',
                'rust/errno_util.rs',
                'rust/iovec_util.rs',
                'rust/iovec_wrapper.rs',
                'rust/parse_util.rs',
                'rust/path_util.rs',
                'rust/path_util/byte_abi.rs',
                'rust/percent_util.rs',
                'rust/prioq.rs',
                'rust/proc_cmdline.rs',
                'rust/ratelimit.rs',
                'rust/rlimit_util.rs',
                'rust/runtime_scope.rs',
                'rust/sha256_hmac.rs',
                'rust/mempool.rs',
                'rust/memory_util.rs',
                'rust/replace_var.rs',
                'rust/nulstr_util.rs',
                'rust/siphash24.rs',
                'rust/sort_util.rs',
                'rust/strbuf.rs',
                'rust/strv.rs',
                'rust/strv/allocating_transforms.rs',
                'rust/strv/matching_escape.rs',
                'rust/string_table.rs',
                'rust/time_util.rs',
                'rust/time_util/arithmetic.rs',
                'rust/time_util/conversion.rs',
                'rust/time_util/formatting.rs',
                'rust/time_util/parsing.rs',
                'rust/time_util/types.rs',
                'rust/string_util.rs',
                'rust/string_util_fundamental.rs',
                'rust/string_util_ffi.rs',
                'rust/string_util_escape.rs',
                'rust/string_util_json.rs',
                'rust/string_util_lines.rs',
                'rust/string_util_owned.rs',
                'rust/string_util_replace.rs',
                'rust/string_util_scan.rs',
                'rust/strxcpyx.rs',
                'rust/utf8.rs',
                'rust/unit_name.rs',
                'rust/unit_inline_abi.rs',
                'rust/signal_util.rs',
                'rust/syslog_util.rs',
                'rust/compress_util.rs',
                'rust/confidential_virt.rs',
                'rust/cgroup_util_str_tables.rs',
                'rust/image_class.rs',
                'rust/locale_util.rs',
                'rust/log_target.rs',
                'rust/process_util_str_tables.rs',
                'rust/uid_range.rs',
                'rust/unit_def.rs',
                'rust/virt.rs',
                'rust/netdev_str_tables.rs',
                'rust/netdev_str_tables/core.rs',
                'rust/netdev_str_tables/network_link.rs',
                'rust/netdev_str_tables/network_virtual.rs',
                'rust/netdev_str_tables/boot_import.rs',
                'rust/netdev_str_tables/resolve_modes.rs',
                'rust/netdev_str_tables/dns_security.rs',
                'rust/netdev_str_tables/tpm_bpf_wifi.rs',
                'rust/netdev_str_tables/tests.rs',
                'rust/dns_type_predicates.rs',
                'rust/dlfcn_util.rs',
                'rust/shared_facades/mod.rs',
                'rust/shared_facades/validation.rs',
                'rust/exit_status.rs',
                'rust/xml_tokenizer.rs',
                'rust/dns_domain_validators.rs',
                'rust/dns_label.rs',
                'rust/shared_facades/lookups.rs',
                'rust/gpt_util.rs',
                'rust/glob_util.rs',
                'rust/fstype_util.rs',
                'rust/user_shell_util.rs',
                'rust/misc_validators.rs',
                'rust/socket_util.rs',
                'rust/nsflags.rs',
                'rust/udev_util.rs',
        'rust/stat_util.rs',
        'rust/stat_util/descriptor.rs',
        'rust/stat_util/filesystem.rs',
        'rust/stat_util/hash.rs',
        'rust/stat_util/inode.rs',
        'rust/stat_util/inode_same.rs',
        'rust/stat_util/moderate.rs',
        'rust/stat_util/verification.rs',
        'rust/stat_util/xstatx.rs',
                'rust/user_util.rs',
                'rust/seccomp_util.rs',
                'rust/import_util.rs',
                'rust/terminal_util.rs',
                'rust/sysctl_util.rs',
                'rust/strverscmp.rs',
                'rust/compare_operator.rs',
                'rust/serialize.rs',
                'rust/procfs_util.rs',
                'rust/unaligned.rs',
                'rust/uid_classification.rs',
                'rust/safe_math.rs',
                'rust/ioprio_util.rs',
                'rust/errno_classify.rs',
                'rust/basic_validators.rs',
                'rust/sha1.rs',
                'rust/pe_binary.rs',
                'rust/bitmap.rs',
                'rust/bootspec_util.rs',
                'rust/id128_util.rs',
                'rust/image_policy_util.rs',
                'rust/exec_util.rs',
                'rust/efivars_util.rs',
                'rust/capability_util.rs',
                'rust/recovery_key.rs',
                'rust/mount_setup.rs',
                'rust/resize_fs_util.rs',
                'rust/specifier_util.rs',
                'rust/hostname_setup.rs',
                'rust/dirent_util.rs',
                'rust/namespace_util.rs',
                'rust/bus_type_util.rs',
                'rust/capability_list.rs',
                'rust/btrfs_util.rs',
                'rust/mountpoint_util.rs',
                'rust/credential_validators.rs',
                'rust/edid.rs',
                'rust/af_list.rs',
                'rust/arphrd_util.rs',
                'rust/xattr_util.rs',
        )
        rust_sources += rust_workspace_inputs + [errno_to_name_rust]

        rust_basic_build_script = '''
import os
import shutil
import subprocess
import sys

(out, manifest, target_dir, cargo,
 errno_to_name_rust,
 greeter_uid_min, greeter_uid_max,
 dynamic_uid_min, dynamic_uid_max,
 container_uid_min, container_uid_max,
 foreign_uid_min, foreign_uid_max,
 seccomp_arch_loongarch64, seccomp_arch_riscv64,
 have_xz, have_lz4, have_zstd, have_zlib, have_bzip2) = sys.argv[1:21]
env = os.environ.copy()
env["CARGO_TARGET_DIR"] = target_dir
env["SYSTEMD_ERRNO_TO_NAME_RS"] = errno_to_name_rust
env["SYSTEMD_GREETER_UID_MIN"] = greeter_uid_min
env["SYSTEMD_GREETER_UID_MAX"] = greeter_uid_max
env["SYSTEMD_DYNAMIC_UID_MIN"] = dynamic_uid_min
env["SYSTEMD_DYNAMIC_UID_MAX"] = dynamic_uid_max
env["SYSTEMD_CONTAINER_UID_MIN"] = container_uid_min
env["SYSTEMD_CONTAINER_UID_MAX"] = container_uid_max
env["SYSTEMD_FOREIGN_UID_MIN"] = foreign_uid_min
env["SYSTEMD_FOREIGN_UID_MAX"] = foreign_uid_max
for enabled, cfg in (
    (seccomp_arch_loongarch64, "systemd_seccomp_arch_loongarch64"),
    (seccomp_arch_riscv64, "systemd_seccomp_arch_riscv64"),
    (have_xz, "systemd_have_xz"),
    (have_lz4, "systemd_have_lz4"),
    (have_zstd, "systemd_have_zstd"),
    (have_zlib, "systemd_have_zlib"),
    (have_bzip2, "systemd_have_bzip2"),
):
    if enabled == "1":
        encoded_rustflags = env.get("CARGO_ENCODED_RUSTFLAGS")
        if encoded_rustflags is not None:
            env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(
                filter(None, (encoded_rustflags, "--cfg=" + cfg))
            )
        else:
            env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " --cfg=" + cfg).strip()
subprocess.check_call(
    [
        cargo,
        "build",
        "--manifest-path",
        manifest,
        "--lib",
        "--release",
        "--locked",
    ],
    env=env,
)
shutil.copy2(os.path.join(target_dir, "release", "libsystemd_basic_rs.a"), out)
'''

        rust_staticlib = custom_target(
                'systemd_basic_rs',
                input : rust_sources,
                output : 'libsystemd_basic_rs.a',
                command : [python, '-c', rust_basic_build_script,
                           '@OUTPUT@',
                           meson.current_source_dir() / 'rust/Cargo.toml',
                           meson.current_build_dir() / 'rust-basic-target',
                           cargo.full_path(),
                           meson.current_build_dir() / 'errno-to-name-rust.rs',
                           '@0@'.format(greeter_uid_min),
                           '@0@'.format(greeter_uid_max),
                           '@0@'.format(dynamic_uid_min),
                           '@0@'.format(dynamic_uid_max),
                           '@0@'.format(container_uid_base_min),
                           '@0@'.format(container_uid_base_max + 0xFFFF),
                           '@0@'.format(foreign_uid_base),
                           '@0@'.format(foreign_uid_base + 0xFFFF),
                           '@0@'.format(have_seccomp_arch_loongarch64 ? 1 : 0),
                           '@0@'.format(have_seccomp_arch_riscv64 ? 1 : 0),
                           '@0@'.format(conf.get('HAVE_XZ')),
                           '@0@'.format(conf.get('HAVE_LZ4')),
                           '@0@'.format(conf.get('HAVE_ZSTD')),
                           '@0@'.format(conf.get('HAVE_ZLIB')),
                           '@0@'.format(conf.get('HAVE_BZIP2'))],
                build_by_default : true,
                build_always_stale : true)
endif

libbasic_static = static_library(
        'basic',
        basic_sources,
        fundamental_sources,
        include_directories : basic_includes,
        implicit_include_directories : false,
        dependencies : [libbzip2_cflags,
                        liblz4_cflags,
                        libxz_cflags,
                        libz_cflags,
                        libzstd_cflags,
                        userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)
