# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Extra tests for improving coverage of src/basic/ and src/shared/
# This directory is intentionally separate from src/test/ so that it can be
# maintained independently when pulling upstream changes.

# Keep the C coverage suite dormant when this directory is entered for the
# Rust C/R shadow targets below.
simple_tests += get_option('rust').enabled() ? [] : files(
        'test-alternative-names-policy-extra.c',
        'test-ansi-color.c',
        'test-architecture-extra.c',
        'test-arphrd-util-extra.c',
        'test-argv-util-extra.c',
        'test-bond-util.c',
        'test-boot-entry.c',
        'test-bootspec-extra.c',
        'test-bridge-util.c',
        'test-btrfs-extra.c',
        'test-bus-label.c',
        'test-capsule-util.c',
        'test-chattr-util.c',
        'test-cgroup-util-extra.c',
        'test-compression.c',
        'test-condition-extra.c',
        'test-coredump-util-extra.c',
        'test-confidential-virt.c',
        'test-device-nodes-extra.c',
        'test-dns-protocol.c',
        'test-dns-rr-extra.c',
        'test-dns-svc-extra.c',
        'test-discover-image.c',
        'test-efivars.c',
        'test-errno-list-extra.c',
        'test-ethtool-util.c',
        'test-factory-reset.c',
        'test-filesystems.c',
        'test-format-ifname.c',
        'test-geneve-util.c',
        'test-glyph-util.c',
        'test-gpt-extra.c',
        'test-hexdecoct-extra.c',
        'test-hexdecoct-extra2.c',
        'test-hostname-setup-extra.c',
        'test-image-extra.c',
        'test-import-util-extra.c',
        'test-in-addr-util-extra.c',
        'test-initrd-util.c',
        'test-install-extra.c',
        'test-ioprio-util.c',
        'test-ipvlan-util.c',
        'test-kernel-image.c',
        'test-locale-util-extra.c',
        'test-locale-variable.c',
        'test-log-context.c',
        'test-log-target.c',
        'test-macvlan-util.c',
        'test-metrics.c',
        'test-mount-setup-extra.c',
        'test-mstack-extra.c',
        'test-murmurhash.c',
        'test-name-policy.c',
        'test-netif-sriov.c',
        'test-netif-util.c',
        'test-numa-util-extra.c',
        'test-open-file-extra.c',
        'test-output-mode.c',
        'test-parse-util-extra.c',
        'test-parse-util-extra2.c',
        'test-percent-util-extra.c',
        'test-reboot-util-extra.c',
        'test-resolve-util.c',
        'test-rlimit-extra.c',
        'test-runtime-scope.c',
        'test-sha256-extra.c',
        'test-sigchld.c',
        'test-siphash24-extra.c',
        'test-sleep-config-extra.c',
        'test-socket-label.c',
        'test-socket-util-extra.c',
        'test-sort-util.c',
        'test-sysctl-util-extra.c',
        'test-syslog-util.c',
        'test-stdio-util.c',
        'test-string-table.c',
        'test-time-util-extra.c',
        'test-timestamp-style.c',
        'test-unit-def.c',
        'test-unit-def-extra.c',
        'test-unit-def-states.c',
        'test-unit-def-states2.c',
        'test-uid-range-extra.c',
        'test-utf8-extra.c',
        'test-utf8-extra2.c',
        'test-user-record-extra.c',
        'test-user-record-extra2.c',
        'test-user-storage.c',
        'test-virt.c',
        'test-volatile-util.c',
        'test-dns-rcode-extra.c',
        'test-bus-util-extra.c',
        'test-creds-util-extra.c',
        'test-efi-loader-extra.c',
        'test-netif-has-carrier-extra.c',
        'test-path-util-extra2.c',
        'test-string-util-extra2.c',
        'test-escape-extra.c',
        'test-pe-binary-extra.c',
        'test-net-condition-extra.c',
        'test-dns-domain-extra.c',
        'test-io-util-extra2.c',
        'test-pretty-print-extra.c',
        'test-xattr-util-extra.c',
        'test-wifi-util-extra.c',
        'test-firewall-util-extra.c',
        'test-uid-classification-extra.c',
        'test-capability-set-extra.c',
        'test-namespace-util-extra.c',
        'test-exec-util-extra.c',
        'test-strv-extra.c',
        'test-serialize-extra.c',
        'test-proc-cmdline-extra.c',
        'test-nulstr-util-extra.c',
        'test-terminal-util-extra.c',
        'test-path-util-extra3.c',
        'test-gunicode-extra.c',
        'test-escape-extra2.c',
        'test-iovec-util-extra.c',
        'test-parse-util-extra3.c',
        'test-time-util-extra2.c',
        'test-process-util-extra.c',
        'test-extract-word-extra.c',
        'test-utf8-extra3.c',
        'test-dns-domain-extra2.c',
        'test-in-addr-util-extra2.c',
        'test-exit-status-extra.c',
        'test-nsflags-extra.c',
        'test-seccomp-util-extra.c',
        'test-gpt-extra2.c',
        'test-dns-type-extra.c',
        'test-ether-addr-util-extra.c',
        'test-dns-rr-extra2.c',
        'test-string-util-extra3.c',
        'test-dns-type-extra2.c',
        'test-rlimit-util-extra.c',
        'test-stat-util-extra.c',
        'test-signal-util-extra.c',
        'test-hostname-util-extra.c',
        'test-dns-type-extra3.c',
        'test-unit-name-extra.c',
        'test-mountpoint-util-extra.c',
        'test-proc-cmdline-extra2.c',
        'test-env-util-extra.c',
        'test-in-addr-util-extra3.c',
        'test-strv-extra2.c',
        'test-volatile-util-extra2.c',
        'test-sleep-config-extra2.c',
        'test-factory-reset-extra2.c',
        'test-condition-extra2.c',
        'test-cgroup-util-extra2.c',
        'test-rlimit-extra2.c',
        'test-runtime-scope-extra2.c',
        'test-rlimit-util-extra2.c',
        'test-install-extra2.c',
        'test-user-record-extra3.c',
        'test-open-file-extra2.c',
        'test-uid-range-extra2.c',
        'test-hashmap-extra.c',
        'test-set-extra.c',
        'test-prioq-extra.c',
        'test-os-util-extra.c',
        'test-discover-image-extra2.c',
        'test-coredump-util-extra2.c',
        'test-socket-util-extra2.c',
        'test-process-util-extra2.c',
        'test-firewall-util-extra2.c',
        'test-numa-util-extra2.c',
        'test-import-util-extra2.c',
        'test-hostname-setup-extra2.c',
        'test-ipvlan-util-extra2.c',
        'test-macvlan-util-extra2.c',
        'test-dns-packet-extra2.c',
        'test-ethtool-util-extra2.c',
        'test-geneve-util-extra2.c',
        'test-netif-naming-scheme-extra2.c',
        'test-locale-util-extra2.c',
        'test-log-extra2.c',
        'test-compress-extra2.c',
        'test-output-mode-extra2.c',
        'test-bridge-util-extra2.c',
        'test-socket-label-extra2.c',
        'test-boot-entry-extra2.c',
        'test-hexdecoct-extra3.c',
        'test-parse-util-extra4.c',
        'test-parse-util-extra5.c',
        'test-misc-pure-extra.c',
        'test-shared-parsers-extra.c',
        'test-dns-domain-extra13.c',
        'test-dns-domain-extra14.c',
        'test-percent-util-extra2.c',
        'test-format-util-extra2.c',
        'test-strxcpyx-extra2.c',
        'test-compare-operator-extra2.c',
        'test-ether-addr-util-extra2.c',
        'test-iovec-util-extra2.c',
        'test-capability-list-extra2.c',
        'test-arphrd-util-extra2.c',
        'test-time-util-extra3.c',
        'test-strv-extra3.c',
        'test-in-addr-util-extra4.c',
        'test-user-util-extra3.c',
        'test-os-util-extra2.c',
        'test-string-util-extra4.c',
        'test-strv-extra4.c',
        'test-user-util-extra4.c',
        'test-cgroup-setup-extra.c',
        'test-bus-util-extra2.c',
        'test-terminal-util-extra2.c',
        'test-virt-extra2.c',
        'test-capability-util-extra2.c',
        'test-process-util-extra3.c',
        'test-namespace-util-extra2.c',
        'test-terminal-util-extra3.c',
        'test-memory-util-extra.c',
        'test-stat-util-extra2.c',
        'test-strv-extra5.c',
        'test-alloc-util-extra.c',
        'test-boot-entry-extra3.c',
        'test-udev-util-extra.c',
        'test-dns-domain-extra3.c',
        'test-terminal-util-extra4.c',
        'test-nsflags-extra2.c',
        'test-path-util-extra4.c',
        'test-ratelimit-extra.c',
        'test-hmac-extra.c',
        'test-af-list-extra2.c',
        'test-utf8-extra4.c',
        'test-format-util-extra3.c',
        'test-exit-status-extra2.c',
        'test-exec-util-extra2.c',
        'test-dns-packet-extra3.c',
        'test-ip-protocol-list-extra.c',
        'test-output-mode-extra3.c',
        'test-coredump-util-extra3.c',
        'test-compare-operator-extra3.c',
        'test-dns-domain-extra4.c',
        'test-dns-domain-extra5.c',
        'test-calendarspec-extra.c',
        'test-serialize-extra2.c',
        'test-serialize-extra3.c',
        'test-conf-parser-extra.c',
        'test-daemon-util-extra3.c',
        'test-reboot-util-extra2.c',
        'test-gpt-extra3.c',
        'test-dns-domain-extra6.c',
        'test-bootspec-extra2.c',
        'test-bootspec-extra3.c',
        'test-ethtool-util-extra3.c',
        'test-format-table-extra.c',
        'test-local-addresses-extra.c',
        'test-hostname-setup-extra3.c',
        'test-securebits-extra.c',
        'test-dns-rr-extra3.c',
        'test-creds-util-extra4.c',
        'test-libcrypt-util-extra2.c',
        'test-gpt-extra4.c',
        'test-web-util-extra2.c',
        'test-recovery-key-extra.c',
        'test-bitmap-extra.c',
        'test-vconsole-util-extra2.c',
        'test-fstab-util-extra3.c',
        'test-kbd-util-extra.c',
        'test-vlan-util-extra.c',
        'test-pkcs11-util-extra.c',
        'test-netif-has-carrier-extra2.c',
        'test-user-record-extra4.c',
        'test-mstack-extra2.c',
        'test-kernel-image-extra.c',
        'test-quota-util-extra.c',
        'test-condition-extra3.c',
        'test-boot-entry-extra4.c',
        'test-open-file-extra3.c',
        'test-import-util-extra3.c',
        'test-coredump-util-extra4.c',
        'test-discover-image-extra3.c',
        'test-fdset-extra2.c',
        'test-compare-operator-extra4.c',
        'test-ip-protocol-list-extra2.c',
        'test-cpu-set-util-extra2.c',
        'test-dns-domain-extra7.c',
        'test-conf-parser-extra2.c',
        'test-dissect-image-extra.c',
        'test-user-record-extra5.c',
        'test-bootspec-extra4.c',
        'test-efi-loader-extra3.c',
        'test-local-addresses-extra2.c',
        'test-format-table-extra2.c',
        'test-vconsole-util-extra3.c',
        'test-recovery-key-extra2.c',
        'test-machine-credential-extra.c',
        'test-creds-util-extra5.c',
        'test-dns-domain-extra8.c',
        'test-udev-util-extra2.c',
        'test-bus-util-extra3.c',
        'test-firewall-util-extra3.c',
        'test-wifi-util-extra2.c',
        'test-dns-rr-extra4.c',
        'test-dns-rr-extra5.c',
        'test-sleep-config-extra3.c',
        'test-volatile-util-extra3.c',
        'test-exec-util-extra3.c',
        'test-serialize-extra4.c',
        'test-seccomp-util-extra3.c',
        'test-dns-packet-extra4.c',
        'test-resolve-util-extra2.c',
        'test-dns-rr-extra6.c',
        'test-install-extra3.c',
        'test-condition-extra4.c',
        'test-open-file-extra4.c',
        'test-coredump-util-extra5.c',
        'test-kernel-image-extra2.c',
        'test-user-record-extra6.c',
        'test-hostname-setup-extra4.c',
        'test-factory-reset-extra3.c',
        'test-metrics-extra2.c',
        'test-socket-label-extra3.c',
        'test-import-util-extra4.c',
        'test-ioprio-util-extra2.c',
        'test-discover-image-extra4.c',
        'test-bond-util-extra2.c',
        'test-netif-naming-scheme-extra3.c',
        'test-ethtool-util-extra4.c',
        'test-dns-packet-extra5.c',
        'test-bootspec-extra5.c',
        'test-dns-domain-extra9.c',
        'test-dns-domain-extra10.c',
        'test-dns-domain-extra11.c',
        'test-dns-domain-extra12.c',
        'test-dns-type-extra4.c',
        'test-mount-util-extra.c',
        'test-net-condition-extra2.c',
        'test-ether-addr-util-extra3.c',
        'test-fstab-util-extra4.c',
        'test-wifi-util-extra3.c',
        'test-bridge-util-extra3.c',
        'test-geneve-util-extra3.c',
        'test-output-mode-extra4.c',
        'test-gpt-extra5.c',
        'test-namespace-util-extra3.c',
        'test-serialize-extra5.c',
        'test-format-table-extra3.c',
        'test-format-table-extra4.c',
        'test-conf-parser-extra4.c',
        'test-condition-extra5.c',
        'test-install-extra4.c',
        'test-bus-util-extra4.c',
        'test-copy-extra.c',
        'test-ether-addr-util-extra4.c',
        'test-serialize-extra6.c',
        'test-format-table-extra5.c',
        'test-image-policy-extra2.c',
        'test-verbs-extra.c',
        'test-udev-util-extra3.c',
        'test-bus-print-properties-extra.c',
        'test-volatile-util-extra4.c',
        'test-watchdog-extra.c',
        'test-blockdev-list-extra.c',
        'test-vpick-extra.c',
        'test-compare-operator-extra5.c',
        'test-nsflags-extra3.c',
        'test-fstab-util-extra5.c',
        'test-kbd-util-extra2.c',
        'test-bootspec-extra6.c',
        'test-group-record-extra.c',
        'test-boot-entry-extra5.c',
        'test-user-record-extra7.c',
        'test-edit-util-extra.c',
        'test-numa-util-extra3.c',
        'test-hibernate-util-extra.c',
        'test-cryptsetup-util-extra2.c',
        'test-mempool-extra.c',
        'test-virt-extra3.c',
        'test-resolve-util-extra3.c',
        'test-volatile-util-extra5.c',
        'test-import-util-extra5.c',
        'test-discover-image-extra5.c',
        'test-factory-reset-extra4.c',
        'test-syslog-util-extra2.c',
        'test-socket-util-extra3.c',
        'test-process-util-extra4.c',
        'test-vconsole-util-extra4.c',
        'test-ethtool-util-extra5.c',
        'test-machine-credential-extra2.c',
        'test-wifi-util-extra4.c',
        'test-exec-util-extra4.c',
        'test-user-record-extra8.c',
        'test-securebits-extra2.c',
        'test-specifier-extra.c',
        'test-quota-util-extra2.c',
        'test-verbs-extra2.c',
        'test-ratelimit-extra2.c',
        'test-unit-file-extra.c',
        'test-errno-util-extra.c',
        'test-compress-extra.c',
        'test-chattr-util-extra2.c',
        'test-device-nodes-extra2.c',
        'test-parse-helpers-extra.c',
        'test-xml-extra.c',
        'test-user-util-extra5.c',
        'test-boot-entry-extra6.c',
        'test-install-extra5.c',
        'test-in-addr-util-extra5.c',
        'test-dissect-image-extra2.c',
        'test-user-record-extra9.c',
        'test-group-record-extra2.c',
        'test-hostname-setup-extra5.c',
        'test-import-util-extra6.c',
        'test-resolve-util-extra4.c',
        'test-cgroup-util-extra3.c',
        'test-replace-var-extra.c',
        'test-in-addr-util-extra6.c',
        'test-mountpoint-util-extra2.c',
        'test-in-addr-util-extra7.c',
        'test-mountpoint-util-extra3.c',
        'test-devnum-util-extra.c',
        'test-mempool-extra2.c',
        'test-namespace-util-extra4.c',
        'test-stat-util-extra3.c',
        'test-uid-range-extra3.c',
        'test-in-addr-util-extra8.c',
        'test-hostname-util-extra2.c',
        'test-user-util-extra6.c',
        'test-in-addr-util-extra9.c',
        'test-string-util-extra5.c',
        'test-path-util-extra5.c',
        'test-efi-loader-extra4.c',
        'test-recovery-key-extra3.c',
        'test-sleep-config-extra4.c',
        'test-iovec-util-extra3.c',
        'test-socket-util-extra4.c',
        'test-process-util-extra5.c',
        'test-namespace-util-extra5.c',
        'test-capability-util-extra3.c',
        'test-socket-util-extra5.c',
        'test-process-util-extra6.c',
        'test-mountpoint-util-extra4.c',
        'test-os-util-extra3.c',
        'test-format-util-extra4.c',
        'test-strxcpyx-extra3.c',
        'test-chattr-util-extra3.c',
        'test-terminal-util-extra5.c',
        'test-errno-util-extra2.c',
        'test-pidfd-util-extra2.c',
        'test-recurse-dir-extra.c',
        'test-namespace-util-extra6.c',
        'test-mountpoint-util-extra5.c',
        'test-stat-util-extra4.c',
        'test-fd-util-extra2.c',
        'test-fileio-extra2.c',
        'test-terminal-util-extra6.c',
        'test-process-util-extra7.c',
        'test-devnum-util-extra2.c',
        'test-proc-cmdline-extra3.c',
        'test-fs-util-extra2.c',
        'test-hashmap-extra2.c',
        'test-set-extra2.c',
        'test-prioq-extra2.c',
        'test-sync-util-extra2.c',
        'test-chattr-util-extra4.c',
        'test-memory-util-extra2.c',
        'test-assert-util-extra2.c',
        'test-process-util-extra8.c',
        'test-iovec-util-extra4.c',
        'test-device-nodes-extra3.c',
        'test-login-util-extra2.c',
        'test-terminal-util-extra7.c',
        'test-build-extra.c',
        'test-random-util-extra.c',
        'test-capability-util-extra4.c',
        'test-compress-extra3.c',
        'test-conf-files-extra2.c',
        'test-namespace-util-extra7.c',
        'test-lock-util-extra2.c',
        'test-xattr-util-extra2.c',
        'test-sysctl-util-extra2.c',
        'test-inotify-util-extra2.c',
        'test-format-ifname-extra.c',
        'test-efivars-extra.c',
        'test-random-util-extra2.c',
        'test-signal-util-extra2.c',
        'test-glyph-util-extra.c',
        'test-mkdir-extra.c',
        'test-in-addr-util-extra10.c',
        'test-socket-util-extra6.c',
        'test-stat-util-extra5.c',
        'test-fs-util-extra3.c',
        'test-process-util-extra9.c',
        'test-time-util-extra4.c',
        'test-socket-util-extra7.c',
        'test-user-util-extra7.c',
        'test-cgroup-util-extra4.c',
        'test-log-extra3.c',
        'test-terminal-util-extra8.c',
        'test-signal-util-extra3.c',
        'test-chase-extra.c',
        'test-pidfd-util-extra3.c',
)

# Rust shadow tests — only built when -Drust=enabled
# These tests link against both the C libbasic (via libshared) and the Rust staticlib.
if get_option('rust').enabled()
        rust_test_exe = executable(
                'test-hexdecoct-rust',
                files('test-hexdecoct-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-hexdecoct-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-sort-util-rust',
                files('test-sort-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-sort-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-string-table-rust',
                files('test-string-table-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-string-table-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-utf8-rust',
                files('test-utf8-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-utf8-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-parse-util-rust',
                files('test-parse-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-parse-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-parse-extra-rust',
                files('test-parse-extra-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-parse-extra-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-escape-rust',
                files('test-escape-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-escape-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-extract-word-rust',
                files('test-extract-word-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-extract-word-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-string-util-rust',
                files('test-string-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-string-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strv-rust',
                files('test-strv-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strv-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-time-util-rust',
                files('test-time-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-time-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-time-util-extra2-rust',
                files('test-time-util-extra2-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-time-util-extra2-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-percent-util-rust',
                files('test-percent-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-percent-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-siphash24-rust',
                files('test-siphash24-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-siphash24-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strxcpyx-rust',
                files('test-strxcpyx-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strxcpyx-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-nulstr-util-rust',
                files('test-nulstr-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-nulstr-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-devnum-util-rust',
                files('test-devnum-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-devnum-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-hostname-util-rust',
                files('test-hostname-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-hostname-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-ether-addr-util-rust',
                files('test-ether-addr-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-ether-addr-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-ratelimit-rust',
                files('test-ratelimit-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-ratelimit-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-sha256-hmac-rust',
                files('test-sha256-hmac-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-sha256-hmac-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-path-util-rust',
                files('test-path-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-path-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-path-util-extra-rust',
                files('test-path-util-extra-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-path-util-extra-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-in-addr-util-rust',
                files('test-in-addr-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-in-addr-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-bus-label-rust',
                files('test-bus-label-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-bus-label-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-gunicode-rust',
                files('test-gunicode-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-gunicode-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-iovec-util-rust',
                files('test-iovec-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-iovec-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-device-nodes-rust',
                files('test-device-nodes-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-device-nodes-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-iovec-wrapper-rust',
                files('test-iovec-wrapper-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-iovec-wrapper-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-alloc-util-rust',
                files('test-alloc-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-alloc-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-alloc-util-extra2-rust',
                files('test-alloc-util-extra2-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-alloc-util-extra2-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strbuf-rust',
                files('test-strbuf-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strbuf-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-prioq-rust',
                files('test-prioq-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-prioq-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-mempool-rust',
                files('test-mempool-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-mempool-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-memory-util-rust',
                files('test-memory-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-memory-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-errno-util-rust',
                files('test-errno-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-errno-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-af-list-rust',
                files('test-af-list-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-af-list-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-env-util-rust',
                files('test-env-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-env-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-unit-name-rust',
                files('test-unit-name-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-unit-name-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-signal-util-rust',
                files('test-signal-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-signal-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-signal-inline-rust',
                files('test-signal-inline-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-signal-inline-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-rlimit-util-rust',
                files('test-rlimit-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-rlimit-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-process-util-str-tables-rust',
                files('test-process-util-str-tables-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-process-util-str-tables-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-str-tables-batch3-rust',
                files('test-str-tables-batch3-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-str-tables-batch3-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-time-util-extra-rust',
                files('test-time-util-extra-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-time-util-extra-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-netdev-str-tables-rust',
                files('test-netdev-str-tables-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-netdev-str-tables-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-shared-str-tables-rust',
                files('test-shared-str-tables-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-shared-str-tables-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-shared-str-tables2-rust',
                files('test-shared-str-tables2-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-shared-str-tables2-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-shared-str-tables3-rust',
                files('test-shared-str-tables3-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-shared-str-tables3-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-shared-str-tables4-rust',
                files('test-shared-str-tables4-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-shared-str-tables4-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-shared-str-tables5-rust',
                files('test-shared-str-tables5-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-shared-str-tables5-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-shared-str-tables6-rust',
                files('test-shared-str-tables6-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-shared-str-tables6-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-dns-type-predicates-rust',
                files('test-dns-type-predicates-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-dns-type-predicates-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-shared-validators-rust',
                files('test-shared-validators-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-shared-validators-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-exit-status-rust',
                files('test-exit-status-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-exit-status-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-xml-rust',
                files('test-xml-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-xml-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-dns-type2-rust',
                files('test-dns-type2-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-dns-type2-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-dns-label-rust',
                files('test-dns-label-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-dns-label-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-shared-str-tables7-rust',
                files('test-shared-str-tables7-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-shared-str-tables7-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-gpt-util-rust',
                files('test-gpt-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-gpt-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-basic-str-tables-extra-rust',
                files('test-basic-str-tables-extra-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-basic-str-tables-extra-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-bitmap-rust',
                files('test-bitmap-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-bitmap-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-sha1-rust',
                files('test-sha1-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-sha1-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-namespace-mountpoint-rust',
                files('test-namespace-mountpoint-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-namespace-mountpoint-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-credential-validators-rust',
                files('test-credential-validators-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-credential-validators-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-mount-setup-rust',
                files('test-mount-setup-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-mount-setup-rust', rust_test_exe)

        if conf.get('HAVE_SECCOMP') == 1
                rust_test_exe = executable(
                        'test-seccomp-util-rust',
                        files('test-seccomp-util-rust.c'),
                        include_directories : includes,
                        link_with : [libshared, rust_staticlib],
                        dependencies : [userspace, libseccomp_cflags],
                        c_args : test_cflags,
                        link_depends : runtest_env,
                        build_by_default : want_tests != 'false',
                        install : install_tests,
                        install_dir : unittestsdir,
                )
                test('test-seccomp-util-rust', rust_test_exe)
        endif

        rust_test_exe = executable(
                'test-credential-rust',
                files('test-credential-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-credential-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-credential-dns-rust',
                files('test-credential-dns-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-credential-dns-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-unit-def-rust',
                files('test-unit-def-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-unit-def-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-parse-range-rust',
                files('test-parse-range-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-parse-range-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-mount-color-btrfs-rust',
                files('test-mount-color-btrfs-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-mount-color-btrfs-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-pe-binary-rust',
                files('test-pe-binary-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-pe-binary-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-id128-rust',
                files('test-id128-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-id128-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-socket-util-rust',
                files('test-socket-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-socket-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-socket-util-extra8',
                files('test-socket-util-extra8.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-socket-util-extra8', rust_test_exe)

        rust_test_exe = executable(
                'test-misc-extra-rust',
                files('test-misc-extra-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-misc-extra-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-nsflags-rust',
                files('test-nsflags-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-nsflags-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-wol-options-rust',
                files('test-wol-options-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-wol-options-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-boot-entry-rust',
                files('test-boot-entry-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-boot-entry-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-misc-validators-rust',
                files('test-misc-validators-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-misc-validators-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-udev-util-rust',
                files('test-udev-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-udev-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-stat-util-rust',
                files('test-stat-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-stat-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-memeqbyte-rust',
                files('test-memeqbyte-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-memeqbyte-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-user-util-rust',
                files('test-user-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-user-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-resolve-util-rust',
                files('test-resolve-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-resolve-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-seccomp-import-rust',
                files('test-seccomp-import-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : [userspace, libseccomp_cflags],
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-seccomp-import-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-stat-verify-rust',
                files('test-stat-verify-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-stat-verify-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-image-name-rust',
                files('test-image-name-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
        )
        test('test-image-name-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-rlimit-parse-rust',
                files('test-rlimit-parse-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
        )
        test('test-rlimit-parse-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-unit-dbus-rust',
                files('test-unit-dbus-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
        )
        test('test-unit-dbus-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-pkcs11-rust',
                files('test-pkcs11-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : [userspace, libp11kit_cflags],
                c_args : test_cflags,
                link_depends : runtest_env,
        )
        test('test-pkcs11-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-path-funcs-rust',
                files('test-path-funcs-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
        )
        test('test-path-funcs-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strverscmp-rust',
                files('test-strverscmp-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strverscmp-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-compare-operator-rust',
                files('test-compare-operator-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-compare-operator-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-serialize-rust',
                files('test-serialize-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-serialize-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strreplace-rust',
                files('test-strreplace-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strreplace-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-image-policy-rust',
                files('test-image-policy-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-image-policy-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-exec-util-rust',
                files('test-exec-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-exec-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-tpm2-rust',
                files('test-tpm2-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : [userspace, libopenssl_cflags, tpm2_cflags],
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-tpm2-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-misc-rust2',
                files('test-misc-rust2.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-misc-rust2', rust_test_exe)

        rust_test_exe = executable(
                'test-misc-rust3',
                files('test-misc-rust3.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-misc-rust3', rust_test_exe)

        rust_test_exe = executable(
                'test-bpf-tpm2-wifi-rust',
                files('test-bpf-tpm2-wifi-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-bpf-tpm2-wifi-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-procfs-util-rust',
                files('test-procfs-util-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-procfs-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-unaligned-rust',
                files('test-unaligned-rust.c'),
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-unaligned-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-percent-scale-rust',
                'test-percent-scale-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-percent-scale-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-virt-rust',
                'test-virt-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-virt-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-securebits-rust',
                'test-securebits-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-securebits-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-errno-classify-rust',
                'test-errno-classify-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : [userspace, libseccomp_cflags],
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-errno-classify-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-errno-util-extra3-rust',
                'test-errno-util-extra3-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-errno-util-extra3-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-string-util-fundamental-rust',
                'test-string-util-fundamental-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-string-util-fundamental-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strv-extra7-rust',
                'test-strv-extra7-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strv-extra7-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-stat-util-extra2-rust',
                'test-stat-util-extra2-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-stat-util-extra2-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-string-util-inline2-rust',
                'test-string-util-inline2-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-string-util-inline2-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-parse-util-inline-rust',
                'test-parse-util-inline-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-parse-util-inline-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-misc-inline-rust',
                'test-misc-inline-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-misc-inline-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-inline-helpers-rust',
                'test-inline-helpers-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-inline-helpers-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-basic-validators-rust',
                'test-basic-validators-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-basic-validators-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-string-util-extra-rust',
                'test-string-util-extra-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-string-util-extra-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-shared-validators3-extra-rust',
                'test-shared-validators3-extra-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-shared-validators3-extra-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-parse-util-extra-rust',
                'test-parse-util-extra-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-parse-util-extra-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-gpt-unit-install-rust',
                'test-gpt-unit-install-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-gpt-unit-install-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-string-mutation-rust',
                'test-string-mutation-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-string-mutation-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strv-extra-rust',
                'test-strv-extra-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strv-extra-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-string-util-extra2-rust',
                'test-string-util-extra2-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-string-util-extra2-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-escape-extra-rust',
                'test-escape-extra-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-escape-extra-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-make-cstring-rust',
                'test-make-cstring-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-make-cstring-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-escape-extra2-rust',
                'test-escape-extra2-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-escape-extra2-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strv-fnmatch-rust',
                'test-strv-fnmatch-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strv-fnmatch-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-string-util-extra6-rust',
                'test-string-util-extra6-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-string-util-extra6-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-string-util-extra7-rust',
                'test-string-util-extra7-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-string-util-extra7-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strv-extra2-rust',
                'test-strv-extra2-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strv-extra2-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strv-extra3-rust',
                'test-strv-extra3-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strv-extra3-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strv-extra4-rust',
                'test-strv-extra4-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strv-extra4-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strv-extra5-rust',
                'test-strv-extra5-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strv-extra5-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-strv-extra6-rust',
                'test-strv-extra6-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-strv-extra6-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-header-inline-rust',
                'test-header-inline-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-header-inline-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-capability-util-rust',
                'test-capability-util-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-capability-util-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-stat-util-inline-rust',
                'test-stat-util-inline-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-stat-util-inline-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-dns-domain-rust',
                'test-dns-domain-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-dns-domain-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-dns-server-address-rust',
                'test-dns-server-address-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-dns-server-address-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-misc-untested-rust',
                'test-misc-untested-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-misc-untested-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-remaining-untested-rust',
                'test-remaining-untested-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-remaining-untested-rust', rust_test_exe)

        rust_test_exe = executable(
                'test-misc-untested2-rust',
                'test-misc-untested2-rust.c',
                include_directories : includes,
                link_with : [libshared, rust_staticlib],
                dependencies : userspace,
                c_args : test_cflags,
                link_depends : runtest_env,
                build_by_default : want_tests != 'false',
                install : install_tests,
                install_dir : unittestsdir,
        )
        test('test-misc-untested2-rust', rust_test_exe)

endif
