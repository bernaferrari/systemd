# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-volatile-root',
                'conditions' : ['ENABLE_INITRD'],
                'sources' : files('volatile-root.c'),
        },
]

# This is intentionally a test-only C/R link boundary. It validates that the
# concrete Rust volatile-root backend can resolve its current C helper without
# changing the installed C executable selected above. The exported Rust entry
# point uses RefuseTransitions on /proc, so the test is read-only and cannot
# mutate the host mount namespace.
if get_option('rust-init-milestones').enabled()
        cargo = find_program('cargo', required : true)
        rust_volatile_root_build_script = '''
import os
import shutil
import subprocess
import sys

out, manifest, target_dir, cargo, errno_to_name_rust = sys.argv[1:6]
env = os.environ.copy()
env["CARGO_TARGET_DIR"] = target_dir
env["SYSTEMD_ERRNO_TO_NAME_RS"] = errno_to_name_rust
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
shutil.copy2(os.path.join(target_dir, "release", "libsystemd_volatile_root_rs.a"), out)
'''

        rust_volatile_root_staticlib = custom_target(
                'systemd_volatile_root_rs',
                input : files(
                        'rust/Cargo.toml',
                        'rust/lib.rs',
                        'rust/linux_mount.rs',
                        'rust/linux_transition_requirement.rs',
                        'rust/linux_unmount.rs',
                        'rust/integration_harness.rs',
                        'rust/orchestration.rs',
                ) + rust_workspace_inputs + [errno_to_name_rust],
                output : 'libsystemd_volatile_root_rs.a',
                command : [python, '-c', rust_volatile_root_build_script,
                           '@OUTPUT@',
                           meson.current_source_dir() / 'rust/Cargo.toml',
                           meson.current_build_dir() / 'rust-volatile-root-target',
                           cargo.full_path(),
                           errno_to_name_rust],
                build_by_default : false,
                build_always_stale : true,
                install : false)

        rust_volatile_root_preflight = executable(
                'test-rust-volatile-root-preflight',
                'test-rust-volatile-root-preflight.c',
                link_with : [rust_volatile_root_staticlib, libshared],
                install : false)

        test('rust-volatile-root-fail-closed-preflight',
             rust_volatile_root_preflight,
             suite : 'integration-tests')

        rust_volatile_root_namespace = executable(
                'test-rust-volatile-root-namespace',
                'test-rust-volatile-root-namespace.c',
                link_with : [rust_volatile_root_staticlib, libshared],
                install : false)

        test('rust-volatile-root-private-namespace-transition',
             rust_volatile_root_namespace,
             suite : 'integration-tests',
             protocol : 'exitcode')
endif
