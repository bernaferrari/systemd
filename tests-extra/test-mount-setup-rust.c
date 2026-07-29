/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <string.h>

#include "tests.h"
#include "mount-setup.h"
#include "rust/mount_setup.h"

/* ── mount_point_is_api ────────────────────────────────────────────────── */

/* RUST-CONTRACT: mount-point-is-api */
static void test_mount_point_is_api_exact(void) {
        static const char *api_paths[] = {
                "/proc", "/sys", "/dev", "/dev/shm", "/dev/pts",
                "/run", "/sys/fs/cgroup", "/sys/fs/pstore",
                "/sys/fs/smackfs", "/sys/kernel/security",
                "/sys/firmware/efi/efivars", "/sys/fs/bpf",
        };
        for (int i = 0; i < (int)ELEMENTSOF(api_paths); i++) {
                bool r_c = mount_point_is_api(api_paths[i]);
                bool r_r = rs_mount_point_is_api(api_paths[i]);
                assert_se(r_c == r_r);
                assert_se(r_c);
        }
}

static void test_mount_point_is_api_cgroup_subdir(void) {
        assert_se(mount_point_is_api("/sys/fs/cgroup/systemd") == rs_mount_point_is_api("/sys/fs/cgroup/systemd"));
        assert_se(mount_point_is_api("/sys/fs/cgroup/cpu/user.slice") == rs_mount_point_is_api("/sys/fs/cgroup/cpu/user.slice"));
}

static void test_mount_point_is_api_not_api(void) {
        static const char *non_api[] = { "/home", "/tmp", "/var", "/etc", "/usr" };
        for (int i = 0; i < (int)ELEMENTSOF(non_api); i++) {
                bool r_c = mount_point_is_api(non_api[i]);
                bool r_r = rs_mount_point_is_api(non_api[i]);
                assert_se(r_c == r_r);
                assert_se(!r_c);
        }
}

static void test_mount_point_is_api_null(void) {
        assert_se(!rs_mount_point_is_api(NULL));
}

static void test_mount_point_is_api_partial(void) {
        assert_se(!mount_point_is_api("/procfs"));
        assert_se(!rs_mount_point_is_api("/procfs"));
        assert_se(!mount_point_is_api("/sysfs"));
        assert_se(!rs_mount_point_is_api("/sysfs"));
}

static void test_mount_point_is_api_path_components_and_bytes(void) {
        static const char proc_nul_suffix[] = { '/', 'p', 'r', 'o', 'c', 0, 'x', 0 };

        assert_se(mount_point_is_api("//./proc/") == rs_mount_point_is_api("//./proc/"));
        assert_se(rs_mount_point_is_api("//./proc/"));
        assert_se(mount_point_is_api("/sys//fs/cgroup/./slice") == rs_mount_point_is_api("/sys//fs/cgroup/./slice"));
        assert_se(rs_mount_point_is_api("/sys//fs/cgroup/./slice"));
        assert_se(mount_point_is_api("/sys/fs/cgroupx") == rs_mount_point_is_api("/sys/fs/cgroupx"));
        assert_se(!rs_mount_point_is_api("/sys/fs/cgroupx"));
        assert_se(mount_point_is_api("/proc\xff") == rs_mount_point_is_api("/proc\xff"));
        assert_se(!rs_mount_point_is_api("/proc\xff"));
        assert_se(mount_point_is_api(proc_nul_suffix) == rs_mount_point_is_api(proc_nul_suffix));
        assert_se(rs_mount_point_is_api(proc_nul_suffix));
}

static void test_mount_point_is_api_oversized_component(void) {
        char path[sizeof("/sys/fs/cgroup/") + 256];

        strcpy(path, "/sys/fs/cgroup/");
        memset(path + strlen(path), 'x', 256);
        path[sizeof(path) - 1] = 0;

        assert_se(mount_point_is_api(path) == rs_mount_point_is_api(path));
        assert_se(!rs_mount_point_is_api(path));
}

/* ── mount_point_ignore ───────────────────────────────────────────────── */

/* RUST-CONTRACT: mount-point-ignore */
static void test_mount_point_ignore_exact(void) {
        static const char *ignore_paths[] = {
                "/sys/fs/selinux", "/dev/console", "/proc/kmsg",
                "/proc/sys", "/proc/sys/kernel/random/boot_id",
        };
        for (int i = 0; i < (int)ELEMENTSOF(ignore_paths); i++) {
                bool r_c = mount_point_ignore(ignore_paths[i]);
                bool r_r = rs_mount_point_ignore(ignore_paths[i]);
                assert_se(r_c == r_r);
                assert_se(r_c);
        }
}

static void test_mount_point_ignore_run_host(void) {
        assert_se(mount_point_ignore("/run/host") == rs_mount_point_ignore("/run/host"));
        assert_se(mount_point_ignore("/run/host/usr") == rs_mount_point_ignore("/run/host/usr"));
        assert_se(mount_point_ignore("/run/host") == rs_mount_point_ignore("/run/host"));
}

static void test_mount_point_ignore_not_ignored(void) {
        assert_se(!mount_point_ignore("/home"));
        assert_se(!rs_mount_point_ignore("/home"));
        assert_se(!mount_point_ignore("/var/log"));
        assert_se(!rs_mount_point_ignore("/var/log"));
}

static void test_mount_point_ignore_null(void) {
        assert_se(!rs_mount_point_ignore(NULL));
}

static void test_mount_point_ignore_path_components_and_bytes(void) {
        static const char run_host_nul_suffix[] = { '/', 'r', 'u', 'n', '/', 'h', 'o', 's', 't', 0, 'x', 0 };

        assert_se(mount_point_ignore("/run//host/./incoming") == rs_mount_point_ignore("/run//host/./incoming"));
        assert_se(rs_mount_point_ignore("/run//host/./incoming"));
        assert_se(mount_point_ignore("/run/hostess") == rs_mount_point_ignore("/run/hostess"));
        assert_se(!rs_mount_point_ignore("/run/hostess"));
        assert_se(mount_point_ignore("/run/hostile") == rs_mount_point_ignore("/run/hostile"));
        assert_se(!rs_mount_point_ignore("/run/hostile"));
        assert_se(mount_point_ignore("/run/host/\xff") == rs_mount_point_ignore("/run/host/\xff"));
        assert_se(rs_mount_point_ignore("/run/host/\xff"));
        assert_se(mount_point_ignore(run_host_nul_suffix) == rs_mount_point_ignore(run_host_nul_suffix));
        assert_se(rs_mount_point_ignore(run_host_nul_suffix));
}

static void test_mount_point_ignore_oversized_component(void) {
        char path[sizeof("/run/host/") + 256];

        strcpy(path, "/run/host/");
        memset(path + strlen(path), 'x', 256);
        path[sizeof(path) - 1] = 0;

        assert_se(mount_point_ignore(path) == rs_mount_point_ignore(path));
        assert_se(!rs_mount_point_ignore(path));
}

int main(int argc, char *argv[]) {
        test_mount_point_is_api_exact();
        test_mount_point_is_api_cgroup_subdir();
        test_mount_point_is_api_not_api();
        test_mount_point_is_api_null();
        test_mount_point_is_api_partial();
        test_mount_point_is_api_path_components_and_bytes();
        test_mount_point_is_api_oversized_component();
        test_mount_point_ignore_exact();
        test_mount_point_ignore_run_host();
        test_mount_point_ignore_not_ignored();
        test_mount_point_ignore_null();
        test_mount_point_ignore_path_components_and_bytes();
        test_mount_point_ignore_oversized_component();

        return 0;
}
