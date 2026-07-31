/* SPDX-License-Identifier: LGPL-2.1-or-later */

#define _GNU_SOURCE

#include <errno.h>
#include <linux/magic.h>
#include <sched.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <unistd.h>

#define YES_SYSROOT "/run/systemd/rust-volatile-root-yes"
#define OVERLAY_SYSROOT "/run/systemd/rust-volatile-root-overlay"
#define VOLATILE_STAGE "/run/systemd/volatile-sysroot"
#define OVERLAY_STAGE "/run/systemd/overlay-sysroot"
#define VOLATILE_LINK "/run/systemd/volatile-root"

extern int rs_volatile_root_namespace_make_yes(void);
extern int rs_volatile_root_namespace_make_overlay(void);
int rs_get_sigrtmin(void);
int rs_get_sigrtmax(void);
int rs_get_nsig(void);

int rs_get_sigrtmin(void) {
        return SIGRTMIN;
}

int rs_get_sigrtmax(void) {
        return SIGRTMAX;
}

int rs_get_nsig(void) {
        return _NSIG;
}

static int fail_errno(const char *what) {
        fprintf(stderr, "%s: %s\n", what, strerror(errno));
        return 1;
}

/* 77 is Meson's portable skipped-test status. Never retry the transition in
 * the caller's namespace when its isolation or filesystem prerequisites are
 * unavailable. */
static bool transition_prerequisite_errno(int error) {
        return error == EPERM || error == EACCES || error == ENOSYS ||
               error == EOPNOTSUPP || error == ENODEV;
}

static int make_directory(const char *path) {
        if (mkdir(path, 0755) < 0)
                return fail_errno(path);
        return 0;
}

static int setup_private_run(void) {
        if (unshare(CLONE_NEWNS) < 0)
                return 77;
        if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) < 0)
                return 77;
        if (mount("tmpfs", "/run", "tmpfs", MS_STRICTATIME, "mode=0755,size=16M") < 0)
                return 77;
        return make_directory("/run/systemd");
}

static int setup_sysroot(const char *path) {
        int r;

        r = make_directory(path);
        if (r != 0)
                return r;
        /* A tmpfs target would take C's already-temporary success path and
         * never exercise a transition. A recursive bind of / gives us a
         * non-temporary root containing /usr, while MS_PRIVATE above ensures
         * its later recursive unmount cannot propagate to the host. */
        if (mount("/", path, NULL, MS_BIND|MS_REC, NULL) < 0)
                return transition_prerequisite_errno(errno) ? 77 : fail_errno(path);
        return 0;
}

static int verify_filesystem(const char *path, long expected_magic, const char *staging) {
        struct statfs fs_info;
        char usr[128];

        if (statfs(path, &fs_info) < 0)
                return fail_errno(path);
        if (fs_info.f_type != expected_magic) {
                fprintf(stderr, "%s: unexpected filesystem type %lx\n", path, (unsigned long) fs_info.f_type);
                return 1;
        }
        if (snprintf(usr, sizeof usr, "%s/usr", path) < 0 || access(usr, F_OK) < 0)
                return fail_errno("replacement /usr");
        if (access(staging, F_OK) == 0) {
                fprintf(stderr, "%s: staging directory was not cleaned up\n", staging);
                return 1;
        }
        return 0;
}

static int run_transition(const char *path, int (*transition)(void), long expected_magic, const char *staging) {
        int r;

        r = setup_sysroot(path);
        if (r != 0)
                return r;
        r = transition();
        if (r < 0 && transition_prerequisite_errno(-r))
                return 77;
        if (r != 0) {
                fprintf(stderr, "Rust volatile-root transition failed: %d\n", r);
                return 1;
        }
        r = verify_filesystem(path, expected_magic, staging);
        if (r != 0)
                return r;

        /* Each C invocation normally starts with a clean initrd /run. Keep
         * the two transition cases independent while remaining entirely in
         * this harness's private tmpfs-backed /run. */
        if (unlink(VOLATILE_LINK) < 0 && errno != ENOENT)
                return fail_errno(VOLATILE_LINK);
        return 0;
}

int main(void) {
        int r;

        r = setup_private_run();
        if (r != 0)
                return r;
        r = run_transition(YES_SYSROOT, rs_volatile_root_namespace_make_yes, TMPFS_MAGIC, VOLATILE_STAGE);
        if (r != 0)
                return r;
        return run_transition(OVERLAY_SYSROOT, rs_volatile_root_namespace_make_overlay, OVERLAYFS_SUPER_MAGIC, OVERLAY_STAGE);
}
