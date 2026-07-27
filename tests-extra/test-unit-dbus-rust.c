/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: unit_dbus_path_from_name, unit_name_from_dbus_path,
 *              unit_dbus_interface_from_type, unit_dbus_interface_from_name,
 *              file_in_same_dir */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "path-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "rust/unit_def.h"
#include "rust/path_util.h"

/* ── unit_dbus_path_from_name ──────────────────────────────────────── */

static void test_unit_dbus_path_from_name(void) {
        char *c_r = NULL, *rs_r = NULL;

        /* Simple service name */
        c_r = unit_dbus_path_from_name("ssh.service");
        rs_r = rs_unit_dbus_path_from_name("ssh.service");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        assert_se(startswith(c_r, "/org/freedesktop/systemd1/unit/"));
        free(c_r); free(rs_r);

        /* Name with dashes */
        c_r = unit_dbus_path_from_name("systemd-journald.service");
        rs_r = rs_unit_dbus_path_from_name("systemd-journald.service");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Name with dots (instance) */
        c_r = unit_dbus_path_from_name("getty@tty1.service");
        rs_r = rs_unit_dbus_path_from_name("getty@tty1.service");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Slice */
        c_r = unit_dbus_path_from_name("system.slice");
        rs_r = rs_unit_dbus_path_from_name("system.slice");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);
}

/* ── unit_name_from_dbus_path ──────────────────────────────────────── */

static void test_unit_name_from_dbus_path(void) {
        char *c_r = NULL, *rs_r = NULL;
        int c_ret, rs_ret;

        /* Valid path */
        c_ret = unit_name_from_dbus_path("/org/freedesktop/systemd1/unit/ssh_2eservice", &c_r);
        rs_ret = rs_unit_name_from_dbus_path("/org/freedesktop/systemd1/unit/ssh_2eservice", &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "ssh.service"));
        free(c_r); free(rs_r);

        /* Path with instance */
        c_ret = unit_name_from_dbus_path("/org/freedesktop/systemd1/unit/getty_40tty1_2eservice", &c_r);
        rs_ret = rs_unit_name_from_dbus_path("/org/freedesktop/systemd1/unit/getty_40tty1_2eservice", &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Invalid prefix */
        c_ret = unit_name_from_dbus_path("/org/freedesktop/something/unit/foo.service", &c_r);
        rs_ret = rs_unit_name_from_dbus_path("/org/freedesktop/something/unit/foo.service", &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret < 0);

        /* Empty path (doesn't start with prefix) */
        c_ret = unit_name_from_dbus_path("", &c_r);
        rs_ret = rs_unit_name_from_dbus_path("", &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret < 0);

        /* Round-trip: path -> name -> path */
        const char *original = "systemd-journald.service";
        char *dbus_path = unit_dbus_path_from_name(original);
        assert_se(dbus_path != NULL);
        c_ret = unit_name_from_dbus_path(dbus_path, &c_r);
        assert_se(c_ret == 0);
        assert_se(streq(c_r, original));

        char *rs_dbus_path = rs_unit_dbus_path_from_name(original);
        assert_se(rs_dbus_path != NULL);
        rs_ret = rs_unit_name_from_dbus_path(rs_dbus_path, &rs_r);
        assert_se(rs_ret == 0);
        assert_se(streq(rs_r, original));

        /* Verify both round-trips produce same D-Bus path */
        assert_se(streq(dbus_path, rs_dbus_path));

        free(c_r); free(rs_r);
        free(dbus_path); free(rs_dbus_path);
}

/* ── unit_dbus_interface_from_type ─────────────────────────────────── */

static void test_unit_dbus_interface_from_type(void) {
        const char *c_r, *rs_r;

        c_r = unit_dbus_interface_from_type(UNIT_SERVICE);
        rs_r = rs_unit_dbus_interface_from_type(UNIT_SERVICE);
        assert_se(streq_ptr(c_r, rs_r));
        assert_se(streq(c_r, "org.freedesktop.systemd1.Service"));

        c_r = unit_dbus_interface_from_type(UNIT_SOCKET);
        rs_r = rs_unit_dbus_interface_from_type(UNIT_SOCKET);
        assert_se(streq_ptr(c_r, rs_r));
        assert_se(streq(c_r, "org.freedesktop.systemd1.Socket"));

        c_r = unit_dbus_interface_from_type(UNIT_MOUNT);
        rs_r = rs_unit_dbus_interface_from_type(UNIT_MOUNT);
        assert_se(streq_ptr(c_r, rs_r));

        c_r = unit_dbus_interface_from_type(UNIT_SLICE);
        rs_r = rs_unit_dbus_interface_from_type(UNIT_SLICE);
        assert_se(streq_ptr(c_r, rs_r));

        c_r = unit_dbus_interface_from_type(UNIT_SCOPE);
        rs_r = rs_unit_dbus_interface_from_type(UNIT_SCOPE);
        assert_se(streq_ptr(c_r, rs_r));

        /* Invalid: negative */
        c_r = unit_dbus_interface_from_type(-1);
        rs_r = rs_unit_dbus_interface_from_type(-1);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);

        /* Invalid: beyond max */
        c_r = unit_dbus_interface_from_type(100);
        rs_r = rs_unit_dbus_interface_from_type(100);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);
}

/* ── unit_dbus_interface_from_name ─────────────────────────────────── */

static void test_unit_dbus_interface_from_name(void) {
        const char *c_r, *rs_r;

        c_r = unit_dbus_interface_from_name("ssh.service");
        rs_r = rs_unit_dbus_interface_from_name("ssh.service");
        assert_se(streq_ptr(c_r, rs_r));
        assert_se(streq(c_r, "org.freedesktop.systemd1.Service"));

        c_r = unit_dbus_interface_from_name("dbus.socket");
        rs_r = rs_unit_dbus_interface_from_name("dbus.socket");
        assert_se(streq_ptr(c_r, rs_r));
        assert_se(streq(c_r, "org.freedesktop.systemd1.Socket"));

        c_r = unit_dbus_interface_from_name("system.slice");
        rs_r = rs_unit_dbus_interface_from_name("system.slice");
        assert_se(streq_ptr(c_r, rs_r));
        assert_se(streq(c_r, "org.freedesktop.systemd1.Slice"));

        /* Invalid name */
        c_r = unit_dbus_interface_from_name("not-a-unit");
        rs_r = rs_unit_dbus_interface_from_name("not-a-unit");
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);

        /* NULL: only test Rust — C's unit_name_to_type asserts on NULL */
        rs_r = rs_unit_dbus_interface_from_name(NULL);
        assert_se(rs_r == NULL);
}

/* ── file_in_same_dir ──────────────────────────────────────────────── */

static void test_file_in_same_dir(void) {
        char *c_r = NULL, *rs_r = NULL;
        int c_ret, rs_ret;

        /* Normal case */
        c_ret = file_in_same_dir("/foo/bar", "baz", &c_r);
        rs_ret = rs_file_in_same_dir("/foo/bar", "baz", &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "/foo/baz"));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* Absolute filename overrides */
        c_ret = file_in_same_dir("/foo/bar", "/quux/corge", &c_r);
        rs_ret = rs_file_in_same_dir("/foo/bar", "/quux/corge", &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "/quux/corge"));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* Path without directory component (EDESTADDRREQ) */
        c_ret = file_in_same_dir("file.txt", "other.txt", &c_r);
        rs_ret = rs_file_in_same_dir("file.txt", "other.txt", &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* Root path: C returns -EADDRNOTAVAIL since "/" has no dir prefix */
        c_ret = file_in_same_dir("/", "etc", &c_r);
        rs_ret = rs_file_in_same_dir("/", "etc", &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret < 0);

        /* Path with trailing slash */
        c_ret = file_in_same_dir("/foo/bar/", "baz", &c_r);
        rs_ret = rs_file_in_same_dir("/foo/bar/", "baz", &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;
}

int main(int argc, char **argv) {
        test_unit_dbus_path_from_name();
        test_unit_name_from_dbus_path();
        test_unit_dbus_interface_from_type();
        test_unit_dbus_interface_from_name();
        test_file_in_same_dir();
        return 0;
}
