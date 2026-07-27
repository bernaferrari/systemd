/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <string.h>

#include "tests.h"
#include "xattr-util.h"
#include "rust/xattr_util.h"

/* ── xattr_is_acl ──────────────────────────────────────────────────────── */

static void test_xattr_is_acl_access(void) {
        assert_se(xattr_is_acl("system.posix_acl_access") == rs_xattr_is_acl("system.posix_acl_access"));
        assert_se(xattr_is_acl("system.posix_acl_access"));
}

static void test_xattr_is_acl_default(void) {
        assert_se(xattr_is_acl("system.posix_acl_default") == rs_xattr_is_acl("system.posix_acl_default"));
        assert_se(xattr_is_acl("system.posix_acl_default"));
}

static void test_xattr_is_acl_other(void) {
        assert_se(xattr_is_acl("user.comment") == rs_xattr_is_acl("user.comment"));
        assert_se(!xattr_is_acl("user.comment"));
}

static void test_xattr_is_acl_prefix(void) {
        assert_se(xattr_is_acl("system.posix_acl") == rs_xattr_is_acl("system.posix_acl"));
        assert_se(!xattr_is_acl("system.posix_acl"));
}

/* ── xattr_is_selinux ──────────────────────────────────────────────────── */

static void test_xattr_is_selinux_match(void) {
        assert_se(xattr_is_selinux("security.selinux") == rs_xattr_is_selinux("security.selinux"));
        assert_se(xattr_is_selinux("security.selinux"));
}

static void test_xattr_is_selinux_other(void) {
        assert_se(xattr_is_selinux("security.capability") == rs_xattr_is_selinux("security.capability"));
        assert_se(!xattr_is_selinux("security.capability"));
}

static void test_xattr_is_selinux_prefix(void) {
        assert_se(xattr_is_selinux("security.selinux_sub") == rs_xattr_is_selinux("security.selinux_sub"));
        assert_se(!xattr_is_selinux("security.selinux_sub"));
}

int main(int argc, char *argv[]) {
        test_xattr_is_acl_access();
        test_xattr_is_acl_default();
        test_xattr_is_acl_other();
        test_xattr_is_acl_prefix();
        test_xattr_is_selinux_match();
        test_xattr_is_selinux_other();
        test_xattr_is_selinux_prefix();

        return 0;
}
