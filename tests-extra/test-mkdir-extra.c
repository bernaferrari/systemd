/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mkdir.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"

TEST(mkdirat_safe_basic) {
        char path[] = "/tmp/test-mkdir-extra-XXXXXX";
        assert_se(mkdtemp(path));

        _cleanup_free_ char *sub = NULL;
        assert_se(asprintf(&sub, "%s/testdir", path) >= 0);

        int r = mkdirat_safe(AT_FDCWD, sub, 0755, UID_INVALID, GID_INVALID, 0);
        assert_se(r >= 0);
        log_debug("mkdirat_safe: %d", r);

        /* Already exists */
        r = mkdirat_safe(AT_FDCWD, sub, 0755, UID_INVALID, GID_INVALID, 0);
        assert_se(r >= 0);

        r = rm_rf(sub, REMOVE_ROOT|REMOVE_PHYSICAL);
        assert_se(r >= 0);
        r = rm_rf(path, REMOVE_ROOT|REMOVE_PHYSICAL);
        assert_se(r >= 0);
}

TEST(mkdir_safe_basic) {
        char path[] = "/tmp/test-mkdir-safe-XXXXXX";
        assert_se(mkdtemp(path));

        _cleanup_free_ char *sub = NULL;
        assert_se(asprintf(&sub, "%s/safedir", path) >= 0);

        int r = mkdir_safe(sub, 0755, UID_INVALID, GID_INVALID, 0);
        assert_se(r >= 0);

        r = rm_rf(path, REMOVE_ROOT|REMOVE_PHYSICAL);
        assert_se(r >= 0);
}

TEST(mkdir_p_basic) {
        char path[] = "/tmp/test-mkdir-p-XXXXXX";
        assert_se(mkdtemp(path));

        _cleanup_free_ char *sub = NULL;
        assert_se(asprintf(&sub, "%s/a/b/c", path) >= 0);

        int r = mkdir_p(sub, 0755);
        assert_se(r >= 0);

        r = rm_rf(path, REMOVE_ROOT|REMOVE_PHYSICAL);
        assert_se(r >= 0);
}

TEST(mkdir_parents_basic) {
        char path[] = "/tmp/test-mkdir-parents-XXXXXX";
        assert_se(mkdtemp(path));

        _cleanup_free_ char *sub = NULL;
        assert_se(asprintf(&sub, "%s/x/y/z", path) >= 0);

        int r = mkdir_parents(sub, 0755);
        assert_se(r >= 0);

        r = rm_rf(path, REMOVE_ROOT|REMOVE_PHYSICAL);
        assert_se(r >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
