/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C install helpers vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "install.h"
#include "rust/install.h"

/* ── install_changes_have_modification ─────────────────────────────── */

TEST(install_changes_have_modification_empty) {
        assert_se(install_changes_have_modification(NULL, 0) == rs_install_changes_have_modification(NULL, 0));
        assert_se(!install_changes_have_modification(NULL, 0));
}

TEST(install_changes_have_modification_no_modification) {
        /* Only INSTALL_CHANGE_IS_MASKED — not a modification. */
        InstallChange c_changes[] = {
                { .type = INSTALL_CHANGE_IS_MASKED, .path = (char*)"a", .source = NULL },
                { .type = INSTALL_CHANGE_IS_MASKED, .path = (char*)"b", .source = NULL },
        };
        assert_se(install_changes_have_modification(c_changes, 2) == rs_install_changes_have_modification(c_changes, 2));
        assert_se(!install_changes_have_modification(c_changes, 2));
}

TEST(install_changes_have_modification_with_symlink) {
        InstallChange c_changes[] = {
                { .type = INSTALL_CHANGE_SYMLINK, .path = (char*)"a", .source = NULL },
        };
        assert_se(install_changes_have_modification(c_changes, 1) == rs_install_changes_have_modification(c_changes, 1));
        assert_se(install_changes_have_modification(c_changes, 1));
}

TEST(install_changes_have_modification_with_unlink) {
        InstallChange c_changes[] = {
                { .type = INSTALL_CHANGE_UNLINK, .path = (char*)"a", .source = NULL },
        };
        assert_se(install_changes_have_modification(c_changes, 1) == rs_install_changes_have_modification(c_changes, 1));
        assert_se(install_changes_have_modification(c_changes, 1));
}

TEST(install_changes_have_modification_mixed) {
        InstallChange c_changes[] = {
                { .type = INSTALL_CHANGE_IS_MASKED, .path = (char*)"a", .source = NULL },
                { .type = INSTALL_CHANGE_UNLINK, .path = (char*)"b", .source = NULL },
                { .type = INSTALL_CHANGE_IS_MASKED, .path = (char*)"c", .source = NULL },
        };
        assert_se(install_changes_have_modification(c_changes, 3) == rs_install_changes_have_modification(c_changes, 3));
        assert_se(install_changes_have_modification(c_changes, 3));
}

TEST(install_changes_have_modification_errno) {
        /* Negative type (errno) should not count as modification */
        InstallChange c_changes[] = {
                { .type = -EINVAL, .path = NULL, .source = NULL },
                { .type = -ENOENT, .path = NULL, .source = NULL },
        };
        assert_se(install_changes_have_modification(c_changes, 2) == rs_install_changes_have_modification(c_changes, 2));
        assert_se(!install_changes_have_modification(c_changes, 2));
}

/* ── main ────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
