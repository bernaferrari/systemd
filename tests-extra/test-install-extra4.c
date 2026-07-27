/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "install.h"
#include "string-util.h"
#include "tests.h"

TEST(install_changes_add_and_free) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;
        InstallChangeType r;

        /* Add a symlink change */
        r = install_changes_add(&changes, &n_changes, INSTALL_CHANGE_SYMLINK, "/etc/foo.service", "/usr/lib/foo.service");
        assert_se(r == INSTALL_CHANGE_SYMLINK);
        assert_se(n_changes == 1);
        assert_se(changes != NULL);
        assert_se(streq(changes[0].path, "/etc/foo.service"));
        assert_se(streq(changes[0].source, "/usr/lib/foo.service"));

        /* Add an unlink change */
        r = install_changes_add(&changes, &n_changes, INSTALL_CHANGE_UNLINK, "/etc/bar.service", NULL);
        assert_se(r == INSTALL_CHANGE_UNLINK);
        assert_se(n_changes == 2);

        /* Add an is-masked change */
        r = install_changes_add(&changes, &n_changes, INSTALL_CHANGE_IS_MASKED, "/etc/baz.service", NULL);
        assert_se(r == INSTALL_CHANGE_IS_MASKED);
        assert_se(n_changes == 3);

        install_changes_free(changes, n_changes);

        /* NULL changes + zero count is safe */
        install_changes_free(NULL, 0);
}

TEST(install_changes_have_modification) {
        InstallChange *changes = NULL;
        size_t n_changes = 0;

        /* No changes → no modification */
        assert_se(!install_changes_have_modification(changes, n_changes));

        /* Add a non-modification type (IS_MASKED) */
        install_changes_add(&changes, &n_changes, INSTALL_CHANGE_IS_MASKED, "/etc/masked.service", NULL);
        assert_se(!install_changes_have_modification(changes, n_changes));

        /* Add a modification type (SYMLINK) */
        install_changes_add(&changes, &n_changes, INSTALL_CHANGE_SYMLINK, "/etc/linked.service", "/usr/lib/linked.service");
        assert_se(install_changes_have_modification(changes, n_changes));

        install_changes_free(changes, n_changes);
        changes = NULL;
        n_changes = 0;

        /* Add UNLINK → is modification */
        install_changes_add(&changes, &n_changes, INSTALL_CHANGE_UNLINK, "/etc/unlinked.service", NULL);
        assert_se(install_changes_have_modification(changes, n_changes));

        install_changes_free(changes, n_changes);
}

TEST(INSTALL_CHANGE_TYPE_VALID) {
        assert_se(INSTALL_CHANGE_TYPE_VALID(INSTALL_CHANGE_SYMLINK));
        assert_se(INSTALL_CHANGE_TYPE_VALID(INSTALL_CHANGE_UNLINK));
        assert_se(INSTALL_CHANGE_TYPE_VALID(INSTALL_CHANGE_IS_MASKED));
        assert_se(INSTALL_CHANGE_TYPE_VALID(INSTALL_CHANGE_IS_DANGLING));

        /* Out of range */
        assert_se(!INSTALL_CHANGE_TYPE_VALID(_INSTALL_CHANGE_TYPE_MAX));
        /* Note: -1 becomes unsigned and may appear valid for enum types */
}

TEST(install_change_dump_error) {
        InstallChange change = {
                .type = -EEXIST,
                .path = (char*) "/etc/test.service",
                .source = (char*) "/usr/lib/test.service",
        };

        _cleanup_free_ char *errmsg = NULL;
        const char *bus_error = NULL;
        int r;

        /* -EEXIST is a known error → returns 0 */
        r = install_change_dump_error(&change, &errmsg, &bus_error);
        assert_se(r == 0);
        assert_se(errmsg != NULL);
        assert_se(bus_error != NULL);
        errmsg = mfree(errmsg);

        /* -ENOENT */
        change.type = -ENOENT;
        r = install_change_dump_error(&change, &errmsg, &bus_error);
        assert_se(r == 0);
        assert_se(errmsg != NULL);
}

TEST(unit_file_presets_done) {
        /* NULL is safe */
        unit_file_presets_done(NULL);

        /* Empty presets is safe */
        UnitFilePresets p = {};
        unit_file_presets_done(&p);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
