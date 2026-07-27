/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "unit-file.h"
#include "unit-name.h"

TEST(unit_symlink_name_compatible) {
        /* Exact match: plain names */
        assert_se(unit_symlink_name_compatible("foo.service", "foo.service", false) == 1);
        assert_se(unit_symlink_name_compatible("bar.socket", "bar.socket", false) == 1);

        /* Exact match: instance names */
        assert_se(unit_symlink_name_compatible("foo@inst.service", "foo@inst.service", false) == 1);

        /* No match: different names */
        assert_se(unit_symlink_name_compatible("foo.service", "bar.service", false) == 0);

        /* Instance → template: foo@inst.service → foo@.service */
        assert_se(unit_symlink_name_compatible("foo@inst.service", "foo@.service", false) == 1);

        /* Template → template with instance_propagation */
        assert_se(unit_symlink_name_compatible("foo@.service", "foo@.service", true) == 1);

        /* Template → template without instance_propagation → 0 */
        assert_se(unit_symlink_name_compatible("foo@.service", "foo@.service", false) == 0);

        /* Not a template: plain name can't match template */
        assert_se(unit_symlink_name_compatible("foo.service", "foo@.service", false) == 0);

        /* Instance → different template → no match */
        assert_se(unit_symlink_name_compatible("foo@inst.service", "bar@.service", false) == 0);

        /* Different types → no match */
        assert_se(unit_symlink_name_compatible("foo.service", "foo.socket", false) == 0);
}

TEST(unit_validate_alias_symlink_or_warn) {
        /* Valid: same type, plain alias */
        assert_se(unit_validate_alias_symlink_or_warn(LOG_DEBUG, "foo.service", "bar.service") >= 0);

        /* Invalid: different types */
        assert_se(unit_validate_alias_symlink_or_warn(LOG_DEBUG, "foo.service", "bar.socket") < 0);

        /* Invalid: target is template but link is plain */
        assert_se(unit_validate_alias_symlink_or_warn(LOG_DEBUG, "foo.service", "bar@.service") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
