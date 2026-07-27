/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "condition.h"
#include "string-util.h"
#include "tests.h"

TEST(condition_new_and_free) {
        Condition *c = NULL;

        c = condition_new(CONDITION_ARCHITECTURE, "x86-64", false, false);
        assert_se(c != NULL);
        assert_se(c->type == CONDITION_ARCHITECTURE);
        assert_se(streq(c->parameter, "x86-64"));
        assert_se(c->trigger == false);
        assert_se(c->negate == false);
        c = condition_free(c);
        assert_se(c == NULL);

        /* With trigger and negate */
        Condition *c2 = NULL;
        c2 = condition_new(CONDITION_KERNEL_COMMAND_LINE, "quiet", true, true);
        assert_se(c2 != NULL);
        assert_se(c2->type == CONDITION_KERNEL_COMMAND_LINE);
        assert_se(c2->trigger == true);
        assert_se(c2->negate == true);
        c2 = condition_free(c2);
}

TEST(condition_free_list_type) {
        Condition *list = NULL, *c1 = NULL, *c2 = NULL;

        c1 = condition_new(CONDITION_PATH_EXISTS, "/tmp", false, false);
        assert_se(c1);
        c2 = condition_new(CONDITION_KERNEL_COMMAND_LINE, "quiet", false, false);
        assert_se(c2);

        LIST_PREPEND(conditions, list, c2);
        LIST_PREPEND(conditions, list, c1);
        assert_se(list != NULL);

        /* Remove only PATH_EXISTS conditions */
        list = condition_free_list_type(list, CONDITION_PATH_EXISTS);
        assert_se(list != NULL);
        assert_se(list->type == CONDITION_KERNEL_COMMAND_LINE);

        /* Remove all (type < 0) */
        list = condition_free_list_type(list, -1);
        assert_se(list == NULL);

        /* NULL is safe */
        condition_free_list_type(NULL, -1);
}

TEST(condition_takes_path) {
        /* Path-based conditions */
        assert_se(condition_takes_path(CONDITION_PATH_EXISTS));
        assert_se(condition_takes_path(CONDITION_PATH_EXISTS_GLOB));
        assert_se(condition_takes_path(CONDITION_PATH_IS_DIRECTORY));
        assert_se(condition_takes_path(CONDITION_PATH_IS_SYMBOLIC_LINK));
        assert_se(condition_takes_path(CONDITION_PATH_IS_MOUNT_POINT));
        assert_se(condition_takes_path(CONDITION_PATH_IS_READ_WRITE));
        assert_se(condition_takes_path(CONDITION_DIRECTORY_NOT_EMPTY));
        assert_se(condition_takes_path(CONDITION_FILE_NOT_EMPTY));
        assert_se(condition_takes_path(CONDITION_FILE_IS_EXECUTABLE));

        /* Non-path conditions */
        assert_se(!condition_takes_path(CONDITION_ARCHITECTURE));
        assert_se(!condition_takes_path(CONDITION_KERNEL_COMMAND_LINE));
        assert_se(!condition_takes_path(CONDITION_HOST));
        assert_se(!condition_takes_path(CONDITION_VIRTUALIZATION));
        assert_se(!condition_takes_path(CONDITION_USER));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
