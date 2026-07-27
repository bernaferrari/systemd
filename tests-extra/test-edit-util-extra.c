/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "edit-util.h"
#include "string-util.h"
#include "tests.h"

TEST(edit_file_context_done_empty) {
        EditFileContext context = {};

        /* Calling done on empty context should be safe */
        edit_file_context_done(&context);
        assert_se(context.files == NULL);
        assert_se(context.n_files == 0);
}

TEST(edit_files_contains_empty) {
        EditFileContext context = {};

        assert_se(!edit_files_contains(&context, "/etc/test.conf"));
}

TEST(edit_files_add_and_contains) {
        _cleanup_(edit_file_context_done) EditFileContext context = {};
        int r;

        r = edit_files_add(&context, "/etc/test.conf", NULL, NULL);
        assert_se(r > 0);
        assert_se(context.n_files == 1);
        assert_se(edit_files_contains(&context, "/etc/test.conf"));
        assert_se(!edit_files_contains(&context, "/etc/other.conf"));

        /* Adding the same path again returns 0 (already present) */
        r = edit_files_add(&context, "/etc/test.conf", NULL, NULL);
        assert_se(r == 0);
        assert_se(context.n_files == 1);
}

TEST(edit_files_add_with_original) {
        _cleanup_(edit_file_context_done) EditFileContext context = {};
        int r;

        r = edit_files_add(&context, "/etc/test.conf", "/usr/share/test.conf", NULL);
        assert_se(r > 0);
        assert_se(context.n_files == 1);
}

TEST(edit_files_add_multiple) {
        _cleanup_(edit_file_context_done) EditFileContext context = {};
        int r;

        r = edit_files_add(&context, "/etc/a.conf", NULL, NULL);
        assert_se(r > 0);

        r = edit_files_add(&context, "/etc/b.conf", NULL, NULL);
        assert_se(r > 0);

        r = edit_files_add(&context, "/etc/c.conf", NULL, NULL);
        assert_se(r > 0);

        assert_se(context.n_files == 3);
        assert_se(edit_files_contains(&context, "/etc/a.conf"));
        assert_se(edit_files_contains(&context, "/etc/b.conf"));
        assert_se(edit_files_contains(&context, "/etc/c.conf"));
        assert_se(!edit_files_contains(&context, "/etc/d.conf"));
}

TEST(edit_file_context_done_with_files) {
        EditFileContext context = {};
        int r;

        r = edit_files_add(&context, "/etc/test1.conf", NULL, NULL);
        assert_se(r > 0);
        r = edit_files_add(&context, "/etc/test2.conf", NULL, NULL);
        assert_se(r > 0);

        assert_se(context.n_files == 2);

        edit_file_context_done(&context);
        assert_se(context.files == NULL);
        assert_se(context.n_files == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
