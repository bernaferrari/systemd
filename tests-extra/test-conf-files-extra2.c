/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-files.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(conf_file_free_basic) {
        /* Free NULL should be safe */
        assert_se(conf_file_free(NULL) == NULL);
}

TEST(conf_file_free_many_basic) {
        /* Free NULL array should be safe */
        conf_file_free_many(NULL, 0);
}

TEST(conf_files_list_basic) {
        _cleanup_strv_free_ char **files = NULL;
        int r = conf_files_list(&files, ".conf", NULL, 0, "/etc/tmpfiles.d");
        if (r >= 0)
                log_debug("conf_files_list: %zu files", strv_length(files));
        else
                log_debug("conf_files_list: %d", r);
}

TEST(conf_files_list_strv_basic) {
        _cleanup_strv_free_ char **files = NULL;
        const char *dirs[] = { "/etc/tmpfiles.d", NULL };
        int r = conf_files_list_strv(&files, ".conf", NULL, 0, dirs);
        if (r >= 0)
                log_debug("conf_files_list_strv: %zu files", strv_length(files));
        else
                log_debug("conf_files_list_strv: %d", r);
}

TEST(conf_files_list_nulstr_basic) {
        _cleanup_strv_free_ char **files = NULL;
        const char nulstr[] = "/etc/tmpfiles.d\0";
        int r = conf_files_list_nulstr(&files, ".conf", NULL, 0, nulstr);
        if (r >= 0)
                log_debug("conf_files_list_nulstr: %zu files", strv_length(files));
        else
                log_debug("conf_files_list_nulstr: %d", r);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
