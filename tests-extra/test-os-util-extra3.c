/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "fd-util.h"
#include "os-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(image_name_is_valid_basic) {
        assert_se(image_name_is_valid("test"));
        assert_se(image_name_is_valid("my-image"));
        assert_se(image_name_is_valid("image123"));
        assert_se(!image_name_is_valid(""));
        assert_se(!image_name_is_valid(NULL));
        assert_se(!image_name_is_valid("."));
        assert_se(!image_name_is_valid(".."));
        assert_se(!image_name_is_valid("has/slash"));
}

TEST(path_extract_image_name_basic) {
        _cleanup_free_ char *name = NULL;
        int r;

        r = path_extract_image_name("/var/lib/machines/myimage", &name);
        if (r >= 0) {
                assert_se(streq(name, "myimage"));
                log_debug("path_extract_image_name: %s", name);
        }

        name = mfree(name);
        r = path_extract_image_name("/path/to/test.raw", &name);
        if (r >= 0)
                log_debug("path_extract_image_name(.raw): %s", name);
}

TEST(path_is_os_tree_basic) {
        int r = path_is_os_tree("/");
        log_debug("path_is_os_tree(/): %d", r);

        r = path_is_os_tree("/nonexistent-path-xyz");
        log_debug("path_is_os_tree(nonexistent): %d", r);
}

TEST(fd_is_os_tree_basic) {
        /* Need a real directory fd, AT_FDCWD is a special value (-100) */
        _cleanup_close_ int fd = open("/etc", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (fd >= 0) {
                int r = fd_is_os_tree(fd);
                log_debug("fd_is_os_tree(/etc): %d", r);
        }
}

TEST(open_os_release_basic) {
        _cleanup_free_ char *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r = open_os_release(NULL, &path, &fd);
        if (r >= 0) {
                assert_se(!isempty(path));
                assert_se(fd >= 0);
                log_debug("os-release path: %s", path);
        } else
                log_debug("open_os_release: %d (%m)", r);
}

TEST(load_os_release_pairs_basic) {
        _cleanup_strv_free_ char **pairs = NULL;
        int r = load_os_release_pairs(NULL, &pairs);
        if (r >= 0) {
                assert_se(pairs);
                STRV_FOREACH_PAIR(k, v, pairs)
                        log_debug("os-release: %s=%s", *k, *v);
        } else
                log_debug("load_os_release_pairs: %d", r);
}

TEST(os_release_support_ended_basic) {
        int r = os_release_support_ended("2020-01-01", true, NULL);
        if (r >= 0)
                log_debug("support_ended(2020-01-01): %d", r);

        r = os_release_support_ended("2099-01-01", true, NULL);
        if (r >= 0) {
                assert_se(r == 0);
                log_debug("support_ended(2099-01-01): %d", r);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
