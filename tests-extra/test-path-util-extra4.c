/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "path-util.h"
#include "tests.h"

TEST(valid_device_node_path_basic) {
        assert_se(valid_device_node_path("/dev/sda"));
        assert_se(valid_device_node_path("/dev/null"));
        assert_se(valid_device_node_path("/dev/loop0"));
        assert_se(valid_device_node_path("/run/systemd/inaccessible/blk"));
        assert_se(!valid_device_node_path("sda"));
        assert_se(!valid_device_node_path("/dev/"));
        assert_se(!valid_device_node_path("/etc/fstab"));
}

TEST(valid_device_allow_pattern_basic) {
        /* Regular device paths */
        assert_se(valid_device_allow_pattern("/dev/sda"));
        assert_se(valid_device_allow_pattern("/dev/null"));

        /* Subsystem patterns */
        assert_se(valid_device_allow_pattern("block-"));
        assert_se(valid_device_allow_pattern("char-"));
        assert_se(valid_device_allow_pattern("block-sda"));
        assert_se(valid_device_allow_pattern("char-"));

        /* Invalid */
        assert_se(!valid_device_allow_pattern("invalid"));
        assert_se(!valid_device_allow_pattern("/etc/fstab"));
}

TEST(dot_or_dot_dot_basic) {
        assert_se(dot_or_dot_dot("."));
        assert_se(dot_or_dot_dot(".."));
        assert_se(!dot_or_dot_dot(".hidden"));
        assert_se(!dot_or_dot_dot("..."));
        assert_se(!dot_or_dot_dot(""));
        assert_se(!dot_or_dot_dot("a"));
        assert_se(!dot_or_dot_dot(NULL));
}

TEST(path_implies_directory_basic) {
        /* Trailing slash implies directory */
        assert_se(path_implies_directory("/foo/"));
        assert_se(path_implies_directory("/"));

        /* . and .. imply directory */
        assert_se(path_implies_directory("."));
        assert_se(path_implies_directory(".."));

        /* Paths ending with /. or /.. imply directory */
        assert_se(path_implies_directory("/foo/."));
        assert_se(path_implies_directory("/foo/.."));

        /* Regular paths don't */
        assert_se(!path_implies_directory("/foo"));
        assert_se(!path_implies_directory("foo"));
        assert_se(!path_implies_directory(NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
