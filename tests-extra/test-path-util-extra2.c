/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "path-util.h"
#include "tests.h"

TEST(empty_or_root) {
        ASSERT_TRUE(empty_or_root(NULL));
        ASSERT_TRUE(empty_or_root(""));
        ASSERT_TRUE(empty_or_root("/"));
        ASSERT_FALSE(empty_or_root("/foo"));
        ASSERT_FALSE(empty_or_root("bar"));
}

TEST(is_path) {
        ASSERT_TRUE(is_path("/"));
        ASSERT_TRUE(is_path("/foo"));
        ASSERT_TRUE(is_path("/foo/bar"));
        ASSERT_FALSE(is_path("foo"));
        ASSERT_FALSE(is_path(""));
}

TEST(path_is_normalized) {
        ASSERT_TRUE(path_is_normalized("/"));
        ASSERT_TRUE(path_is_normalized("/foo"));
        ASSERT_TRUE(path_is_normalized("/foo/bar"));
        ASSERT_FALSE(path_is_normalized("/foo/../bar"));
        ASSERT_FALSE(path_is_normalized("/foo/./bar"));
        ASSERT_FALSE(path_is_normalized("/foo//bar"));
}

TEST(filename_is_valid) {
        ASSERT_TRUE(filename_is_valid("foo"));
        ASSERT_TRUE(filename_is_valid("foo.txt"));
        ASSERT_TRUE(filename_is_valid(".hidden"));
        ASSERT_FALSE(filename_is_valid("foo/bar"));
        ASSERT_FALSE(filename_is_valid(""));
        ASSERT_FALSE(filename_is_valid("."));
        ASSERT_FALSE(filename_is_valid(".."));
}

TEST(path_is_safe) {
        ASSERT_TRUE(path_is_safe("foo"));
        ASSERT_TRUE(path_is_safe("foo/bar"));
        ASSERT_FALSE(path_is_safe("foo/.."));
        ASSERT_FALSE(path_is_safe("../bar"));
}

TEST(hidden_or_backup_file) {
        ASSERT_TRUE(hidden_or_backup_file(".hidden"));
        ASSERT_TRUE(hidden_or_backup_file("file~"));
        ASSERT_TRUE(hidden_or_backup_file("file.bak"));
        ASSERT_FALSE(hidden_or_backup_file("normal"));
}

TEST(is_device_path) {
        ASSERT_FALSE(is_device_path("/dev"));    /* bare /dev is not a device path */
        ASSERT_TRUE(is_device_path("/dev/null"));
        ASSERT_TRUE(is_device_path("/dev/sda1"));
        ASSERT_TRUE(is_device_path("/sys/class"));
        ASSERT_FALSE(is_device_path("/home"));
        ASSERT_FALSE(is_device_path("/dev../"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
