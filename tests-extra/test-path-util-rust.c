/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "tests.h"
#include "fd-util.h"
#include "path-util.h"

/* Rust FFI */
#include "rust/path_util.h"

/* RUST-CONTRACT: path-base-predicates */
/* ── is_path ─────────────────────────────────────────────────────────── */

TEST(is_path_basic) {
        assert_se(is_path("/foo/bar") == rs_is_path("/foo/bar"));
        assert_se(is_path("/foo/bar"));
        assert_se(!is_path("foobar"));
        assert_se(!rs_is_path("foobar"));
}

TEST(is_path_null) {
        assert_se(is_path(NULL) == rs_is_path(NULL));
        assert_se(!is_path(NULL));
}

TEST(is_path_root) {
        assert_se(is_path("/") == rs_is_path("/"));
        assert_se(is_path("/"));
}

/* ── dot_or_dot_dot ─────────────────────────────────────────────────── */

TEST(dot_or_dot_dot_dot) {
        assert_se(dot_or_dot_dot(".") == rs_dot_or_dot_dot("."));
        assert_se(dot_or_dot_dot("."));
}

TEST(dot_or_dot_dot_dotdot) {
        assert_se(dot_or_dot_dot("..") == rs_dot_or_dot_dot(".."));
        assert_se(dot_or_dot_dot(".."));
}

TEST(dot_or_dot_dot_triple) {
        assert_se(dot_or_dot_dot("...") == rs_dot_or_dot_dot("..."));
        assert_se(!dot_or_dot_dot("..."));
}

TEST(dot_or_dot_dot_null) {
        assert_se(dot_or_dot_dot(NULL) == rs_dot_or_dot_dot(NULL));
        assert_se(!dot_or_dot_dot(NULL));
}

TEST(dot_or_dot_dot_foo) {
        assert_se(dot_or_dot_dot("foo") == rs_dot_or_dot_dot("foo"));
        assert_se(!dot_or_dot_dot("foo"));
}

/* ── filename_part_is_valid ──────────────────────────────────────────── */

TEST(filename_part_is_valid_basic) {
        assert_se(filename_part_is_valid("foo") == rs_filename_part_is_valid("foo"));
        assert_se(filename_part_is_valid("foo"));
}

TEST(filename_part_is_valid_dot) {
        assert_se(filename_part_is_valid(".") == rs_filename_part_is_valid("."));
        assert_se(filename_part_is_valid("."));
}

TEST(filename_part_is_valid_dotdot) {
        assert_se(filename_part_is_valid("..") == rs_filename_part_is_valid(".."));
        assert_se(filename_part_is_valid(".."));
}

TEST(filename_part_is_valid_empty) {
        assert_se(filename_part_is_valid("") == rs_filename_part_is_valid(""));
        assert_se(filename_part_is_valid(""));
}

TEST(filename_part_is_valid_null) {
        assert_se(filename_part_is_valid(NULL) == rs_filename_part_is_valid(NULL));
        assert_se(!filename_part_is_valid(NULL));
}

TEST(filename_part_is_valid_with_slash) {
        assert_se(filename_part_is_valid("foo/bar") == rs_filename_part_is_valid("foo/bar"));
        assert_se(!filename_part_is_valid("foo/bar"));
}

TEST(filename_part_is_valid_name_max) {
        char name[NAME_MAX + 2];

        memset(name, 'x', sizeof(name) - 1);
        name[sizeof(name) - 1] = 0;

        assert_se(filename_part_is_valid(name) == rs_filename_part_is_valid(name));
        assert_se(!filename_part_is_valid(name));
}

/* ── filename_is_valid ───────────────────────────────────────────────── */

TEST(filename_is_valid_basic) {
        assert_se(filename_is_valid("foo") == rs_filename_is_valid("foo"));
        assert_se(filename_is_valid("foo"));
}

TEST(filename_is_valid_dot) {
        assert_se(filename_is_valid(".") == rs_filename_is_valid("."));
        assert_se(!filename_is_valid("."));
}

TEST(filename_is_valid_dotdot) {
        assert_se(filename_is_valid("..") == rs_filename_is_valid(".."));
        assert_se(!filename_is_valid(".."));
}

TEST(filename_is_valid_empty) {
        assert_se(filename_is_valid("") == rs_filename_is_valid(""));
        assert_se(!filename_is_valid(""));
}

TEST(filename_is_valid_null) {
        assert_se(filename_is_valid(NULL) == rs_filename_is_valid(NULL));
        assert_se(!filename_is_valid(NULL));
}

TEST(filename_is_valid_with_slash) {
        assert_se(filename_is_valid("foo/bar") == rs_filename_is_valid("foo/bar"));
        assert_se(!filename_is_valid("foo/bar"));
}

/* ── hidden_or_backup_file ───────────────────────────────────────────── */

TEST(hidden_or_backup_file_dotfile) {
        assert_se(hidden_or_backup_file(".hidden") == rs_hidden_or_backup_file(".hidden"));
        assert_se(hidden_or_backup_file(".hidden"));
}

TEST(hidden_or_backup_file_tilde) {
        assert_se(hidden_or_backup_file("foo~") == rs_hidden_or_backup_file("foo~"));
        assert_se(hidden_or_backup_file("foo~"));
}

TEST(hidden_or_backup_file_bak) {
        assert_se(hidden_or_backup_file("foo.bak") == rs_hidden_or_backup_file("foo.bak"));
        assert_se(hidden_or_backup_file("foo.bak"));
}

TEST(hidden_or_backup_file_rpmnew) {
        assert_se(hidden_or_backup_file("foo.rpmnew") == rs_hidden_or_backup_file("foo.rpmnew"));
        assert_se(hidden_or_backup_file("foo.rpmnew"));
}

TEST(hidden_or_backup_file_normal) {
        assert_se(hidden_or_backup_file("foo.txt") == rs_hidden_or_backup_file("foo.txt"));
        assert_se(!hidden_or_backup_file("foo.txt"));
}

TEST(hidden_or_backup_file_lost_found) {
        assert_se(hidden_or_backup_file("lost+found") == rs_hidden_or_backup_file("lost+found"));
        assert_se(hidden_or_backup_file("lost+found"));
}

/* ── empty_or_root ───────────────────────────────────────────────────── */

TEST(empty_or_root_null) {
        assert_se(empty_or_root(NULL) == rs_empty_or_root(NULL));
        assert_se(empty_or_root(NULL));
}

TEST(empty_or_root_empty) {
        assert_se(empty_or_root("") == rs_empty_or_root(""));
        assert_se(empty_or_root(""));
}

TEST(empty_or_root_slash) {
        assert_se(empty_or_root("/") == rs_empty_or_root("/"));
        assert_se(empty_or_root("/"));
}

TEST(empty_or_root_path) {
        assert_se(empty_or_root("/foo") == rs_empty_or_root("/foo"));
        assert_se(!empty_or_root("/foo"));
}

/* ── empty_to_root ───────────────────────────────────────────────────── */

/* RUST-CONTRACT: path-empty-to-root */
TEST(empty_to_root_empty) {
        assert_se(streq(empty_to_root(""), rs_empty_to_root("")));
}

TEST(empty_to_root_null) {
        assert_se(streq(empty_to_root(NULL), rs_empty_to_root(NULL)));
}

TEST(empty_to_root_path) {
        assert_se(streq(empty_to_root("/foo"), rs_empty_to_root("/foo")));
}

TEST(empty_to_root_borrows_nonempty_input) {
        static const char path[] = "/foo";

        assert_se(empty_to_root(path) == path);
        assert_se(rs_empty_to_root(path) == path);
}

/* ── path_implies_directory ──────────────────────────────────────────── */

TEST(path_implies_directory_slash) {
        assert_se(path_implies_directory("/foo/") == rs_path_implies_directory("/foo/"));
        assert_se(path_implies_directory("/foo/"));
}

TEST(path_implies_directory_dot) {
        assert_se(path_implies_directory(".") == rs_path_implies_directory("."));
        assert_se(path_implies_directory("."));
}

TEST(path_implies_directory_dotdot) {
        assert_se(path_implies_directory("..") == rs_path_implies_directory(".."));
        assert_se(path_implies_directory(".."));
}

TEST(path_implies_directory_slash_dot) {
        assert_se(path_implies_directory("/foo/.") == rs_path_implies_directory("/foo/."));
        assert_se(path_implies_directory("/foo/."));
}

TEST(path_implies_directory_slash_dotdot) {
        assert_se(path_implies_directory("/foo/..") == rs_path_implies_directory("/foo/.."));
        assert_se(path_implies_directory("/foo/.."));
}

TEST(path_implies_directory_normal) {
        assert_se(path_implies_directory("/foo/bar") == rs_path_implies_directory("/foo/bar"));
        assert_se(!path_implies_directory("/foo/bar"));
}

TEST(path_implies_directory_null) {
        assert_se(path_implies_directory(NULL) == rs_path_implies_directory(NULL));
        assert_se(!path_implies_directory(NULL));
}

/* RUST-CONTRACT: path-extra-abi */
/* RUST-CONTRACT: path-extra-predicates */
/* RUST-CONTRACT: path-file-in-same-dir */
TEST(path_extra_abi_c_vs_rs) {
        char *c_result = NULL, *rs_result = NULL;

        assert_se(fdname_is_valid("listen-fd") == rs_fdname_is_valid("listen-fd"));
        assert_se(!fdname_is_valid("bad:name") == !rs_fdname_is_valid("bad:name"));
        assert_se(path_is_absolute("/var/lib") == rs_path_is_absolute("/var/lib"));
        assert_se(path_is_absolute("relative") == rs_path_is_absolute("relative"));
        assert_se(path_is_normalized("/var/lib/systemd") == rs_path_is_normalized("/var/lib/systemd"));
        assert_se(path_is_normalized("/var//lib") == rs_path_is_normalized("/var//lib"));
        assert_se(valid_device_node_path("/dev/null") == rs_valid_device_node_path("/dev/null"));
        assert_se(valid_device_node_path("/dev/") == rs_valid_device_node_path("/dev/"));
        assert_se(valid_device_allow_pattern("block-*") == rs_valid_device_allow_pattern("block-*"));
        assert_se(valid_device_allow_pattern("/run/systemd/inaccessible/null") == rs_valid_device_allow_pattern("/run/systemd/inaccessible/null"));

        assert_se(file_in_same_dir("/var/lib/systemd/unit", "foo.service", &c_result) ==
                  rs_file_in_same_dir("/var/lib/systemd/unit", "foo.service", &rs_result));
        assert_se(streq(c_result, rs_result));
        free(c_result);
        free(rs_result);
}

/* ── main ────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
