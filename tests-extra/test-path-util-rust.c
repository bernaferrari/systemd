/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "tests.h"
#include "path-util.h"

/* Rust FFI */
#include "rust/path_util.h"

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

TEST(empty_to_root_empty) {
        assert_se(streq(empty_to_root(""), rs_empty_to_root("")));
}

TEST(empty_to_root_null) {
        assert_se(streq(empty_to_root(NULL), rs_empty_to_root(NULL)));
}

TEST(empty_to_root_path) {
        assert_se(streq(empty_to_root("/foo"), rs_empty_to_root("/foo")));
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

/* ── main ────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
