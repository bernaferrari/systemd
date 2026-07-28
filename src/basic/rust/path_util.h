/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.path-util; authority=src/basic/path-util.c,src/basic/path-util.h */
#pragma once

/* Rust FFI declarations for path_util module. */

#include <stdbool.h>

#include "path-util.h"

bool rs_is_path(const char *p);
bool rs_is_device_path(const char *path);
bool rs_dot_or_dot_dot(const char *path);
bool rs_filename_part_is_valid(const char *p);
bool rs_filename_is_valid(const char *p);
bool rs_hidden_or_backup_file(const char *filename);
bool rs_empty_or_root(const char *path);
const char *rs_empty_to_root(const char *path);
bool rs_path_implies_directory(const char *path);
bool rs_fdname_is_valid(const char *s);
int rs_file_in_same_dir(const char *path, const char *filename, char **ret);
bool rs_path_is_absolute(const char *p);
bool rs_path_is_normalized(const char *p);
bool rs_valid_device_node_path(const char *path);
bool rs_valid_device_allow_pattern(const char *path);
/* Returns a borrowed pointer into p, matching path-util.h's inline helper. */
const char *rs_skip_dev_prefix(const char *p);

int rs_path_find_first_component(const char **p, bool accept_dot_dot, const char **ret);
int rs_path_find_last_component(const char *path, bool accept_dot_dot, const char **next, const char **ret);
const char *rs_last_path_component(const char *path);
int rs_path_compare(const char *a, const char *b);
bool rs_path_equal(const char *a, const char *b);
char *rs_path_startswith_full(const char *path, const char *prefix, PathStartWithFlags flags);
char *rs_path_startswith(const char *path, const char *prefix);
char *rs_path_simplify_full(char *path, PathSimplifyFlags flags);
char *rs_path_simplify(char *path);
int rs_path_simplify_alloc(const char *path, char **ret);
int rs_path_make_relative(const char *from, const char *to, char **ret);
bool rs_path_is_valid(const char *p);
bool rs_path_is_safe(const char *p);
bool rs_filename_or_absolute_path_is_valid(const char *p);
char *rs_path_startswith_strv(const char *p, char * const *strv);
bool rs_path_strv_contains(char * const *l, const char *path);
bool rs_prefixed_path_strv_contains(char * const *l, const char *path);
int rs_path_split_prefix_filename(const char *path, char **ret_dir, char **ret_filename);
int rs_path_extract_filename(const char *path, char **ret);
int rs_path_extract_directory(const char *path, char **ret);
int rs_path_compare_filename(const char *a, const char *b);
bool rs_path_equal_filename(const char *a, const char *b);
