/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/* Every non-NULL char* returned through an output pointer, and the direct
 * return from the unit-name escape helper, is allocated with the process C
 * allocator and must be released with free(). Inputs are NUL-terminated byte
 * strings; no UTF-8 interpretation is performed. */

/* Validation */
bool rs_unit_name_is_valid(const char *n, int flags);
bool rs_unit_prefix_is_valid(const char *p);
bool rs_unit_instance_is_valid(const char *i);
bool rs_unit_suffix_is_valid(const char *s);
bool rs_unit_name_is_hashed(const char *name);
bool rs_slice_name_is_valid(const char *name);
bool rs_unit_name_prefix_equal(const char *a, const char *b);

/* Parsing */
int rs_unit_name_to_prefix(const char *n, char **ret);
int rs_unit_name_to_instance(const char *n, char **ret);
int rs_unit_name_to_prefix_and_instance(const char *n, char **ret);
int rs_unit_name_to_type(const char *n);

/* Building */
int rs_unit_name_change_suffix(const char *n, const char *suffix, char **ret);
int rs_unit_name_build(const char *prefix, const char *instance, const char *suffix, char **ret);
int rs_unit_name_build_from_type(const char *prefix, const char *instance, int type, char **ret);
int rs_slice_build_parent_slice(const char *slice, char **ret);
int rs_slice_build_subslice(const char *slice, const char *name, char **ret);

/* Escape/unescape */
char *rs_unit_name_escape(const char *f);
int rs_unit_name_unescape(const char *f, char **ret);
int rs_unit_name_replace_instance_full(const char *original, const char *instance, bool accept_glob, char **ret);
int rs_unit_name_template(const char *f, char **ret);
