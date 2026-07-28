/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=shared.compare-operator; authority=src/shared/compare-operator.c,src/shared/compare-operator.h */
#pragma once

#include <stdbool.h>

/* Narrow C ABI facades for src/shared/compare-operator.h.
 *
 * String and ordering comparisons accept NULL. Fnmatch comparisons require
 * live NUL-terminated strings. */
int rs_version_or_fnmatch_compare(int op, const char *a, const char *b);
bool rs_COMPARE_OPERATOR_IS_STRING(int c);
bool rs_COMPARE_OPERATOR_IS_FNMATCH(int c);
bool rs_COMPARE_OPERATOR_IS_ORDER(int c);
