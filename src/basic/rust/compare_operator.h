/* SPDX-License-Identifier: LGPL-2.1-or-later */
int rs_version_or_fnmatch_compare(int op, const char *a, const char *b);
bool rs_COMPARE_OPERATOR_IS_STRING(int c);
bool rs_COMPARE_OPERATOR_IS_FNMATCH(int c);
bool rs_COMPARE_OPERATOR_IS_ORDER(int c);
