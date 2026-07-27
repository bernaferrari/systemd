/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Rust FFI declarations for shadow testing hostname-setup.c */
int rs_shorten_overlong(const char *s, char **ret);
