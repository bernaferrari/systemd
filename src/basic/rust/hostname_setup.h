/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=shared.hostname-setup; authority=src/shared/hostname-setup.c,src/shared/hostname-setup.h,src/basic/hostname-util.c,src/basic/hostname-util.h */
#pragma once

/* Rust FFI declarations for shadow testing hostname-setup.c */
int rs_shorten_overlong(const char *s, char **ret);
