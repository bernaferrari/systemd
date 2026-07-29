/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.sysctl-util; authority=src/basic/sysctl-util.c,src/basic/sysctl-util.h */

/* Mutates a non-null writable C byte string in place and returns the same pointer. */
char *rs_sysctl_normalize(char *s);
