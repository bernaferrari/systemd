/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.devnum-util; authority=src/basic/devnum-util.c,src/basic/devnum-util.h */
#pragma once

#include <stdbool.h>
#include <sys/types.h>

int rs_parse_devnum(const char *s, dev_t *ret);
char* rs_format_devnum(dev_t d, char buf[]);
bool rs_devnum_is_zero(dev_t d);
bool rs_devnum_set_and_equal(dev_t a, dev_t b);
int rs_device_path_parse_major_minor(const char *path, mode_t *ret_mode, dev_t *ret_devnum);
int rs_device_path_make_major_minor(mode_t mode, dev_t devnum, char **ret);
int rs_device_path_make_inaccessible(mode_t mode, char **ret);
