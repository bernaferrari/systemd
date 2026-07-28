/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.image-class; authority=src/basic/os-util.c,src/basic/os-util.h */

#include <stdbool.h>

const char *rs_image_class_to_string(int c);
int rs_image_class_from_string(const char *s);

/* Returns either one of the borrowed non-empty arguments or immutable static
 * storage for "Linux". The result must not be freed. */
const char *rs_os_release_pretty_name(const char *pretty_name, const char *name);
