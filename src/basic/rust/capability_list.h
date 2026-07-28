/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.capability-list; authority=src/basic/capability-list.c,src/basic/capability-list.h,src/basic/parse-util.c,src/basic/parse-util.h,src/basic/generate-capability-list.sh,src/basic/capability-to-name.awk,src/basic/meson.build,src/include/meson.build,src/include/uapi/linux/capability.h,tools/generate-gperfs.py */

#include "capability-list.h"

const char *rs_capability_to_name(int id);
const char *rs_capability_to_string(int id, char buf[static CAPABILITY_TO_STRING_MAX]);
int rs_capability_from_name(const char *name);
unsigned rs_capability_list_length(void);
