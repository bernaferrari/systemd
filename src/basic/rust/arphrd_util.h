/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.arphrd-util; authority=src/basic/arphrd-util.c,src/basic/arphrd-util.h,src/basic/arphrd-to-name.awk,src/basic/generate-arphrd-list.sh,src/basic/meson.build,src/include/uapi/linux/if_arp.h,tools/generate-gperfs.py */

#include <stddef.h>
#include <stdint.h>

int rs_arphrd_from_name(const char *name);
const char *rs_arphrd_to_name(int id);
size_t rs_arphrd_to_hw_addr_len(uint16_t arphrd);
