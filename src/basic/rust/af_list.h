/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.af-list; authority=src/basic/af-list.c,src/basic/af-list.h,src/basic/generate-af-list.sh,src/basic/af-to-name.awk,src/basic/meson.build,src/include/meson.build,src/include/override/sys/socket.h,tools/generate-gperfs.py */

const char *rs_af_to_name(int id);
const char *rs_af_to_name_short(int id);
int rs_af_from_name(const char *name);
const char *rs_af_to_ipv4_ipv6(int id);
int rs_af_from_ipv4_ipv6(const char *af);
int rs_af_max(void);
