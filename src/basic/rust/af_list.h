/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

const char *rs_af_to_name(int id);
const char *rs_af_to_name_short(int id);
int rs_af_from_name(const char *name);
const char *rs_af_to_ipv4_ipv6(int id);
int rs_af_from_ipv4_ipv6(const char *af);
int rs_af_max(void);
