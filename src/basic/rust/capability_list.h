/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

const char *rs_capability_to_name(int id);
const char *rs_capability_to_string(int id, char buf[static 20]);
int rs_capability_from_name(const char *name);
unsigned rs_capability_list_length(void);
