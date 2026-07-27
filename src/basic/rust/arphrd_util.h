/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>

int rs_arphrd_from_name(const char *name);
const char *rs_arphrd_to_name(int id);
size_t rs_arphrd_to_hw_addr_len(unsigned int arphrd);
