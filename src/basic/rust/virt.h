/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

const char *rs_virtualization_to_string(int v);
int rs_virtualization_from_string(const char *s);
bool rs_VIRTUALIZATION_IS_VM(int value);
bool rs_VIRTUALIZATION_IS_CONTAINER(int value);
