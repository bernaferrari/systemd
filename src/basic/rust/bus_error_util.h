/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus-protocol.h"

/* Shadow FFI for sd_bus_error pure accessor functions */

bool rs_bus_error_is_dirty(sd_bus_error *e);
int rs_sd_bus_error_is_set(const sd_bus_error *e);
int rs_sd_bus_error_has_name(const sd_bus_error *e, const char *name);
