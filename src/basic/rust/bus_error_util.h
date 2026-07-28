/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.bus-error-util; authority=src/libsystemd/sd-bus/bus-error.c,src/libsystemd/sd-bus/bus-error.h,src/systemd/sd-bus-protocol.h */
#pragma once

#include "sd-bus-protocol.h"

/* Narrow Rust facades for sd_bus_error's pure accessors. */

bool rs_bus_error_is_dirty(sd_bus_error *e);
int rs_sd_bus_error_is_set(const sd_bus_error *e);
int rs_sd_bus_error_has_name(const sd_bus_error *e, const char *name);
