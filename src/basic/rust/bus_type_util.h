/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Shadow FFI for bus-type pure functions from src/libsystemd/sd-bus/bus-type.c */

bool rs_bus_type_is_valid(char c);
bool rs_bus_type_is_basic(char c);
bool rs_bus_type_is_trivial(char c);
bool rs_bus_type_is_container(char c);
int rs_bus_type_get_alignment(char c);
int rs_bus_type_get_size(char c);

/* Shadow FFI for trivial hash/comparison from src/basic/hash-funcs.c */

int rs_trivial_compare_func(const void *a, const void *b);
int rs_uint64_compare_func(const uint64_t *a, const uint64_t *b);
int rs_devt_compare_func(const dev_t *a, const dev_t *b);
