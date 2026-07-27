/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "sd-id128.h"

/* Shadow FFI for sd_id128 functions */

/* sd_id128_t is passed by value; Rust uses repr(C, align(8)) matching the C union */
char *rs_sd_id128_to_string(sd_id128_t id, char *s);
char *rs_sd_id128_to_uuid_string(sd_id128_t id, char *s);
int rs_sd_id128_from_string(const char *s, sd_id128_t *ret);
int rs_sd_id128_string_equal(const char *s, sd_id128_t id);

int rs_id128_from_string_nonzero(const char *s, sd_id128_t *ret);
sd_id128_t rs_id128_make_v4_uuid(sd_id128_t id);
int rs_id128_compare_func(const sd_id128_t *a, const sd_id128_t *b);

int rs_sd_id128_equal(sd_id128_t a, sd_id128_t b);
int rs_sd_id128_is_null(sd_id128_t a);
sd_id128_t rs_id128_digest(const void *data, size_t size);
