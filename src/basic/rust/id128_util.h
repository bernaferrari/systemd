/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=basic.id128-util; authority=src/libsystemd/sd-id128/sd-id128.c,src/libsystemd/sd-id128/id128-util.c,src/libsystemd/sd-id128/id128-util.h,src/systemd/sd-id128.h,src/fundamental/sha256.c,src/fundamental/sha256.h */

#include <stdint.h>
#include <stddef.h>

#include "sd-id128.h"

/* Safe-Rust ABI facades for the pure sd-id128 helpers. */

/* sd_id128_t is passed by value; Rust preserves the C union's 16-byte layout. */
char *rs_sd_id128_to_string(sd_id128_t id, char s[static SD_ID128_STRING_MAX]);
char *rs_sd_id128_to_uuid_string(sd_id128_t id, char s[static SD_ID128_UUID_STRING_MAX]);
int rs_sd_id128_from_string(const char *s, sd_id128_t *ret);
int rs_sd_id128_string_equal(const char *s, sd_id128_t id);

int rs_id128_from_string_nonzero(const char *s, sd_id128_t *ret);
sd_id128_t rs_id128_make_v4_uuid(sd_id128_t id);
int rs_id128_compare_func(const sd_id128_t *a, const sd_id128_t *b);

int rs_sd_id128_equal(sd_id128_t a, sd_id128_t b);
int rs_sd_id128_is_null(sd_id128_t a);
sd_id128_t rs_id128_digest(const void *data, size_t size);
