/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.serialize; authority=src/shared/serialize.c,src/shared/serialize.h */
#include <stdint.h>

struct dual_timestamp;

/* Both outputs are written only when the function returns 0. */
int rs_deserialize_usec(const char *value, uint64_t *ret);
int rs_deserialize_dual_timestamp(const char *value, struct dual_timestamp *ret);
