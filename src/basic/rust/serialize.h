/* SPDX-License-Identifier: LGPL-2.1-or-later */
struct dual_timestamp;
int rs_deserialize_usec(const char *value, uint64_t *ret);
int rs_deserialize_dual_timestamp(const char *value, struct dual_timestamp *ret);
