/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "ratelimit.h"

/* For backwards compatibility with existing test code */
typedef RateLimit rs_RateLimit;

bool rs_ratelimit_below(RateLimit *rl);
uint32_t rs_ratelimit_num_dropped(const RateLimit *rl);
uint64_t rs_ratelimit_end(const RateLimit *rl);
uint64_t rs_ratelimit_left(const RateLimit *rl);
void rs_ratelimit_reset(RateLimit *rl);
bool rs_ratelimit_configured(const RateLimit *rl);
