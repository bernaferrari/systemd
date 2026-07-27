/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Keep the public capability mask and CapabilityQuintet layout owned by the
 * current C authority. The Rust facade uses a repr(C) mirror of that complete
 * five-uint64_t type; it does not borrow a guessed prefix of another object. */
#include "capability-util.h"

bool rs_capability_is_set(uint64_t v);

/* A NULL quintet is treated as unset/not-fully-set. */
bool rs_capability_quintet_is_set(const CapabilityQuintet *q);
bool rs_capability_quintet_is_fully_set(const CapabilityQuintet *q);

/* Two NULL pointers compare equal; exactly one NULL pointer compares unequal. */
bool rs_capability_quintet_equal(const CapabilityQuintet *a, const CapabilityQuintet *b);
