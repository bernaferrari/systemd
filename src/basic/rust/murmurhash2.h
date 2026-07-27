/* SPDX-License-Identifier: LicenseRef-murmurhash2-public-domain */
#pragma once

#include <stdint.h>

uint32_t rs_MurmurHash2(const void *key, int len, uint32_t seed);
