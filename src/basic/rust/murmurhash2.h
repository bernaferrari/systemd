/* SPDX-License-Identifier: LicenseRef-murmurhash2-public-domain */
// PORT-SYNC: scope=basic.murmurhash2; authority=src/basic/MurmurHash2.c,src/basic/MurmurHash2.h
#pragma once

#include <stdint.h>

uint32_t rs_MurmurHash2(const void *key, int len, uint32_t seed);
