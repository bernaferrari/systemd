/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.efivars-util; authority=src/fundamental/efivars.c,src/fundamental/efivars.h,src/basic/efivars.c,src/basic/efivars.h,src/shared/efi-api.c,src/shared/efi-api.h */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

const char* rs_secure_boot_mode_to_string(int m);
int rs_decode_secure_boot_mode(bool secure, bool audit, bool deployed, bool setup, bool moksb);
char* rs_efi_tilt_backslashes(char *s);

/* Uses output pointers to avoid aarch64 ABI differences with C unions */
int rs_efi_guid_to_id128(const void *guid, uint8_t *ret);
void rs_efi_id128_to_guid(const uint8_t *id, void *ret_guid);
