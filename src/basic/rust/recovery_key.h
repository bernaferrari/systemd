/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=shared.recovery-key; authority=src/shared/recovery-key.c,src/shared/recovery-key.h */
#pragma once

int rs_decode_modhex_char(char x);
int rs_normalize_recovery_key(const char *password, char **ret);
