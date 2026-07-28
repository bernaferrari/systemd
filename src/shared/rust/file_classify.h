/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.file-classify; authority=src/basic/login-util.c,src/basic/login-util.h */
#pragma once

#include <stdbool.h>

bool rs_session_id_valid(const char *id);
