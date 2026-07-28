/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.terminal-util; authority=src/basic/terminal-util.c,src/basic/terminal-util.h,src/shared/pretty-print.c */
#pragma once

#include <stdbool.h>

bool rs_tty_is_vc(const char *tty);
bool rs_tty_is_console(const char *tty);
int rs_vtnr_from_tty(const char *tty);
bool rs_url_suitable_for_osc8(const char *url);
bool rs_osc_char_is_valid(char c);
bool rs_vtnr_is_valid(unsigned n);
