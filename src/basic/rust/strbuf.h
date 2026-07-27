/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

struct rs_Strbuf;
struct rs_Strbuf *rs_strbuf_new(void);
ssize_t rs_strbuf_add_string_full(struct rs_Strbuf *str, const char *s, size_t len);
void rs_strbuf_complete(struct rs_Strbuf *str);
struct rs_Strbuf *rs_strbuf_free(struct rs_Strbuf *str);
