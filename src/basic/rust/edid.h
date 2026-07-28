/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* PORT-SYNC: scope=fundamental.edid; authority=src/fundamental/edid.c,src/fundamental/edid.h */

#include <stddef.h>
#include <stdint.h>
#include "edid.h"

int rs_edid_parse_blob(const void *blob, size_t blob_size, EdidHeader *ret_header);
int rs_edid_get_panel_id(const EdidHeader *edid_header, char16_t ret_panel[static 8]);
