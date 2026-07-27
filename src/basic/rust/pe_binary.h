/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>
#include <stddef.h>

/* Shadow FFI — uses void* for cross-language struct compatibility */
bool rs_pe_header_is_64bit(const void *h);
const void *rs_pe_section_table_find(const void *sections, size_t n_sections, const char *name);
const void *rs_pe_header_find_section(const void *pe_header, const void *sections, const char *name);
bool rs_pe_is_uki(const void *pe_header, const void *sections);
bool rs_pe_is_addon(const void *pe_header, const void *sections);
bool rs_pe_is_native(const void *pe_header);
const void *rs_pe_header_get_data_directory(const void *pe_header, size_t i);
