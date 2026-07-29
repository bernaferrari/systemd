/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.pe-binary; authority=src/shared/pe-binary.c,src/shared/pe-binary.h */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Packed PE inspection shadows. Every pointer is borrowed: `pe_header` must
 * reference a readable packed PeHeader and `sections` its counted packed
 * IMAGE_SECTION_HEADER records. Returned section/data-directory pointers borrow
 * from those inputs and must never be freed. Malformed C assertion-precondition
 * inputs fail closed instead of reaching C's assertion path.
 */
bool rs_pe_header_is_64bit(const void *h);
const void *rs_pe_section_table_find(const void *sections, size_t n_sections, const char *name);
const void *rs_pe_header_find_section(const void *pe_header, const void *sections, const char *name);
bool rs_pe_is_uki(const void *pe_header, const void *sections);
bool rs_pe_is_addon(const void *pe_header, const void *sections);
bool rs_pe_is_native(const void *pe_header);
const void *rs_pe_header_get_data_directory(const void *pe_header, size_t i);
