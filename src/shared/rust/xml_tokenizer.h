/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=shared.xml-tokenizer; authority=src/shared/xml.c,src/shared/xml.h */
#pragma once

/* Rust FFI declarations for shadow testing xml.c */

int rs_xml_tokenize(const char **p, char **name, void **state, unsigned *line);
