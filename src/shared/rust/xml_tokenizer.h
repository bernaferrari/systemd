/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Rust FFI declarations for shadow testing xml.c */

int rs_xml_tokenize(const char **p, char **name, void **state, unsigned *line);
