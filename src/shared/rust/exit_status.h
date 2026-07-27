/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Rust FFI declarations for shadow testing exit-status and securebits */

/* exit-status */
const char *rs_exit_status_to_string(int code, int class);
const char *rs_exit_status_class(int code);
int rs_exit_status_from_string(const char *s);

/* securebits-util */
const char *rs_secure_bit_to_string(int i);
bool rs_secure_bits_is_valid(int i);
