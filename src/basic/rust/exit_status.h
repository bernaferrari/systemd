/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "exit-status.h"

/* Exit status string lookups */
const char* rs_exit_status_to_string(int code, int class);
const char* rs_exit_status_class(int code);
int rs_exit_status_from_string(const char *s);

/* Securebits */
const char* rs_secure_bit_to_string(int i);
bool rs_secure_bits_is_valid(int i);

/* Exit status set operations */
bool rs_is_clean_exit(int code, int status, int clean, const ExitStatusSet *success_status);
void rs_exit_status_set_free(ExitStatusSet *x);
bool rs_exit_status_set_is_empty(const ExitStatusSet *x);
bool rs_exit_status_set_test(const ExitStatusSet *x, int code, int status);
