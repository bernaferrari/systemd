/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

const char* rs_exec_command_flags_to_string(int i);
int rs_exec_command_flags_from_string(const char *s);
int rs_exec_command_flags_from_strv(char * const *ex_opts, int *ret);
int rs_exec_command_flags_to_strv(int flags, char ***ret);
int rs_indent_embedded_newlines(const char *cmdline, char **ret_cmdline);
