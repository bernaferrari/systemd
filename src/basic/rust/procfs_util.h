/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.procfs-util; authority=src/basic/procfs-util.c,src/basic/procfs-util.h */
#pragma once

#include <stdint.h>

int rs_convert_meminfo_value_to_uint64_bytes(const char *s, uint64_t *ret);
int rs_procfs_get_pid_max(uint64_t *ret);
int rs_procfs_get_threads_max(uint64_t *ret);
int rs_procfs_tasks_set_limit(uint64_t limit);
int rs_procfs_tasks_get_current(uint64_t *ret);
int rs_procfs_cpu_get_usage(uint64_t *ret);
int rs_procfs_memory_get(uint64_t *ret_total, uint64_t *ret_used);
