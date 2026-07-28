/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.confidential-virt; authority=src/basic/confidential-virt.c,src/basic/confidential-virt.h */
#pragma once

/* Borrowed process-lifetime string table entries; unknown values return NULL.
 * The from-string wrapper accepts NULL and returns -EINVAL. */
const char *rs_confidential_virtualization_to_string(int v);
int rs_confidential_virtualization_from_string(const char *s);
