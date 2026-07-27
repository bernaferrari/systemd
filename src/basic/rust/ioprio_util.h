/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int rs_ioprio_prio_class(int value);
int rs_ioprio_prio_data(int value);
int rs_ioprio_prio_value(int class, int data);
int rs_ioprio_normalize(int value);

#ifdef __cplusplus
}
#endif
