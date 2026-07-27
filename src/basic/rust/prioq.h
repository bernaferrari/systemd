/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

struct rs_Prioq;

#define RS_PRIOQ_IDX_NULL UINT_MAX

struct rs_Prioq *rs_prioq_new(int (*compare)(const void *a, const void *b));
struct rs_Prioq *rs_prioq_free(struct rs_Prioq *q);
int rs_prioq_put(struct rs_Prioq *q, void *data, unsigned *idx);
int rs_prioq_remove(struct rs_Prioq *q, void *data, unsigned *idx);
void rs_prioq_reshuffle(struct rs_Prioq *q, void *data, unsigned *idx);
void *rs_prioq_peek_by_index(struct rs_Prioq *q, unsigned idx);
void *rs_prioq_pop(struct rs_Prioq *q);
unsigned rs_prioq_size(const struct rs_Prioq *q);
int rs_prioq_isempty(const struct rs_Prioq *q);
