/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "image-policy.h"

/* PORT-SYNC: scope=shared.image-policy; authority=src/shared/image-policy.c,src/shared/image-policy.h */

/* Flags manipulation */
int rs_partition_policy_flags_extend(int flags);
int rs_partition_policy_flags_reduce(int flags);

/* Flags parsing/formatting */
int rs_partition_policy_flags_from_string(const char *s, bool graceful);
int rs_partition_policy_flags_to_string(int flags, bool simplify, char **ret);

/* Policy allocation */
ImagePolicy* rs_image_policy_free(ImagePolicy *p);

/* Policy lookup */
int rs_image_policy_get(const ImagePolicy *policy, int designator);
int rs_image_policy_get_exhaustively(const ImagePolicy *policy, int designator);

/* Policy comparison */
bool rs_image_policy_equal(const ImagePolicy *a, const ImagePolicy *b);
int rs_image_policy_equivalent(const ImagePolicy *a, const ImagePolicy *b);

/* Special equivalence checks */
bool rs_image_policy_equiv_ignore(const ImagePolicy *policy);
bool rs_image_policy_equiv_allow(const ImagePolicy *policy);
bool rs_image_policy_equiv_deny(const ImagePolicy *policy);

/* Policy parsing, formatting, composition, and filesystem selection */
int rs_image_policy_from_string(const char *s, bool graceful, ImagePolicy **ret);
int rs_image_policy_to_string(const ImagePolicy *policy, bool simplify, char **ret);

int rs_image_policy_intersect(const ImagePolicy *a, const ImagePolicy *b, ImagePolicy **ret);
int rs_image_policy_union(const ImagePolicy *a, const ImagePolicy *b, ImagePolicy **ret);

int rs_partition_policy_determine_fstype(
                const ImagePolicy *policy,
                int designator,
                bool *ret_encrypted,
                char **ret_fstype);
