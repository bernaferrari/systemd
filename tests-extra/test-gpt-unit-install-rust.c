/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: GPT partition type and unit_type helpers vs Rust */

#include <assert.h>
#include "tests.h"
#include "gpt.h"
#include "unit-file.h"
#include "rust/gpt_util.h"
#include "rust/unit_file.h"

/* Helper: make a GptPartitionType from a designator */
static GptPartitionType gpt_from(int d) {
        return (GptPartitionType) {
                .uuid = SD_ID128_NULL,
                .name = NULL,
                .arch = _ARCHITECTURE_INVALID,
                .designator = d,
        };
}

/* RUST-CONTRACT: gpt-type-predicates */
static void test_gpt_partition_type_knows_read_only(void) {
        int d;
        for (d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                GptPartitionType t = gpt_from(d);
                assert_se(gpt_partition_type_knows_read_only(t) == rs_gpt_partition_type_knows_read_only(t));
        }
        assert_se(gpt_partition_type_knows_read_only(gpt_from(-1)) ==
                  rs_gpt_partition_type_knows_read_only(gpt_from(-1)));
}

static void test_gpt_partition_type_knows_growfs(void) {
        int d;
        for (d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                GptPartitionType t = gpt_from(d);
                assert_se(gpt_partition_type_knows_growfs(t) == rs_gpt_partition_type_knows_growfs(t));
        }
}

static void test_gpt_partition_type_knows_no_auto(void) {
        int d;
        for (d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                GptPartitionType t = gpt_from(d);
                assert_se(gpt_partition_type_knows_no_auto(t) == rs_gpt_partition_type_knows_no_auto(t));
        }
}

static void test_gpt_partition_type_has_filesystem(void) {
        int d;
        for (d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                GptPartitionType t = gpt_from(d);
                assert_se(gpt_partition_type_has_filesystem(t) == rs_gpt_partition_type_has_filesystem(t));
        }
}

static void test_unit_type_may_alias(void) {
        assert_se(unit_type_may_alias(UNIT_SERVICE) == rs_unit_type_may_alias(UNIT_SERVICE));
        assert_se(unit_type_may_alias(UNIT_SOCKET) == rs_unit_type_may_alias(UNIT_SOCKET));
        assert_se(unit_type_may_alias(UNIT_TARGET) == rs_unit_type_may_alias(UNIT_TARGET));
        assert_se(unit_type_may_alias(UNIT_DEVICE) == rs_unit_type_may_alias(UNIT_DEVICE));
        assert_se(unit_type_may_alias(UNIT_TIMER) == rs_unit_type_may_alias(UNIT_TIMER));
        assert_se(unit_type_may_alias(UNIT_PATH) == rs_unit_type_may_alias(UNIT_PATH));
        assert_se(unit_type_may_alias(UNIT_MOUNT) == rs_unit_type_may_alias(UNIT_MOUNT));
        assert_se(unit_type_may_alias(UNIT_SWAP) == rs_unit_type_may_alias(UNIT_SWAP));
        assert_se(unit_type_may_alias(UNIT_SLICE) == rs_unit_type_may_alias(UNIT_SLICE));
        assert_se(unit_type_may_alias(-1) == rs_unit_type_may_alias(-1));
}

static void test_unit_type_may_template(void) {
        assert_se(unit_type_may_template(UNIT_SERVICE) == rs_unit_type_may_template(UNIT_SERVICE));
        assert_se(unit_type_may_template(UNIT_SOCKET) == rs_unit_type_may_template(UNIT_SOCKET));
        assert_se(unit_type_may_template(UNIT_TARGET) == rs_unit_type_may_template(UNIT_TARGET));
        assert_se(unit_type_may_template(UNIT_TIMER) == rs_unit_type_may_template(UNIT_TIMER));
        assert_se(unit_type_may_template(UNIT_PATH) == rs_unit_type_may_template(UNIT_PATH));
        assert_se(unit_type_may_template(UNIT_MOUNT) == rs_unit_type_may_template(UNIT_MOUNT));
        assert_se(unit_type_may_template(UNIT_SWAP) == rs_unit_type_may_template(UNIT_SWAP));
        assert_se(unit_type_may_template(UNIT_SLICE) == rs_unit_type_may_template(UNIT_SLICE));
        assert_se(unit_type_may_template(_UNIT_TYPE_MAX) == rs_unit_type_may_template(_UNIT_TYPE_MAX));
}

int main(int argc, char **argv) {
        test_gpt_partition_type_knows_read_only();
        test_gpt_partition_type_knows_growfs();
        test_gpt_partition_type_knows_no_auto();
        test_gpt_partition_type_has_filesystem();
        test_unit_type_may_alias();
        test_unit_type_may_template();
        return 0;
}
