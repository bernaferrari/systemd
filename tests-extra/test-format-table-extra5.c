/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sd-json.h>

#include "format-table.h"
#include "string-util.h"
#include "tests.h"

TEST(table_vertical_format) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *out = NULL;
        int r;

        t = table_new_vertical();
        assert_se(t != NULL);

        /* Vertical table: field-value layout */
        r = table_add_many(t,
                           TABLE_FIELD, "Name",
                           TABLE_STRING, "alice");
        assert_se(r >= 0);

        r = table_add_many(t,
                           TABLE_FIELD, "Age",
                           TABLE_UINT32, (uint32_t)30);
        assert_se(r >= 0);

        r = table_format(t, &out);
        assert_se(r >= 0);
        assert_se(out != NULL);
        assert_se(strstr(out, "alice") != NULL);
        assert_se(strstr(out, "30") != NULL);
}

TEST(table_json_output) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        t = table_new("name", "value");
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_STRING, "alice",
                           TABLE_UINT32, (uint32_t)42);
        assert_se(r >= 0);

        r = table_add_many(t,
                           TABLE_STRING, "bob",
                           TABLE_UINT32, (uint32_t)99);
        assert_se(r >= 0);

        r = table_to_json(t, &v);
        assert_se(r >= 0);
        assert_se(v != NULL);
        assert_se(sd_json_variant_is_array(v));
}

TEST(table_vertical_json) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        t = table_new_vertical();
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_FIELD, "Key1",
                           TABLE_STRING, "val1");
        assert_se(r >= 0);

        r = table_to_json(t, &v);
        assert_se(r >= 0);
        assert_se(v != NULL);
}

TEST(table_print_json_to_null) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("a");
        assert_se(t != NULL);

        r = table_add_many(t, TABLE_STRING, "x");
        assert_se(r >= 0);

        /* Print JSON to /dev/null */
        r = table_print_json(t, NULL, SD_JSON_FORMAT_OFF);
        assert_se(r >= 0);
}

TEST(table_print_with_pager) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("name", "val");
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_STRING, "hello",
                           TABLE_STRING, "world");
        assert_se(r >= 0);

        /* table_print_with_pager with JSON off mode */
        r = table_print_with_pager(t, SD_JSON_FORMAT_OFF, 0, true);
        assert_se(r >= 0);
}

TEST(table_add_cell_full) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("data");
        assert_se(t != NULL);

        /* Add cell with all formatting options */
        r = table_add_cell_full(t, &cell, TABLE_STRING, "test",
                                10,    /* minimum_width */
                                100,   /* maximum_width */
                                50,    /* weight */
                                100,   /* align_percent */
                                50);   /* ellipsize_percent */
        assert_se(r >= 0);
        assert_se(cell != NULL);

        _cleanup_free_ char *out = NULL;
        r = table_format(t, &out);
        assert_se(r >= 0);
        assert_se(strstr(out, "test") != NULL);
}

TEST(table_add_many_types) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *out = NULL;
        int r;

        t = table_new("str", "num", "bool", "pct", "uid", "pid", "mode");
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_STRING, "test",
                           TABLE_INT, (int)42,
                           TABLE_BOOLEAN, true,
                           TABLE_PERCENT, (int)75,
                           TABLE_UID, (uid_t)1000,
                           TABLE_PID, (pid_t)1234,
                           TABLE_MODE, (mode_t)0644);
        assert_se(r >= 0);

        r = table_format(t, &out);
        assert_se(r >= 0);
}

TEST(table_header_cell) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("col1", "col2");
        assert_se(t != NULL);

        /* TABLE_HEADER_CELL converts index to cell */
        TableCell *h0 = TABLE_HEADER_CELL(0);
        TableCell *h1 = TABLE_HEADER_CELL(1);
        assert_se(h0 != NULL);
        assert_se(h1 != NULL);

        /* Set formatting on header cells */
        r = table_set_align_percent(t, h0, 50);
        assert_se(r >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
