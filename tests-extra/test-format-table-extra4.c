/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sd-json.h>

#include "format-table.h"
#include "string-util.h"
#include "tests.h"

TEST(table_set_minimum_maximum_width) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("name");
        assert_se(t != NULL);

        r = table_add_cell(t, &cell, TABLE_STRING, "hello");
        assert_se(r >= 0);

        r = table_set_minimum_width(t, cell, 20);
        assert_se(r >= 0);

        r = table_set_maximum_width(t, cell, 50);
        assert_se(r >= 0);
}

TEST(table_set_weight) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("name");
        assert_se(t != NULL);

        r = table_add_cell(t, &cell, TABLE_STRING, "data");
        assert_se(r >= 0);

        r = table_set_weight(t, cell, 100);
        assert_se(r >= 0);
}

TEST(table_set_align_percent) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("name");
        assert_se(t != NULL);

        r = table_add_cell(t, &cell, TABLE_STRING, "data");
        assert_se(r >= 0);

        r = table_set_align_percent(t, cell, 0);   /* left */
        assert_se(r >= 0);
        r = table_set_align_percent(t, cell, 100); /* right */
        assert_se(r >= 0);
        r = table_set_align_percent(t, cell, 50);  /* center */
        assert_se(r >= 0);
}

TEST(table_set_ellipsize_percent) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("name");
        assert_se(t != NULL);

        r = table_add_cell(t, &cell, TABLE_STRING, "data");
        assert_se(r >= 0);

        r = table_set_ellipsize_percent(t, cell, 0);
        assert_se(r >= 0);
        r = table_set_ellipsize_percent(t, cell, 100);
        assert_se(r >= 0);
}

TEST(table_set_color) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("name");
        assert_se(t != NULL);

        r = table_add_cell(t, &cell, TABLE_STRING, "data");
        assert_se(r >= 0);

        r = table_set_color(t, cell, "red");
        assert_se(r >= 0);
        r = table_set_color(t, cell, NULL);
        assert_se(r >= 0);
}

TEST(table_set_underline) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("name");
        assert_se(t != NULL);

        r = table_add_cell(t, &cell, TABLE_STRING, "data");
        assert_se(r >= 0);

        r = table_set_underline(t, cell, true);
        assert_se(r >= 0);
        r = table_set_underline(t, cell, false);
        assert_se(r >= 0);
}

TEST(table_set_url) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("name");
        assert_se(t != NULL);

        r = table_add_cell(t, &cell, TABLE_STRING, "link");
        assert_se(r >= 0);

        r = table_set_url(t, cell, "https://example.com");
        assert_se(r >= 0);
        r = table_set_url(t, cell, NULL);
        assert_se(r >= 0);
}

TEST(table_set_uppercase) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("name");
        assert_se(t != NULL);

        r = table_add_cell(t, &cell, TABLE_STRING, "data");
        assert_se(r >= 0);

        r = table_set_uppercase(t, cell, true);
        assert_se(r >= 0);
        r = table_set_uppercase(t, cell, false);
        assert_se(r >= 0);
}

TEST(table_update) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("name");
        assert_se(t != NULL);

        r = table_add_cell(t, &cell, TABLE_STRING, "old");
        assert_se(r >= 0);

        r = table_update(t, cell, TABLE_STRING, "new");
        assert_se(r >= 0);

        const char *s = table_get(t, cell);
        assert_se(s && streq(s, "new"));
}

TEST(table_data_requested_width) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("name");
        assert_se(t != NULL);

        r = table_add_many(t, TABLE_STRING, "hello");
        assert_se(r >= 0);

        size_t w = 0;
        r = table_data_requested_width(t, 0, &w);
        assert_se(r >= 0);
        assert_se(w > 0);
}

TEST(table_set_column_width) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("a", "b");
        assert_se(t != NULL);

        r = table_set_column_width(t, 0, 20);
        assert_se(r >= 0);
}

TEST(table_sync_column_width) {
        _cleanup_(table_unrefp) Table *a = NULL, *b = NULL;
        int r;

        a = table_new("name");
        assert_se(a != NULL);
        b = table_new("name");
        assert_se(b != NULL);

        r = table_add_many(a, TABLE_STRING, "hello");
        assert_se(r >= 0);
        r = table_add_many(b, TABLE_STRING, "world");
        assert_se(r >= 0);

        r = table_sync_column_width(a, 0, b, 0);
        assert_se(r >= 0);
}

TEST(table_to_json) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        t = table_new("name", "value");
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_STRING, "alice",
                           TABLE_UINT32, (uint32_t)42);
        assert_se(r >= 0);

        r = table_to_json(t, &v);
        assert_se(r >= 0);
        assert_se(v != NULL);
}

TEST(table_set_json_field_name) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("my column", "other-col");
        assert_se(t != NULL);

        r = table_set_json_field_name(t, 0, "my_column");
        assert_se(r >= 0);
        r = table_set_json_field_name(t, 1, "other_col");
        assert_se(r >= 0);
}

TEST(table_add_cell_stringf) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("msg");
        assert_se(t != NULL);

        r = table_add_cell_stringf(t, NULL, "value %d", 42);
        assert_se(r >= 0);

        _cleanup_free_ char *out = NULL;
        r = table_format(t, &out);
        assert_se(r >= 0);
        assert_se(strstr(out, "42") != NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
