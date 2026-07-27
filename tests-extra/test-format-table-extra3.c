/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-table.h"
#include "string-util.h"
#include "tests.h"

TEST(table_new_raw) {
        _cleanup_(table_unrefp) Table *t = NULL;

        t = table_new_raw(5);
        assert_se(t != NULL);
        assert_se(table_get_columns(t) == 5);
        assert_se(table_get_rows(t) == 0);
}

TEST(table_new_vertical) {
        _cleanup_(table_unrefp) Table *t = NULL;

        t = table_new_vertical();
        assert_se(t != NULL);
        assert_se(table_get_columns(t) == 2);
}

TEST(table_get_rows_and_columns) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("a", "b", "c");
        assert_se(t != NULL);
        assert_se(table_get_columns(t) == 3);
        assert_se(table_get_rows(t) == 1); /* header row */

        r = table_add_many(t,
                           TABLE_STRING, "x",
                           TABLE_STRING, "y",
                           TABLE_STRING, "z");
        assert_se(r >= 0);
        assert_se(table_get_rows(t) == 2); /* header + 1 data */

        r = table_add_many(t,
                           TABLE_STRING, "p",
                           TABLE_STRING, "q",
                           TABLE_STRING, "r");
        assert_se(r >= 0);
        assert_se(table_get_rows(t) == 3);
}

TEST(table_get_current_column) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("a", "b");
        assert_se(t != NULL);

        /* Start of a row → column 0 */
        assert_se(table_get_current_column(t) == 0);

        r = table_add_cell(t, NULL, TABLE_STRING, "first");
        assert_se(r >= 0);

        /* After adding 1 cell in 2-col table → column 1 */
        assert_se(table_get_current_column(t) == 1);

        r = table_add_cell(t, NULL, TABLE_STRING, "second");
        assert_se(r >= 0);

        /* Row complete → back to column 0 */
        assert_se(table_get_current_column(t) == 0);
}

TEST(table_get_cell) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("name", "value");
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_STRING, "hello",
                           TABLE_STRING, "world");
        assert_se(r >= 0);

        /* Header cells */
        TableCell *h0 = table_get_cell(t, 0, 0);
        assert_se(h0 != NULL);
        TableCell *h1 = table_get_cell(t, 0, 1);
        assert_se(h1 != NULL);

        /* Data cells */
        TableCell *c0 = table_get_cell(t, 1, 0);
        assert_se(c0 != NULL);
        TableCell *c1 = table_get_cell(t, 1, 1);
        assert_se(c1 != NULL);

        /* Out of range → NULL */
        assert_se(table_get_cell(t, 99, 0) == NULL);
        assert_se(table_get_cell(t, 0, 99) == NULL);
}

TEST(table_get_and_get_at) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("key", "val");
        assert_se(t != NULL);

        r = table_add_cell(t, &cell, TABLE_STRING, "mykey");
        assert_se(r >= 0);
        r = table_add_cell(t, NULL, TABLE_STRING, "myval");
        assert_se(r >= 0);

        /* table_get returns the data pointer for a cell */
        const char *s = table_get(t, cell);
        assert_se(s && streq(s, "mykey"));

        /* table_get_at returns data by row/col */
        const char *s2 = table_get_at(t, 1, 1);
        assert_se(s2 && streq(s2, "myval"));
}

TEST(table_isempty) {
        _cleanup_(table_unrefp) Table *t = NULL;

        t = table_new("a");
        assert_se(t != NULL);
        /* A table with only headers is considered empty (no data rows) */
        assert_se(table_isempty(t));
}

TEST(table_set_display) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("a", "b", "c");
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_STRING, "1",
                           TABLE_STRING, "2",
                           TABLE_STRING, "3");
        assert_se(r >= 0);

        /* Display only columns 0 and 2 */
        r = table_set_display(t, 0, 2);
        assert_se(r >= 0);
}

TEST(table_set_sort) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("name", "val");
        assert_se(t != NULL);

        r = table_add_many(t, TABLE_STRING, "banana", TABLE_STRING, "b");
        assert_se(r >= 0);
        r = table_add_many(t, TABLE_STRING, "apple", TABLE_STRING, "a");
        assert_se(r >= 0);

        /* Sort by first column */
        r = table_set_sort(t, 0);
        assert_se(r >= 0);

        /* Set reverse sort */
        r = table_set_reverse(t, 0, true);
        assert_se(r >= 0);
        r = table_set_reverse(t, 0, false);
        assert_se(r >= 0);
}

TEST(table_hide_column_from_display) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("a", "b", "c");
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_STRING, "1",
                           TABLE_STRING, "2",
                           TABLE_STRING, "3");
        assert_se(r >= 0);

        /* Hide column 1 */
        r = table_hide_column_from_display(t, 1);
        assert_se(r >= 0);
}

TEST(table_format) {
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_free_ char *out = NULL;
        int r;

        t = table_new("name", "value");
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_STRING, "hello",
                           TABLE_STRING, "world");
        assert_se(r >= 0);

        r = table_format(t, &out);
        assert_se(r >= 0);
        assert_se(out != NULL);
        assert_se(strstr(out, "hello") != NULL);
        assert_se(strstr(out, "world") != NULL);
}

TEST(table_set_ersatz_string) {
        _cleanup_(table_unrefp) Table *t = NULL;

        t = table_new("a", "b");
        assert_se(t != NULL);

        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);
        table_set_ersatz_string(t, TABLE_ERSATZ_EMPTY);
        table_set_ersatz_string(t, TABLE_ERSATZ_NA);
        table_set_ersatz_string(t, TABLE_ERSATZ_UNSET);
}

TEST(table_print) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("a", "b");
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_STRING, "x",
                           TABLE_STRING, "y");
        assert_se(r >= 0);

        /* Print to /dev/null (just test it doesn't crash) */
        r = table_print(t, NULL);
        assert_se(r >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
