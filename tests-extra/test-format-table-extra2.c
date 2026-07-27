/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-table.h"
#include "string-util.h"
#include "tests.h"

TEST(table_new_and_add) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("name", "value");
        assert_se(t != NULL);
        assert_se(table_get_columns(t) == 2);

        /* Add a row */
        r = table_add_cell(t, &cell, TABLE_STRING, "hello");
        assert_se(r >= 0);
        assert_se(cell != NULL);

        r = table_add_cell(t, NULL, TABLE_STRING, "world");
        assert_se(r >= 0);

        /* Add another row */
        r = table_add_cell(t, NULL, TABLE_STRING, "foo");
        assert_se(r >= 0);
        r = table_add_cell(t, NULL, TABLE_STRING, "bar");
        assert_se(r >= 0);
}

TEST(table_set_header) {
        _cleanup_(table_unrefp) Table *t = NULL;

        t = table_new("a", "b");
        assert_se(t != NULL);

        /* Toggle header */
        table_set_header(t, true);
        table_set_header(t, false);
}

TEST(table_set_width) {
        _cleanup_(table_unrefp) Table *t = NULL;

        t = table_new("a", "b");
        assert_se(t != NULL);

        table_set_width(t, 80);
        table_set_width(t, 0);
        table_set_width(t, SIZE_MAX);
}

TEST(table_set_cell_height_max) {
        _cleanup_(table_unrefp) Table *t = NULL;

        t = table_new("a", "b");
        assert_se(t != NULL);

        table_set_cell_height_max(t, 10);
        table_set_cell_height_max(t, 1);
        table_set_cell_height_max(t, SIZE_MAX);
}

TEST(table_dup_cell) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell = NULL;
        int r;

        t = table_new("a", "b");
        assert_se(t != NULL);

        /* Add a cell and duplicate it */
        r = table_add_cell(t, &cell, TABLE_STRING, "dupme");
        assert_se(r >= 0);
        r = table_add_cell(t, NULL, TABLE_STRING, "second");
        assert_se(r >= 0);

        /* Dup the first cell */
        r = table_dup_cell(t, cell);
        assert_se(r >= 0);

        /* Dup invalid cell (row out of range) → -ENXIO */
        TableCell *bad = table_get_cell(t, 999, 0);
        if (bad)
                assert_se(table_dup_cell(t, bad) == -ENXIO);
}

TEST(table_fill_empty) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("a", "b", "c");
        assert_se(t != NULL);
        assert_se(table_get_columns(t) == 3);

        /* Add one cell, then fill to end of row */
        r = table_add_cell(t, NULL, TABLE_STRING, "first");
        assert_se(r >= 0);

        /* Fill until column 0 (rest of row) */
        r = table_fill_empty(t, 0);
        assert_se(r >= 0);

        /* Invalid: until_column >= n_columns */
        r = table_fill_empty(t, 3);
        assert_se(r == -EINVAL);
}

TEST(table_add_many) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        t = table_new("name", "number", "flag");
        assert_se(t != NULL);

        r = table_add_many(t,
                           TABLE_STRING, "alice",
                           TABLE_UINT32, (uint32_t)42,
                           TABLE_BOOLEAN, true);
        assert_se(r >= 0);

        r = table_add_many(t,
                           TABLE_STRING, "bob",
                           TABLE_UINT32, (uint32_t)99,
                           TABLE_BOOLEAN, false);
        assert_se(r >= 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
