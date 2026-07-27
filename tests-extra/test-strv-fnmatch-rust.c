/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: strv_fnmatch_full vs Rust */

#include <assert.h>
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "strv.h"
#include "rust/strv.h"

static void test_strv_fnmatch_full(void) {
        char * const patterns1[] = { (char*)"hello*", (char*)"world*", NULL };
        char * const patterns2[] = { (char*)"foo*", (char*)"bar*", NULL };
        char * const patterns3[] = { (char*)"*.txt", (char*)"*.md", NULL };
        char * const escaped_star[] = { (char*)"*\\*", NULL };
        char * const empty[] = { NULL };
        size_t c_pos, rs_pos;
        bool c_r, rs_r;

        /* Simple match */
        c_r = strv_fnmatch_full(patterns1, "hello world", 0, NULL);
        rs_r = rs_strv_fnmatch_full(patterns1, "hello world", 0, NULL);
        assert_se(c_r == rs_r);
        assert_se(c_r == true);

        /* No match */
        c_r = strv_fnmatch_full(patterns2, "hello world", 0, NULL);
        rs_r = rs_strv_fnmatch_full(patterns2, "hello world", 0, NULL);
        assert_se(c_r == rs_r);
        assert_se(c_r == false);

        /* With matched position */
        c_r = strv_fnmatch_full(patterns3, "readme.md", 0, &c_pos);
        rs_r = rs_strv_fnmatch_full(patterns3, "readme.md", 0, &rs_pos);
        assert_se(c_r == rs_r);
        assert_se(c_r == true);
        assert_se(c_pos == rs_pos);

        /* No match with position — should set SIZE_MAX */
        c_r = strv_fnmatch_full(patterns3, "readme.txt.bak", 0, &c_pos);
        rs_r = rs_strv_fnmatch_full(patterns3, "readme.txt.bak", 0, &rs_pos);
        assert_se(c_r == rs_r);
        assert_se(c_r == false);
        assert_se(c_pos == rs_pos);

        /* NULL patterns */
        c_r = strv_fnmatch_full(NULL, "hello", 0, NULL);
        rs_r = rs_strv_fnmatch_full(NULL, "hello", 0, NULL);
        assert_se(c_r == rs_r);
        assert_se(c_r == false);

        /* Empty arrays are distinct from NULL but retain the same no-match
         * result and write C's SIZE_MAX sentinel. */
        c_r = strv_fnmatch_full(empty, "hello", 0, &c_pos);
        rs_r = rs_strv_fnmatch_full(empty, "hello", 0, &rs_pos);
        assert_se(c_r == rs_r);
        assert_se(c_pos == rs_pos);

        /* Do not reinterpret libc's FNM_NOESCAPE semantics in Rust. */
        c_r = strv_fnmatch_full(escaped_star, "\\", FNM_NOESCAPE, &c_pos);
        rs_r = rs_strv_fnmatch_full(escaped_star, "\\", FNM_NOESCAPE, &rs_pos);
        assert_se(c_r == rs_r);
        assert_se(c_pos == rs_pos);
}

int main(int argc, char **argv) {
        test_strv_fnmatch_full();
        return 0;
}
