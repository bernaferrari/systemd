/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "fd-util.h"
#include "serialize.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

TEST(serialize_usec) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        /* Normal value */
        {
                _cleanup_fclose_ FILE *f = open_memstream(&buf, &sz);
                assert_se(f);
                assert_se(serialize_usec(f, "timestamp", 1234567) >= 0);
                fflush(f);
                assert_se(startswith(buf, "timestamp="));
        }

        /* USEC_INFINITY → not written */
        buf = mfree(buf);
        {
                _cleanup_fclose_ FILE *f = open_memstream(&buf, &sz);
                assert_se(f);
                assert_se(serialize_usec(f, "ts", USEC_INFINITY) == 0);
                fflush(f);
                assert_se(sz == 0);
        }
}

TEST(serialize_bool) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        /* true → yes */
        {
                _cleanup_fclose_ FILE *f = open_memstream(&buf, &sz);
                assert_se(f);
                assert_se(serialize_bool(f, "flag", true) >= 0);
                fflush(f);
                assert_se(startswith(buf, "flag=yes"));
        }

        /* false → no */
        buf = mfree(buf);
        {
                _cleanup_fclose_ FILE *f = open_memstream(&buf, &sz);
                assert_se(f);
                assert_se(serialize_bool(f, "flag", false) >= 0);
                fflush(f);
                assert_se(startswith(buf, "flag=no"));
        }
}

TEST(serialize_strv) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        /* Empty strv → nothing written */
        {
                _cleanup_fclose_ FILE *f = open_memstream(&buf, &sz);
                assert_se(f);
                assert_se(serialize_strv(f, "item", STRV_MAKE(NULL)) == 0);
                fflush(f);
                assert_se(sz == 0);
        }

        /* Multiple items */
        buf = mfree(buf);
        {
                _cleanup_fclose_ FILE *f = open_memstream(&buf, &sz);
                const char *list[] = {"hello", "world", NULL};
                assert_se(f);
                assert_se(serialize_strv(f, "item", (char * const *) list) > 0);
                fflush(f);
                assert_se(sz > 0);
                assert_se(startswith(buf, "item="));
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
