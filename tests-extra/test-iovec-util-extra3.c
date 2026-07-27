/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "string-util.h"
#include "tests.h"

TEST(iovec_memcmp_basic) {
        struct iovec a, b;
        char sa[] = "hello";
        char sb[] = "hello";

        a = IOVEC_MAKE(sa, strlen(sa));
        b = IOVEC_MAKE(sb, strlen(sb));

        assert_se(iovec_memcmp(&a, &b) == 0);

        /* Different content */
        char sc[] = "world";
        b = IOVEC_MAKE(sc, strlen(sc));
        assert_se(iovec_memcmp(&a, &b) != 0);
}

TEST(iovec_memdup_basic) {
        struct iovec source;
        struct iovec ret = {};
        char data[] = "testdata";

        source = IOVEC_MAKE(data, strlen(data));

        assert_se(iovec_memdup(&source, &ret));
        assert_se(ret.iov_base != NULL);
        assert_se(ret.iov_len == strlen(data));
        assert_se(memcmp(ret.iov_base, data, strlen(data)) == 0);

        free(ret.iov_base);

        /* NULL base → sets ret to empty iovec */
        source.iov_base = NULL;
        source.iov_len = 0;
        ret = (struct iovec) {};
        assert_se(iovec_memdup(&source, &ret));
        assert_se(ret.iov_base == NULL);
        assert_se(ret.iov_len == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
