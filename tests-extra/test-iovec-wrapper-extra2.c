/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-wrapper.h"
#include "string-util.h"
#include "tests.h"

TEST(iovw_new_basic) {
        struct iovec_wrapper *iovw = iovw_new();
        assert_se(iovw);
        assert_se(iovw->count == 0);
        iovw_free_free(iovw);
}

TEST(iovw_consume_basic) {
        struct iovec_wrapper *iovw = iovw_new();
        assert_se(iovw);

        _cleanup_free_ char *data = strdup("testdata");
        assert_se(data);
        assert_se(iovw_consume(iovw, TAKE_PTR(data), 8) >= 0);
        assert_se(iovw->count == 1);

        /* Use iovw_free_freep since iovw_consume passes ownership */
        iovw_free_free(iovw);
}

TEST(iovw_size_basic) {
        struct iovec_wrapper *iovw = iovw_new();
        assert_se(iovw);
        assert_se(iovw_size(iovw) == 0);

        char *d1 = strdup("hello");
        assert_se(d1);
        assert_se(iovw_consume(iovw, d1, 5) >= 0);
        assert_se(iovw_size(iovw) == 5);

        char *d2 = strdup("world");
        assert_se(d2);
        assert_se(iovw_consume(iovw, d2, 5) >= 0);
        assert_se(iovw_size(iovw) == 10);

        iovw_free_free(iovw);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
