/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/uio.h>

#include "iovec-wrapper.h"
#include "tests.h"

TEST(iovw_new_free) {
        struct iovec_wrapper *w = iovw_new();
        ASSERT_NOT_NULL(w);
        ASSERT_EQ(w->count, 0u);
        ASSERT_NULL(w->iovec);
        w = iovw_free(w);
}

TEST(iovw_free_null) {
        /* iovw_free(NULL) should be safe */
        struct iovec_wrapper *r = iovw_free(NULL);
        ASSERT_NULL(r);
}

TEST(iovw_put_basic) {
        struct iovec_wrapper *w = iovw_new();
        ASSERT_NOT_NULL(w);

        char data[] = "hello";
        ASSERT_OK(iovw_put(w, data, 5));
        ASSERT_EQ(w->count, 1u);
        assert_se(w->iovec[0].iov_base == data);
        ASSERT_EQ(w->iovec[0].iov_len, 5u);

        iovw_free(w);
}

TEST(iovw_put_multiple) {
        struct iovec_wrapper *w = iovw_new();
        ASSERT_NOT_NULL(w);

        char d1[] = "abc";
        char d2[] = "defgh";
        char d3[] = "ij";

        ASSERT_OK(iovw_put(w, d1, 3));
        ASSERT_OK(iovw_put(w, d2, 5));
        ASSERT_OK(iovw_put(w, d3, 2));

        ASSERT_EQ(w->count, 3u);
        ASSERT_EQ(iovw_size(w), 10u);

        iovw_free(w);
}

TEST(iovw_put_zero_length) {
        struct iovec_wrapper *w = iovw_new();
        ASSERT_NOT_NULL(w);

        char x = 'x';
        /* Zero-length put should succeed but not add an entry */
        ASSERT_OK(iovw_put(w, &x, 0));
        ASSERT_EQ(w->count, 0u);

        iovw_free(w);
}

TEST(iovw_size) {
        struct iovec_wrapper *w = iovw_new();
        ASSERT_EQ(iovw_size(w), 0u);

        char d1[] = "hello";
        ASSERT_OK(iovw_put(w, d1, 5));
        ASSERT_EQ(iovw_size(w), 5u);

        char d2[] = "world";
        ASSERT_OK(iovw_put(w, d2, 5));
        ASSERT_EQ(iovw_size(w), 10u);

        iovw_free(w);
}

TEST(iovw_size_null) {
        ASSERT_EQ(iovw_size(NULL), 0u);
}

TEST(iovw_done) {
        struct iovec_wrapper *w = iovw_new();
        ASSERT_NOT_NULL(w);

        char d1[] = "hello";
        ASSERT_OK(iovw_put(w, d1, 5));
        ASSERT_EQ(w->count, 1u);

        iovw_done(w);
        ASSERT_EQ(w->count, 0u);
        ASSERT_NULL(w->iovec);

        iovw_free(w);
}

TEST(iovw_isempty) {
        ASSERT_TRUE(iovw_isempty(NULL));

        struct iovec_wrapper *w = iovw_new();
        ASSERT_TRUE(iovw_isempty(w));

        char d[] = "x";
        ASSERT_OK(iovw_put(w, d, 1));
        ASSERT_FALSE(iovw_isempty(w));

        iovw_free(w);
}

TEST(iovw_put_string_field) {
        struct iovec_wrapper *w = iovw_new();
        ASSERT_NOT_NULL(w);

        ASSERT_OK(iovw_put_string_field(w, "KEY=", "value"));
        ASSERT_EQ(w->count, 1u);
        ASSERT_STREQ((const char *)w->iovec[0].iov_base, "KEY=value");

        iovw_free(w);
}

TEST(iovw_replace_string_field) {
        struct iovec_wrapper *w = iovw_new();
        ASSERT_NOT_NULL(w);

        ASSERT_OK(iovw_put_string_field(w, "KEY=", "old"));
        ASSERT_EQ(w->count, 1u);

        ASSERT_OK(iovw_replace_string_field(w, "KEY=", "new"));
        ASSERT_EQ(w->count, 1u);
        ASSERT_STREQ((const char *)w->iovec[0].iov_base, "KEY=new");

        iovw_free(w);
}

TEST(iovw_put_string_fieldf) {
        struct iovec_wrapper *w = iovw_new();
        ASSERT_NOT_NULL(w);

        ASSERT_OK(iovw_put_string_fieldf(w, "NUM=", "%d", 42));
        ASSERT_EQ(w->count, 1u);
        ASSERT_STREQ((const char *)w->iovec[0].iov_base, "NUM=42");

        iovw_free(w);
}

TEST(iovw_append_basic) {
        struct iovec_wrapper *target = iovw_new();
        struct iovec_wrapper *source = iovw_new();

        char d1[] = "hello";
        char d2[] = "world";
        ASSERT_OK(iovw_put(source, d1, 5));
        ASSERT_OK(iovw_put(source, d2, 5));

        ASSERT_OK(iovw_append(target, source));
        ASSERT_EQ(target->count, 2u);
        ASSERT_EQ(iovw_size(target), 10u);

        iovw_free(source);
        iovw_free(target);
}

TEST(iovw_append_empty_source) {
        struct iovec_wrapper *target = iovw_new();
        struct iovec_wrapper *source = iovw_new();

        ASSERT_OK(iovw_append(target, source));
        ASSERT_EQ(target->count, 0u);

        iovw_free(source);
        iovw_free(target);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
