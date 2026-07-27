/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/uio.h>

#include "log-context.h"
#include "strv.h"
#include "tests.h"

TEST(log_context_new_null_value) {
        /* NULL value should return NULL */
        LogContext *c = log_context_new("KEY=", NULL);
        ASSERT_NULL(c);
}

TEST(log_context_new_strv_null) {
        /* NULL fields should return NULL */
        LogContext *c = log_context_new_strv(NULL, false);
        ASSERT_NULL(c);
}

TEST(log_context_new_iov_null) {
        LogContext *c = log_context_new_iov(NULL, 0, false);
        ASSERT_NULL(c);
}

TEST(log_context_push_key_value) {
        size_t before = log_context_num_contexts();
        size_t fields_before = log_context_num_fields();

        {
                _cleanup_(log_context_unrefp) LogContext *c = log_context_new("MY_KEY=", "my_value");
                ASSERT_NOT_NULL(c);
                ASSERT_EQ(log_context_num_contexts(), before + 1);
                ASSERT_EQ(log_context_num_fields(), fields_before + 1);
        }

        /* After scope exit, should be back to original */
        ASSERT_EQ(log_context_num_contexts(), before);
        ASSERT_EQ(log_context_num_fields(), fields_before);
}

TEST(log_context_push_strv) {
        size_t before = log_context_num_contexts();
        size_t fields_before = log_context_num_fields();

        {
                char *f1 = strdup("FIELD1=value1");
                char *f2 = strdup("FIELD2=value2");
                char *fields[] = { f1, f2, NULL };
                _cleanup_(log_context_unrefp) LogContext *c = log_context_new_strv(fields, false);
                ASSERT_NOT_NULL(c);
                ASSERT_EQ(log_context_num_contexts(), before + 1);
                ASSERT_EQ(log_context_num_fields(), fields_before + 2);
                free(f1);
                free(f2);
        }

        ASSERT_EQ(log_context_num_contexts(), before);
        ASSERT_EQ(log_context_num_fields(), fields_before);
}

TEST(log_context_ref) {
        _cleanup_(log_context_unrefp) LogContext *c1 = log_context_new("KEY=", "value");
        ASSERT_NOT_NULL(c1);

        /* Ref should return the same pointer */
        LogContext *c2 = log_context_ref(c1);
        assert_se(c1 == c2);

        /* Unref once - should still be alive */
        log_context_unref(c2);
        /* c1 still holds a ref, context should still exist */
        ASSERT_NOT_NULL(log_context_head());
}

TEST(log_context_new_strv_consume) {
        char **fields = strv_new("A=1", "B=2");
        ASSERT_NOT_NULL(fields);

        _cleanup_(log_context_unrefp) LogContext *c = log_context_new_strv_consume(fields);
        ASSERT_NOT_NULL(c);
        /* fields has been consumed (taken ownership) */
}

TEST(log_context_new_iov_consume) {
        struct iovec *iov = new(struct iovec, 2);
        assert_se(iov);
        iov[0] = (struct iovec){ .iov_base = strdup("X=1"), .iov_len = 3 };
        iov[1] = (struct iovec){ .iov_base = strdup("Y=2"), .iov_len = 3 };

        _cleanup_(log_context_unrefp) LogContext *c = log_context_new_iov_consume(iov, 2);
        ASSERT_NOT_NULL(c);
}

TEST(log_context_new_iov_empty) {
        /* NULL iovec should return NULL */
        LogContext *c = log_context_new_iov(NULL, 0, false);
        ASSERT_NULL(c);
}

TEST(log_context_head_null) {
        /* When no contexts are pushed, head should be NULL */
        size_t before = log_context_num_contexts();
        if (before == 0)
                ASSERT_NULL(log_context_head());
}

DEFINE_TEST_MAIN(LOG_DEBUG);
