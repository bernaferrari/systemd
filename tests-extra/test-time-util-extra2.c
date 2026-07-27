/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "time-util.h"
#include "tests.h"

TEST(timespec_load) {
        struct timespec ts;

        ts = (struct timespec){ .tv_sec = 12345, .tv_nsec = 999999999 };
        ASSERT_EQ(timespec_load(&ts), UINT64_C(12345999999));

        ts = (struct timespec){ .tv_sec = 0, .tv_nsec = 0 };
        ASSERT_EQ(timespec_load(&ts), UINT64_C(0));

        ts = (struct timespec){ .tv_sec = 1, .tv_nsec = 500000000 };
        ASSERT_EQ(timespec_load(&ts), UINT64_C(1500000));
}

TEST(timespec_load_nsec) {
        struct timespec ts;

        ts = (struct timespec){ .tv_sec = 12345, .tv_nsec = 999999999 };
        ASSERT_EQ(timespec_load_nsec(&ts), UINT64_C(12345999999999));
}

TEST(timeval_load) {
        struct timeval tv;

        tv = (struct timeval){ .tv_sec = 100, .tv_usec = 500000 };
        ASSERT_EQ(timeval_load(&tv), UINT64_C(100500000));

        tv = (struct timeval){ .tv_sec = 0, .tv_usec = 0 };
        ASSERT_EQ(timeval_load(&tv), UINT64_C(0));
}

TEST(usec_to_jiffies) {
        /* Zero always maps to zero */
        ASSERT_EQ(usec_to_jiffies(0), 0u);

        /* Round-trip: jiffies_to_usec(usec_to_jiffies(x)) >= x */
        ASSERT_GE(jiffies_to_usec(usec_to_jiffies(USEC_PER_SEC)), USEC_PER_SEC);
        ASSERT_GE(jiffies_to_usec(usec_to_jiffies(5000000)), 5000000u);
}

TEST(jiffies_to_usec) {
        ASSERT_EQ(jiffies_to_usec(0), UINT64_C(0));

        /* 1 jiffy should be positive */
        ASSERT_GT(jiffies_to_usec(1), UINT64_C(0));

        /* Round-trip: usec_to_jiffies(jiffies_to_usec(n)) >= n */
        ASSERT_GE(usec_to_jiffies(jiffies_to_usec(100)), 100u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
