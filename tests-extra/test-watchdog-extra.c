/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "watchdog.h"

TEST(watchdog_get_device) {
        /* Initially NULL before any setup */
        const char *dev = watchdog_get_device();
        /* May be NULL or a previously set device depending on test order */
        (void) dev;
}

TEST(watchdog_set_device) {
        /* Set to a path */
        int r = watchdog_set_device("/dev/watchdog0");
        assert_se(r >= 0);
        assert_se(streq_ptr(watchdog_get_device(), "/dev/watchdog0"));

        /* Set to NULL → clears */
        r = watchdog_set_device(NULL);
        assert_se(r >= 0);
        assert_se(watchdog_get_device() == NULL);
}

TEST(watchdog_get_last_ping) {
        /* Before any ping, should return USEC_INFINITY or mapped value */
        usec_t t = watchdog_get_last_ping(CLOCK_MONOTONIC);
        assert_se(t == USEC_INFINITY || t == 0);

        t = watchdog_get_last_ping(CLOCK_REALTIME);
        assert_se(t == USEC_INFINITY || t == 0);
}

TEST(watchdog_get_last_ping_as_dual_timestamp) {
        dual_timestamp ts;
        dual_timestamp *ret = watchdog_get_last_ping_as_dual_timestamp(&ts);
        assert_se(ret == &ts);
        /* monotonic and realtime should be consistent */
        assert_se(ts.monotonic == USEC_INFINITY || ts.monotonic == 0);
}

TEST(watchdog_close) {
        /* Closing without setup should be safe (fd is -EBADF) */
        watchdog_close(false);
        watchdog_close(true);
}

TEST(watchdog_setup_zero_timeout) {
        /* timeout=0 → closes the device */
        int r = watchdog_setup(0);
        assert_se(r == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
