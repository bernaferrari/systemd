/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sysctl-util.h"
#include "tests.h"

TEST(sysctl_normalize_basic) {
        char s1[] = "net.ipv4.ip_forward";
        char *r = sysctl_normalize(s1);
        assert_se(streq(r, "net/ipv4/ip_forward"));

        char s2[] = "kernel.pid_max";
        r = sysctl_normalize(s2);
        assert_se(streq(r, "kernel/pid_max"));

        char s3[] = "net/core/somaxconn";
        r = sysctl_normalize(s3);
        assert_se(streq(r, "net/core/somaxconn"));
}

TEST(sysctl_read_basic) {
        _cleanup_free_ char *val = NULL;
        int r = sysctl_read("kernel/pid_max", &val);
        if (r >= 0) {
                assert_se(!isempty(val));
                log_debug("kernel/pid_max: %s", val);
        } else
                log_debug("sysctl_read: %d", r);
}

TEST(sysctl_write_basic) {
        /* Read current, write same value back */
        _cleanup_free_ char *val = NULL;
        int r = sysctl_read("kernel/pid_max", &val);
        if (r >= 0) {
                r = sysctl_write("kernel/pid_max", val);
                log_debug("sysctl_write: %d", r);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
