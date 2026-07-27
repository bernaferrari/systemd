/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C sysctl-util vs Rust rs_sysctl_normalize */

#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C header */
#include "sysctl-util.h"

/* Rust FFI */
#include "rust/sysctl_util.h"

static void test_sysctl_normalize(void) {
        char c_buf[256], r_buf[256];
        char *cr, *rr;

        /* Path-style (slash first): no dot/slash swapping */
        strcpy(c_buf, "kernel/domainname");
        strcpy(r_buf, "kernel/domainname");
        cr = sysctl_normalize(c_buf);
        rr = rs_sysctl_normalize(r_buf);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        /* Dot-style (dot first): dots become slashes, slashes become dots */
        strcpy(c_buf, "net.ipv4.conf.lo.forwarding");
        strcpy(r_buf, "net.ipv4.conf.lo.forwarding");
        cr = sysctl_normalize(c_buf);
        rr = rs_sysctl_normalize(r_buf);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        /* "net/ipv4/conf/lo/forwarding" */

        /* Leading slash removal */
        strcpy(c_buf, "/proc/sys/kernel/domainname");
        strcpy(r_buf, "/proc/sys/kernel/domainname");
        cr = sysctl_normalize(c_buf);
        rr = rs_sysctl_normalize(r_buf);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        /* Dot-style with leading slash */
        strcpy(c_buf, "/net.ipv4.ip_forward");
        strcpy(r_buf, "/net.ipv4.ip_forward");
        cr = sysctl_normalize(c_buf);
        rr = rs_sysctl_normalize(r_buf);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        /* "net/ipv4/ip_forward" */

        /* Double dots become double slashes, then simplified */
        strcpy(c_buf, "net..ipv4");
        strcpy(r_buf, "net..ipv4");
        cr = sysctl_normalize(c_buf);
        rr = rs_sysctl_normalize(r_buf);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        /* Empty string */
        strcpy(c_buf, "");
        strcpy(r_buf, "");
        cr = sysctl_normalize(c_buf);
        rr = rs_sysctl_normalize(r_buf);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        /* Single character */
        strcpy(c_buf, "a");
        strcpy(r_buf, "a");
        cr = sysctl_normalize(c_buf);
        rr = rs_sysctl_normalize(r_buf);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        /* No separators at all */
        strcpy(c_buf, "abcdef");
        strcpy(r_buf, "abcdef");
        cr = sysctl_normalize(c_buf);
        rr = rs_sysctl_normalize(r_buf);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
}

int main(int argc, char **argv) {
        test_sysctl_normalize();
        return 0;
}
