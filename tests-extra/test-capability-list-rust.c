/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C capability-list vs Rust rs_capability_list */

#include <string.h>
#include <linux/capability.h>

#include "capability-list.h"
#include "rust/capability_list.h"
#include "string-util.h"
#include "tests.h"

/* ── capability_to_name ───────────────────────────────────────────────── */

static void test_capability_to_name(void) {
        const char *cr, *rr;

        cr = capability_to_name(CAP_CHOWN);
        rr = rs_capability_to_name(CAP_CHOWN);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "cap_chown"));

        cr = capability_to_name(CAP_NET_ADMIN);
        rr = rs_capability_to_name(CAP_NET_ADMIN);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = capability_to_name(CAP_SYS_ADMIN);
        rr = rs_capability_to_name(CAP_SYS_ADMIN);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        /* Out of range */
        cr = capability_to_name(99);
        rr = rs_capability_to_name(99);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Negative */
        cr = capability_to_name(-1);
        rr = rs_capability_to_name(-1);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

/* ── capability_to_string ─────────────────────────────────────────────── */

static void test_capability_to_string(void) {
        char c_buf[20], r_buf[20];
        const char *cr, *rr;

        cr = capability_to_string(CAP_CHOWN, c_buf);
        rr = rs_capability_to_string(CAP_CHOWN, r_buf);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        cr = capability_to_string(CAP_NET_ADMIN, c_buf);
        rr = rs_capability_to_string(CAP_NET_ADMIN, r_buf);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));

        /* Numeric fallback (capability 41 doesn't have a name in our table) */
        cr = capability_to_string(41, c_buf);
        rr = rs_capability_to_string(41, r_buf);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "0x29"));

        /* Out of range */
        cr = capability_to_string(99, c_buf);
        rr = rs_capability_to_string(99, r_buf);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Negative */
        cr = capability_to_string(-1, c_buf);
        rr = rs_capability_to_string(-1, r_buf);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

/* ── capability_from_name ─────────────────────────────────────────────── */

static void test_capability_from_name(void) {
        int cr, rr;

        cr = capability_from_name("cap_chown");
        rr = rs_capability_from_name("cap_chown");
        assert_se(cr == rr);
        assert_se(cr == CAP_CHOWN);

        cr = capability_from_name("cap_net_admin");
        rr = rs_capability_from_name("cap_net_admin");
        assert_se(cr == rr);
        assert_se(cr == CAP_NET_ADMIN);

        /* Numeric */
        cr = capability_from_name("0");
        rr = rs_capability_from_name("0");
        assert_se(cr == rr);
        assert_se(cr == 0);

        cr = capability_from_name("40");
        rr = rs_capability_from_name("40");
        assert_se(cr == rr);
        assert_se(cr == CAP_CHECKPOINT_RESTORE);

        /* Out of range numeric */
        cr = capability_from_name("99");
        rr = rs_capability_from_name("99");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Unknown name */
        cr = capability_from_name("cap_nonexistent");
        rr = rs_capability_from_name("cap_nonexistent");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* NULL — C asserts, skip shadow test */
        rr = rs_capability_from_name(NULL);
        assert_se(rr < 0);
}

/* ── capability_list_length ──────────────────────────────────────────── */

static void test_capability_list_length(void) {
        unsigned cr, rr;
        cr = capability_list_length();
        rr = rs_capability_list_length();
        assert_se(cr == rr);
}

/* ── Roundtrip ────────────────────────────────────────────────────────── */

static void test_capability_roundtrip(void) {
        assert_se(capability_from_name(capability_to_name(CAP_CHOWN)) == CAP_CHOWN);
        assert_se(rs_capability_from_name(rs_capability_to_name(CAP_CHOWN)) == CAP_CHOWN);

        assert_se(capability_from_name(capability_to_name(CAP_SYS_ADMIN)) == CAP_SYS_ADMIN);
        assert_se(rs_capability_from_name(rs_capability_to_name(CAP_SYS_ADMIN)) == CAP_SYS_ADMIN);
}

int main(int argc, char **argv) {
        test_capability_to_name();
        test_capability_to_string();
        test_capability_from_name();
        test_capability_list_length();
        test_capability_roundtrip();
        return 0;
}
