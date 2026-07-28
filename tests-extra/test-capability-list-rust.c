/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C capability-list vs Rust rs_capability_list */

#include <string.h>
#include <linux/capability.h>

#include "capability-list.h"
#include "capability-util.h"
#include "rust/capability_list.h"
#include "string-util.h"
#include "tests.h"

/* ── capability_to_name ───────────────────────────────────────────────── */

/* RUST-CONTRACT: capability-name-rendering */
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

        /* Exhaust the target-generated C table. This intentionally detects a
         * newer build target whose capability UAPI has outgrown the reviewed
         * static Rust table. */
        for (int id = -1; id <= (int) capability_list_length(); id++) {
                cr = capability_to_name(id);
                rr = rs_capability_to_name(id);
                assert_se((cr == NULL) == (rr == NULL));
                if (cr)
                        assert_se(streq(cr, rr));
        }
}

/* ── capability_to_string ─────────────────────────────────────────────── */

/* RUST-CONTRACT: capability-string-rendering */
static void test_capability_to_string(void) {
        char c_buf[CAPABILITY_TO_STRING_MAX], r_buf[CAPABILITY_TO_STRING_MAX];
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

        for (int id = -1; id <= CAP_LIMIT + 1; id++) {
                memset(c_buf, 0xa5, sizeof(c_buf));
                memset(r_buf, 0xa5, sizeof(r_buf));

                cr = capability_to_string(id, c_buf);
                rr = rs_capability_to_string(id, r_buf);
                assert_se((cr == NULL) == (rr == NULL));
                assert_se(memcmp(c_buf, r_buf, sizeof(c_buf)) == 0);
                if (!cr)
                        continue;

                assert_se(streq(cr, rr));
                /* Known names are borrowed statics; numeric fallbacks live in
                 * caller storage. Preserve that ownership distinction. */
                assert_se((cr == c_buf) == (rr == r_buf));
        }
}

/* ── capability_from_name ─────────────────────────────────────────────── */

/* RUST-CONTRACT: capability-name-parsing */
static void test_capability_from_name(void) {
        static const char * const numeric_cases[] = {
                "0", "+0", "-0", " 15", "\t0x0f", "017", "0b1111", "0B1111",
                "0o17", "0O17", "62", "63", "09", "15 ", "+0b1", "",
                "999999999999999999999999999999999999",
        };
        const char invalid_bytes[] = { (char) 0xff, 0 };
        int cr, rr;

        cr = capability_from_name("cap_chown");
        rr = rs_capability_from_name("cap_chown");
        assert_se(cr == rr);
        assert_se(cr == CAP_CHOWN);

        cr = capability_from_name("cap_net_admin");
        rr = rs_capability_from_name("cap_net_admin");
        assert_se(cr == rr);
        assert_se(cr == CAP_NET_ADMIN);

        /* The generated gperf authority folds ASCII case. */
        assert_se(capability_from_name("CAP_AUDIT_READ") == rs_capability_from_name("CAP_AUDIT_READ"));
        assert_se(capability_from_name("cAp_aUdIt_rEAd") == rs_capability_from_name("cAp_aUdIt_rEAd"));

        /* Numeric parsing is safe_atoi(), including prefixes, signs, leading
         * systemd whitespace, strict trailing bytes, and overflow. */
        FOREACH_ELEMENT(name, numeric_cases)
                assert_se(capability_from_name(*name) == rs_capability_from_name(*name));

        /* Unknown name */
        cr = capability_from_name("cap_nonexistent");
        rr = rs_capability_from_name("cap_nonexistent");
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* NULL — C asserts, skip shadow test */
        rr = rs_capability_from_name(NULL);
        assert_se(rr < 0);

        /* Names are opaque C bytes; invalid UTF-8 is rejected, not decoded. */
        assert_se(capability_from_name(invalid_bytes) == rs_capability_from_name(invalid_bytes));

        for (unsigned id = 0; id < capability_list_length(); id++) {
                const char *name = capability_to_name(id);
                if (name)
                        assert_se(capability_from_name(name) == rs_capability_from_name(name));
        }
}

/* ── capability_list_length ──────────────────────────────────────────── */

/* RUST-CONTRACT: capability-list-length */
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
