/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <string.h>

#include "tests.h"
#include "log.h"
#include "rust/log_target.h"

/* ── log_target_to_string ──────────────────────────────────────────────── */

static void test_log_target_to_string_all(void) {
        /* RUST-CONTRACT: log-target-to-string */
        static const struct {
                int target;
                const char *expected;
        } table[] = {
                { LOG_TARGET_CONSOLE,          "console" },
                { LOG_TARGET_KMSG,             "kmsg" },
                { LOG_TARGET_JOURNAL,          "journal" },
                { LOG_TARGET_SYSLOG,           "syslog" },
                { LOG_TARGET_CONSOLE_PREFIXED, "console-prefixed" },
                { LOG_TARGET_JOURNAL_OR_KMSG,  "journal-or-kmsg" },
                { LOG_TARGET_SYSLOG_OR_KMSG,   "syslog-or-kmsg" },
                { LOG_TARGET_AUTO,             "auto" },
                { LOG_TARGET_NULL,             "null" },
        };

        for (int i = 0; i < (int)ELEMENTSOF(table); i++) {
                const char *r_c = log_target_to_string(table[i].target);
                const char *r_r = rs_log_target_to_string(table[i].target);
                assert_se(r_c && r_r);
                assert_se(streq(r_c, r_r));
                assert_se(streq(r_c, table[i].expected));
        }
}

static void test_log_target_to_string_invalid(void) {
        const char *r_c = log_target_to_string(-1);
        const char *r_r = rs_log_target_to_string(-1);
        assert_se(!r_c && !r_r);

        r_c = log_target_to_string(99);
        r_r = rs_log_target_to_string(99);
        assert_se(!r_c && !r_r);
}

/* ── log_target_from_string ────────────────────────────────────────────── */

static void test_log_target_from_string_all(void) {
        /* RUST-CONTRACT: log-target-from-string */
        static const struct {
                const char *name;
                int expected;
        } table[] = {
                { "console",          LOG_TARGET_CONSOLE },
                { "kmsg",             LOG_TARGET_KMSG },
                { "journal",          LOG_TARGET_JOURNAL },
                { "syslog",           LOG_TARGET_SYSLOG },
                { "console-prefixed", LOG_TARGET_CONSOLE_PREFIXED },
                { "journal-or-kmsg",  LOG_TARGET_JOURNAL_OR_KMSG },
                { "syslog-or-kmsg",   LOG_TARGET_SYSLOG_OR_KMSG },
                { "auto",             LOG_TARGET_AUTO },
                { "null",             LOG_TARGET_NULL },
        };

        for (int i = 0; i < (int)ELEMENTSOF(table); i++) {
                int r_c = log_target_from_string(table[i].name);
                int r_r = rs_log_target_from_string(table[i].name);
                assert_se(r_c == r_r);
                assert_se(r_c >= 0);
                assert_se(r_c == table[i].expected);
        }
}

static void test_log_target_from_string_invalid(void) {
        int r_c = log_target_from_string("foobar");
        int r_r = rs_log_target_from_string("foobar");
        assert_se(r_c == r_r);
        assert_se(r_c < 0);

        r_c = log_target_from_string("CONSOLE");
        r_r = rs_log_target_from_string("CONSOLE");
        assert_se(r_c == r_r);
        assert_se(r_c < 0);

        r_c = log_target_from_string(NULL);
        r_r = rs_log_target_from_string(NULL);
        assert_se(r_c == r_r);
        assert_se(r_c < 0);

        r_c = log_target_from_string("\xff");
        r_r = rs_log_target_from_string("\xff");
        assert_se(r_c == r_r);
        assert_se(r_c < 0);
}

/* ── roundtrip ─────────────────────────────────────────────────────────── */

static void test_log_target_roundtrip(void) {
        for (int t = 0; t <= 8; t++) {
                const char *s_c = log_target_to_string(t);
                const char *s_r = rs_log_target_to_string(t);
                assert_se(s_c && s_r);
                assert_se(streq(s_c, s_r));

                int r_c = log_target_from_string(s_c);
                int r_r = rs_log_target_from_string(s_r);
                assert_se(r_c == r_r);
                assert_se(r_c == t);
        }
}

int main(int argc, char *argv[]) {
        test_log_target_to_string_all();
        test_log_target_to_string_invalid();
        test_log_target_from_string_all();
        test_log_target_from_string_invalid();
        test_log_target_roundtrip();

        return 0;
}
