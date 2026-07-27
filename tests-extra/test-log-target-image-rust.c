/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C log_target/image_class string tables vs Rust */

#include "tests.h"
#include "log.h"
#include "os-util.h"
#include "string-util.h"

/* Rust FFI */
#include "rust/log_target.h"
#include "rust/image_class.h"

/* ── log_target ──────────────────────────────────────────────────────── */

static void test_log_target(void) {
        const char *cv, *rv;
        int c, r;

        cv = log_target_to_string(LOG_TARGET_CONSOLE);
        rv = rs_log_target_to_string(LOG_TARGET_CONSOLE);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));
        assert_se(streq(cv, "console"));

        cv = log_target_to_string(LOG_TARGET_KMSG);
        rv = rs_log_target_to_string(LOG_TARGET_KMSG);
        assert_se(streq(cv, rv));

        cv = log_target_to_string(LOG_TARGET_JOURNAL);
        rv = rs_log_target_to_string(LOG_TARGET_JOURNAL);
        assert_se(streq(cv, rv));

        cv = log_target_to_string(LOG_TARGET_SYSLOG);
        rv = rs_log_target_to_string(LOG_TARGET_SYSLOG);
        assert_se(streq(cv, rv));

        cv = log_target_to_string(LOG_TARGET_CONSOLE_PREFIXED);
        rv = rs_log_target_to_string(LOG_TARGET_CONSOLE_PREFIXED);
        assert_se(streq(cv, rv));

        cv = log_target_to_string(LOG_TARGET_JOURNAL_OR_KMSG);
        rv = rs_log_target_to_string(LOG_TARGET_JOURNAL_OR_KMSG);
        assert_se(streq(cv, rv));

        cv = log_target_to_string(LOG_TARGET_SYSLOG_OR_KMSG);
        rv = rs_log_target_to_string(LOG_TARGET_SYSLOG_OR_KMSG);
        assert_se(streq(cv, rv));

        cv = log_target_to_string(LOG_TARGET_AUTO);
        rv = rs_log_target_to_string(LOG_TARGET_AUTO);
        assert_se(streq(cv, rv));
        assert_se(streq(cv, "auto"));

        cv = log_target_to_string(LOG_TARGET_NULL);
        rv = rs_log_target_to_string(LOG_TARGET_NULL);
        assert_se(streq(cv, rv));
        assert_se(streq(cv, "null"));

        /* Invalid */
        cv = log_target_to_string(-1);
        rv = rs_log_target_to_string(-1);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        cv = log_target_to_string(99);
        rv = rs_log_target_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = log_target_from_string("console");
        r = rs_log_target_from_string("console");
        assert_se(c == r);
        assert_se(c == LOG_TARGET_CONSOLE);

        c = log_target_from_string("kmsg");
        r = rs_log_target_from_string("kmsg");
        assert_se(c == r);
        assert_se(c == LOG_TARGET_KMSG);

        c = log_target_from_string("journal");
        r = rs_log_target_from_string("journal");
        assert_se(c == r);
        assert_se(c == LOG_TARGET_JOURNAL);

        c = log_target_from_string("auto");
        r = rs_log_target_from_string("auto");
        assert_se(c == r);
        assert_se(c == LOG_TARGET_AUTO);

        c = log_target_from_string("null");
        r = rs_log_target_from_string("null");
        assert_se(c == r);
        assert_se(c == LOG_TARGET_NULL);

        c = log_target_from_string("bogus");
        r = rs_log_target_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);

        c = log_target_from_string(NULL);
        r = rs_log_target_from_string(NULL);
        assert_se(c < 0);
        assert_se(r < 0);
}

/* ── image_class ─────────────────────────────────────────────────────── */

static void test_image_class(void) {
        const char *cv, *rv;
        int c, r;

        cv = image_class_to_string(IMAGE_MACHINE);
        rv = rs_image_class_to_string(IMAGE_MACHINE);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));

        cv = image_class_to_string(IMAGE_PORTABLE);
        rv = rs_image_class_to_string(IMAGE_PORTABLE);
        assert_se(streq(cv, rv));

        cv = image_class_to_string(IMAGE_SYSEXT);
        rv = rs_image_class_to_string(IMAGE_SYSEXT);
        assert_se(streq(cv, rv));

        cv = image_class_to_string(IMAGE_CONFEXT);
        rv = rs_image_class_to_string(IMAGE_CONFEXT);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = image_class_to_string(-1);
        rv = rs_image_class_to_string(-1);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        cv = image_class_to_string(99);
        rv = rs_image_class_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = image_class_from_string("machine");
        r = rs_image_class_from_string("machine");
        assert_se(c == r);
        assert_se(c == IMAGE_MACHINE);

        c = image_class_from_string("portable");
        r = rs_image_class_from_string("portable");
        assert_se(c == r);
        assert_se(c == IMAGE_PORTABLE);

        c = image_class_from_string("sysext");
        r = rs_image_class_from_string("sysext");
        assert_se(c == r);
        assert_se(c == IMAGE_SYSEXT);

        c = image_class_from_string("confext");
        r = rs_image_class_from_string("confext");
        assert_se(c == r);
        assert_se(c == IMAGE_CONFEXT);

        c = image_class_from_string("bogus");
        r = rs_image_class_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);

        c = image_class_from_string(NULL);
        r = rs_image_class_from_string(NULL);
        assert_se(c < 0);
        assert_se(r < 0);
}

int main(int argc, char **argv) {
        test_log_target();
        test_image_class();
        return 0;
}
