/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C exit-status/securebits vs Rust */

#include <assert.h>
#include <string.h>
#include <sysexits.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "exit-status.h"
#include "securebits-util.h"

/* Rust FFI */
#include "rust/exit_status.h"

/* secure_bit_to_string is static inline in securebits-util.c, not in the header.
 * Re-declare it here for testing. */
static inline const char *secure_bit_to_string(int i) {
        /* match a single bit */
        switch (i) {
        case SECBIT_KEEP_CAPS: return "keep-caps";
        case SECBIT_KEEP_CAPS_LOCKED: return "keep-caps-locked";
        case SECBIT_NO_SETUID_FIXUP: return "no-setuid-fixup";
        case SECBIT_NO_SETUID_FIXUP_LOCKED: return "no-setuid-fixup-locked";
        case SECBIT_NOROOT: return "noroot";
        case SECBIT_NOROOT_LOCKED: return "noroot-locked";
        default: return NULL;
        }
}

/* ── exit_status_to_string ────────────────────────────────────────────── */

static void test_exit_status_to_string(void) {
        const char *cv, *rv;

        /* EXIT_SUCCESS (0) — libc class */
        cv = exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_LIBC);
        rv = rs_exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_LIBC);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "SUCCESS"));

        /* EXIT_FAILURE (1) — libc class */
        cv = exit_status_to_string(EXIT_FAILURE, EXIT_STATUS_LIBC);
        rv = rs_exit_status_to_string(EXIT_FAILURE, EXIT_STATUS_LIBC);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "FAILURE"));

        /* EXIT_SUCCESS — systemd class (should NOT match) */
        cv = exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_SYSTEMD);
        rv = rs_exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_SYSTEMD);
        assert_se(streq_ptr(cv, rv));
        assert_se(cv == NULL);

        /* EXIT_CHDIR (200) — systemd class */
        cv = exit_status_to_string(EXIT_CHDIR, EXIT_STATUS_SYSTEMD);
        rv = rs_exit_status_to_string(EXIT_CHDIR, EXIT_STATUS_SYSTEMD);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "CHDIR"));

        /* EXIT_CHDIR — libc class (should NOT match) */
        cv = exit_status_to_string(EXIT_CHDIR, EXIT_STATUS_LIBC);
        rv = rs_exit_status_to_string(EXIT_CHDIR, EXIT_STATUS_LIBC);
        assert_se(streq_ptr(cv, rv));
        assert_se(cv == NULL);

        /* EXIT_INVALIDARGUMENT (2) — LSB class */
        cv = exit_status_to_string(EXIT_INVALIDARGUMENT, EXIT_STATUS_LSB);
        rv = rs_exit_status_to_string(EXIT_INVALIDARGUMENT, EXIT_STATUS_LSB);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "INVALIDARGUMENT"));

        /* EX_USAGE (64) — BSD class */
        cv = exit_status_to_string(EX_USAGE, EXIT_STATUS_BSD);
        rv = rs_exit_status_to_string(EX_USAGE, EXIT_STATUS_BSD);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "USAGE"));

        /* EXIT_EXCEPTION (255) — systemd class */
        cv = exit_status_to_string(EXIT_EXCEPTION, EXIT_STATUS_SYSTEMD);
        rv = rs_exit_status_to_string(EXIT_EXCEPTION, EXIT_STATUS_SYSTEMD);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "EXCEPTION"));

        /* EXIT_FULL should match everything */
        cv = exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_FULL);
        rv = rs_exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_FULL);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "SUCCESS"));

        /* Out of range */
        cv = exit_status_to_string(-1, EXIT_STATUS_FULL);
        rv = rs_exit_status_to_string(-1, EXIT_STATUS_FULL);
        assert_se(streq_ptr(cv, rv));
        assert_se(cv == NULL);

        cv = exit_status_to_string(256, EXIT_STATUS_FULL);
        rv = rs_exit_status_to_string(256, EXIT_STATUS_FULL);
        assert_se(streq_ptr(cv, rv));
        assert_se(cv == NULL);

        /* Unmapped code 8 */
        cv = exit_status_to_string(8, EXIT_STATUS_FULL);
        rv = rs_exit_status_to_string(8, EXIT_STATUS_FULL);
        assert_se(streq_ptr(cv, rv));
        assert_se(cv == NULL);

        /* Various systemd codes */
        cv = exit_status_to_string(EXIT_MEMORY, EXIT_STATUS_FULL);
        rv = rs_exit_status_to_string(EXIT_MEMORY, EXIT_STATUS_FULL);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "MEMORY"));

        cv = exit_status_to_string(EXIT_CONFIGURATION_DIRECTORY, EXIT_STATUS_FULL);
        rv = rs_exit_status_to_string(EXIT_CONFIGURATION_DIRECTORY, EXIT_STATUS_FULL);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "CONFIGURATION_DIRECTORY"));

        /* BSD codes */
        cv = exit_status_to_string(EX_CONFIG, EXIT_STATUS_FULL);
        rv = rs_exit_status_to_string(EX_CONFIG, EXIT_STATUS_FULL);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "CONFIG"));
}

/* ── exit_status_class ────────────────────────────────────────────────── */

static void test_exit_status_class(void) {
        const char *cv, *rv;

        cv = exit_status_class(EXIT_SUCCESS);
        rv = rs_exit_status_class(EXIT_SUCCESS);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "libc"));

        cv = exit_status_class(EXIT_CHDIR);
        rv = rs_exit_status_class(EXIT_CHDIR);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "systemd"));

        cv = exit_status_class(EXIT_INVALIDARGUMENT);
        rv = rs_exit_status_class(EXIT_INVALIDARGUMENT);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "LSB"));

        cv = exit_status_class(EX_USAGE);
        rv = rs_exit_status_class(EX_USAGE);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "BSD"));

        /* Unmapped code */
        cv = exit_status_class(8);
        rv = rs_exit_status_class(8);
        assert_se(streq_ptr(cv, rv));
        assert_se(cv == NULL);

        /* Out of range */
        cv = exit_status_class(-1);
        rv = rs_exit_status_class(-1);
        assert_se(streq_ptr(cv, rv));
        assert_se(cv == NULL);
}

/* ── exit_status_from_string ──────────────────────────────────────────── */

static void test_exit_status_from_string(void) {
        int cv, rv;

        cv = exit_status_from_string("SUCCESS");
        rv = rs_exit_status_from_string("SUCCESS");
        assert_se(cv == rv);
        assert_se(cv == EXIT_SUCCESS);

        cv = exit_status_from_string("FAILURE");
        rv = rs_exit_status_from_string("FAILURE");
        assert_se(cv == rv);
        assert_se(cv == EXIT_FAILURE);

        cv = exit_status_from_string("CHDIR");
        rv = rs_exit_status_from_string("CHDIR");
        assert_se(cv == rv);
        assert_se(cv == EXIT_CHDIR);

        cv = exit_status_from_string("MEMORY");
        rv = rs_exit_status_from_string("MEMORY");
        assert_se(cv == rv);
        assert_se(cv == EXIT_MEMORY);

        cv = exit_status_from_string("USAGE");
        rv = rs_exit_status_from_string("USAGE");
        assert_se(cv == rv);
        assert_se(cv == EX_USAGE);

        cv = exit_status_from_string("EXCEPTION");
        rv = rs_exit_status_from_string("EXCEPTION");
        assert_se(cv == rv);
        assert_se(cv == EXIT_EXCEPTION);

        /* Numeric fallback */
        cv = exit_status_from_string("0");
        rv = rs_exit_status_from_string("0");
        assert_se(cv == rv);
        assert_se(cv == 0);

        cv = exit_status_from_string("255");
        rv = rs_exit_status_from_string("255");
        assert_se(cv == rv);
        assert_se(cv == 255);

        cv = exit_status_from_string("42");
        rv = rs_exit_status_from_string("42");
        assert_se(cv == rv);
        assert_se(cv == 42);

        /* Case sensitive */
        cv = exit_status_from_string("success");
        rv = rs_exit_status_from_string("success");
        assert_se(cv == rv);
        assert_se(cv < 0); /* -EINVAL */

        /* Unknown string */
        cv = exit_status_from_string("FOOBAR");
        rv = rs_exit_status_from_string("FOOBAR");
        assert_se(cv == rv);
        assert_se(cv < 0);

        /* Overflow */
        cv = exit_status_from_string("256");
        rv = rs_exit_status_from_string("256");
        assert_se(cv == rv);
        assert_se(cv < 0); /* -ERANGE */

        /* Empty/NULL */
        cv = exit_status_from_string("");
        rv = rs_exit_status_from_string("");
        assert_se(cv == rv);
        assert_se(cv < 0);
}

/* ── secure_bits_is_valid ─────────────────────────────────────────────── */

static void test_secure_bits_is_valid(void) {
        assert_se(secure_bits_is_valid(0) == rs_secure_bits_is_valid(0));
        assert_se(secure_bits_is_valid(0) == true);

        assert_se(secure_bits_is_valid(SECBIT_NOROOT) == rs_secure_bits_is_valid(SECBIT_NOROOT));
        assert_se(secure_bits_is_valid(SECBIT_NOROOT) == true);

        assert_se(secure_bits_is_valid(SECBIT_NOROOT | SECBIT_KEEP_CAPS) == rs_secure_bits_is_valid(SECBIT_NOROOT | SECBIT_KEEP_CAPS));
        assert_se(secure_bits_is_valid(SECBIT_NOROOT | SECBIT_KEEP_CAPS) == true);

        /* All bits valid */
        assert_se(secure_bits_is_valid(SECURE_ALL_BITS | SECURE_ALL_LOCKS) == rs_secure_bits_is_valid(SECURE_ALL_BITS | SECURE_ALL_LOCKS));
        assert_se(secure_bits_is_valid(SECURE_ALL_BITS | SECURE_ALL_LOCKS) == true);

        /* Invalid: bit outside range (bit 12) */
        assert_se(secure_bits_is_valid(1 << 12) == rs_secure_bits_is_valid(1 << 12));
        assert_se(secure_bits_is_valid(1 << 12) == false);

        /* Valid: SECBIT_NO_CAP_AMBIENT_RAISE is part of SECURE_ALL_BITS */
        assert_se(secure_bits_is_valid(SECBIT_NO_CAP_AMBIENT_RAISE) == rs_secure_bits_is_valid(SECBIT_NO_CAP_AMBIENT_RAISE));
        assert_se(secure_bits_is_valid(SECBIT_NO_CAP_AMBIENT_RAISE) == true);

        assert_se(secure_bits_is_valid(0x7FFFFFFF) == rs_secure_bits_is_valid(0x7FFFFFFF));
        assert_se(secure_bits_is_valid(0x7FFFFFFF) == false);
}

/* ── secure_bit_to_string ─────────────────────────────────────────────── */

static void test_secure_bit_to_string(void) {
        const char *cv, *rv;

        cv = secure_bit_to_string(SECBIT_NOROOT);
        rv = rs_secure_bit_to_string(SECBIT_NOROOT);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "noroot"));

        cv = secure_bit_to_string(SECBIT_NOROOT_LOCKED);
        rv = rs_secure_bit_to_string(SECBIT_NOROOT_LOCKED);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "noroot-locked"));

        cv = secure_bit_to_string(SECBIT_NO_SETUID_FIXUP);
        rv = rs_secure_bit_to_string(SECBIT_NO_SETUID_FIXUP);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "no-setuid-fixup"));

        cv = secure_bit_to_string(SECBIT_NO_SETUID_FIXUP_LOCKED);
        rv = rs_secure_bit_to_string(SECBIT_NO_SETUID_FIXUP_LOCKED);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "no-setuid-fixup-locked"));

        cv = secure_bit_to_string(SECBIT_KEEP_CAPS);
        rv = rs_secure_bit_to_string(SECBIT_KEEP_CAPS);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "keep-caps"));

        cv = secure_bit_to_string(SECBIT_KEEP_CAPS_LOCKED);
        rv = rs_secure_bit_to_string(SECBIT_KEEP_CAPS_LOCKED);
        assert_se(streq_ptr(cv, rv));
        assert_se(streq(cv, "keep-caps-locked"));
}

/* ── is_clean_exit ─────────────────────────────────────────────────────── */

static void test_is_clean_exit(void) {
        bool cv, rv;

        /* Normal exit with status 0 is clean */
        cv = is_clean_exit(CLD_EXITED, 0, EXIT_CLEAN_DAEMON, NULL);
        rv = rs_is_clean_exit(CLD_EXITED, 0, EXIT_CLEAN_DAEMON, NULL);
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Normal exit with non-zero status, no success set → not clean */
        cv = is_clean_exit(CLD_EXITED, 1, EXIT_CLEAN_DAEMON, NULL);
        rv = rs_is_clean_exit(CLD_EXITED, 1, EXIT_CLEAN_DAEMON, NULL);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Killed by SIGTERM, daemon mode → clean */
        cv = is_clean_exit(CLD_KILLED, SIGTERM, EXIT_CLEAN_DAEMON, NULL);
        rv = rs_is_clean_exit(CLD_KILLED, SIGTERM, EXIT_CLEAN_DAEMON, NULL);
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Killed by SIGTERM, command mode → not clean */
        cv = is_clean_exit(CLD_KILLED, SIGTERM, EXIT_CLEAN_COMMAND, NULL);
        rv = rs_is_clean_exit(CLD_KILLED, SIGTERM, EXIT_CLEAN_COMMAND, NULL);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Killed by SIGHUP, daemon mode → clean */
        cv = is_clean_exit(CLD_KILLED, SIGHUP, EXIT_CLEAN_DAEMON, NULL);
        rv = rs_is_clean_exit(CLD_KILLED, SIGHUP, EXIT_CLEAN_DAEMON, NULL);
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Killed by SIGKILL (9), daemon mode → not clean */
        cv = is_clean_exit(CLD_KILLED, SIGKILL, EXIT_CLEAN_DAEMON, NULL);
        rv = rs_is_clean_exit(CLD_KILLED, SIGKILL, EXIT_CLEAN_DAEMON, NULL);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* CLD_DUMPED → not clean */
        cv = is_clean_exit(CLD_DUMPED, SIGSEGV, EXIT_CLEAN_DAEMON, NULL);
        rv = rs_is_clean_exit(CLD_DUMPED, SIGSEGV, EXIT_CLEAN_DAEMON, NULL);
        assert_se(cv == rv);
        assert_se(cv == false);
}

/* ── exit_status_set ───────────────────────────────────────────────────── */

static void test_exit_status_set_is_empty(void) {
        bool cv, rv;

        /* NULL → empty */
        cv = exit_status_set_is_empty(NULL);
        rv = rs_exit_status_set_is_empty(NULL);
        assert_se(cv == rv);
        assert_se(cv == true);

        /* Fresh set is empty */
        ExitStatusSet x = {};
        cv = exit_status_set_is_empty(&x);
        rv = rs_exit_status_set_is_empty(&x);
        assert_se(cv == rv);
        assert_se(cv == true);
}

static void test_exit_status_set_test(void) {
        bool cv, rv;

        /* NULL set → no match */
        cv = exit_status_set_test(NULL, CLD_EXITED, 0);
        rv = rs_exit_status_set_test(NULL, CLD_EXITED, 0);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Empty set → no match */
        ExitStatusSet x = {};
        cv = exit_status_set_test(&x, CLD_EXITED, 42);
        rv = rs_exit_status_set_test(&x, CLD_EXITED, 42);
        assert_se(cv == rv);
        assert_se(cv == false);
}

int main(int argc, char **argv) {
        test_exit_status_to_string();
        test_exit_status_class();
        test_exit_status_from_string();
        test_secure_bits_is_valid();
        test_secure_bit_to_string();
        test_is_clean_exit();
        test_exit_status_set_is_empty();
        test_exit_status_set_test();
        return 0;
}
