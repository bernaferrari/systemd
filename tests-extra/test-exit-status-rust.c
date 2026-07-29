/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: exit-status-lookup */
/* RUST-CONTRACT: exit-status-class */
/* RUST-CONTRACT: securebit-name */
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

        /* Class is a raw C bit mask, including combinations and unrelated bits. */
        cv = exit_status_to_string(EXIT_CHDIR, EXIT_STATUS_LIBC | EXIT_STATUS_SYSTEMD);
        rv = rs_exit_status_to_string(EXIT_CHDIR, EXIT_STATUS_LIBC | EXIT_STATUS_SYSTEMD);
        assert_se(streq_ptr(cv, rv));

        cv = exit_status_to_string(EXIT_CHDIR, 1 << 8);
        rv = rs_exit_status_to_string(EXIT_CHDIR, 1 << 8);
        assert_se(streq_ptr(cv, rv));
        assert_se(cv == NULL);

        cv = exit_status_to_string(EXIT_CHDIR, -1);
        rv = rs_exit_status_to_string(EXIT_CHDIR, -1);
        assert_se(streq_ptr(cv, rv));
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

int main(int argc, char **argv) {
        test_exit_status_to_string();
        test_exit_status_class();
        test_secure_bits_is_valid();
        test_secure_bit_to_string();
        return 0;
}
