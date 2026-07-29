/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: securebit-mask-validation */
/* Shadow test: C securebits-util.h inline functions vs Rust */

#include <assert.h>
#include <linux/securebits.h>
#include "tests.h"
#include "securebits-util.h"
#include "rust/exit_status.h"

static void test_secure_bits_is_valid(void) {
        assert_se(secure_bits_is_valid(0) == rs_secure_bits_is_valid(0));
        assert_se(secure_bits_is_valid(SECURE_ALL_BITS) == rs_secure_bits_is_valid(SECURE_ALL_BITS));
        assert_se(secure_bits_is_valid(SECURE_ALL_LOCKS) == rs_secure_bits_is_valid(SECURE_ALL_LOCKS));
        assert_se(secure_bits_is_valid(SECURE_ALL_BITS | SECURE_ALL_LOCKS) == rs_secure_bits_is_valid(SECURE_ALL_BITS | SECURE_ALL_LOCKS));
        assert_se(secure_bits_is_valid(SECBIT_NOROOT) == rs_secure_bits_is_valid(SECBIT_NOROOT));
        assert_se(secure_bits_is_valid(SECBIT_NOROOT_LOCKED) == rs_secure_bits_is_valid(SECBIT_NOROOT_LOCKED));
        assert_se(secure_bits_is_valid(SECBIT_NO_SETUID_FIXUP) == rs_secure_bits_is_valid(SECBIT_NO_SETUID_FIXUP));
        assert_se(secure_bits_is_valid(SECBIT_KEEP_CAPS) == rs_secure_bits_is_valid(SECBIT_KEEP_CAPS));
        assert_se(secure_bits_is_valid(SECBIT_NO_CAP_AMBIENT_RAISE) == rs_secure_bits_is_valid(SECBIT_NO_CAP_AMBIENT_RAISE));
        /* Invalid: bit 1 is not in SECURE_ALL_BITS (NOROOT_LOCKED=bit 1, but only as part of ALL_LOCKS) */
        /* Actually SECBIT_NOROOT_LOCKED = bit 1 which IS part of SECURE_ALL_LOCKS */
        assert_se(secure_bits_is_valid(-1) == rs_secure_bits_is_valid(-1));
        assert_se(secure_bits_is_valid(0xDEAD) == rs_secure_bits_is_valid(0xDEAD));
        assert_se(secure_bits_is_valid(SECURE_ALL_BITS + 1) == rs_secure_bits_is_valid(SECURE_ALL_BITS + 1));
}

int main(int argc, char **argv) {
        test_secure_bits_is_valid();
        return 0;
}
