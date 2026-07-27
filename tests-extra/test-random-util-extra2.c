/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "iovec-util.h"
#include "random-util.h"
#include "tests.h"

TEST(crypto_random_bytes_basic) {
        uint8_t buf[32] = {};
        int r = crypto_random_bytes(buf, sizeof(buf));
        assert_se(r == 0);

        /* Verify not all zeros */
        bool all_zero = true;
        for (size_t i = 0; i < sizeof(buf); i++)
                if (buf[i] != 0) all_zero = false;
        assert_se(!all_zero);
}

TEST(crypto_random_bytes_allocate_iovec_basic) {
        struct iovec iov = {};
        int r = crypto_random_bytes_allocate_iovec(32, &iov);
        if (r >= 0) {
                assert_se(iov.iov_base);
                assert_se(iov.iov_len == 32);
                iovec_done(&iov);
        }
}

TEST(random_write_entropy_basic) {
        /* /dev/null is not a valid entropy device, but test the function */
        _cleanup_close_ int fd = open("/dev/null", O_RDWR|O_CLOEXEC);
        if (fd >= 0) {
                uint8_t seed[32] = {};
                int r = random_write_entropy(fd, seed, sizeof(seed), false);
                log_debug("random_write_entropy: %d", r);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
