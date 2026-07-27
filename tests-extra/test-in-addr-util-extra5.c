/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>
#include <sys/socket.h>

#include "in-addr-util.h"
#include "string-util.h"
#include "tests.h"

TEST(in4_addr_is_set) {
        struct in_addr a = {};

        assert_se(!in4_addr_is_set(&a));

        /* 127.0.0.1 in network byte order */
        a.s_addr = (in_addr_t) 0x0100007f;
        assert_se(in4_addr_is_set(&a));

        a.s_addr = 0;
        assert_se(!in4_addr_is_set(&a));

        /* Some non-zero address */
        a.s_addr = (in_addr_t) 0x04030201;
        assert_se(in4_addr_is_set(&a));
}

TEST(in6_addr_is_set) {
        struct in6_addr a = {};

        assert_se(!in6_addr_is_set(&a));

        /* ::1 */
        a.s6_addr[15] = 1;
        assert_se(in6_addr_is_set(&a));

        /* ff00:: */
        a = (struct in6_addr) {};
        a.s6_addr[0] = 0xff;
        assert_se(in6_addr_is_set(&a));
}

TEST(family_address_size) {
        assert_se(FAMILY_ADDRESS_SIZE(AF_INET) == sizeof(struct in_addr));
        assert_se(FAMILY_ADDRESS_SIZE(AF_INET6) == sizeof(struct in6_addr));
}

TEST(in4_addr_to_ptr_roundtrip) {
        struct in_addr a = { .s_addr = (in_addr_t) 0x04030201 };
        void *ptr;

        ptr = IN4_ADDR_TO_PTR(&a);
        assert_se(ptr != NULL);

        struct in_addr b;
        PTR_TO_IN4_ADDR(ptr, &b);
        assert_se(a.s_addr == b.s_addr);
}

TEST(in_addr_data_is_null) {
        struct in_addr_data d = {
                .family = AF_INET,
                .address = {},
        };

        /* Zeroed address is null */
        assert_se(in_addr_data_is_null(&d));

        d.address.in.s_addr = (in_addr_t) 0x0100007f;
        assert_se(!in_addr_data_is_null(&d));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
