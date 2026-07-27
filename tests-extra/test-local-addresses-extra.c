/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include "in-addr-util.h"
#include "local-addresses.h"
#include "tests.h"

TEST(has_local_address_empty) {
        struct local_address needle = {
                .ifindex = 1,
                .family = AF_INET,
                .scope = 0,
        };

        /* Empty list should not contain anything */
        assert_se(!has_local_address(NULL, 0, &needle));
}

TEST(add_local_address_basic) {
        _cleanup_free_ struct local_address *list = NULL;
        size_t n_list = 0;
        union in_addr_union a = {};

        assert_se(inet_pton(AF_INET, "192.168.1.1", &a.in) == 1);
        assert_se(add_local_address(&list, &n_list, 1, 0, AF_INET, &a) >= 0);
        assert_se(n_list == 1);
        assert_se(list[0].ifindex == 1);
        assert_se(list[0].family == AF_INET);
        assert_se(list[0].scope == 0);

        /* Add a second address */
        union in_addr_union b = {};
        assert_se(inet_pton(AF_INET, "10.0.0.1", &b.in) == 1);
        assert_se(add_local_address(&list, &n_list, 2, 0, AF_INET, &b) >= 0);
        assert_se(n_list == 2);
        assert_se(list[1].ifindex == 2);
}

TEST(has_local_address_found) {
        _cleanup_free_ struct local_address *list = NULL;
        size_t n_list = 0;
        union in_addr_union a = {};

        assert_se(inet_pton(AF_INET, "192.168.1.1", &a.in) == 1);
        assert_se(add_local_address(&list, &n_list, 1, 0, AF_INET, &a) >= 0);

        struct local_address needle = {
                .ifindex = 1,
                .family = AF_INET,
                .scope = 0,
                .address = a,
        };

        assert_se(has_local_address(list, n_list, &needle));

        /* Different ifindex → not found */
        needle.ifindex = 99;
        assert_se(!has_local_address(list, n_list, &needle));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
