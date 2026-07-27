/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <sys/socket.h>

#include "in-addr-util.h"
#include "dns-domain.h"
#include "tests.h"

/* ── dns_name_reverse (IPv4) ──────────────────────────────────────── */

TEST(dns_name_reverse_v4) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        union in_addr_union addr;
        int r;

        /* 192.168.1.1 → 1.1.168.192.in-addr.arpa */
        addr.in.s_addr = htobe32((192U << 24) | (168U << 16) | (1U << 8) | 1U);
        r = dns_name_reverse(AF_INET, &addr, &cr);
        assert_se(r == 0);
        ASSERT_STREQ(cr, "1.1.168.192.in-addr.arpa");

        /* 10.0.0.1 → 1.0.0.10.in-addr.arpa */
        addr.in.s_addr = htobe32((10U << 24) | (0U << 16) | (0U << 8) | 1U);
        r = dns_name_reverse(AF_INET, &addr, &rr);
        assert_se(r == 0);
        ASSERT_STREQ(rr, "1.0.0.10.in-addr.arpa");

        /* 255.255.255.255 → 255.255.255.255.in-addr.arpa */
        addr.in.s_addr = htobe32(0xFFFFFFFFU);
        r = dns_name_reverse(AF_INET, &addr, &rr);
        assert_se(r == 0);
        ASSERT_STREQ(rr, "255.255.255.255.in-addr.arpa");

        /* Unsupported family */
        r = dns_name_reverse(AF_UNSPEC, &addr, &rr);
        assert_se(r == -EAFNOSUPPORT);
}

/* ── dns_name_address (IPv4) ─────────────────────────────────────── */

TEST(dns_name_address_v4) {
        union in_addr_union addr;
        int family;
        int r;

        /* 1.1.168.192.in-addr.arpa → 192.168.1.1 */
        r = dns_name_address("1.1.168.192.in-addr.arpa", &family, &addr);
        assert_se(r > 0);
        assert_se(family == AF_INET);
        assert_se(be32toh(addr.in.s_addr) == ((192U << 24) | (168U << 16) | (1U << 8) | 1U));

        /* Not a reverse name */
        r = dns_name_address("www.example.com", &family, &addr);
        assert_se(r == 0);
        assert_se(family == AF_UNSPEC);
}

/* ── dns_name_normalize ──────────────────────────────────────────── */

TEST(dns_name_normalize_basic) {
        _cleanup_free_ char *cr = NULL;
        int r;

        r = dns_name_normalize("www.example.com", 0, &cr);
        ASSERT_EQ(r, 0);
        assert_se(cr);
        ASSERT_STREQ(cr, "www.example.com");

        cr = mfree(cr);

        /* Normalization should collapse consecutive dots */
        r = dns_name_normalize("www..example.com", 0, &cr);
        ASSERT_EQ(r, -EINVAL);

        /* NULL ret means just validate */
        r = dns_name_normalize("www.example.com", 0, NULL);
        ASSERT_EQ(r, 0);

        /* Invalid name */
        r = dns_name_normalize("invalid..name", 0, NULL);
        ASSERT_EQ(r, -EINVAL);
}

/* ── dns_name_is_valid / dns_name_is_valid_ldh ─────────────────────── */

TEST(dns_name_is_valid_basic) {
        int r;

        r = dns_name_is_valid("www.example.com");
        ASSERT_GT(r, 0);

        r = dns_name_is_valid("");
        ASSERT_GT(r, 0); /* empty string is the root domain "." — valid */

        r = dns_name_is_valid("valid-label");
        ASSERT_GT(r, 0);

        r = dns_name_is_valid("-invalid");
        ASSERT_GT(r, 0); /* leading hyphen is valid for dns_name_is_valid (allows escapes) */

        r = dns_name_is_valid("invalid.");
        ASSERT_GT(r, 0); /* trailing dot = root domain, valid */

        /* LDH variant: only letters, digits, hyphens, no escapes */
        r = dns_name_is_valid_ldh("www.example.com");
        ASSERT_GT(r, 0);

        r = dns_name_is_valid_ldh("my-host");
        ASSERT_GT(r, 0);

        r = dns_name_is_valid_ldh("my_host"); /* underscore not LDH */
        ASSERT_EQ(r, 0);

        r = dns_name_is_valid_ldh("-invalid"); /* leading hyphen */
        ASSERT_EQ(r, 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
