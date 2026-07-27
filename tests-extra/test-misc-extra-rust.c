/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C mountpoint-util / in-addr-util extra functions vs Rust */

#include "tests.h"
#include "mountpoint-util.h"
#include "in-addr-util.h"

/* Rust FFI */
#include "rust/mountpoint_util.h"
#include "rust/in_addr_util.h"

/* ── is_name_to_handle_at_fatal_error ───────────────────────────────────── */

static void test_is_name_to_handle_at_fatal_error(void) {
        bool cb, rb;

        /* Non-fatal: EOPNOTSUPP */
        cb = is_name_to_handle_at_fatal_error(-EOPNOTSUPP);
        rb = rs_is_name_to_handle_at_fatal_error(-EOPNOTSUPP);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: EACCES */
        cb = is_name_to_handle_at_fatal_error(-EACCES);
        rb = rs_is_name_to_handle_at_fatal_error(-EACCES);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: EPERM */
        cb = is_name_to_handle_at_fatal_error(-EPERM);
        rb = rs_is_name_to_handle_at_fatal_error(-EPERM);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: EOVERFLOW */
        cb = is_name_to_handle_at_fatal_error(-EOVERFLOW);
        rb = rs_is_name_to_handle_at_fatal_error(-EOVERFLOW);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: EINVAL */
        cb = is_name_to_handle_at_fatal_error(-EINVAL);
        rb = rs_is_name_to_handle_at_fatal_error(-EINVAL);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: ENOSYS */
        cb = is_name_to_handle_at_fatal_error(-ENOSYS);
        rb = rs_is_name_to_handle_at_fatal_error(-ENOSYS);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: ENOTTY */
        cb = is_name_to_handle_at_fatal_error(-ENOTTY);
        rb = rs_is_name_to_handle_at_fatal_error(-ENOTTY);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: EAFNOSUPPORT */
        cb = is_name_to_handle_at_fatal_error(-EAFNOSUPPORT);
        rb = rs_is_name_to_handle_at_fatal_error(-EAFNOSUPPORT);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: EPFNOSUPPORT */
        cb = is_name_to_handle_at_fatal_error(-EPFNOSUPPORT);
        rb = rs_is_name_to_handle_at_fatal_error(-EPFNOSUPPORT);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: EPROTONOSUPPORT */
        cb = is_name_to_handle_at_fatal_error(-EPROTONOSUPPORT);
        rb = rs_is_name_to_handle_at_fatal_error(-EPROTONOSUPPORT);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: ESOCKTNOSUPPORT */
        cb = is_name_to_handle_at_fatal_error(-ESOCKTNOSUPPORT);
        rb = rs_is_name_to_handle_at_fatal_error(-ESOCKTNOSUPPORT);
        assert_se(cb == rb); assert_se(cb == false);

        /* Non-fatal: ENOPROTOOPT */
        cb = is_name_to_handle_at_fatal_error(-ENOPROTOOPT);
        rb = rs_is_name_to_handle_at_fatal_error(-ENOPROTOOPT);
        assert_se(cb == rb); assert_se(cb == false);

        /* Fatal: ENOMEM */
        cb = is_name_to_handle_at_fatal_error(-ENOMEM);
        rb = rs_is_name_to_handle_at_fatal_error(-ENOMEM);
        assert_se(cb == rb); assert_se(cb == true);

        /* Fatal: EIO */
        cb = is_name_to_handle_at_fatal_error(-EIO);
        rb = rs_is_name_to_handle_at_fatal_error(-EIO);
        assert_se(cb == rb); assert_se(cb == true);

        /* Fatal: ENOENT */
        cb = is_name_to_handle_at_fatal_error(-ENOENT);
        rb = rs_is_name_to_handle_at_fatal_error(-ENOENT);
        assert_se(cb == rb); assert_se(cb == true);
}

/* ── in_addr_parse_prefixlen ───────────────────────────────────────────── */

static void test_in_addr_parse_prefixlen(void) {
        unsigned char cr, rr;
        int rc, rrr;

        /* AF_INET valid */
        rc = in_addr_parse_prefixlen(AF_INET, "24", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET, "24", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == rr); assert_se(cr == 24);

        rc = in_addr_parse_prefixlen(AF_INET, "0", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET, "0", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == 0);

        rc = in_addr_parse_prefixlen(AF_INET, "32", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET, "32", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == 32);

        /* AF_INET6 valid */
        rc = in_addr_parse_prefixlen(AF_INET6, "64", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET6, "64", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == 64);

        rc = in_addr_parse_prefixlen(AF_INET6, "128", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET6, "128", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == 128);

        /* AF_INET too large */
        rc = in_addr_parse_prefixlen(AF_INET, "33", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET, "33", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        /* AF_INET6 too large */
        rc = in_addr_parse_prefixlen(AF_INET6, "129", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET6, "129", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        /* AF_INET6 prefixlen valid for INET but not INET6 */
        rc = in_addr_parse_prefixlen(AF_INET6, "32", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET6, "32", &rr);
        assert_se(rc == rrr); assert_se(rc == 0); assert_se(cr == 32);

        /* Invalid family */
        rc = in_addr_parse_prefixlen(AF_UNIX, "24", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_UNIX, "24", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        /* Invalid: non-numeric */
        rc = in_addr_parse_prefixlen(AF_INET, "abc", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET, "abc", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        /* Invalid: empty */
        rc = in_addr_parse_prefixlen(AF_INET, "", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET, "", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        /* Invalid: negative */
        rc = in_addr_parse_prefixlen(AF_INET, "-1", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET, "-1", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);

        /* AF_INET 128 too large for IPv4 */
        rc = in_addr_parse_prefixlen(AF_INET, "128", &cr);
        rrr = rs_in_addr_parse_prefixlen(AF_INET, "128", &rr);
        assert_se(rc == rrr); assert_se(rc < 0);
}

/* ── in4_addr_default_subnet_mask ──────────────────────────────────────── */

static void test_in4_addr_default_subnet_mask(void) {
        struct in_addr addr, mask_c, mask_r;
        int rc, rrr;

        /* Class A: 10.x.x.x -> /8 -> 255.0.0.0 */
        memset(&addr, 0, sizeof(addr));
        addr.s_addr = htobe32(0x0A000001);
        rc = in4_addr_default_subnet_mask(&addr, &mask_c);
        rrr = rs_in4_addr_default_subnet_mask((const struct rs_InAddr *)&addr, (struct rs_InAddr *)&mask_r);
        assert_se(rc == rrr); assert_se(rc == 0);
        assert_se(mask_c.s_addr == mask_r.s_addr);
        assert_se(mask_c.s_addr == htobe32(0xFF000000));

        /* Class B: 172.16.x.x -> /16 -> 255.255.0.0 */
        addr.s_addr = htobe32(0xAC100001);
        rc = in4_addr_default_subnet_mask(&addr, &mask_c);
        rrr = rs_in4_addr_default_subnet_mask((const struct rs_InAddr *)&addr, (struct rs_InAddr *)&mask_r);
        assert_se(rc == rrr); assert_se(rc == 0);
        assert_se(mask_c.s_addr == mask_r.s_addr);
        assert_se(mask_c.s_addr == htobe32(0xFFFF0000));

        /* Class C: 192.168.1.x -> /24 -> 255.255.255.0 */
        addr.s_addr = htobe32(0xC0A80101);
        rc = in4_addr_default_subnet_mask(&addr, &mask_c);
        rrr = rs_in4_addr_default_subnet_mask((const struct rs_InAddr *)&addr, (struct rs_InAddr *)&mask_r);
        assert_se(rc == rrr); assert_se(rc == 0);
        assert_se(mask_c.s_addr == mask_r.s_addr);
        assert_se(mask_c.s_addr == htobe32(0xFFFFFF00));

        /* Loopback: 127.0.0.1 -> /8 -> 255.0.0.0 */
        addr.s_addr = htobe32(0x7F000001);
        rc = in4_addr_default_subnet_mask(&addr, &mask_c);
        rrr = rs_in4_addr_default_subnet_mask((const struct rs_InAddr *)&addr, (struct rs_InAddr *)&mask_r);
        assert_se(rc == rrr); assert_se(rc == 0);
        assert_se(mask_c.s_addr == mask_r.s_addr);

        /* Class D (multicast): 224.x.x.x -> returns -ERANGE */
        addr.s_addr = htobe32(0xE0000001);
        rc = in4_addr_default_subnet_mask(&addr, &mask_c);
        rrr = rs_in4_addr_default_subnet_mask((const struct rs_InAddr *)&addr, (struct rs_InAddr *)&mask_r);
        assert_se(rc == rrr); assert_se(rc < 0);
}

int main(int argc, char **argv) {
        test_is_name_to_handle_at_fatal_error();
        test_in_addr_parse_prefixlen();
        test_in4_addr_default_subnet_mask();
        return 0;
}
