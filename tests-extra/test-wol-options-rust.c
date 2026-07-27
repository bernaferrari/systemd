/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C ethtool-util.c wol_options vs Rust */

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "ethtool-util.h"

/* Rust FFI */
#include "rust/netdev_str_tables.h"

/* -- wol_options_to_string_alloc ------------------------------------------ */

#define WAKE_PHY         (1 << 0)
#define WAKE_UCAST       (1 << 1)
#define WAKE_MCAST       (1 << 2)
#define WAKE_BCAST       (1 << 3)
#define WAKE_ARP         (1 << 4)
#define WAKE_MAGIC       (1 << 5)
#define WAKE_MAGICSECURE (1 << 6)

static void test_wol_options_to_string_alloc(void) {
        _cleanup_free_ char *c_str = NULL;
        _cleanup_free_ char *rs_str = NULL;
        int r;

        /* UINT32_MAX → *ret=NULL, return 0 */
        r = wol_options_to_string_alloc(UINT32_MAX, &c_str);
        assert_se(r == 0);
        assert_se(c_str == NULL);
        r = rs_wol_options_to_string_alloc(UINT32_MAX, &rs_str);
        assert_se(r == 0);
        assert_se(rs_str == NULL);

        /* No bits set → "off" */
        r = wol_options_to_string_alloc(0, &c_str);
        assert_se(r == 1);
        assert_se(streq(c_str, "off"));
        r = rs_wol_options_to_string_alloc(0, &rs_str);
        assert_se(r == 1);
        assert_se(streq(rs_str, "off"));
        assert_se(streq(c_str, rs_str));
        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* Single bit: phy */
        r = wol_options_to_string_alloc(WAKE_PHY, &c_str);
        assert_se(r == 1);
        r = rs_wol_options_to_string_alloc(WAKE_PHY, &rs_str);
        assert_se(r == 1);
        assert_se(streq(c_str, rs_str));
        assert_se(streq(c_str, "phy"));
        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* Single bit: magic */
        r = wol_options_to_string_alloc(WAKE_MAGIC, &c_str);
        assert_se(r == 1);
        r = rs_wol_options_to_string_alloc(WAKE_MAGIC, &rs_str);
        assert_se(r == 1);
        assert_se(streq(c_str, rs_str));
        assert_se(streq(c_str, "magic"));
        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* Multiple bits: phy+magic */
        r = wol_options_to_string_alloc(WAKE_PHY | WAKE_MAGIC, &c_str);
        assert_se(r == 1);
        r = rs_wol_options_to_string_alloc(WAKE_PHY | WAKE_MAGIC, &rs_str);
        assert_se(r == 1);
        assert_se(streq(c_str, rs_str));
        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* All bits */
        r = wol_options_to_string_alloc(WAKE_PHY | WAKE_UCAST | WAKE_MCAST | WAKE_BCAST |
                                        WAKE_ARP | WAKE_MAGIC | WAKE_MAGICSECURE,
                                        &c_str);
        assert_se(r == 1);
        r = rs_wol_options_to_string_alloc(WAKE_PHY | WAKE_UCAST | WAKE_MCAST | WAKE_BCAST |
                                           WAKE_ARP | WAKE_MAGIC | WAKE_MAGICSECURE,
                                           &rs_str);
        assert_se(r == 1);
        assert_se(streq(c_str, rs_str));
        c_str = mfree(c_str);
        rs_str = mfree(rs_str);

        /* secureon alone */
        r = wol_options_to_string_alloc(WAKE_MAGICSECURE, &c_str);
        assert_se(r == 1);
        r = rs_wol_options_to_string_alloc(WAKE_MAGICSECURE, &rs_str);
        assert_se(r == 1);
        assert_se(streq(c_str, rs_str));
        assert_se(streq(c_str, "secureon"));
}

int main(int argc, char **argv) {
        test_wol_options_to_string_alloc();
        return 0;
}
