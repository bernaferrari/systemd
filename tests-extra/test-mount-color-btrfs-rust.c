/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C mount_propagation_flag, color-util, btrfs, coredump_filter vs Rust */

#include "tests.h"
#include <sys/mount.h>
#include "mountpoint-util.h"
#include "color-util.h"
#include "linux/btrfs.h"
#include "coredump-util.h"

/* Rust FFI */
#include "rust/mountpoint_util.h"
#include "rust/shared_facades/validation.h"
#include "rust/btrfs_util.h"
#include "rust/netdev_str_tables.h"

/* ── mount_propagation_flag ─────────────────────────────────────────────── */

static void test_mount_propagation_flag(void) {
        const char *cv, *rv;
        unsigned long cul, rul;
        int cr, rr;
        bool cb, rb;

        /* to_string: 0 */
        cv = mount_propagation_flag_to_string(0);
        rv = rs_mount_propagation_flag_to_string(0);
        assert_se(cv && rv);
        assert_se(streq(cv, ""));
        assert_se(streq(rv, ""));

        /* to_string: shared */
        cv = mount_propagation_flag_to_string(MS_SHARED);
        rv = rs_mount_propagation_flag_to_string(MS_SHARED);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));
        assert_se(streq(cv, "shared"));

        /* to_string: slave */
        cv = mount_propagation_flag_to_string(MS_SLAVE);
        rv = rs_mount_propagation_flag_to_string(MS_SLAVE);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));
        assert_se(streq(cv, "slave"));

        /* to_string: private */
        cv = mount_propagation_flag_to_string(MS_PRIVATE);
        rv = rs_mount_propagation_flag_to_string(MS_PRIVATE);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));
        assert_se(streq(cv, "private"));

        /* to_string: invalid combination */
        cv = mount_propagation_flag_to_string(MS_SHARED | MS_SLAVE);
        rv = rs_mount_propagation_flag_to_string(MS_SHARED | MS_SLAVE);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string: empty → 0 */
        cr = mount_propagation_flag_from_string("", &cul);
        rr = rs_mount_propagation_flag_from_string("", &rul);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cul == 0);
        assert_se(rul == 0);

        /* from_string: shared */
        cr = mount_propagation_flag_from_string("shared", &cul);
        rr = rs_mount_propagation_flag_from_string("shared", &rul);
        assert_se(cr == rr);
        assert_se(cul == (unsigned long)MS_SHARED);
        assert_se(rul == (unsigned long)MS_SHARED);

        /* from_string: slave */
        cr = mount_propagation_flag_from_string("slave", &cul);
        rr = rs_mount_propagation_flag_from_string("slave", &rul);
        assert_se(cr == rr);
        assert_se(cul == (unsigned long)MS_SLAVE);
        assert_se(rul == (unsigned long)MS_SLAVE);

        /* from_string: private */
        cr = mount_propagation_flag_from_string("private", &cul);
        rr = rs_mount_propagation_flag_from_string("private", &rul);
        assert_se(cr == rr);
        assert_se(cul == (unsigned long)MS_PRIVATE);
        assert_se(rul == (unsigned long)MS_PRIVATE);

        /* from_string: invalid */
        cr = mount_propagation_flag_from_string("bogus", &cul);
        rr = rs_mount_propagation_flag_from_string("bogus", &rul);
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* is_valid */
        cb = mount_propagation_flag_is_valid(0);
        rb = rs_mount_propagation_flag_is_valid(0);
        assert_se(cb == rb);
        assert_se(cb == true);

        cb = mount_propagation_flag_is_valid(MS_SHARED);
        rb = rs_mount_propagation_flag_is_valid(MS_SHARED);
        assert_se(cb == rb);
        assert_se(cb == true);

        cb = mount_propagation_flag_is_valid(MS_SLAVE);
        rb = rs_mount_propagation_flag_is_valid(MS_SLAVE);
        assert_se(cb == rb);
        assert_se(cb == true);

        cb = mount_propagation_flag_is_valid(MS_PRIVATE);
        rb = rs_mount_propagation_flag_is_valid(MS_PRIVATE);
        assert_se(cb == rb);
        assert_se(cb == true);

        cb = mount_propagation_flag_is_valid(42);
        rb = rs_mount_propagation_flag_is_valid(42);
        assert_se(cb == rb);
        assert_se(cb == false);
}

/* ── rgb_to_hsv / hsv_to_rgb ────────────────────────────────────────────── */

static void test_rgb_hsv(void) {
        double ch, cs, cv;
        double rh, rs, rv;
        uint8_t cr_r, cr_g, cr_b;
        uint8_t rr_r, rr_g, rr_b;

        /* Black: RGB(0,0,0) → V=0, S=0, H=NaN */
        rs_rgb_to_hsv(0.0, 0.0, 0.0, &rh, &rs, &rv);
        rs_hsv_to_rgb(0.0, 0.0, 0.0, &rr_r, &rr_g, &rr_b);
        assert_se(rv == 0.0);
        assert_se(rs == 0.0);
        assert_se(rh != rh); /* NaN check */
        assert_se(rr_r == 0 && rr_g == 0 && rr_b == 0);

        /* White: RGB(1,1,1) → V=100, S=0, H=NaN */
        rs_rgb_to_hsv(1.0, 1.0, 1.0, &rh, &rs, &rv);
        assert_se(rv == 100.0);
        assert_se(rs == 0.0);
        assert_se(rh != rh); /* NaN check */

        /* Pure red: RGB(1,0,0) → H=0, S=100, V=100 */
        rs_rgb_to_hsv(1.0, 0.0, 0.0, &rh, &rs, &rv);
        assert_se(rh == 0.0);
        assert_se(rs == 100.0);
        assert_se(rv == 100.0);

        /* Pure green: RGB(0,1,0) → H=120, S=100, V=100 */
        rs_rgb_to_hsv(0.0, 1.0, 0.0, &rh, &rs, &rv);
        assert_se(rh == 120.0);
        assert_se(rs == 100.0);
        assert_se(rv == 100.0);

        /* Pure blue: RGB(0,0,1) → H=240, S=100, V=100 */
        rs_rgb_to_hsv(0.0, 0.0, 1.0, &rh, &rs, &rv);
        assert_se(rh == 240.0);
        assert_se(rv == 100.0);

        /* Round-trip: verify Rust hsv_to_rgb values */
        rs_hsv_to_rgb(0.0, 100.0, 100.0, &rr_r, &rr_g, &rr_b);
        assert_se(rr_r == 255 && rr_g == 0 && rr_b == 0);

        rs_hsv_to_rgb(120.0, 100.0, 100.0, &rr_r, &rr_g, &rr_b);
        assert_se(rr_r == 0 && rr_g == 255 && rr_b == 0);

        rs_hsv_to_rgb(240.0, 100.0, 100.0, &rr_r, &rr_g, &rr_b);
        assert_se(rr_r == 0 && rr_g == 0 && rr_b == 255);

        /* C and Rust rgb_to_hsv agree */
        rgb_to_hsv(0.5, 0.3, 0.7, &ch, &cs, &cv);
        rs_rgb_to_hsv(0.5, 0.3, 0.7, &rh, &rs, &rv);
        assert_se(ch == rh);
        assert_se(cs == rs);
        assert_se(cv == rv);

        /* C and Rust hsv_to_rgb agree */
        hsv_to_rgb(270.0, 50.0, 80.0, &cr_r, &cr_g, &cr_b);
        rs_hsv_to_rgb(270.0, 50.0, 80.0, &rr_r, &rr_g, &rr_b);
        assert_se(cr_r == rr_r);
        assert_se(cr_g == rr_g);
        assert_se(cr_b == rr_b);

        /* H=360 is the supported cyclic boundary and is equivalent to H=0. */
        hsv_to_rgb(360.0, 100.0, 100.0, &cr_r, &cr_g, &cr_b);
        rs_hsv_to_rgb(360.0, 100.0, 100.0, &rr_r, &rr_g, &rr_b);
        assert_se(cr_r == rr_r);
        assert_se(cr_g == rr_g);
        assert_se(cr_b == rr_b);

        /* rgb_to_hsv outputs are independently optional in both implementations. */
        rgb_to_hsv(0.5, 0.5, 0.5, NULL, NULL, NULL);
        rs_rgb_to_hsv(0.5, 0.5, 0.5, NULL, NULL, NULL);
}

/* ── btrfs_validate_subvolume_name ───────────────────────────────────────── */

static void test_btrfs_validate_subvolume_name(void) {
        int cr, rr;

        /* Valid name */
        cr = btrfs_validate_subvolume_name("my-subvol");
        rr = rs_btrfs_validate_subvolume_name("my-subvol");
        assert_se(cr == rr);
        assert_se(cr == 0);

        /* Valid: simple name */
        cr = btrfs_validate_subvolume_name("root");
        rr = rs_btrfs_validate_subvolume_name("root");
        assert_se(cr == rr);
        assert_se(cr == 0);

        /* Invalid: empty */
        cr = btrfs_validate_subvolume_name("");
        rr = rs_btrfs_validate_subvolume_name("");
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Invalid: NULL */
        cr = btrfs_validate_subvolume_name(NULL);
        rr = rs_btrfs_validate_subvolume_name(NULL);
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Invalid: slash */
        cr = btrfs_validate_subvolume_name("foo/bar");
        rr = rs_btrfs_validate_subvolume_name("foo/bar");
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Invalid: dot */
        cr = btrfs_validate_subvolume_name(".");
        rr = rs_btrfs_validate_subvolume_name(".");
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Invalid: dotdot */
        cr = btrfs_validate_subvolume_name("..");
        rr = rs_btrfs_validate_subvolume_name("..");
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Invalid: too long (filename_is_valid rejects at NAME_MAX=255
           before BTRFS_SUBVOL_NAME_MAX=4039 check is reached) */
        char longname[4100];
        memset(longname, 'a', sizeof(longname) - 1);
        longname[sizeof(longname) - 1] = '\0';
        cr = btrfs_validate_subvolume_name(longname);
        rr = rs_btrfs_validate_subvolume_name(longname);
        assert_se(cr == rr);
        assert_se(cr < 0);
}

/* ── coredump_filter_mask_from_string ───────────────────────────────────── */

static void test_coredump_filter_mask(void) {
        uint64_t cm, rm;
        int cr, rr;

        /* "default" */
        cr = coredump_filter_mask_from_string("default", &cm);
        rr = rs_coredump_filter_mask_from_string("default", &rm);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cm == rm);

        /* "all" */
        cr = coredump_filter_mask_from_string("all", &cm);
        rr = rs_coredump_filter_mask_from_string("all", &rm);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cm == rm);
        assert_se(cm == COREDUMP_FILTER_MASK_ALL);

        /* Named filter: "private-anonymous" → bit 0 */
        cr = coredump_filter_mask_from_string("private-anonymous", &cm);
        rr = rs_coredump_filter_mask_from_string("private-anonymous", &rm);
        assert_se(cr == rr);
        assert_se(cm == 1u);

        /* Named filter: "elf-headers" → bit 4 */
        cr = coredump_filter_mask_from_string("elf-headers", &cm);
        rr = rs_coredump_filter_mask_from_string("elf-headers", &rm);
        assert_se(cr == rr);
        assert_se(cm == (1u << 4));

        /* Multiple named filters */
        cr = coredump_filter_mask_from_string("private-anonymous elf-headers", &cm);
        rr = rs_coredump_filter_mask_from_string("private-anonymous elf-headers", &rm);
        assert_se(cr == rr);
        assert_se(cm == (1u | (1u << 4)));

        /* Hex value */
        cr = coredump_filter_mask_from_string("0xff", &cm);
        rr = rs_coredump_filter_mask_from_string("0xff", &rm);
        assert_se(cr == rr);
        assert_se(cm == 0xff);

        /* Invalid: unknown name */
        cr = coredump_filter_mask_from_string("bogus", &cm);
        rr = rs_coredump_filter_mask_from_string("bogus", &rm);
        assert_se(cr < 0);
        assert_se(rr < 0);

        /* Empty string */
        cr = coredump_filter_mask_from_string("", &cm);
        rr = rs_coredump_filter_mask_from_string("", &rm);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cm == 0);
}

int main(int argc, char **argv) {
        test_mount_propagation_flag();
        test_rgb_hsv();
        test_btrfs_validate_subvolume_name();
        test_coredump_filter_mask();
        return 0;
}
