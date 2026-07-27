/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "devnum-util.h"
#include "string-util.h"
#include "tests.h"

TEST(parse_devnum) {
        dev_t d;
        int r;

        r = parse_devnum("1:3", &d);
        assert_se(r >= 0);
        assert_se(major(d) == 1);
        assert_se(minor(d) == 3);

        r = parse_devnum("0:0", &d);
        assert_se(r >= 0);
        assert_se(major(d) == 0);
        assert_se(minor(d) == 0);

        r = parse_devnum("254:65535", &d);
        assert_se(r >= 0);
        assert_se(major(d) == 254);
        assert_se(minor(d) == 65535);

        /* No colon */
        assert_se(parse_devnum("123", &d) == -EINVAL);

        /* Empty string */
        assert_se(parse_devnum("", &d) == -EINVAL);

        /* Non-numeric */
        assert_se(parse_devnum("abc:def", &d) == -EINVAL);

        /* Major out of range (> 4095) */
        assert_se(parse_devnum("4096:0", &d) == -ERANGE);
}

TEST(format_devnum) {
        char buf[DEVNUM_STR_MAX];
        char *result;

        result = format_devnum(makedev(1, 3), buf);
        assert_se(result);
        assert_se(streq(result, "1:3"));

        result = format_devnum(makedev(0, 0), buf);
        assert_se(result);
        assert_se(streq(result, "0:0"));

        result = format_devnum(makedev(254, 255), buf);
        assert_se(result);
        assert_se(streq(result, "254:255"));
}

TEST(device_path_make_major_minor) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = device_path_make_major_minor(S_IFCHR, makedev(1, 3), &p);
        assert_se(r >= 0);
        assert_se(streq(p, "/dev/char/1:3"));
        p = mfree(p);

        r = device_path_make_major_minor(S_IFBLK, makedev(8, 0), &p);
        assert_se(r >= 0);
        assert_se(streq(p, "/dev/block/8:0"));
        p = mfree(p);

        /* Neither char nor block → -ENODEV */
        assert_se(device_path_make_major_minor(S_IFREG, makedev(1, 3), &p) == -ENODEV);
}

TEST(device_path_parse_major_minor) {
        mode_t mode;
        dev_t devnum;
        int r;

        r = device_path_parse_major_minor("/dev/char/1:3", &mode, &devnum);
        assert_se(r >= 0);
        assert_se(mode == S_IFCHR);
        assert_se(major(devnum) == 1);
        assert_se(minor(devnum) == 3);

        r = device_path_parse_major_minor("/dev/block/8:0", &mode, &devnum);
        assert_se(r >= 0);
        assert_se(mode == S_IFBLK);
        assert_se(major(devnum) == 8);
        assert_se(minor(devnum) == 0);

        /* Inaccessible char device */
        r = device_path_parse_major_minor("/run/systemd/inaccessible/chr", &mode, &devnum);
        assert_se(r >= 0);
        assert_se(mode == S_IFCHR);
        assert_se(major(devnum) == 0);
        assert_se(minor(devnum) == 0);

        /* Inaccessible block device */
        r = device_path_parse_major_minor("/run/systemd/inaccessible/blk", &mode, &devnum);
        assert_se(r >= 0);
        assert_se(mode == S_IFBLK);

        /* Random path → -ENODEV */
        assert_se(device_path_parse_major_minor("/dev/sda1", &mode, &devnum) == -ENODEV);
}

TEST(devnum_set_and_equal) {
        assert_se(devnum_set_and_equal(makedev(1, 3), makedev(1, 3)));
        assert_se(!devnum_set_and_equal(makedev(1, 3), makedev(1, 4)));
        assert_se(!devnum_set_and_equal(makedev(0, 0), makedev(0, 0)));
        assert_se(!devnum_set_and_equal(makedev(1, 3), makedev(0, 0)));
}

TEST(devnum_is_zero) {
        assert_se(devnum_is_zero(makedev(0, 0)));
        assert_se(!devnum_is_zero(makedev(1, 0)));
        assert_se(!devnum_is_zero(makedev(0, 1)));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
