/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "devnum-util.h"
#include "string-util.h"
#include "tests.h"

TEST(parse_devnum_basic) {
        dev_t dev;
        assert_se(parse_devnum("8:0", &dev) >= 0);
        assert_se(major(dev) == 8);
        assert_se(minor(dev) == 0);

        assert_se(parse_devnum("253:1", &dev) >= 0);
        assert_se(major(dev) == 253);
        assert_se(minor(dev) == 1);

        assert_se(parse_devnum("0:0", &dev) >= 0);
        assert_se(major(dev) == 0);
        assert_se(minor(dev) == 0);

        /* Invalid */
        assert_se(parse_devnum("", &dev) < 0);
        assert_se(parse_devnum("abc", &dev) < 0);
        assert_se(parse_devnum("8", &dev) < 0);
        assert_se(parse_devnum(":0", &dev) < 0);
}

TEST(device_path_make_major_minor_basic) {
        _cleanup_free_ char *p = NULL;
        dev_t dev = makedev(8, 0);

        assert_se(device_path_make_major_minor(S_IFBLK, dev, &p) >= 0);
        assert_se(p && startswith(p, "/dev/"));
        p = mfree(p);

        dev = makedev(136, 0);
        assert_se(device_path_make_major_minor(S_IFCHR, dev, &p) >= 0);
        assert_se(p);
        log_debug("char device path: %s", p);
}

TEST(device_path_parse_major_minor_basic) {
        dev_t dev;
        mode_t mode;
        int r;

        /* This function parses block/char device paths. /dev/sda may not exist. */
        r = device_path_parse_major_minor("/dev/sda", &mode, &dev);
        if (r >= 0) {
                log_debug("parsed /dev/sda: major=%u minor=%u mode=%o", major(dev), minor(dev), mode);
        }
}

TEST(format_devnum_basic) {
        dev_t dev = makedev(8, 5);
        assert_se(streq(FORMAT_DEVNUM(dev), "8:5"));

        dev = makedev(0, 0);
        assert_se(streq(FORMAT_DEVNUM(dev), "0:0"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
