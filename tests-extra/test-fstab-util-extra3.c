/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fstab-util.h"
#include "tests.h"

TEST(fstab_is_bind) {
        assert_se(fstab_is_bind("bind", NULL));
        assert_se(fstab_is_bind("rbind", NULL));
        assert_se(fstab_is_bind("ro,bind", NULL));
        assert_se(fstab_is_bind("rbind,noexec", NULL));

        /* Via fstype */
        assert_se(fstab_is_bind(NULL, "bind"));
        assert_se(fstab_is_bind(NULL, "rbind"));
        assert_se(fstab_is_bind("ro", "bind"));

        assert_se(!fstab_is_bind("ro", NULL));
        assert_se(!fstab_is_bind(NULL, "ext4"));
        assert_se(!fstab_is_bind(NULL, NULL));
}

TEST(fstab_is_extrinsic) {
        assert_se(fstab_is_extrinsic("/", NULL));
        assert_se(fstab_is_extrinsic("/usr", NULL));
        assert_se(fstab_is_extrinsic("/etc", NULL));
        assert_se(fstab_is_extrinsic("/proc", NULL));
        assert_se(fstab_is_extrinsic("/sys", NULL));
        assert_se(fstab_is_extrinsic("/dev", NULL));

        assert_se(!fstab_is_extrinsic("/home", NULL));
        assert_se(!fstab_is_extrinsic("/var", NULL));
        assert_se(!fstab_is_extrinsic("/tmp", NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
