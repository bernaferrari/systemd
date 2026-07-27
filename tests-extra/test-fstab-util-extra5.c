/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fstab-util.h"
#include "string-util.h"
#include "tests.h"

TEST(fstab_is_extrinsic_paths) {
        /* Root filesystem is extrinsic */
        assert_se(fstab_is_extrinsic("/", NULL));
        assert_se(fstab_is_extrinsic("/usr", NULL));
        assert_se(fstab_is_extrinsic("/etc", NULL));

        /* Virtual filesystems */
        assert_se(fstab_is_extrinsic("/proc", NULL));
        assert_se(fstab_is_extrinsic("/sys", NULL));
        assert_se(fstab_is_extrinsic("/dev", NULL));

        /* Initramfs */
        assert_se(fstab_is_extrinsic("/run/initramfs", NULL));

        /* Normal mount is NOT extrinsic */
        assert_se(!fstab_is_extrinsic("/home", NULL));
        assert_se(!fstab_is_extrinsic("/var", NULL));
        assert_se(!fstab_is_extrinsic("/mnt/data", NULL));
}

TEST(fstab_filter_options_lookup) {
        const char *name = NULL;
        _cleanup_free_ char *value = NULL;
        int r;

        /* Find existing option */
        r = fstab_filter_options("ro,noexec,nodev", "ro\0", &name, NULL, NULL, NULL);
        assert_se(r > 0);
        assert_se(streq(name, "ro"));

        /* Option not found */
        r = fstab_filter_options("ro,noexec", "noauto\0", &name, NULL, NULL, NULL);
        assert_se(r == 0);

        /* Extract value */
        r = fstab_filter_options("rw,size=256M", "size\0", NULL, &value, NULL, NULL);
        assert_se(r > 0);
        assert_se(streq(value, "256M"));
}

TEST(fstab_filter_options_with_filter) {
        _cleanup_free_ char *value = NULL;
        _cleanup_free_ char *filtered = NULL;
        int r;

        r = fstab_filter_options("rw,size=256M,noexec", "size\0", NULL, &value, NULL, &filtered);
        assert_se(r > 0);
        assert_se(streq(value, "256M"));
        assert_se(filtered != NULL);
        assert_se(strstr(filtered, "rw") != NULL);
        assert_se(strstr(filtered, "noexec") != NULL);
        assert_se(strstr(filtered, "size") == NULL);
}

TEST(fstab_filter_options_null_opts) {
        int r = fstab_filter_options(NULL, "ro\0", NULL, NULL, NULL, NULL);
        assert_se(r == 0);
}

TEST(fstab_test_option_macro) {
        assert_se(fstab_test_option("ro,nosuid", "ro\0"));
        assert_se(fstab_test_option("ro,nosuid", "nosuid\0"));
        assert_se(!fstab_test_option("ro,nosuid", "noexec\0"));
        assert_se(!fstab_test_option(NULL, "ro\0"));
}

TEST(fstab_test_yes_no_option_macro) {
        /* Returns true if first option in list was the last found */
        assert_se(fstab_test_yes_no_option("yes", "yes\0no\0"));
        assert_se(!fstab_test_yes_no_option("no", "yes\0no\0"));
        assert_se(fstab_test_yes_no_option("auto", "auto\0noauto\0"));
        assert_se(!fstab_test_yes_no_option("noauto", "auto\0noauto\0"));
        assert_se(!fstab_test_yes_no_option("other", "yes\0no\0"));
}

TEST(fstab_node_to_udev_node_basic) {
        _cleanup_free_ char *node = NULL;

        /* Normal device path unchanged */
        node = fstab_node_to_udev_node("/dev/sda1");
        assert_se(node != NULL);
        assert_se(streq(node, "/dev/sda1"));

        /* UUID= style */
        node = mfree(node);
        node = fstab_node_to_udev_node("UUID=1234-5678");
        assert_se(node != NULL);

        /* LABEL= style */
        node = mfree(node);
        node = fstab_node_to_udev_node("LABEL=MyDrive");
        assert_se(node != NULL);
}

TEST(fstab_is_bind_check) {
        assert_se(fstab_is_bind("bind", NULL));
        assert_se(!fstab_is_bind("ro", NULL));
        assert_se(!fstab_is_bind(NULL, "ext4"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
