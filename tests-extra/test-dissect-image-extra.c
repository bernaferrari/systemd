/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dissect-image.h"
#include "string-util.h"
#include "tests.h"

TEST(dissected_image_name_from_path) {
        _cleanup_free_ char *name = NULL;
        int r;

        /* Simple name with .raw suffix */
        r = dissected_image_name_from_path("/var/lib/machines/myimage.raw", &name);
        assert_se(r >= 0);
        assert_se(streq(name, "myimage"));
        name = mfree(name);

        /* Path without .raw suffix */
        r = dissected_image_name_from_path("/var/lib/machines/myimage", &name);
        assert_se(r >= 0);
        if (name)
                assert_se(streq(name, "myimage"));
        name = mfree(name);

        /* Just filename */
        r = dissected_image_name_from_path("test.raw", &name);
        assert_se(r >= 0);
        assert_se(streq(name, "test"));
        name = mfree(name);
}

TEST(image_filter_parse) {
        _cleanup_(image_filter_freep) ImageFilter *f = NULL;
        int r;

        /* Empty string → NULL filter */
        r = image_filter_parse("", &f);
        assert_se(r >= 0);
        assert_se(f == NULL);

        /* NULL ret → still parses */
        r = image_filter_parse("root=.*", NULL);
        assert_se(r >= 0);

        /* Invalid: no equals sign */
        r = image_filter_parse("invalid", &f);
        assert_se(r < 0);

        /* Invalid: unknown designator */
        r = image_filter_parse("nonexistent=patt", &f);
        assert_se(r < 0);
}

TEST(mount_options_set_and_consume) {
        _cleanup_(mount_options_free_allp) MountOptions *opts = NULL;
        int r;

        /* Create new options */
        r = mount_options_set_and_consume(&opts, PARTITION_ROOT, strdup("ro"));
        assert_se(r >= 0);
        assert_se(opts != NULL);
        assert_se(streq(opts->options[PARTITION_ROOT], "ro"));

        /* Replace existing */
        r = mount_options_set_and_consume(&opts, PARTITION_ROOT, strdup("rw"));
        assert_se(r >= 0);
        assert_se(streq(opts->options[PARTITION_ROOT], "rw"));

        /* Add another designator */
        r = mount_options_set_and_consume(&opts, PARTITION_USR, strdup("noexec"));
        assert_se(r >= 0);
        assert_se(streq(opts->options[PARTITION_USR], "noexec"));
}

TEST(mount_options_from_designator) {
        _cleanup_(mount_options_free_allp) MountOptions *opts = NULL;
        int r;

        /* NULL options → NULL result */
        assert_se(mount_options_from_designator(NULL, PARTITION_ROOT) == NULL);

        /* Set and retrieve */
        r = mount_options_set_and_consume(&opts, PARTITION_ROOT, strdup("ro"));
        assert_se(r >= 0);
        assert_se(streq(mount_options_from_designator(opts, PARTITION_ROOT), "ro"));
        assert_se(mount_options_from_designator(opts, PARTITION_USR) == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
