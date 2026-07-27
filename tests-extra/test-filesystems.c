/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "filesystems.h"
#include "tests.h"

TEST(filesystem_set_find_basic) {
        const FilesystemSet *s;

        s = filesystem_set_find("@basic-api");
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s->name, "@basic-api");
        ASSERT_STREQ(s->help, "Basic filesystem API");

        s = filesystem_set_find("@known");
        ASSERT_NOT_NULL(s);
        ASSERT_STREQ(s->name, "@known");
}

TEST(filesystem_set_find_empty) {
        ASSERT_NULL(filesystem_set_find(""));
        ASSERT_NULL(filesystem_set_find(NULL));
}

TEST(filesystem_set_find_no_at_prefix) {
        /* Names must start with @ */
        ASSERT_NULL(filesystem_set_find("basic-api"));
        ASSERT_NULL(filesystem_set_find("known"));
}

TEST(filesystem_set_find_invalid) {
        ASSERT_NULL(filesystem_set_find("@nonexistent-set"));
        ASSERT_NULL(filesystem_set_find("@"));
}

TEST(filesystem_set_find_all) {
        /* Verify all defined sets are findable */
        static const char * const sets[] = {
                "@basic-api",
                "@anonymous",
                "@application",
                "@auxiliary-api",
                "@common-block",
                "@historical-block",
                "@network",
                "@privileged-api",
                "@security",
                "@temporary",
                "@known",
                NULL,
        };

        for (size_t i = 0; sets[i]; i++) {
                const FilesystemSet *s = filesystem_set_find(sets[i]);
                ASSERT_NOT_NULL(s);
                ASSERT_STREQ(s->name, sets[i]);
                ASSERT_NOT_NULL(s->help);
                ASSERT_NOT_NULL(s->value);
        }
}

TEST(fs_type_from_string_known) {
        const statfs_f_type_t *magic;

        ASSERT_OK(fs_type_from_string("ext4", &magic));
        ASSERT_NOT_NULL(magic);

        ASSERT_OK(fs_type_from_string("btrfs", &magic));
        ASSERT_NOT_NULL(magic);

        ASSERT_OK(fs_type_from_string("xfs", &magic));
        ASSERT_NOT_NULL(magic);

        ASSERT_OK(fs_type_from_string("tmpfs", &magic));
        ASSERT_NOT_NULL(magic);
}

TEST(fs_type_from_string_unknown) {
        const statfs_f_type_t *magic;

        ASSERT_EQ(fs_type_from_string("nonexistent-fs", &magic), -EINVAL);
        ASSERT_EQ(fs_type_from_string("", &magic), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
