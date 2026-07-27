/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dissect-image.h"
#include "string-util.h"
#include "tests.h"

TEST(dissected_image_is_bootable_os) {
        /* NULL is not bootable */
        assert_se(!dissected_image_is_bootable_os(NULL));

        /* Zeroed has_init_system = 0 → not bootable */
        DissectedImage m = {};
        assert_se(!dissected_image_is_bootable_os(&m));

        /* Positive has_init_system → bootable */
        m.has_init_system = 1;
        assert_se(dissected_image_is_bootable_os(&m));

        m.has_init_system = 5;
        assert_se(dissected_image_is_bootable_os(&m));
}

TEST(dissected_image_is_bootable_uefi) {
        /* NULL is not UEFI bootable */
        assert_se(!dissected_image_is_bootable_uefi(NULL));

        /* Has init system but no ESP → not UEFI bootable */
        DissectedImage m = {
                .has_init_system = 1,
        };
        assert_se(!dissected_image_is_bootable_uefi(&m));

        /* Has ESP but no init system → not UEFI bootable */
        m = (DissectedImage) {
                .partitions = {
                        [PARTITION_ESP] = { .found = true },
                },
        };
        assert_se(!dissected_image_is_bootable_uefi(&m));

        /* Has both ESP and init system → UEFI bootable */
        m.has_init_system = 1;
        assert_se(dissected_image_is_bootable_uefi(&m));
}

TEST(verity_settings_set) {
        /* NULL → not set */
        assert_se(!verity_settings_set(NULL));

        /* Zeroed → not set */
        VeritySettings v = VERITY_SETTINGS_DEFAULT;
        assert_se(!verity_settings_set(&v));

        /* Has root_hash → set */
        char buf[] = "hash";
        v = (VeritySettings) {
                .root_hash = IOVEC_MAKE(buf, sizeof(buf)),
        };
        assert_se(verity_settings_set(&v));

        /* Has root_hash_sig → set */
        v = (VeritySettings) {
                .root_hash_sig = IOVEC_MAKE(buf, sizeof(buf)),
        };
        assert_se(verity_settings_set(&v));

        /* Has data_path → set */
        v = (VeritySettings) {
                .data_path = (char*) "/some/path",
        };
        assert_se(verity_settings_set(&v));
}

TEST(verity_settings_data_covers) {
        char hash[] = "abcd";

        /* NULL → does not cover */
        assert_se(!verity_settings_data_covers(NULL, PARTITION_ROOT));

        /* No root_hash → does not cover */
        VeritySettings v = {
                .designator = PARTITION_ROOT,
                .data_path = (char*) "/data",
        };
        assert_se(!verity_settings_data_covers(&v, PARTITION_ROOT));

        /* No data_path → does not cover */
        v = (VeritySettings) {
                .root_hash = IOVEC_MAKE(hash, sizeof(hash)),
                .designator = PARTITION_ROOT,
        };
        assert_se(!verity_settings_data_covers(&v, PARTITION_ROOT));

        /* Matching designator with root_hash and data_path → covers */
        v = (VeritySettings) {
                .root_hash = IOVEC_MAKE(hash, sizeof(hash)),
                .designator = PARTITION_ROOT,
                .data_path = (char*) "/data",
        };
        assert_se(verity_settings_data_covers(&v, PARTITION_ROOT));

        /* Non-matching designator → does not cover */
        assert_se(!verity_settings_data_covers(&v, PARTITION_USR));

        /* designator < 0 with PARTITION_ROOT → covers */
        v.designator = _PARTITION_DESIGNATOR_INVALID;
        assert_se(verity_settings_data_covers(&v, PARTITION_ROOT));

        /* designator < 0 with PARTITION_USR → does not cover */
        assert_se(!verity_settings_data_covers(&v, PARTITION_USR));
}

TEST(dissected_partition_fstype) {
        /* No decryption → returns fstype */
        DissectedPartition p = {
                .fstype = (char*) "ext4",
                .decrypted_node = NULL,
        };
        assert_se(streq(dissected_partition_fstype(&p), "ext4"));

        /* With decryption → returns decrypted_fstype */
        p.decrypted_node = (char*) "/dev/mapper/luks";
        p.decrypted_fstype = (char*) "ext4";
        assert_se(streq(dissected_partition_fstype(&p), "ext4"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
