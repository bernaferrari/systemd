/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "blockdev-list.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(block_device_done) {
        BlockDevice d = BLOCK_DEVICE_NULL;
        d.node = strdup("/dev/sda1");
        assert_se(d.node != NULL);

        char **symlinks = strv_new("/dev/disk/by-id/xxx", "/dev/disk/by-path/yyy");
        assert_se(symlinks != NULL);
        d.symlinks = symlinks;
        d.model = strdup("TestModel");
        assert_se(d.model != NULL);
        d.vendor = strdup("TestVendor");
        assert_se(d.vendor != NULL);
        d.subsystem = strdup("nvme");
        assert_se(d.subsystem != NULL);

        block_device_done(&d);

        assert_se(d.node == NULL);
        assert_se(d.symlinks == NULL);
        assert_se(d.model == NULL);
        assert_se(d.vendor == NULL);
        assert_se(d.subsystem == NULL);
}

TEST(block_device_done_null_fields) {
        /* All fields NULL → should not crash */
        BlockDevice d = BLOCK_DEVICE_NULL;
        block_device_done(&d);

        assert_se(d.node == NULL);
        assert_se(d.symlinks == NULL);
        assert_se(d.model == NULL);
        assert_se(d.vendor == NULL);
        assert_se(d.subsystem == NULL);
}

TEST(block_device_array_free) {
        BlockDevice *d = new(BlockDevice, 3);
        assert_se(d != NULL);

        for (int i = 0; i < 3; i++) {
                d[i] = BLOCK_DEVICE_NULL;
                d[i].node = strjoin("/dev/sd", (char[2]){ 'a' + i, '\0' });
                assert_se(d[i].node != NULL);
        }

        block_device_array_free(d, 3);
        /* d is freed, should not be accessed */
}

TEST(block_device_array_free_empty) {
        /* Zero-size array */
        block_device_array_free(NULL, 0);
}

TEST(block_device_null_macro) {
        BlockDevice d = BLOCK_DEVICE_NULL;
        assert_se(d.node == NULL);
        assert_se(d.symlinks == NULL);
        assert_se(d.model == NULL);
        assert_se(d.vendor == NULL);
        assert_se(d.subsystem == NULL);
        assert_se(d.diskseq == UINT64_MAX);
        assert_se(d.size == UINT64_MAX);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
