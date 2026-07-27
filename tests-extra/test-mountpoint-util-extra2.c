/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mountpoint-util.h"
#include "string-util.h"
#include "tests.h"

TEST(fstype_is_api_vfs) {
        assert_se(fstype_is_api_vfs("proc"));
        assert_se(fstype_is_api_vfs("sysfs"));
        assert_se(fstype_is_api_vfs("devtmpfs"));
        assert_se(fstype_is_api_vfs("tmpfs"));
        assert_se(fstype_is_api_vfs("debugfs"));
        assert_se(fstype_is_api_vfs("securityfs"));
        assert_se(fstype_is_api_vfs("cgroup"));
        assert_se(fstype_is_api_vfs("cgroup2"));

        assert_se(!fstype_is_api_vfs("ext4"));
        assert_se(!fstype_is_api_vfs("xfs"));
        assert_se(!fstype_is_api_vfs("nfs"));
}

TEST(fstype_is_blockdev_backed) {
        assert_se(fstype_is_blockdev_backed("ext4"));
        assert_se(fstype_is_blockdev_backed("xfs"));
        assert_se(fstype_is_blockdev_backed("btrfs"));
        assert_se(fstype_is_blockdev_backed("vfat"));

        assert_se(!fstype_is_blockdev_backed("tmpfs"));
        assert_se(!fstype_is_blockdev_backed("proc"));
        assert_se(!fstype_is_blockdev_backed("sysfs"));
        assert_se(!fstype_is_blockdev_backed("nfs"));
}

TEST(fstype_can_uid_gid) {
        /* Filesystems that support uid= / gid= mount options */
        assert_se(fstype_can_uid_gid("vfat"));
        assert_se(fstype_can_uid_gid("fat"));
        assert_se(fstype_can_uid_gid("msdos"));
        assert_se(fstype_can_uid_gid("exfat"));
        assert_se(fstype_can_uid_gid("ntfs"));
        assert_se(fstype_can_uid_gid("iso9660"));

        /* ext4 has native Unix permissions, no uid=/gid= option */
        assert_se(!fstype_can_uid_gid("ext4"));
        assert_se(!fstype_can_uid_gid("xfs"));
        assert_se(!fstype_can_uid_gid("tmpfs"));
}

TEST(fstype_can_discard) {
        assert_se(fstype_can_discard("ext4"));
        assert_se(fstype_can_discard("f2fs"));

        assert_se(!fstype_can_discard("tmpfs"));
}

TEST(fstype_needs_quota) {
        assert_se(fstype_needs_quota("ext2"));
        assert_se(fstype_needs_quota("ext3"));
        assert_se(fstype_needs_quota("ext4"));
        assert_se(fstype_needs_quota("reiserfs"));
        assert_se(fstype_needs_quota("jfs"));
        assert_se(fstype_needs_quota("f2fs"));

        /* xfs has built-in quota support */
        assert_se(!fstype_needs_quota("xfs"));
        assert_se(!fstype_needs_quota("btrfs"));
        assert_se(!fstype_needs_quota("tmpfs"));
        assert_se(!fstype_needs_quota("vfat"));
}

TEST(fstype_is_ro) {
        assert_se(fstype_is_ro("iso9660"));
        assert_se(fstype_is_ro("squashfs"));
        assert_se(fstype_is_ro("cramfs"));
        assert_se(fstype_is_ro("erofs"));

        assert_se(!fstype_is_ro("ext4"));
        assert_se(!fstype_is_ro("tmpfs"));
        assert_se(!fstype_is_ro("udf"));
}

TEST(fstype_norecovery_option) {
        const char *opt;

        /* ext4 has norecovery */
        opt = fstype_norecovery_option("ext4");
        assert_se(opt && streq(opt, "norecovery"));

        /* xfs has norecovery */
        opt = fstype_norecovery_option("xfs");
        assert_se(opt && streq(opt, "norecovery"));

        /* tmpfs doesn't have norecovery */
        opt = fstype_norecovery_option("tmpfs");
        assert_se(opt == NULL);

        /* vfat doesn't have norecovery */
        opt = fstype_norecovery_option("vfat");
        assert_se(opt == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
