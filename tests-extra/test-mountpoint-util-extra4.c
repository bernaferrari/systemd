/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mountpoint-util.h"
#include "string-util.h"
#include "tests.h"

TEST(fstype_is_api_vfs_basic) {
        assert_se(fstype_is_api_vfs("proc"));
        assert_se(fstype_is_api_vfs("sysfs"));
        assert_se(fstype_is_api_vfs("devtmpfs"));
        assert_se(fstype_is_api_vfs("tmpfs"));
        assert_se(fstype_is_api_vfs("debugfs"));
        assert_se(fstype_is_api_vfs("cgroup"));
        assert_se(fstype_is_api_vfs("cgroup2"));
        assert_se(!fstype_is_api_vfs("ext4"));
        assert_se(!fstype_is_api_vfs("xfs"));
        assert_se(!fstype_is_api_vfs("btrfs"));
}

TEST(fstype_is_blockdev_backed_basic) {
        assert_se(fstype_is_blockdev_backed("ext4"));
        assert_se(fstype_is_blockdev_backed("xfs"));
        assert_se(fstype_is_blockdev_backed("btrfs"));
        assert_se(!fstype_is_blockdev_backed("tmpfs"));
        assert_se(!fstype_is_blockdev_backed("proc"));
        assert_se(!fstype_is_blockdev_backed("nfs"));
}

TEST(fstype_is_ro_basic) {
        assert_se(fstype_is_ro("squashfs"));
        assert_se(fstype_is_ro("iso9660"));
        assert_se(!fstype_is_ro("ext4"));
        assert_se(!fstype_is_ro("tmpfs"));
}

TEST(fstype_can_discard_basic) {
        assert_se(fstype_can_discard("ext4"));
        assert_se(!fstype_can_discard("tmpfs"));
        assert_se(!fstype_can_discard("proc"));
}

TEST(fstype_can_uid_gid_basic) {
        assert_se(fstype_can_uid_gid("vfat"));
        assert_se(fstype_can_uid_gid("ntfs"));
        assert_se(fstype_can_uid_gid("exfat"));
        assert_se(!fstype_can_uid_gid("ext4"));
        assert_se(!fstype_can_uid_gid("proc"));
        assert_se(!fstype_can_uid_gid("sysfs"));
}

TEST(fstype_needs_quota_basic) {
        assert_se(fstype_needs_quota("ext4"));
        assert_se(!fstype_needs_quota("tmpfs"));
        assert_se(!fstype_needs_quota("proc"));
}

TEST(path_below_api_vfs_basic) {
        assert_se(path_below_api_vfs("/proc"));
        assert_se(path_below_api_vfs("/sys"));
        assert_se(path_below_api_vfs("/dev"));
        assert_se(!path_below_api_vfs("/home"));
        assert_se(!path_below_api_vfs("/usr"));
        assert_se(!path_below_api_vfs("/tmp"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
