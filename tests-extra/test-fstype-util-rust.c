/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C mountpoint-util.c fstype functions vs Rust */
/* RUST-CONTRACT: fstype-predicates */
/* RUST-CONTRACT: path-below-api-vfs */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "mountpoint-util.h"

/* Rust FFI */
#include "rust/fstype_util.h"

/* -- fstype_is_ro ---------------------------------------------------------- */

static void test_fstype_is_ro(void) {
        assert_se(fstype_is_ro("ext4") == rs_fstype_is_ro("ext4"));
        assert_se(fstype_is_ro("ext4") == false);

        assert_se(fstype_is_ro("iso9660") == rs_fstype_is_ro("iso9660"));
        assert_se(fstype_is_ro("iso9660") == true);

        assert_se(fstype_is_ro("squashfs") == rs_fstype_is_ro("squashfs"));
        assert_se(fstype_is_ro("squashfs") == true);

        assert_se(fstype_is_ro("erofs") == rs_fstype_is_ro("erofs"));
        assert_se(fstype_is_ro("erofs") == true);

        assert_se(fstype_is_ro("cramfs") == rs_fstype_is_ro("cramfs"));
        assert_se(fstype_is_ro("cramfs") == true);

        assert_se(fstype_is_ro("DM_verity_hash") == rs_fstype_is_ro("DM_verity_hash"));
        assert_se(fstype_is_ro("DM_verity_hash") == true);

        assert_se(fstype_is_ro("xfs") == rs_fstype_is_ro("xfs"));
        assert_se(fstype_is_ro("xfs") == false);

        assert_se(fstype_is_ro("btrfs") == rs_fstype_is_ro("btrfs"));
        assert_se(fstype_is_ro("btrfs") == false);

        assert_se(fstype_is_ro("tmpfs") == rs_fstype_is_ro("tmpfs"));
        assert_se(fstype_is_ro("tmpfs") == false);

        /* NULL */
        assert_se(rs_fstype_is_ro(NULL) == false);
}

/* -- fstype_needs_quota ---------------------------------------------------- */

static void test_fstype_needs_quota(void) {
        assert_se(fstype_needs_quota("ext4") == rs_fstype_needs_quota("ext4"));
        assert_se(fstype_needs_quota("ext4") == true);

        assert_se(fstype_needs_quota("ext2") == rs_fstype_needs_quota("ext2"));
        assert_se(fstype_needs_quota("ext2") == true);

        assert_se(fstype_needs_quota("ext3") == rs_fstype_needs_quota("ext3"));
        assert_se(fstype_needs_quota("ext3") == true);

        assert_se(fstype_needs_quota("reiserfs") == rs_fstype_needs_quota("reiserfs"));
        assert_se(fstype_needs_quota("reiserfs") == true);

        assert_se(fstype_needs_quota("jfs") == rs_fstype_needs_quota("jfs"));
        assert_se(fstype_needs_quota("jfs") == true);

        assert_se(fstype_needs_quota("f2fs") == rs_fstype_needs_quota("f2fs"));
        assert_se(fstype_needs_quota("f2fs") == true);

        assert_se(fstype_needs_quota("xfs") == rs_fstype_needs_quota("xfs"));
        assert_se(fstype_needs_quota("xfs") == false);

        assert_se(fstype_needs_quota("btrfs") == rs_fstype_needs_quota("btrfs"));
        assert_se(fstype_needs_quota("btrfs") == false);

        assert_se(fstype_needs_quota("tmpfs") == rs_fstype_needs_quota("tmpfs"));
        assert_se(fstype_needs_quota("tmpfs") == false);

        assert_se(fstype_needs_quota("") == rs_fstype_needs_quota(""));
        assert_se(fstype_needs_quota("") == false);

        /* NULL */
        assert_se(rs_fstype_needs_quota(NULL) == false);
}

/* -- fstype_can_uid_gid ---------------------------------------------------- */

static void test_fstype_can_uid_gid(void) {
        assert_se(fstype_can_uid_gid("vfat") == rs_fstype_can_uid_gid("vfat"));
        assert_se(fstype_can_uid_gid("vfat") == true);

        assert_se(fstype_can_uid_gid("ntfs") == rs_fstype_can_uid_gid("ntfs"));
        assert_se(fstype_can_uid_gid("ntfs") == true);

        assert_se(fstype_can_uid_gid("exfat") == rs_fstype_can_uid_gid("exfat"));
        assert_se(fstype_can_uid_gid("exfat") == true);

        assert_se(fstype_can_uid_gid("fat") == rs_fstype_can_uid_gid("fat"));
        assert_se(fstype_can_uid_gid("fat") == true);

        assert_se(fstype_can_uid_gid("msdos") == rs_fstype_can_uid_gid("msdos"));
        assert_se(fstype_can_uid_gid("msdos") == true);

        assert_se(fstype_can_uid_gid("iso9660") == rs_fstype_can_uid_gid("iso9660"));
        assert_se(fstype_can_uid_gid("iso9660") == true);

        assert_se(fstype_can_uid_gid("ext4") == rs_fstype_can_uid_gid("ext4"));
        assert_se(fstype_can_uid_gid("ext4") == false);

        assert_se(fstype_can_uid_gid("xfs") == rs_fstype_can_uid_gid("xfs"));
        assert_se(fstype_can_uid_gid("xfs") == false);

        assert_se(fstype_can_uid_gid("btrfs") == rs_fstype_can_uid_gid("btrfs"));
        assert_se(fstype_can_uid_gid("btrfs") == false);

        assert_se(fstype_can_uid_gid("") == rs_fstype_can_uid_gid(""));
        assert_se(fstype_can_uid_gid("") == false);

        /* NULL */
        assert_se(rs_fstype_can_uid_gid(NULL) == false);
}

/* -- path_below_api_vfs ---------------------------------------------------- */

static void test_path_below_api_vfs(void) {
        assert_se(path_below_api_vfs("/dev") == rs_path_below_api_vfs("/dev"));
        assert_se(path_below_api_vfs("/dev") == true);

        assert_se(path_below_api_vfs("/dev/null") == rs_path_below_api_vfs("/dev/null"));
        assert_se(path_below_api_vfs("/dev/null") == true);

        assert_se(path_below_api_vfs("/sys") == rs_path_below_api_vfs("/sys"));
        assert_se(path_below_api_vfs("/sys") == true);

        assert_se(path_below_api_vfs("/sys/fs/cgroup") == rs_path_below_api_vfs("/sys/fs/cgroup"));
        assert_se(path_below_api_vfs("/sys/fs/cgroup") == true);

        assert_se(path_below_api_vfs("/proc") == rs_path_below_api_vfs("/proc"));
        assert_se(path_below_api_vfs("/proc") == true);

        assert_se(path_below_api_vfs("/proc/1") == rs_path_below_api_vfs("/proc/1"));
        assert_se(path_below_api_vfs("/proc/1") == true);

        assert_se(path_below_api_vfs("/usr") == rs_path_below_api_vfs("/usr"));
        assert_se(path_below_api_vfs("/usr") == false);

        assert_se(path_below_api_vfs("/etc") == rs_path_below_api_vfs("/etc"));
        assert_se(path_below_api_vfs("/etc") == false);

        assert_se(path_below_api_vfs("/home") == rs_path_below_api_vfs("/home"));
        assert_se(path_below_api_vfs("/home") == false);

        assert_se(path_below_api_vfs("") == rs_path_below_api_vfs(""));
        assert_se(path_below_api_vfs("") == false);

        assert_se(path_below_api_vfs("/devicetree") == rs_path_below_api_vfs("/devicetree"));
        assert_se(path_below_api_vfs("/devicetree") == false);

        /* NULL */
        assert_se(rs_path_below_api_vfs(NULL) == false);
}

/* -- fstype_is_network ------------------------------------------------------ */

static void test_fstype_is_network(void) {
        /* Network types */
        assert_se(fstype_is_network("nfs") == rs_fstype_is_network("nfs"));
        assert_se(fstype_is_network("nfs") == true);

        assert_se(fstype_is_network("nfs4") == rs_fstype_is_network("nfs4"));
        assert_se(fstype_is_network("nfs4") == true);

        assert_se(fstype_is_network("cifs") == rs_fstype_is_network("cifs"));
        assert_se(fstype_is_network("cifs") == true);

        assert_se(fstype_is_network("smb3") == rs_fstype_is_network("smb3"));
        assert_se(fstype_is_network("smb3") == true);

        assert_se(fstype_is_network("ceph") == rs_fstype_is_network("ceph"));
        assert_se(fstype_is_network("ceph") == true);

        /* Additional not-in-set types */
        assert_se(fstype_is_network("davfs") == rs_fstype_is_network("davfs"));
        assert_se(fstype_is_network("davfs") == true);

        assert_se(fstype_is_network("glusterfs") == rs_fstype_is_network("glusterfs"));
        assert_se(fstype_is_network("glusterfs") == true);

        assert_se(fstype_is_network("lustre") == rs_fstype_is_network("lustre"));
        assert_se(fstype_is_network("lustre") == true);

        assert_se(fstype_is_network("sshfs") == rs_fstype_is_network("sshfs"));
        assert_se(fstype_is_network("sshfs") == true);

        /* fuse.sshfs should strip fuse. prefix */
        assert_se(fstype_is_network("fuse.sshfs") == rs_fstype_is_network("fuse.sshfs"));
        assert_se(fstype_is_network("fuse.sshfs") == true);

        assert_se(fstype_is_network("fuse.nfs") == rs_fstype_is_network("fuse.nfs"));
        assert_se(fstype_is_network("fuse.nfs") == true);

        /* Non-network types */
        assert_se(fstype_is_network("ext4") == rs_fstype_is_network("ext4"));
        assert_se(fstype_is_network("ext4") == false);

        assert_se(fstype_is_network("xfs") == rs_fstype_is_network("xfs"));
        assert_se(fstype_is_network("xfs") == false);

        assert_se(fstype_is_network("tmpfs") == rs_fstype_is_network("tmpfs"));
        assert_se(fstype_is_network("tmpfs") == false);

        assert_se(fstype_is_network("") == rs_fstype_is_network(""));
        assert_se(fstype_is_network("") == false);

        /* NULL */
        assert_se(rs_fstype_is_network(NULL) == false);
}

/* -- fstype_is_api_vfs ------------------------------------------------------ */

static void test_fstype_is_api_vfs(void) {
        /* API VFS types */
        assert_se(fstype_is_api_vfs("proc") == rs_fstype_is_api_vfs("proc"));
        assert_se(fstype_is_api_vfs("proc") == true);

        assert_se(fstype_is_api_vfs("sysfs") == rs_fstype_is_api_vfs("sysfs"));
        assert_se(fstype_is_api_vfs("sysfs") == true);

        assert_se(fstype_is_api_vfs("devpts") == rs_fstype_is_api_vfs("devpts"));
        assert_se(fstype_is_api_vfs("devpts") == true);

        assert_se(fstype_is_api_vfs("tmpfs") == rs_fstype_is_api_vfs("tmpfs"));
        assert_se(fstype_is_api_vfs("tmpfs") == true);

        assert_se(fstype_is_api_vfs("cgroup") == rs_fstype_is_api_vfs("cgroup"));
        assert_se(fstype_is_api_vfs("cgroup") == true);

        assert_se(fstype_is_api_vfs("cgroup2") == rs_fstype_is_api_vfs("cgroup2"));
        assert_se(fstype_is_api_vfs("cgroup2") == true);

        assert_se(fstype_is_api_vfs("debugfs") == rs_fstype_is_api_vfs("debugfs"));
        assert_se(fstype_is_api_vfs("debugfs") == true);

        assert_se(fstype_is_api_vfs("mqueue") == rs_fstype_is_api_vfs("mqueue"));
        assert_se(fstype_is_api_vfs("mqueue") == true);

        assert_se(fstype_is_api_vfs("securityfs") == rs_fstype_is_api_vfs("securityfs"));
        assert_se(fstype_is_api_vfs("securityfs") == true);

        assert_se(fstype_is_api_vfs("configfs") == rs_fstype_is_api_vfs("configfs"));
        assert_se(fstype_is_api_vfs("configfs") == true);

        assert_se(fstype_is_api_vfs("hugetlbfs") == rs_fstype_is_api_vfs("hugetlbfs"));
        assert_se(fstype_is_api_vfs("hugetlbfs") == true);

        assert_se(fstype_is_api_vfs("ramfs") == rs_fstype_is_api_vfs("ramfs"));
        assert_se(fstype_is_api_vfs("ramfs") == true);

        /* Additional not-in-set types */
        assert_se(fstype_is_api_vfs("autofs") == rs_fstype_is_api_vfs("autofs"));
        assert_se(fstype_is_api_vfs("autofs") == true);

        assert_se(fstype_is_api_vfs("cpuset") == rs_fstype_is_api_vfs("cpuset"));
        assert_se(fstype_is_api_vfs("cpuset") == true);

        /* Non-API-VFS types */
        assert_se(fstype_is_api_vfs("ext4") == rs_fstype_is_api_vfs("ext4"));
        assert_se(fstype_is_api_vfs("ext4") == false);

        assert_se(fstype_is_api_vfs("xfs") == rs_fstype_is_api_vfs("xfs"));
        assert_se(fstype_is_api_vfs("xfs") == false);

        assert_se(fstype_is_api_vfs("nfs") == rs_fstype_is_api_vfs("nfs"));
        assert_se(fstype_is_api_vfs("nfs") == false);

        assert_se(fstype_is_api_vfs("") == rs_fstype_is_api_vfs(""));
        assert_se(fstype_is_api_vfs("") == false);

        /* NULL */
        assert_se(rs_fstype_is_api_vfs(NULL) == false);
}

/* -- fstype_is_blockdev_backed ---------------------------------------------- */

static void test_fstype_is_blockdev_backed(void) {
        /* Block-dev-backed types */
        assert_se(fstype_is_blockdev_backed("ext4") == rs_fstype_is_blockdev_backed("ext4"));
        assert_se(fstype_is_blockdev_backed("ext4") == true);

        assert_se(fstype_is_blockdev_backed("xfs") == rs_fstype_is_blockdev_backed("xfs"));
        assert_se(fstype_is_blockdev_backed("xfs") == true);

        assert_se(fstype_is_blockdev_backed("btrfs") == rs_fstype_is_blockdev_backed("btrfs"));
        assert_se(fstype_is_blockdev_backed("btrfs") == true);

        assert_se(fstype_is_blockdev_backed("vfat") == rs_fstype_is_blockdev_backed("vfat"));
        assert_se(fstype_is_blockdev_backed("vfat") == true);

        /* 9p and overlay are NOT block-dev-backed */
        assert_se(fstype_is_blockdev_backed("9p") == rs_fstype_is_blockdev_backed("9p"));
        assert_se(fstype_is_blockdev_backed("9p") == false);

        assert_se(fstype_is_blockdev_backed("overlay") == rs_fstype_is_blockdev_backed("overlay"));
        assert_se(fstype_is_blockdev_backed("overlay") == false);

        /* Network filesystems are NOT block-dev-backed */
        assert_se(fstype_is_blockdev_backed("nfs") == rs_fstype_is_blockdev_backed("nfs"));
        assert_se(fstype_is_blockdev_backed("nfs") == false);

        assert_se(fstype_is_blockdev_backed("cifs") == rs_fstype_is_blockdev_backed("cifs"));
        assert_se(fstype_is_blockdev_backed("cifs") == false);

        /* API VFS filesystems are NOT block-dev-backed */
        assert_se(fstype_is_blockdev_backed("tmpfs") == rs_fstype_is_blockdev_backed("tmpfs"));
        assert_se(fstype_is_blockdev_backed("tmpfs") == false);

        assert_se(fstype_is_blockdev_backed("proc") == rs_fstype_is_blockdev_backed("proc"));
        assert_se(fstype_is_blockdev_backed("proc") == false);

        assert_se(fstype_is_blockdev_backed("sysfs") == rs_fstype_is_blockdev_backed("sysfs"));
        assert_se(fstype_is_blockdev_backed("sysfs") == false);

        /* fuse.blkfs: fuse. stripped, "blkfs" is not network/api => blockdev_backed */
        assert_se(fstype_is_blockdev_backed("fuse.blkfs") == rs_fstype_is_blockdev_backed("fuse.blkfs"));
        assert_se(fstype_is_blockdev_backed("fuse.blkfs") == true);

        /* fuse.sshfs: fuse. stripped, "sshfs" IS network => not blockdev_backed */
        assert_se(fstype_is_blockdev_backed("fuse.sshfs") == rs_fstype_is_blockdev_backed("fuse.sshfs"));
        assert_se(fstype_is_blockdev_backed("fuse.sshfs") == false);

        assert_se(fstype_is_blockdev_backed("") == rs_fstype_is_blockdev_backed(""));
        assert_se(fstype_is_blockdev_backed("") == true);

        /* NULL */
        assert_se(rs_fstype_is_blockdev_backed(NULL) == false);
}

/* The C predicates compare raw C-string bytes; UTF-8 is not a precondition. */
static void test_non_utf8_inputs(void) {
        static const char invalid_utf8[] = "\xff";
        static const char invalid_utf8_path[] = "/\xff";

        assert_se(fstype_is_ro(invalid_utf8) == rs_fstype_is_ro(invalid_utf8));
        assert_se(fstype_needs_quota(invalid_utf8) == rs_fstype_needs_quota(invalid_utf8));
        assert_se(fstype_can_uid_gid(invalid_utf8) == rs_fstype_can_uid_gid(invalid_utf8));
        assert_se(path_below_api_vfs(invalid_utf8_path) == rs_path_below_api_vfs(invalid_utf8_path));
        assert_se(fstype_is_network(invalid_utf8) == rs_fstype_is_network(invalid_utf8));
        assert_se(fstype_is_api_vfs(invalid_utf8) == rs_fstype_is_api_vfs(invalid_utf8));
        assert_se(fstype_is_blockdev_backed(invalid_utf8) == rs_fstype_is_blockdev_backed(invalid_utf8));
}

int main(int argc, char **argv) {
        test_fstype_is_ro();
        test_fstype_needs_quota();
        test_fstype_can_uid_gid();
        test_path_below_api_vfs();
        test_fstype_is_network();
        test_fstype_is_api_vfs();
        test_fstype_is_blockdev_backed();
        test_non_utf8_inputs();
        return 0;
}
