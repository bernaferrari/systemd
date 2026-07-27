/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "tests.h"
#include "linux/btrfs.h"
#include "rust/btrfs_util.h"

static void test_btrfs_validate_subvolume_name_valid(void) {
        assert_se(btrfs_validate_subvolume_name("my-subvol") == rs_btrfs_validate_subvolume_name("my-subvol"));
        assert_se(btrfs_validate_subvolume_name("my-subvol") == 0);

        assert_se(btrfs_validate_subvolume_name("a") == rs_btrfs_validate_subvolume_name("a"));
        assert_se(btrfs_validate_subvolume_name("a") == 0);
}

static void test_btrfs_validate_subvolume_name_null(void) {
        assert_se(rs_btrfs_validate_subvolume_name(NULL) < 0);
        assert_se(rs_btrfs_validate_subvolume_name(NULL) == -EINVAL);
}

static void test_btrfs_validate_subvolume_name_empty(void) {
        assert_se(rs_btrfs_validate_subvolume_name("") < 0);
        assert_se(rs_btrfs_validate_subvolume_name("") == -EINVAL);
}

static void test_btrfs_validate_subvolume_name_with_slash(void) {
        assert_se(rs_btrfs_validate_subvolume_name("sub/vol") < 0);
        assert_se(rs_btrfs_validate_subvolume_name("sub/vol") == -EINVAL);
}

static void test_btrfs_validate_subvolume_name_dot(void) {
        assert_se(rs_btrfs_validate_subvolume_name(".hidden") == 0);
        assert_se(rs_btrfs_validate_subvolume_name(".") < 0);
        assert_se(rs_btrfs_validate_subvolume_name("..") < 0);
}

int main(int argc, char *argv[]) {
        test_btrfs_validate_subvolume_name_valid();
        test_btrfs_validate_subvolume_name_null();
        test_btrfs_validate_subvolume_name_empty();
        test_btrfs_validate_subvolume_name_with_slash();
        test_btrfs_validate_subvolume_name_dot();

        return 0;
}
