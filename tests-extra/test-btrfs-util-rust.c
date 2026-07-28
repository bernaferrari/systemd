/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "tests.h"
#include "btrfs-util.h"
#include "linux/btrfs.h"
#include "rust/btrfs_util.h"

/* RUST-CONTRACT: btrfs-validate-subvolume-name */
static void test_btrfs_validate_subvolume_name_valid(void) {
        assert_se(btrfs_validate_subvolume_name("my-subvol") == rs_btrfs_validate_subvolume_name("my-subvol"));
        assert_se(btrfs_validate_subvolume_name("my-subvol") == 0);

        assert_se(btrfs_validate_subvolume_name("a") == rs_btrfs_validate_subvolume_name("a"));
        assert_se(btrfs_validate_subvolume_name("a") == 0);
}

static void test_btrfs_validate_subvolume_name_null(void) {
        assert_se(btrfs_validate_subvolume_name(NULL) == rs_btrfs_validate_subvolume_name(NULL));
        assert_se(btrfs_validate_subvolume_name(NULL) == -EINVAL);
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

static void test_btrfs_validate_subvolume_name_byte_and_length_boundaries(void) {
        char non_utf8[] = { (char) 0xff, 0 };
        char name_max[256], name_too_long[257];

        memset(name_max, 'a', sizeof(name_max) - 1);
        name_max[sizeof(name_max) - 1] = 0;
        memset(name_too_long, 'a', sizeof(name_too_long) - 1);
        name_too_long[sizeof(name_too_long) - 1] = 0;

        assert_se(btrfs_validate_subvolume_name(non_utf8) == rs_btrfs_validate_subvolume_name(non_utf8));
        assert_se(btrfs_validate_subvolume_name(non_utf8) == 0);
        assert_se(btrfs_validate_subvolume_name(name_max) == rs_btrfs_validate_subvolume_name(name_max));
        assert_se(btrfs_validate_subvolume_name(name_max) == 0);
        assert_se(btrfs_validate_subvolume_name(name_too_long) == rs_btrfs_validate_subvolume_name(name_too_long));
        assert_se(btrfs_validate_subvolume_name(name_too_long) == -EINVAL);
}

int main(int argc, char *argv[]) {
        test_btrfs_validate_subvolume_name_valid();
        test_btrfs_validate_subvolume_name_null();
        test_btrfs_validate_subvolume_name_empty();
        test_btrfs_validate_subvolume_name_with_slash();
        test_btrfs_validate_subvolume_name_dot();
        test_btrfs_validate_subvolume_name_byte_and_length_boundaries();

        return 0;
}
