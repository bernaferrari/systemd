/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C resize-fs functions vs Rust */
/* RUST-CONTRACT: resize-fs-minimum-size-policy */
/* RUST-CONTRACT: resize-fs-minimum-size-by-name */
/* RUST-CONTRACT: resize-fs-minimum-size-by-magic */
/* RUST-CONTRACT: resize-fs-online-shrink-grow-policy */

#include <limits.h>

#include "tests.h"
#include "resize-fs.h"

/* Rust FFI */
#include "rust/resize_fs_util.h"

/* ── minimal_size_by_fs_name ──────────────────────────────────────────── */

TEST(minimal_size_by_fs_name_ext4) {
        assert_se(minimal_size_by_fs_name("ext4") == rs_minimal_size_by_fs_name("ext4"));
        assert_se(minimal_size_by_fs_name("ext4") == 32U * U64_MB);
}

TEST(minimal_size_by_fs_name_xfs) {
        assert_se(minimal_size_by_fs_name("xfs") == rs_minimal_size_by_fs_name("xfs"));
        assert_se(minimal_size_by_fs_name("xfs") == 300U * U64_MB);
}

TEST(minimal_size_by_fs_name_btrfs) {
        assert_se(minimal_size_by_fs_name("btrfs") == rs_minimal_size_by_fs_name("btrfs"));
        assert_se(minimal_size_by_fs_name("btrfs") == 256U * U64_MB);
}

TEST(minimal_size_by_fs_name_unknown) {
        assert_se(minimal_size_by_fs_name("tmpfs") == rs_minimal_size_by_fs_name("tmpfs"));
        assert_se(minimal_size_by_fs_name("tmpfs") == UINT64_MAX);
}

TEST(minimal_size_by_fs_name_null) {
        assert_se(minimal_size_by_fs_name(NULL) == rs_minimal_size_by_fs_name(NULL));
        assert_se(minimal_size_by_fs_name(NULL) == UINT64_MAX);
}

TEST(minimal_size_by_fs_name_empty) {
        assert_se(minimal_size_by_fs_name("") == rs_minimal_size_by_fs_name(""));
        assert_se(minimal_size_by_fs_name("") == UINT64_MAX);
}

TEST(minimal_size_by_fs_name_non_utf8) {
        static const char name[] = { 'e', 'x', 't', '4', '\xff', 0 };

        assert_se(minimal_size_by_fs_name(name) == rs_minimal_size_by_fs_name(name));
        assert_se(minimal_size_by_fs_name(name) == UINT64_MAX);
}

TEST(minimal_size_by_fs_name_stops_at_nul) {
        static const char name[] = { 'e', 'x', 't', '4', 0, 'x', 'f', 's', 0 };

        assert_se(minimal_size_by_fs_name(name) == rs_minimal_size_by_fs_name(name));
        assert_se(minimal_size_by_fs_name(name) == 32U * U64_MB);
}

/* ── minimal_size_by_fs_magic ──────────────────────────────────────────── */

TEST(minimal_size_by_fs_magic_ext4) {
        assert_se(minimal_size_by_fs_magic(0xEF53) == rs_minimal_size_by_fs_magic(0xEF53));
        assert_se(minimal_size_by_fs_magic(0xEF53) == 32U * U64_MB);
}

TEST(minimal_size_by_fs_magic_xfs) {
        assert_se(minimal_size_by_fs_magic(0x58465342) == rs_minimal_size_by_fs_magic(0x58465342));
        assert_se(minimal_size_by_fs_magic(0x58465342) == 300U * U64_MB);
}

TEST(minimal_size_by_fs_magic_btrfs) {
        assert_se(minimal_size_by_fs_magic(0x9123683E) == rs_minimal_size_by_fs_magic(0x9123683E));
        assert_se(minimal_size_by_fs_magic(0x9123683E) == 256U * U64_MB);
}

TEST(minimal_size_by_fs_magic_unknown) {
        assert_se(minimal_size_by_fs_magic(0) == rs_minimal_size_by_fs_magic(0));
        assert_se(minimal_size_by_fs_magic(0) == UINT64_MAX);
}

TEST(minimal_size_by_fs_magic_tmpfs) {
        assert_se(minimal_size_by_fs_magic(0x01021994) == rs_minimal_size_by_fs_magic(0x01021994));
        assert_se(minimal_size_by_fs_magic(0x01021994) == UINT64_MAX);
}

TEST(minimal_size_by_fs_magic_negative) {
        statfs_f_type_t magic = -1;

        assert_se(minimal_size_by_fs_magic(magic) == rs_minimal_size_by_fs_magic(magic));
        assert_se(minimal_size_by_fs_magic(magic) == UINT64_MAX);
}

/* ── fs_can_online_shrink_and_grow ─────────────────────────────────────── */

TEST(fs_can_online_shrink_and_grow_btrfs) {
        assert_se(fs_can_online_shrink_and_grow(0x9123683E) == rs_fs_can_online_shrink_and_grow(0x9123683E));
        assert_se(fs_can_online_shrink_and_grow(0x9123683E) == true);
}

TEST(fs_can_online_shrink_and_grow_ext4) {
        assert_se(fs_can_online_shrink_and_grow(0xEF53) == rs_fs_can_online_shrink_and_grow(0xEF53));
        assert_se(fs_can_online_shrink_and_grow(0xEF53) == false);
}

TEST(fs_can_online_shrink_and_grow_xfs) {
        assert_se(fs_can_online_shrink_and_grow(0x58465342) == rs_fs_can_online_shrink_and_grow(0x58465342));
        assert_se(fs_can_online_shrink_and_grow(0x58465342) == false);
}

TEST(fs_can_online_shrink_and_grow_zero) {
        assert_se(fs_can_online_shrink_and_grow(0) == rs_fs_can_online_shrink_and_grow(0));
        assert_se(fs_can_online_shrink_and_grow(0) == false);
}

TEST(fs_can_online_shrink_and_grow_negative) {
        statfs_f_type_t magic = LONG_MIN;

        assert_se(fs_can_online_shrink_and_grow(magic) == rs_fs_can_online_shrink_and_grow(magic));
        assert_se(fs_can_online_shrink_and_grow(magic) == false);
}

DEFINE_TEST_MAIN(LOG_INFO);
