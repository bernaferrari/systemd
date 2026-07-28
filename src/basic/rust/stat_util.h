/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.stat-util; authority=src/basic/stat-util.c,src/basic/stat-util.h */
#pragma once

/* The native header owns the platform ABI names and integer typedefs. */
#include "stat-util.h"

/*
 * Rust mirrors of small, pure stat helpers. The pointer and scalar types
 * deliberately use native C definitions instead of Rust-owned prefixes, so
 * mode_t, off_t, nlink_t, struct stat, and struct statx remain target-correct.
 */
bool rs_inode_type_can_chattr(mode_t mode);
const char *rs_inode_type_to_string(mode_t m);
mode_t rs_inode_type_from_string(const char *s);
int rs_inode_compare_func(const struct stat *a, const struct stat *b);
int rs_inode_unmodified_compare_func(const struct stat *a, const struct stat *b);
bool rs_stat_inode_same(const struct stat *a, const struct stat *b);
bool rs_stat_inode_unmodified(const struct stat *a, const struct stat *b);
bool rs_statx_inode_same(const struct statx *a, const struct statx *b);
int rs_statx_mount_same(const struct statx *a, const struct statx *b);
int rs_xstatx_full(int fd,
                   const char *path,
                   int statx_flags,
                   XStatXFlags xstatx_flags,
                   unsigned mandatory_mask,
                   unsigned optional_mask,
                   uint64_t mandatory_attributes,
                   struct statx *ret);
int rs_xstatx(int fd,
              const char *path,
              int statx_flags,
              unsigned mandatory_mask,
              struct statx *ret);
int rs_inode_same_at(int fda, const char *filea, int fdb, const char *fileb, int flags);
int rs_inode_same(const char *filea, const char *fileb, int flags);
int rs_fd_inode_same(int fda, int fdb);
void rs_inode_hash_func(const struct stat *q, struct siphash *state);
void rs_inode_unmodified_hash_func(const struct stat *q, struct siphash *state);

int rs_stat_verify_regular(const struct stat *st);
int rs_statx_verify_regular(const struct statx *stx);
int rs_stat_verify_directory(const struct stat *st);
int rs_statx_verify_directory(const struct statx *stx);
int rs_stat_verify_symlink(const struct stat *st);
int rs_stat_verify_socket(const struct stat *st);
int rs_statx_verify_socket(const struct statx *stx);
int rs_stat_verify_linked(const struct stat *st);
int rs_stat_verify_block(const struct stat *st);
int rs_stat_verify_char(const struct stat *st);
int rs_stat_verify_device_node(const struct stat *st);
int rs_stat_verify_regular_or_block(const struct stat *st);
bool rs_stat_may_be_dev_null(struct stat *st);
bool rs_stat_is_empty(struct stat *st);
bool rs_inode_type_can_hardlink(mode_t m);

int rs_verify_regular_at(int fd, const char *path, bool follow);
int rs_fd_verify_regular(int fd);
int rs_fd_verify_directory(int fd);
int rs_is_dir_at(int fd, const char *path, bool follow);
int rs_is_dir(const char *path, bool follow);
int rs_fd_verify_symlink(int fd);
int rs_is_symlink(const char *path);
int rs_fd_verify_socket(int fd);
int rs_is_socket(const char *path);
int rs_fd_verify_linked(int fd);
int rs_fd_verify_block(int fd);
int rs_is_device_node(const char *path);
int rs_fd_verify_regular_or_block(int fd);

int rs_dir_is_empty_at(int dir_fd, const char *path, bool ignore_hidden_or_backup);
int rs_dir_is_empty(const char *path, bool ignore_hidden_or_backup);
bool rs_null_or_empty(struct stat *st);
int rs_null_or_empty_path_with_root(const char *path, const char *root);
int rs_null_or_empty_path(const char *path);

bool rs_stat_is_set(const struct stat *st);
bool rs_statx_is_set(const struct statx *stx);
usec_t rs_statx_timestamp_load(const struct statx_timestamp *ts);
nsec_t rs_statx_timestamp_load_nsec(const struct statx_timestamp *ts);
bool rs_is_fs_type(const struct statfs *statfs, statfs_f_type_t magic_value);
int rs_xstatfsat(int dir_fd, const char *path, struct statfs *ret);
int rs_is_fs_type_at(int dir_fd, const char *path, statfs_f_type_t magic_value);
int rs_fd_is_read_only_fs(int fd);
int rs_path_is_read_only_fs(const char *path);
bool rs_is_temporary_fs(const struct statfs *statfs);
bool rs_is_network_fs(const struct statfs *statfs);
int rs_fd_is_temporary_fs(int fd);
int rs_fd_is_network_fs(int fd);
int rs_path_is_temporary_fs(const char *path);
int rs_path_is_network_fs(const char *path);
int rs_fd_is_fs_type(int fd, statfs_f_type_t magic_value);
int rs_path_is_fs_type(const char *path, statfs_f_type_t magic_value);
int rs_proc_mounted(void);
bool rs_btrfs_might_be_subvol(const struct stat *st);
int rs_vfs_free_bytes(int fd, uint64_t *ret);
