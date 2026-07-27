/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C clone_flag_to_namespace_type, dirent_is_file vs Rust */

#include "tests.h"
#include <dirent.h>
#include <sched.h>
#include "namespace-util.h"
#include "dirent-util.h"

/* Rust FFI */
#include "rust/namespace_util.h"
#include "rust/dirent_util.h"

/* ── clone_flag_to_namespace_type ────────────────────────────────────────── */

static void test_clone_flag_to_namespace_type(void) {
        int cr, rr;

        cr = clone_flag_to_namespace_type(CLONE_NEWCGROUP);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWCGROUP);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_CGROUP);

        cr = clone_flag_to_namespace_type(CLONE_NEWIPC);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWIPC);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_IPC);

        cr = clone_flag_to_namespace_type(CLONE_NEWNET);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWNET);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_NET);

        cr = clone_flag_to_namespace_type(CLONE_NEWNS);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWNS);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_MOUNT);

        cr = clone_flag_to_namespace_type(CLONE_NEWPID);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWPID);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_PID);

        cr = clone_flag_to_namespace_type(CLONE_NEWUSER);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWUSER);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_USER);

        cr = clone_flag_to_namespace_type(CLONE_NEWUTS);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWUTS);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_UTS);

        cr = clone_flag_to_namespace_type(CLONE_NEWTIME);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWTIME);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_TIME);

        /* Invalid: no matching flag */
        cr = clone_flag_to_namespace_type(0);
        rr = rs_clone_flag_to_namespace_type(0);
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* 0xDEAD matches NAMESPACE_TIME (bit 7 = CLONE_NEWTIME) */
        cr = clone_flag_to_namespace_type(0xDEAD);
        rr = rs_clone_flag_to_namespace_type(0xDEAD);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_TIME);

        /* Combination: CLONE_NEWNS | extra bits matches NAMESPACE_MOUNT
           (extra bits not in CLONE_* mask are ignored) */
        cr = clone_flag_to_namespace_type(CLONE_NEWNS | 0x1);
        rr = rs_clone_flag_to_namespace_type(CLONE_NEWNS | 0x1);
        assert_se(cr == rr);
        assert_se(cr == NAMESPACE_MOUNT);
}

/* ── dirent_is_file / dirent_is_file_with_suffix ─────────────────────────── */

static void test_dirent_is_file(void) {
        struct dirent de;
        bool cb, rb;

        /* Regular file */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_REG;
        strcpy(de.d_name, "foo.txt");
        cb = dirent_is_file(&de);
        rb = rs_dirent_is_file(&de);
        assert_se(cb == rb);
        assert_se(cb == true);

        /* Symlink */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_LNK;
        strcpy(de.d_name, "link");
        cb = dirent_is_file(&de);
        rb = rs_dirent_is_file(&de);
        assert_se(cb == rb);
        assert_se(cb == true);

        /* Directory */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_DIR;
        strcpy(de.d_name, "dir");
        cb = dirent_is_file(&de);
        rb = rs_dirent_is_file(&de);
        assert_se(cb == rb);
        assert_se(cb == false);

        /* Hidden file (starts with '.') */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_REG;
        strcpy(de.d_name, ".hidden");
        cb = dirent_is_file(&de);
        rb = rs_dirent_is_file(&de);
        assert_se(cb == rb);
        assert_se(cb == false);

        /* Backup file (ends with '~') */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_REG;
        strcpy(de.d_name, "file~");
        cb = dirent_is_file(&de);
        rb = rs_dirent_is_file(&de);
        assert_se(cb == rb);
        assert_se(cb == false);

        /* DT_UNKNOWN should pass (assumed to be file) */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_UNKNOWN;
        strcpy(de.d_name, "mystery");
        cb = dirent_is_file(&de);
        rb = rs_dirent_is_file(&de);
        assert_se(cb == rb);
        assert_se(cb == true);

        /* DT_UNKNOWN with hidden name should fail */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_UNKNOWN;
        strcpy(de.d_name, ".dotfile");
        cb = dirent_is_file(&de);
        rb = rs_dirent_is_file(&de);
        assert_se(cb == rb);
        assert_se(cb == false);
}

static void test_dirent_is_file_with_suffix(void) {
        struct dirent de;
        bool cb, rb;

        /* Regular file with matching suffix */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_REG;
        strcpy(de.d_name, "test.conf");
        cb = dirent_is_file_with_suffix(&de, ".conf");
        rb = rs_dirent_is_file_with_suffix(&de, ".conf");
        assert_se(cb == rb);
        assert_se(cb == true);

        /* Non-matching suffix */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_REG;
        strcpy(de.d_name, "test.service");
        cb = dirent_is_file_with_suffix(&de, ".conf");
        rb = rs_dirent_is_file_with_suffix(&de, ".conf");
        assert_se(cb == rb);
        assert_se(cb == false);

        /* NULL suffix returns true */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_REG;
        strcpy(de.d_name, "anything");
        cb = dirent_is_file_with_suffix(&de, NULL);
        rb = rs_dirent_is_file_with_suffix(&de, NULL);
        assert_se(cb == rb);
        assert_se(cb == true);

        /* Hidden file (starts with '.') should fail regardless of suffix */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_REG;
        strcpy(de.d_name, ".hidden.conf");
        cb = dirent_is_file_with_suffix(&de, ".conf");
        rb = rs_dirent_is_file_with_suffix(&de, ".conf");
        assert_se(cb == rb);
        assert_se(cb == false);

        /* Directory should fail */
        memset(&de, 0, sizeof(de));
        de.d_type = DT_DIR;
        strcpy(de.d_name, "dir.conf");
        cb = dirent_is_file_with_suffix(&de, ".conf");
        rb = rs_dirent_is_file_with_suffix(&de, ".conf");
        assert_se(cb == rb);
        assert_se(cb == false);
}

int main(int argc, char **argv) {
        test_clone_flag_to_namespace_type();
        test_dirent_is_file();
        test_dirent_is_file_with_suffix();
        return 0;
}
