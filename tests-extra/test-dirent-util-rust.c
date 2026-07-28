/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C dirent_is_file vs Rust rs_dirent_is_file */
/* RUST-CONTRACT: dirent-is-file */
/* RUST-CONTRACT: dirent-is-file-with-suffix */

#include <dirent.h>
#include <string.h>

#include "tests.h"
#include "dirent-util.h"
#include "rust/dirent_util.h"

static struct dirent make_dirent(const char *name, unsigned char d_type) {
        struct dirent de;
        memset(&de, 0, sizeof(de));
        de.d_ino = 1;
        de.d_off = 0;
        de.d_reclen = (unsigned short)sizeof(de);
        de.d_type = d_type;
        strncpy(de.d_name, name, sizeof(de.d_name) - 1);
        return de;
}

/* ── dirent_is_file ─────────────────────────────────────────────────── */

static void test_dirent_is_file_null(void) {
        /* C has ASSERT_PTR(de) — only test Rust with NULL */
        assert_se(!rs_dirent_is_file(NULL));
}

static void test_dirent_is_file_regular(void) {
        struct dirent de = make_dirent("test.txt", DT_REG);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == true);
}

static void test_dirent_is_file_symlink(void) {
        struct dirent de = make_dirent("link.txt", DT_LNK);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == true);
}

static void test_dirent_is_file_unknown(void) {
        struct dirent de = make_dirent("mystery", DT_UNKNOWN);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == true);
}

static void test_dirent_is_file_directory(void) {
        struct dirent de = make_dirent("mydir", DT_DIR);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_fifo(void) {
        struct dirent de = make_dirent("pipe", DT_FIFO);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_socket(void) {
        struct dirent de = make_dirent("sock", DT_SOCK);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_char_device(void) {
        struct dirent de = make_dirent("chardev", DT_CHR);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_block_device(void) {
        struct dirent de = make_dirent("blockdev", DT_BLK);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_hidden(void) {
        struct dirent de = make_dirent(".hidden", DT_REG);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_backup_tilde(void) {
        struct dirent de = make_dirent("file~", DT_REG);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_lost_found(void) {
        struct dirent de = make_dirent("lost+found", DT_REG);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_opaque_bytes(void) {
        char name[] = { 'f', (char) 0xff, '.', 'b', 'a', 'k', 0 };
        struct dirent de = make_dirent(name, DT_REG);
        bool c = dirent_is_file(&de);
        bool r = rs_dirent_is_file(&de);
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_normal_names(void) {
        const char *names[] = { "file.conf", "data.txt", "script.sh", "README" };
        for (int i = 0; i < (int)ELEMENTSOF(names); i++) {
                struct dirent de = make_dirent(names[i], DT_REG);
                bool c = dirent_is_file(&de);
                bool r = rs_dirent_is_file(&de);
                assert_se(c == r);
                assert_se(c == true);
        }
}

/* ── dirent_is_file_with_suffix ─────────────────────────────────────── */

static void test_dirent_is_file_with_suffix_null_de(void) {
        /* C has ASSERT_PTR(de) — only test Rust with NULL */
        assert_se(!rs_dirent_is_file_with_suffix(NULL, ".txt"));
}

static void test_dirent_is_file_with_suffix_null_suffix(void) {
        struct dirent de = make_dirent("test.txt", DT_REG);
        bool c = dirent_is_file_with_suffix(&de, NULL);
        bool r = rs_dirent_is_file_with_suffix(&de, NULL);
        assert_se(c == r);
        assert_se(c == true);
}

static void test_dirent_is_file_with_suffix_matching(void) {
        struct dirent de = make_dirent("test.txt", DT_REG);
        bool c = dirent_is_file_with_suffix(&de, ".txt");
        bool r = rs_dirent_is_file_with_suffix(&de, ".txt");
        assert_se(c == r);
        assert_se(c == true);
}

static void test_dirent_is_file_with_suffix_non_matching(void) {
        struct dirent de = make_dirent("test.txt", DT_REG);
        bool c = dirent_is_file_with_suffix(&de, ".log");
        bool r = rs_dirent_is_file_with_suffix(&de, ".log");
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_with_suffix_hidden(void) {
        struct dirent de = make_dirent(".hidden.txt", DT_REG);
        bool c = dirent_is_file_with_suffix(&de, ".txt");
        bool r = rs_dirent_is_file_with_suffix(&de, ".txt");
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_with_suffix_directory(void) {
        struct dirent de = make_dirent("dir.txt", DT_DIR);
        bool c = dirent_is_file_with_suffix(&de, ".txt");
        bool r = rs_dirent_is_file_with_suffix(&de, ".txt");
        assert_se(c == r);
        assert_se(c == false);
}

static void test_dirent_is_file_with_suffix_empty_suffix(void) {
        struct dirent de = make_dirent("test.txt", DT_REG);
        bool c = dirent_is_file_with_suffix(&de, "");
        bool r = rs_dirent_is_file_with_suffix(&de, "");
        assert_se(c == r);
        /* empty suffix: every string ends with "" */
        assert_se(c == true);
}

static void test_dirent_is_file_with_suffix_symlink(void) {
        struct dirent de = make_dirent("link.conf", DT_LNK);
        bool c = dirent_is_file_with_suffix(&de, ".conf");
        bool r = rs_dirent_is_file_with_suffix(&de, ".conf");
        assert_se(c == r);
        assert_se(c == true);
}

static void test_dirent_is_file_with_suffix_unknown_type(void) {
        struct dirent de = make_dirent("file.dat", DT_UNKNOWN);
        bool c = dirent_is_file_with_suffix(&de, ".dat");
        bool r = rs_dirent_is_file_with_suffix(&de, ".dat");
        assert_se(c == r);
        assert_se(c == true);
}

int main(int argc, char *argv[]) {
        test_dirent_is_file_null();
        test_dirent_is_file_regular();
        test_dirent_is_file_symlink();
        test_dirent_is_file_unknown();
        test_dirent_is_file_directory();
        test_dirent_is_file_fifo();
        test_dirent_is_file_socket();
        test_dirent_is_file_char_device();
        test_dirent_is_file_block_device();
        test_dirent_is_file_hidden();
        test_dirent_is_file_backup_tilde();
        test_dirent_is_file_lost_found();
        test_dirent_is_file_opaque_bytes();
        test_dirent_is_file_normal_names();
        test_dirent_is_file_with_suffix_null_de();
        test_dirent_is_file_with_suffix_null_suffix();
        test_dirent_is_file_with_suffix_matching();
        test_dirent_is_file_with_suffix_non_matching();
        test_dirent_is_file_with_suffix_hidden();
        test_dirent_is_file_with_suffix_directory();
        test_dirent_is_file_with_suffix_empty_suffix();
        test_dirent_is_file_with_suffix_symlink();
        test_dirent_is_file_with_suffix_unknown_type();

        return 0;
}
