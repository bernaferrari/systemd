/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"

static char *test_dir = NULL;

static int setup_test_dir(void) {
        test_dir = strdup("/tmp/test-fileio-extra2-XXXXXX");
        assert_se(test_dir);
        assert_se(mkdtemp(test_dir));
        return 0;
}

static void teardown_test_dir(void) {
        if (test_dir) {
                (void) rm_rf(test_dir, REMOVE_ROOT|REMOVE_PHYSICAL);
                free(test_dir);
                test_dir = NULL;
        }
}

TEST(fopen_mode_to_flags_basic) {
        assert_se(fopen_mode_to_flags("r") == O_RDONLY);
        assert_se(fopen_mode_to_flags("w") == (O_WRONLY | O_CREAT | O_TRUNC));
        assert_se(fopen_mode_to_flags("a") == (O_WRONLY | O_CREAT | O_APPEND));
        assert_se(fopen_mode_to_flags("r+") == O_RDWR);
        assert_se(fopen_mode_to_flags("w+") == (O_RDWR | O_CREAT | O_TRUNC));
}

TEST(read_one_line_file_basic) {
        setup_test_dir();
        assert_se(test_dir);

        const char *path = strjoina(test_dir, "/oneline");
        assert_se(write_string_file(path, "hello world", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC) >= 0);

        _cleanup_free_ char *line = NULL;
        assert_se(read_one_line_file(path, &line) >= 0);
        assert_se(streq(line, "hello world"));

        teardown_test_dir();
}

TEST(read_full_file_basic) {
        setup_test_dir();
        assert_se(test_dir);

        const char *path = strjoina(test_dir, "/fullfile");
        assert_se(write_string_file(path, "line1\nline2\nline3", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC) >= 0);

        _cleanup_free_ char *contents = NULL;
        size_t size = 0;
        assert_se(read_full_file(path, &contents, &size) >= 0);
        assert_se(startswith(contents, "line1\nline2\nline3"));
        assert_se(size >= strlen("line1\nline2\nline3"));

        teardown_test_dir();
}

TEST(write_string_stream_basic) {
        _cleanup_free_ char *buf = NULL;
        size_t sz = 0;
        _cleanup_fclose_ FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        assert_se(write_string_stream(f, "hello", WRITE_STRING_FILE_CREATE) >= 0);
        assert_se(fflush_and_check(f) >= 0);

        assert_se(streq(buf, "hello\n"));
        assert_se(sz == 6);
}

TEST(read_line_basic) {
        _cleanup_fclose_ FILE *f = fmemopen_unlocked((char*)"line1\nline2\n", 12, "r");
        assert_se(f);

        _cleanup_free_ char *line = NULL;
        assert_se(read_line(f, 1024, &line) >= 0);
        assert_se(streq(line, "line1"));

        assert_se(read_line(f, 1024, &line) >= 0);
        assert_se(streq(line, "line2"));

        /* EOF */
        assert_se(read_line(f, 1024, &line) == 0);
}

TEST(safe_fgetc_basic) {
        _cleanup_fclose_ FILE *f = fmemopen_unlocked((char*)"AB", 2, "r");
        assert_se(f);

        char c;
        assert_se(safe_fgetc(f, &c) >= 0);
        assert_se(c == 'A');
        assert_se(safe_fgetc(f, &c) >= 0);
        assert_se(c == 'B');

        /* EOF */
        assert_se(safe_fgetc(f, &c) == 0);
}

TEST(fputs_with_separator_basic) {
        _cleanup_free_ char *buf = NULL;
        size_t sz = 0;
        _cleanup_fclose_ FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        bool space = false;
        assert_se(fputs_with_separator(f, "a", " ", &space) >= 0);
        assert_se(fputs_with_separator(f, "b", " ", &space) >= 0);
        assert_se(fputs_with_separator(f, "c", " ", &space) >= 0);
        assert_se(fflush_and_check(f) >= 0);

        assert_se(streq(buf, "a b c"));
}

TEST(verify_file_at_basic) {
        setup_test_dir();
        assert_se(test_dir);

        const char *path = strjoina(test_dir, "/verify");
        assert_se(write_string_file(path, "exact content", WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC) >= 0);

        assert_se(verify_file_at(AT_FDCWD, path, "exact content", true) == 1);
        assert_se(verify_file_at(AT_FDCWD, path, "wrong content", true) == 0);

        teardown_test_dir();
}

DEFINE_TEST_MAIN(LOG_DEBUG);
