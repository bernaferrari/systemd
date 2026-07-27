/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "parse-util.h"
#include "tests.h"

TEST(parse_boolean) {
        int b;
        b = parse_boolean("1");
        ASSERT_EQ(b, true);
        b = parse_boolean("yes");
        ASSERT_EQ(b, true);
        b = parse_boolean("true");
        ASSERT_EQ(b, true);
        b = parse_boolean("on");
        ASSERT_EQ(b, true);
        b = parse_boolean("0");
        ASSERT_EQ(b, false);
        b = parse_boolean("no");
        ASSERT_EQ(b, false);
        b = parse_boolean("false");
        ASSERT_EQ(b, false);
        b = parse_boolean("off");
        ASSERT_EQ(b, false);
        ASSERT_EQ(parse_boolean("invalid"), -EINVAL);
}

TEST(parse_pid) {
        pid_t pid;
        ASSERT_OK(parse_pid("1234", &pid));
        ASSERT_EQ(pid, 1234);
        ASSERT_EQ(parse_pid("0", &pid), -ERANGE);
        ASSERT_EQ(parse_pid("-1", &pid), -ERANGE);
        ASSERT_EQ(parse_pid("abc", &pid), -EINVAL);
}

TEST(parse_mode) {
        mode_t m;
        ASSERT_OK(parse_mode("0644", &m));
        ASSERT_EQ(m, 0644);
        ASSERT_OK(parse_mode("0755", &m));
        ASSERT_EQ(m, 0755);
        ASSERT_EQ(parse_mode("9999", &m), -EINVAL);
}

TEST(parse_size) {
        uint64_t sz;
        ASSERT_OK(parse_size("1024", 1024, &sz));
        ASSERT_EQ(sz, 1024);
        ASSERT_OK(parse_size("1K", 1024, &sz));
        ASSERT_EQ(sz, 1024);
        ASSERT_OK(parse_size("4M", 1024, &sz));
        ASSERT_EQ(sz, 4 * 1024 * 1024);
        ASSERT_OK(parse_size("1G", 1024, &sz));
        ASSERT_EQ(sz, 1ULL * 1024 * 1024 * 1024);
        ASSERT_OK(parse_size("2T", 1024, &sz));
        ASSERT_EQ(sz, 2ULL * 1024 * 1024 * 1024 * 1024);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
