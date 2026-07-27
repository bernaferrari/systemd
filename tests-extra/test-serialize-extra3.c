/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-id128.h"

#include "fd-util.h"
#include "fileio.h"
#include "serialize.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

TEST(serialize_item_basic) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        /* Normal write */
        assert_se(serialize_item(f, "key", "value") == 1);
        /* NULL value → skipped */
        assert_se(serialize_item(f, "skip", NULL) == 0);

        fclose(f);
        assert_se(startswith(buf, "key=value\n"));
        assert_se(!strstr(buf, "skip="));
}

TEST(serialize_item_escaped) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        /* Value with spaces gets escaped */
        assert_se(serialize_item_escaped(f, "key", "hello world") == 1);

        fclose(f);
        assert_se(strstr(buf, "key="));
}

TEST(serialize_item_format) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        assert_se(serialize_item_format(f, "count", "%d", 42) == 1);
        assert_se(serialize_item_format(f, "name", "%s", "test") == 1);

        fclose(f);
        assert_se(strstr(buf, "count=42\n"));
        assert_se(strstr(buf, "name=test\n"));
}

TEST(serialize_usec_basic) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        assert_se(serialize_usec(f, "ts", 1000000) == 1);
        /* USEC_INFINITY → skipped */
        assert_se(serialize_usec(f, "skip", USEC_INFINITY) == 0);

        fclose(f);
        assert_se(strstr(buf, "ts=1000000\n"));
        assert_se(!strstr(buf, "skip="));
}

TEST(serialize_bool_basic) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        assert_se(serialize_bool(f, "flag", true) > 0);
        assert_se(serialize_bool(f, "flag2", false) > 0);

        fclose(f);
        assert_se(strstr(buf, "flag=yes\n"));
        assert_se(strstr(buf, "flag2=no\n"));
}

TEST(serialize_bool_elide) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;

        FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        /* true → written */
        assert_se(serialize_bool_elide(f, "flag", true) > 0);
        /* false → elided */
        assert_se(serialize_bool_elide(f, "flag2", false) == 0);

        fclose(f);
        assert_se(strstr(buf, "flag=yes\n"));
        assert_se(!strstr(buf, "flag2="));
}

TEST(serialize_id128_basic) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;
        sd_id128_t id;

        FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        assert_se(sd_id128_from_string("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", &id) >= 0);
        assert_se(serialize_id128(f, "id", id) == 1);

        /* Null ID → skipped */
        assert_se(serialize_id128(f, "skip", SD_ID128_NULL) == 0);

        fclose(f);
        assert_se(strstr(buf, "id=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n"));
        assert_se(!strstr(buf, "skip="));
}

TEST(serialize_strv_basic) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;
        char *items[] = { (char*) "one", (char*) "two", (char*) "three", NULL };

        FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        assert_se(serialize_strv(f, "item", items) > 0);

        fclose(f);
        assert_se(strstr(buf, "item=one\n"));
        assert_se(strstr(buf, "item=two\n"));
        assert_se(strstr(buf, "item=three\n"));
}

TEST(serialize_item_hexmem) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;
        uint8_t data[] = { 0xDE, 0xAD, 0xBE, 0xEF };

        FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        assert_se(serialize_item_hexmem(f, "hex", data, sizeof(data)) == 1);
        /* Zero length → skipped */
        assert_se(serialize_item_hexmem(f, "skip", data, 0) == 0);

        fclose(f);
        assert_se(strstr(buf, "hex=deadbeef\n") || strstr(buf, "hex=DEADBEEF\n"));
        assert_se(!strstr(buf, "skip="));
}

TEST(serialize_item_base64mem) {
        _cleanup_free_ char *buf = NULL;
        size_t sz;
        const char *data = "hello";

        FILE *f = open_memstream_unlocked(&buf, &sz);
        assert_se(f);

        assert_se(serialize_item_base64mem(f, "b64", data, strlen(data)) == 1);
        /* Zero length → skipped */
        assert_se(serialize_item_base64mem(f, "skip", data, 0) == 0);

        fclose(f);
        assert_se(strstr(buf, "b64="));
        assert_se(!strstr(buf, "skip="));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
