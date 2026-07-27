/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-util.h"
#include "string-util.h"
#include "tests.h"

TEST(bus_path_encode_unique) {
        _cleanup_free_ char *path = NULL;
        int r;

        /* With both sender_id and external_id provided, bus can be NULL */
        r = bus_path_encode_unique(NULL, "/org/freedesktop", "sender123", "external456", &path);
        assert_se(r >= 0);
        assert_se(path != NULL);
        assert_se(startswith(path, "/org/freedesktop/"));
        assert_se(strstr(path, "/external456") != NULL);
}

TEST(bus_path_decode_unique) {
        _cleanup_free_ char *sender = NULL, *external = NULL;
        int r;

        /* First encode a path to decode */
        _cleanup_free_ char *encoded = NULL;
        r = bus_path_encode_unique(NULL, "/org/freedesktop", "sender123", "external456", &encoded);
        assert_se(r >= 0);

        /* Decode it back */
        r = bus_path_decode_unique(encoded, "/org/freedesktop", &sender, &external);
        assert_se(r > 0);
        assert_se(streq(sender, "sender123"));
        assert_se(streq(external, "external456"));
        sender = mfree(sender);
        external = mfree(external);

        /* Prefix doesn't match → returns 0, both NULL */
        _cleanup_free_ char *encoded2 = NULL;
        r = bus_path_encode_unique(NULL, "/org/other", "sender123", "external456", &encoded2);
        assert_se(r >= 0);

        r = bus_path_decode_unique(encoded2, "/org/freedesktop", &sender, &external);
        assert_se(r == 0);
        assert_se(sender == NULL);
        assert_se(external == NULL);
}

TEST(bus_path_encode_decode_roundtrip) {
        _cleanup_free_ char *encoded = NULL, *sender = NULL, *external = NULL;
        int r;

        /* Encode then decode should give back the original IDs */
        r = bus_path_encode_unique(NULL, "/org/example", "my_sender", "my_external", &encoded);
        assert_se(r >= 0);

        r = bus_path_decode_unique(encoded, "/org/example", &sender, &external);
        assert_se(r > 0);
        assert_se(streq(sender, "my_sender"));
        assert_se(streq(external, "my_external"));
}

TEST(bus_path_encode_special_chars) {
        _cleanup_free_ char *encoded = NULL, *sender = NULL, *external = NULL;
        int r;

        /* Test with special characters that need escaping */
        r = bus_path_encode_unique(NULL, "/org/test", "sender.id", "ext-name", &encoded);
        assert_se(r >= 0);

        r = bus_path_decode_unique(encoded, "/org/test", &sender, &external);
        assert_se(r > 0);
        assert_se(streq(sender, "sender.id"));
        assert_se(streq(external, "ext-name"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
