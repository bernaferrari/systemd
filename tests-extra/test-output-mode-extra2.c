/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "output-mode.h"
#include "tests.h"

TEST(output_mode_to_from_string) {
        assert_se(streq(output_mode_to_string(OUTPUT_SHORT), "short"));
        assert_se(streq(output_mode_to_string(OUTPUT_SHORT_FULL), "short-full"));
        assert_se(streq(output_mode_to_string(OUTPUT_SHORT_ISO), "short-iso"));
        assert_se(streq(output_mode_to_string(OUTPUT_SHORT_ISO_PRECISE), "short-iso-precise"));
        assert_se(streq(output_mode_to_string(OUTPUT_SHORT_PRECISE), "short-precise"));
        assert_se(streq(output_mode_to_string(OUTPUT_SHORT_MONOTONIC), "short-monotonic"));
        assert_se(streq(output_mode_to_string(OUTPUT_SHORT_DELTA), "short-delta"));
        assert_se(streq(output_mode_to_string(OUTPUT_SHORT_UNIX), "short-unix"));
        assert_se(streq(output_mode_to_string(OUTPUT_VERBOSE), "verbose"));
        assert_se(streq(output_mode_to_string(OUTPUT_EXPORT), "export"));
        assert_se(streq(output_mode_to_string(OUTPUT_JSON), "json"));
        assert_se(streq(output_mode_to_string(OUTPUT_JSON_PRETTY), "json-pretty"));
        assert_se(streq(output_mode_to_string(OUTPUT_JSON_SSE), "json-sse"));
        assert_se(streq(output_mode_to_string(OUTPUT_JSON_SEQ), "json-seq"));
        assert_se(streq(output_mode_to_string(OUTPUT_CAT), "cat"));
        assert_se(streq(output_mode_to_string(OUTPUT_WITH_UNIT), "with-unit"));

        assert_se(output_mode_from_string("short") == OUTPUT_SHORT);
        assert_se(output_mode_from_string("short-iso") == OUTPUT_SHORT_ISO);
        assert_se(output_mode_from_string("verbose") == OUTPUT_VERBOSE);
        assert_se(output_mode_from_string("json") == OUTPUT_JSON);
        assert_se(output_mode_from_string("json-pretty") == OUTPUT_JSON_PRETTY);
        assert_se(output_mode_from_string("cat") == OUTPUT_CAT);
        assert_se(output_mode_from_string("with-unit") == OUTPUT_WITH_UNIT);
        assert_se(output_mode_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
