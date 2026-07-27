/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "output-mode.h"
#include "tests.h"

TEST(output_mode_to_string) {
        ASSERT_STREQ(output_mode_to_string(OUTPUT_SHORT), "short");
        ASSERT_STREQ(output_mode_to_string(OUTPUT_VERBOSE), "verbose");
        ASSERT_STREQ(output_mode_to_string(OUTPUT_JSON), "json");
        ASSERT_STREQ(output_mode_to_string(OUTPUT_EXPORT), "export");
        ASSERT_STREQ(output_mode_to_string(OUTPUT_CAT), "cat");
        ASSERT_STREQ(output_mode_to_string(OUTPUT_WITH_UNIT), "with-unit");
        ASSERT_STREQ(output_mode_to_string(OUTPUT_JSON_PRETTY), "json-pretty");
        ASSERT_STREQ(output_mode_to_string(OUTPUT_JSON_SSE), "json-sse");
        ASSERT_STREQ(output_mode_to_string(OUTPUT_JSON_SEQ), "json-seq");
}

TEST(output_mode_from_string) {
        ASSERT_EQ(output_mode_from_string("short"), OUTPUT_SHORT);
        ASSERT_EQ(output_mode_from_string("verbose"), OUTPUT_VERBOSE);
        ASSERT_EQ(output_mode_from_string("json"), OUTPUT_JSON);
        ASSERT_EQ(output_mode_from_string("export"), OUTPUT_EXPORT);
        ASSERT_EQ(output_mode_from_string("cat"), OUTPUT_CAT);
        ASSERT_EQ(output_mode_from_string("invalid"), _OUTPUT_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
