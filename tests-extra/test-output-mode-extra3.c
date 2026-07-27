/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "output-mode.h"
#include "sd-json.h"
#include "tests.h"

TEST(output_mode_to_json_format_flags) {
        assert_se(output_mode_to_json_format_flags(OUTPUT_JSON_SSE) == SD_JSON_FORMAT_SSE);
        assert_se(output_mode_to_json_format_flags(OUTPUT_JSON_SEQ) == SD_JSON_FORMAT_SEQ);
        assert_se(output_mode_to_json_format_flags(OUTPUT_JSON_PRETTY) == SD_JSON_FORMAT_PRETTY);
        /* Default case returns SD_JSON_FORMAT_NEWLINE */
        assert_se(output_mode_to_json_format_flags(OUTPUT_JSON) == SD_JSON_FORMAT_NEWLINE);
        assert_se(output_mode_to_json_format_flags(OUTPUT_SHORT) == SD_JSON_FORMAT_NEWLINE);
}

TEST(output_mode_roundtrip) {
        for (int i = 0; i < _OUTPUT_MODE_MAX; i++) {
                const char *s = output_mode_to_string(i);
                if (s) {
                        int v = output_mode_from_string(s);
                        assert_se(v == i);
                }
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
