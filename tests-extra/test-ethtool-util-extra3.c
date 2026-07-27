/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ethtool-util.h"
#include "string-util.h"
#include "tests.h"

TEST(mdi_to_string) {
        const char *s;

        /* mdi uses DEFINE_STRING_TABLE_LOOKUP_TO_STRING — returns const char* */
        s = mdi_to_string(ETH_TP_MDI_INVALID);
        assert_se(s && streq(s, "unknown"));

        s = mdi_to_string(ETH_TP_MDI);
        assert_se(s && streq(s, "mdi"));

        s = mdi_to_string(ETH_TP_MDI_X);
        assert_se(s && streq(s, "mdi-x"));

        s = mdi_to_string(ETH_TP_MDI_AUTO);
        assert_se(s && streq(s, "auto"));
}

TEST(wol_options_to_string_alloc) {
        _cleanup_free_ char *s = NULL;

        /* No options → "off" */
        assert_se(wol_options_to_string_alloc(0, &s) >= 0);
        assert_se(streq(s, "off"));
        s = mfree(s);

        /* Single option */
        assert_se(wol_options_to_string_alloc(WAKE_MAGIC, &s) >= 0);
        assert_se(streq(s, "magic"));
        s = mfree(s);

        /* Multiple options */
        assert_se(wol_options_to_string_alloc(WAKE_MAGIC | WAKE_PHY, &s) >= 0);
        assert_se(s);
        assert_se(strstr(s, "magic"));
        assert_se(strstr(s, "phy"));
        s = mfree(s);

        /* UINT32_MAX → NULL */
        assert_se(wol_options_to_string_alloc(UINT32_MAX, &s) == 0);
        assert_se(s == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
