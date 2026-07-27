/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "vconsole-util.h"

TEST(x11_context_isempty) {
        X11Context xc = {};

        /* Zeroed context is empty */
        assert_se(x11_context_isempty(&xc) == true);

        /* With layout set */
        xc.layout = (char*)"us";
        assert_se(x11_context_isempty(&xc) == false);
        xc.layout = NULL;

        /* With model set */
        xc.model = (char*)"pc105";
        assert_se(x11_context_isempty(&xc) == false);
        xc.model = NULL;

        /* With variant set */
        xc.variant = (char*)"dvorak";
        assert_se(x11_context_isempty(&xc) == false);
        xc.variant = NULL;

        /* With options set */
        xc.options = (char*)"ctrl:nocaps";
        assert_se(x11_context_isempty(&xc) == false);
}

TEST(x11_context_equal) {
        X11Context a = {}, b = {};

        /* Both empty */
        assert_se(x11_context_equal(&a, &b) == true);

        /* Same layout */
        a.layout = (char*)"us";
        b.layout = (char*)"us";
        assert_se(x11_context_equal(&a, &b) == true);

        /* Different layout */
        b.layout = (char*)"de";
        assert_se(x11_context_equal(&a, &b) == false);
}

TEST(x11_context_empty_to_null) {
        X11Context xc = {
                .layout = (char*)"",
                .model = (char*)"",
                .variant = (char*)"",
                .options = (char*)"",
        };

        x11_context_empty_to_null(&xc);
        assert_se(xc.layout == NULL);
        assert_se(xc.model == NULL);
        assert_se(xc.variant == NULL);
        assert_se(xc.options == NULL);
}

TEST(vc_context_isempty) {
        VCContext vc = {};

        /* Zeroed context is empty */
        assert_se(vc_context_isempty(&vc) == true);

        /* With keymap set */
        vc.keymap = (char*)"us";
        assert_se(vc_context_isempty(&vc) == false);
        vc.keymap = NULL;

        /* With toggle set */
        vc.toggle = (char*)"alt_shift_toggle";
        assert_se(vc_context_isempty(&vc) == false);
}

TEST(vc_context_equal) {
        VCContext a = {}, b = {};

        /* Both empty */
        assert_se(vc_context_equal(&a, &b) == true);

        /* Same keymap */
        a.keymap = (char*)"us";
        b.keymap = (char*)"us";
        assert_se(vc_context_equal(&a, &b) == true);

        /* Different keymap */
        b.keymap = (char*)"de";
        assert_se(vc_context_equal(&a, &b) == false);
}

TEST(vc_context_empty_to_null) {
        VCContext vc = {
                .keymap = (char*)"",
                .toggle = (char*)"",
        };

        vc_context_empty_to_null(&vc);
        assert_se(vc.keymap == NULL);
        assert_se(vc.toggle == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
