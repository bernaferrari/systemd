/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "string-util.h"
#include "tests.h"
#include "vconsole-util.h"

TEST(x11_context_isempty) {
        X11Context xc = {};
        assert_se(x11_context_isempty(&xc));

        xc.layout = (char*) "us";
        assert_se(!x11_context_isempty(&xc));
        xc.layout = NULL;

        xc.model = (char*) "pc105";
        assert_se(!x11_context_isempty(&xc));
        xc.model = NULL;

        xc.variant = (char*) "dvorak";
        assert_se(!x11_context_isempty(&xc));
        xc.variant = NULL;

        xc.options = (char*) "ctrl:nocaps";
        assert_se(!x11_context_isempty(&xc));
}

TEST(x11_context_equal) {
        X11Context a = {}, b = {};

        /* Both empty */
        assert_se(x11_context_equal(&a, &b));

        /* Same values */
        a.layout = (char*) "us";
        b.layout = (char*) "us";
        assert_se(x11_context_equal(&a, &b));

        /* Different values */
        b.layout = (char*) "de";
        assert_se(!x11_context_equal(&a, &b));

        /* One NULL, other set */
        b.layout = NULL;
        assert_se(!x11_context_equal(&a, &b));
}

TEST(x11_context_is_safe) {
        X11Context xc = {};

        /* Empty is safe */
        assert_se(x11_context_is_safe(&xc));

        /* Valid layout */
        xc.layout = (char*) "us";
        assert_se(x11_context_is_safe(&xc));
}

TEST(vc_context_isempty) {
        VCContext vc = {};
        assert_se(vc_context_isempty(&vc));

        vc.keymap = (char*) "us";
        assert_se(!vc_context_isempty(&vc));
        vc.keymap = NULL;

        vc.toggle = (char*) "alt_shift";
        assert_se(!vc_context_isempty(&vc));
}

TEST(vc_context_equal) {
        VCContext a = {}, b = {};

        assert_se(vc_context_equal(&a, &b));

        a.keymap = (char*) "us";
        b.keymap = (char*) "us";
        assert_se(vc_context_equal(&a, &b));

        b.keymap = (char*) "de";
        assert_se(!vc_context_equal(&a, &b));

        b.keymap = NULL;
        assert_se(!vc_context_equal(&a, &b));
}

TEST(x11_context_empty_to_null) {
        X11Context xc = {
                .layout = NULL,
                .model = NULL,
                .variant = NULL,
                .options = NULL,
        };
        x11_context_empty_to_null(&xc);
        assert_se(xc.layout == NULL);
        assert_se(xc.model == NULL);
        assert_se(xc.variant == NULL);
        assert_se(xc.options == NULL);
}

TEST(vc_context_empty_to_null) {
        VCContext vc = {
                .keymap = NULL,
                .toggle = NULL,
        };
        vc_context_empty_to_null(&vc);
        assert_se(vc.keymap == NULL);
        assert_se(vc.toggle == NULL);
}

TEST(x11_context_clear) {
        X11Context xc = {
                .layout = strdup("us"),
                .model = strdup("pc105"),
        };
        assert_se(xc.layout && xc.model);

        x11_context_clear(&xc);
        /* After clear, struct should be zeroed */
        assert_se(xc.layout == NULL);
        assert_se(xc.model == NULL);
}

TEST(vc_context_clear) {
        VCContext vc = {
                .keymap = strdup("us"),
        };
        assert_se(vc.keymap);

        vc_context_clear(&vc);
        assert_se(vc.keymap == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
