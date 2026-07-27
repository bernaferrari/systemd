/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "string-util.h"
#include "tests.h"
#include "vconsole-util.h"

TEST(x11_context_isempty) {
        X11Context xc = {};
        assert_se(x11_context_isempty(&xc));

        xc.layout = (char *) "us";
        assert_se(!x11_context_isempty(&xc));
}

TEST(x11_context_equal) {
        X11Context a = {}, b = {};
        assert_se(x11_context_equal(&a, &b));

        a.layout = (char *) "us";
        assert_se(!x11_context_equal(&a, &b));

        b.layout = (char *) "us";
        assert_se(x11_context_equal(&a, &b));

        a.variant = (char *) "dvorak";
        assert_se(!x11_context_equal(&a, &b));
}

TEST(vc_context_isempty) {
        VCContext vc = {};
        assert_se(vc_context_isempty(&vc));

        vc.keymap = (char *) "us";
        assert_se(!vc_context_isempty(&vc));
}

TEST(vc_context_equal) {
        VCContext a = {}, b = {};
        assert_se(vc_context_equal(&a, &b));

        a.keymap = (char *) "us";
        assert_se(!vc_context_equal(&a, &b));

        b.keymap = (char *) "us";
        assert_se(vc_context_equal(&a, &b));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
