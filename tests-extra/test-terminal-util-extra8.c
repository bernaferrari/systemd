/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "terminal-util.h"
#include "tests.h"

TEST(reset_terminal_feature_caches_basic) {
        reset_terminal_feature_caches();
}

TEST(getttyname_malloc_basic) {
        _cleanup_free_ char *tty = NULL;
        int r = getttyname_malloc(0, &tty);
        if (r >= 0)
                log_debug("tty: %s", tty);
        else
                log_debug("getttyname_malloc failed: %d", r);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
