/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: signal-si-code-from-process */

#include <signal.h>

#include "signal-util.h"
#include "rust/signal_util.h"
#include "tests.h"

/* signal_util.rs keeps these target constants behind a narrow test-only C ABI. */
int rs_get_sigrtmin(void);
int rs_get_sigrtmax(void);
int rs_get_nsig(void);
int rs_get_sigrtmin(void) {
        return SIGRTMIN;
}

int rs_get_sigrtmax(void) {
        return SIGRTMAX;
}

int rs_get_nsig(void) {
        return _NSIG;
}

TEST(si_code_from_process_c_vs_rs) {
        for (int code = -10; code <= 10; code++)
                ASSERT_EQ(si_code_from_process(code), rs_si_code_from_process(code));

        ASSERT_TRUE(si_code_from_process(SI_USER));
        ASSERT_TRUE(rs_si_code_from_process(SI_USER));
        ASSERT_TRUE(si_code_from_process(SI_QUEUE));
        ASSERT_TRUE(rs_si_code_from_process(SI_QUEUE));
        ASSERT_FALSE(si_code_from_process(SI_KERNEL));
        ASSERT_FALSE(rs_si_code_from_process(SI_KERNEL));
}

DEFINE_TEST_MAIN(LOG_INFO);
