/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: signal-name-and-number */
/* RUST-CONTRACT: signal-number-parser */
/* Shadow test: C signal-util vs Rust rs_signal_util */

#include "signal-util.h"
#include "rust/signal_util.h"
#include "string-util.h"
#include "tests.h"
#include <stdio.h>

/* C helpers needed by Rust signal_util module (runtime signal constants) */
int rs_get_sigrtmin(void);
int rs_get_sigrtmax(void);
int rs_get_nsig(void);
int rs_get_sigrtmin(void) { return SIGRTMIN; }
int rs_get_sigrtmax(void) { return SIGRTMAX; }
int rs_get_nsig(void) { return _NSIG; }

/* ── signal_from_string: named signals ─────────────────────────────────── */

TEST(signal_from_string_named) {
        const char *names[] = {
                "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT",
                "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2",
                "PIPE", "ALRM", "TERM",
#ifdef SIGSTKFLT
                "STKFLT",
#endif
                "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU",
                "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH",
                "IO", "PWR", "SYS",
                NULL
        };

        for (const char **p = names; *p; p++) {
                int c_val = signal_from_string(*p);
                int rs_val = rs_signal_from_string(*p);
                ASSERT_EQ(c_val, rs_val);
                assert_se(c_val > 0);
        }
}

/* ── signal_from_string: SIG prefix ───────────────────────────────────── */

TEST(signal_from_string_sig_prefix) {
        const char *names[] = {
                "SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM", "SIGKILL",
                "SIGUSR1", "SIGUSR2", "SIGPIPE", "SIGCHLD", "SIGSYS",
                NULL
        };

        for (const char **p = names; *p; p++) {
                int c_val = signal_from_string(*p);
                int rs_val = rs_signal_from_string(*p);
                ASSERT_EQ(c_val, rs_val);
                assert_se(c_val > 0);
        }
}

/* ── signal_from_string: numeric ──────────────────────────────────────── */

TEST(signal_from_string_numeric) {
        /* Valid numeric signals */
        ASSERT_EQ(signal_from_string("1"), rs_signal_from_string("1"));
        ASSERT_EQ(signal_from_string("9"), rs_signal_from_string("9"));
        ASSERT_EQ(signal_from_string("15"), rs_signal_from_string("15"));
        ASSERT_EQ(signal_from_string("31"), rs_signal_from_string("31"));

        /* Out of range */
        ASSERT_EQ(signal_from_string("0"), rs_signal_from_string("0"));
        assert_se(signal_from_string("0") < 0); /* 0 is not a valid signal */

        ASSERT_EQ(signal_from_string("999"), rs_signal_from_string("999"));
        assert_se(signal_from_string("999") < 0);

        /* signal_from_string() uses safe_atoi(), including its base prefixes
         * and leading-whitespace behavior. */
        ASSERT_EQ(signal_from_string(" 15"), rs_signal_from_string(" 15"));
        ASSERT_EQ(signal_from_string("+15"), rs_signal_from_string("+15"));
        ASSERT_EQ(signal_from_string("0xf"), rs_signal_from_string("0xf"));
        ASSERT_EQ(signal_from_string("0b1111"), rs_signal_from_string("0b1111"));
        ASSERT_EQ(signal_from_string("0o17"), rs_signal_from_string("0o17"));
        ASSERT_EQ(signal_from_string("15 "), rs_signal_from_string("15 "));
}

/* ── signal_from_string: RTMIN/RTMAX ─────────────────────────────────── */

TEST(signal_from_string_rtmin_rtmax) {
        /* RTMIN alone */
        ASSERT_EQ(signal_from_string("RTMIN"), rs_signal_from_string("RTMIN"));
        assert_se(signal_from_string("RTMIN") > 0);

        /* RTMIN+n */
        ASSERT_EQ(signal_from_string("RTMIN+0"), rs_signal_from_string("RTMIN+0"));
        ASSERT_EQ(signal_from_string("RTMIN+5"), rs_signal_from_string("RTMIN+5"));
        ASSERT_EQ(signal_from_string("RTMIN+10"), rs_signal_from_string("RTMIN+10"));

        /* RTMAX alone */
        ASSERT_EQ(signal_from_string("RTMAX"), rs_signal_from_string("RTMAX"));
        assert_se(signal_from_string("RTMAX") > 0);

        /* RTMAX-n */
        ASSERT_EQ(signal_from_string("RTMAX-0"), rs_signal_from_string("RTMAX-0"));
        ASSERT_EQ(signal_from_string("RTMAX-5"), rs_signal_from_string("RTMAX-5"));

        /* Invalid: RTMIN without +, RTMAX without - */
        ASSERT_EQ(signal_from_string("RTMINx"), rs_signal_from_string("RTMINx"));
        ASSERT_EQ(signal_from_string("RTMAXx"), rs_signal_from_string("RTMAXx"));

        /* Invalid: out of range */
        ASSERT_EQ(signal_from_string("RTMIN+999"), rs_signal_from_string("RTMIN+999"));
        ASSERT_EQ(signal_from_string("RTMAX-999"), rs_signal_from_string("RTMAX-999"));

        /* With SIG prefix */
        ASSERT_EQ(signal_from_string("SIGRTMIN+3"), rs_signal_from_string("SIGRTMIN+3"));
        ASSERT_EQ(signal_from_string("SIGRTMAX-2"), rs_signal_from_string("SIGRTMAX-2"));
}

/* ── signal_from_string: invalid inputs ───────────────────────────────── */

TEST(signal_from_string_invalid) {
        ASSERT_EQ(signal_from_string(""), rs_signal_from_string(""));
        assert_se(signal_from_string("") < 0);

        ASSERT_EQ(signal_from_string("bogus"), rs_signal_from_string("bogus"));
        assert_se(signal_from_string("bogus") < 0);

        ASSERT_EQ(signal_from_string("SIGBOGUS"), rs_signal_from_string("SIGBOGUS"));
        assert_se(signal_from_string("SIGBOGUS") < 0);
}

/* ── parse_signo ──────────────────────────────────────────────────────── */

TEST(parse_signo_c_vs_rs) {
        int c_val = 0, rs_val = 0;

        /* Valid */
        ASSERT_EQ(parse_signo("1", &c_val), rs_parse_signo("1", &rs_val));
        ASSERT_EQ(c_val, rs_val);
        ASSERT_EQ(c_val, SIGHUP);

        ASSERT_EQ(parse_signo("9", &c_val), rs_parse_signo("9", &rs_val));
        ASSERT_EQ(c_val, rs_val);
        ASSERT_EQ(c_val, SIGKILL);

        ASSERT_EQ(parse_signo("15", &c_val), rs_parse_signo("15", &rs_val));
        ASSERT_EQ(c_val, rs_val);
        ASSERT_EQ(c_val, SIGTERM);

        /* Invalid: 0 */
        ASSERT_EQ(parse_signo("0", &c_val), rs_parse_signo("0", &rs_val));
        ASSERT_LT(parse_signo("0", &c_val), 0);

        /* Invalid: negative */
        ASSERT_EQ(parse_signo("-1", &c_val), rs_parse_signo("-1", &rs_val));
        ASSERT_LT(parse_signo("-1", &c_val), 0);

        /* Invalid: not a number */
        ASSERT_EQ(parse_signo("abc", &c_val), rs_parse_signo("abc", &rs_val));
        ASSERT_LT(parse_signo("abc", &c_val), 0);

        /* Invalid: out of range */
        ASSERT_EQ(parse_signo("999", &c_val), rs_parse_signo("999", &rs_val));
        ASSERT_LT(parse_signo("999", &c_val), 0);

        /* NULL ret pointer is OK */
        ASSERT_EQ(parse_signo("1", NULL), rs_parse_signo("1", NULL));
        assert_se(parse_signo("1", NULL) >= 0);
}

/* ── si_code_from_process ─────────────────────────────────────────────── */

TEST(si_code_from_process_c_vs_rs) {
        for (int i = -10; i <= 10; i++)
                ASSERT_EQ(si_code_from_process(i), rs_si_code_from_process(i));

        /* SI_USER (0) → true */
        assert_se(si_code_from_process(SI_USER));
        assert_se(rs_si_code_from_process(SI_USER));

        /* SI_QUEUE (-1) → true */
        assert_se(si_code_from_process(SI_QUEUE));
        assert_se(rs_si_code_from_process(SI_QUEUE));

        /* SI_KERNEL (1) → false */
        assert_se(!si_code_from_process(SI_KERNEL));
        assert_se(!rs_si_code_from_process(SI_KERNEL));
}

/* ── SIGNAL_VALID ─────────────────────────────────────────────────────── */

TEST(signal_is_valid_c_vs_rs) {
        assert_se(SIGNAL_VALID(SIGHUP) == rs_signal_is_valid(SIGHUP));
        assert_se(SIGNAL_VALID(SIGKILL) == rs_signal_is_valid(SIGKILL));
        assert_se(SIGNAL_VALID(SIGTERM) == rs_signal_is_valid(SIGTERM));
        assert_se(SIGNAL_VALID(0) == rs_signal_is_valid(0));
        assert_se(!SIGNAL_VALID(0));
        assert_se(SIGNAL_VALID(-1) == rs_signal_is_valid(-1));
        assert_se(!SIGNAL_VALID(-1));
        assert_se(SIGNAL_VALID(64) == rs_signal_is_valid(64));
}

/* ── signal_to_string ─────────────────────────────────────────────────── */

TEST(signal_to_string_named) {
        const char *names[] = {
                "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT",
                "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2",
                "PIPE", "ALRM", "TERM",
#ifdef SIGSTKFLT
                "STKFLT",
#endif
                "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU",
                "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH",
                "IO", "PWR", "SYS",
                NULL
        };

        for (const char **p = names; *p; p++) {
                int sig = signal_from_string(*p);
                assert_se(sig > 0);
                const char *c_ret = signal_to_string(sig);
                const char *r_ret = rs_signal_to_string(sig);
                assert_se(c_ret && r_ret);
                assert_se(streq(c_ret, r_ret));
        }
}

TEST(signal_to_string_invalid) {
        /* Signal 0 is not valid */
        const char *c_ret = signal_to_string(0);
        const char *r_ret = rs_signal_to_string(0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "0"));

        /* Signal 16 (between SIGTERM=15 and SIGCHLD=17) has no name on some arches */
        /* Negative signal */
        c_ret = signal_to_string(-1);
        r_ret = rs_signal_to_string(-1);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
}

TEST(signal_to_string_static_storage) {
        const char *first = rs_signal_to_string(SIGTERM);
        const char *second = rs_signal_to_string(SIGTERM);

        assert_se(first == second);
        assert_se(streq(first, "TERM"));
}

TEST(signal_to_string_rtmin) {
        /* RTMIN — C always uses "RTMIN+0" format even for offset 0 */
        const char *c_ret = signal_to_string(SIGRTMIN);
        const char *r_ret = rs_signal_to_string(SIGRTMIN);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "RTMIN+0"));

        /* RTMIN+5 */
        c_ret = signal_to_string(SIGRTMIN + 5);
        r_ret = rs_signal_to_string(SIGRTMIN + 5);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));
        assert_se(streq(c_ret, "RTMIN+5"));
}

DEFINE_TEST_MAIN(LOG_INFO);
