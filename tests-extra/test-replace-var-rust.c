/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C replace_var vs Rust rs_replace_var */

#include <string.h>

#include "alloc-util.h"
#include "replace-var.h"
#include "rust/replace_var.h"
#include "string-util.h"
#include "tests.h"

/* RUST-CONTRACT: replace-var-byte-substitution */
/* RUST-CONTRACT: replace-var-token-boundaries */
/* RUST-CONTRACT: replace-var-callback-ownership-and-order */
/* RUST-CONTRACT: replace-var-lookup-failure */

typedef struct LookupState {
        const char *fail_on;
        size_t n_calls;
        size_t n_allocations;
        char seen[8][32];
} LookupState;

static char *test_lookup(const char *variable, void *userdata) {
        static const unsigned char binary[] = { 0xfe, 0x7f, 0x80, 0 };
        LookupState *state = ASSERT_PTR(userdata);
        char *result;

        assert_se(variable);
        assert_se(state->n_calls < ELEMENTSOF(state->seen));
        assert_se(strlen(variable) < sizeof(state->seen[0]));

        strcpy(state->seen[state->n_calls], variable);
        state->n_calls++;

        if (streq_ptr(variable, state->fail_on))
                return NULL;
        if (streq(variable, "FOO"))
                result = strdup("hello");
        else if (streq(variable, "BAR"))
                result = strdup("world");
        else if (streq(variable, "EMPTY"))
                result = strdup("");
        else if (streq(variable, "BINARY"))
                result = memdup(binary, sizeof(binary));
        else
                result = strdup(variable);

        assert_se(result);
        state->n_allocations++;
        return result;
}

static void run_pair(
                const char *text,
                const char *fail_on,
                char **ret_c,
                char **ret_r,
                LookupState *ret_c_state,
                LookupState *ret_r_state) {

        *ret_c_state = (LookupState) {
                .fail_on = fail_on,
        };
        *ret_r_state = (LookupState) {
                .fail_on = fail_on,
        };

        *ret_c = replace_var(text, test_lookup, ret_c_state);
        *ret_r = rs_replace_var(text, test_lookup, ret_r_state);

        assert_se((*ret_c == NULL) == (*ret_r == NULL));
        if (*ret_c)
                assert_se(streq(*ret_c, *ret_r));

        assert_se(ret_c_state->n_calls == ret_r_state->n_calls);
        assert_se(ret_c_state->n_allocations == ret_r_state->n_allocations);
        for (size_t i = 0; i < ret_c_state->n_calls; i++)
                assert_se(streq(ret_c_state->seen[i], ret_r_state->seen[i]));
}

TEST(replace_var_rust_substitution_and_order) {
        LookupState c_state, r_state;
        char *c_result, *r_result;

        run_pair(
                        "x@FOO@@EMPTY@@BAR@y",
                        NULL,
                        &c_result,
                        &r_result,
                        &c_state,
                        &r_state);

        assert_se(streq(c_result, "xhelloworldy"));
        assert_se(c_state.n_calls == 3);
        assert_se(c_state.n_allocations == 3);
        assert_se(streq(c_state.seen[0], "FOO"));
        assert_se(streq(c_state.seen[1], "EMPTY"));
        assert_se(streq(c_state.seen[2], "BAR"));

        free(c_result);
        free(r_result);
}

TEST(replace_var_rust_empty_and_no_variables) {
        LookupState c_state, r_state;
        char *c_result, *r_result;

        run_pair("", NULL, &c_result, &r_result, &c_state, &r_state);
        assert_se(c_result);
        assert_se(streq(c_result, ""));
        assert_se(c_state.n_calls == 0);
        free(c_result);
        free(r_result);

        run_pair(
                        "plain text",
                        NULL,
                        &c_result,
                        &r_result,
                        &c_state,
                        &r_state);
        assert_se(streq(c_result, "plain text"));
        assert_se(c_state.n_calls == 0);
        free(c_result);
        free(r_result);
}

TEST(replace_var_rust_lookup_failure) {
        LookupState c_state, r_state;
        char *c_result, *r_result;

        run_pair(
                        "a@FOO@b@FAIL@c@BAR@",
                        "FAIL",
                        &c_result,
                        &r_result,
                        &c_state,
                        &r_state);

        assert_se(c_result == NULL);
        assert_se(r_result == NULL);
        assert_se(c_state.n_calls == 2);
        assert_se(c_state.n_allocations == 1);
        assert_se(streq(c_state.seen[0], "FOO"));
        assert_se(streq(c_state.seen[1], "FAIL"));
}

TEST(replace_var_rust_token_boundaries) {
        LookupState c_state, r_state;
        char *c_result, *r_result;

        run_pair(
                        "@@ @foo@ @A1@ @A-B@ @_@ @A_B@ @Z@ @A@B@ @OPEN",
                        NULL,
                        &c_result,
                        &r_result,
                        &c_state,
                        &r_state);

        assert_se(streq(c_result, "@@ @foo@ @A1@ @A-B@ _ A_B Z AB@ @OPEN"));
        assert_se(c_state.n_calls == 4);
        assert_se(streq(c_state.seen[0], "_"));
        assert_se(streq(c_state.seen[1], "A_B"));
        assert_se(streq(c_state.seen[2], "Z"));
        assert_se(streq(c_state.seen[3], "A"));

        free(c_result);
        free(r_result);
}

TEST(replace_var_rust_non_utf8_bytes) {
        static const unsigned char text[] = {
                'p', 0x80, '@', 'B', 'I', 'N', 'A', 'R', 'Y', '@', 0xff, 'q', 0,
        };
        static const unsigned char expected[] = {
                'p', 0x80, 0xfe, 0x7f, 0x80, 0xff, 'q', 0,
        };
        LookupState c_state, r_state;
        char *c_result, *r_result;

        run_pair(
                        (const char*) text,
                        NULL,
                        &c_result,
                        &r_result,
                        &c_state,
                        &r_state);

        assert_se(memcmp(c_result, expected, sizeof(expected)) == 0);
        assert_se(memcmp(r_result, expected, sizeof(expected)) == 0);
        assert_se(c_state.n_calls == 1);
        assert_se(streq(c_state.seen[0], "BINARY"));

        free(c_result);
        free(r_result);
}

DEFINE_TEST_MAIN(LOG_INFO);
