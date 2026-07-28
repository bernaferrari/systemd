/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: valid-ldh-char */
/* RUST-CONTRACT: hostname-validation */
/* RUST-CONTRACT: hostname-cleanup */
/* RUST-CONTRACT: hostname-classifiers */
/* RUST-CONTRACT: split-user-at-host */
/* RUST-CONTRACT: machine-spec-validation */

#include <string.h>

#include "hostname-util.h"
#include "tests.h"

/* Rust FFI */
#include "rust/hostname_util.h"

/* ── valid_ldh_char ─────────────────────────────────────────────────────── */

TEST(valid_ldh_char_basic) {
        assert_se(valid_ldh_char('a') == rs_valid_ldh_char('a'));
        assert_se(valid_ldh_char('Z') == rs_valid_ldh_char('Z'));
        assert_se(valid_ldh_char('0') == rs_valid_ldh_char('0'));
        assert_se(valid_ldh_char('9') == rs_valid_ldh_char('9'));
        assert_se(valid_ldh_char('-') == rs_valid_ldh_char('-'));
}

TEST(valid_ldh_char_invalid) {
        assert_se(valid_ldh_char('.') == rs_valid_ldh_char('.'));
        assert_se(valid_ldh_char('_') == rs_valid_ldh_char('_'));
        assert_se(valid_ldh_char(' ') == rs_valid_ldh_char(' '));
        assert_se(valid_ldh_char('/') == rs_valid_ldh_char('/'));
        assert_se(valid_ldh_char(0) == rs_valid_ldh_char(0));
}

/* ── hostname_is_valid ─────────────────────────────────────────────────── */

TEST(hostname_is_valid_basic) {
        assert_se(hostname_is_valid("foo", 0) == rs_hostname_is_valid("foo", 0));
        assert_se(hostname_is_valid("foo.bar", 0) == rs_hostname_is_valid("foo.bar", 0));
        assert_se(hostname_is_valid("foo-bar", 0) == rs_hostname_is_valid("foo-bar", 0));
        assert_se(hostname_is_valid("FOO", 0) == rs_hostname_is_valid("FOO", 0));
}

TEST(hostname_is_valid_trailing_dot) {
        assert_se(hostname_is_valid("foo.bar.", VALID_HOSTNAME_TRAILING_DOT) ==
                   rs_hostname_is_valid("foo.bar.", VALID_HOSTNAME_TRAILING_DOT));
        /* Single label with trailing dot should be invalid */
        assert_se(hostname_is_valid("foo.", VALID_HOSTNAME_TRAILING_DOT) ==
                   rs_hostname_is_valid("foo.", VALID_HOSTNAME_TRAILING_DOT));
}

TEST(hostname_is_valid_dot_host) {
        assert_se(hostname_is_valid(".host", VALID_HOSTNAME_DOT_HOST) ==
                   rs_hostname_is_valid(".host", VALID_HOSTNAME_DOT_HOST));
        assert_se(hostname_is_valid(".host", 0) ==
                   rs_hostname_is_valid(".host", 0));
}

TEST(hostname_is_valid_question_mark) {
        assert_se(hostname_is_valid("foo?bar", VALID_HOSTNAME_QUESTION_MARK) ==
                   rs_hostname_is_valid("foo?bar", VALID_HOSTNAME_QUESTION_MARK));
        assert_se(hostname_is_valid("foo?bar", 0) ==
                   rs_hostname_is_valid("foo?bar", 0));
}

TEST(hostname_is_valid_invalid) {
        assert_se(hostname_is_valid("", 0) == rs_hostname_is_valid("", 0));
        assert_se(hostname_is_valid(".foo", 0) == rs_hostname_is_valid(".foo", 0));
        assert_se(hostname_is_valid("-foo", 0) == rs_hostname_is_valid("-foo", 0));
        assert_se(hostname_is_valid("foo-", 0) == rs_hostname_is_valid("foo-", 0));
        assert_se(hostname_is_valid("foo..bar", 0) == rs_hostname_is_valid("foo..bar", 0));
        assert_se(hostname_is_valid("foo_bar", 0) == rs_hostname_is_valid("foo_bar", 0));
}

TEST(hostname_is_valid_raw_bytes) {
        const char invalid_utf8[] = "host\xFF";

        assert_se(hostname_is_valid(invalid_utf8, 0) == rs_hostname_is_valid(invalid_utf8, 0));
}

/* ── hostname_cleanup ───────────────────────────────────────────────────── */

TEST(hostname_cleanup_basic) {
        char cb[256] = "Hello.World";
        char rb[256] = "Hello.World";
        assert_se(streq(hostname_cleanup(cb), rs_hostname_cleanup(rb)));
}

TEST(hostname_cleanup_invalid_chars) {
        char cb[256] = "---myhost---";
        char rb[256] = "---myhost---";
        assert_se(streq(hostname_cleanup(cb), rs_hostname_cleanup(rb)));
}

TEST(hostname_cleanup_consecutive_dots) {
        char cb[256] = "foo..bar";
        char rb[256] = "foo..bar";
        assert_se(streq(hostname_cleanup(cb), rs_hostname_cleanup(rb)));
}

TEST(hostname_cleanup_leading_hyphen) {
        char cb[256] = "-leading";
        char rb[256] = "-leading";
        assert_se(streq(hostname_cleanup(cb), rs_hostname_cleanup(rb)));
}

TEST(hostname_cleanup_trailing_dot) {
        char cb[256] = "host.";
        char rb[256] = "host.";
        assert_se(streq(hostname_cleanup(cb), rs_hostname_cleanup(rb)));
}

TEST(hostname_cleanup_preserves_input_pointer) {
        char cb[256] = "foo..bar---";
        char rb[256] = "foo..bar---";

        assert_se(hostname_cleanup(cb) == cb);
        assert_se(rs_hostname_cleanup(rb) == rb);
        assert_se(streq(cb, rb));
}

/* ── is_localhost ───────────────────────────────────────────────────────── */

TEST(is_localhost_basic) {
        assert_se(is_localhost("localhost") == rs_is_localhost("localhost"));
        assert_se(is_localhost("localhost.") == rs_is_localhost("localhost."));
        assert_se(is_localhost("localhost.localdomain") == rs_is_localhost("localhost.localdomain"));
        assert_se(is_localhost("myhost.localhost") == rs_is_localhost("myhost.localhost"));
}

TEST(is_localhost_negative) {
        assert_se(is_localhost("myhost") == rs_is_localhost("myhost"));
        assert_se(is_localhost("") == rs_is_localhost(""));
}

/* ── is_gateway_hostname ────────────────────────────────────────────────── */

TEST(is_gateway_hostname) {
        assert_se(is_gateway_hostname("_gateway") == rs_is_gateway_hostname("_gateway"));
        assert_se(is_gateway_hostname("_gateway.") == rs_is_gateway_hostname("_gateway."));
        assert_se(is_gateway_hostname("_Gateway") == rs_is_gateway_hostname("_Gateway"));
        assert_se(is_gateway_hostname("gateway") == rs_is_gateway_hostname("gateway"));
}

/* ── is_outbound_hostname ───────────────────────────────────────────────── */

TEST(is_outbound_hostname) {
        assert_se(is_outbound_hostname("_outbound") == rs_is_outbound_hostname("_outbound"));
        assert_se(is_outbound_hostname("_outbound.") == rs_is_outbound_hostname("_outbound."));
        assert_se(is_outbound_hostname("_Outbound") == rs_is_outbound_hostname("_Outbound"));
        assert_se(is_outbound_hostname("outbound") == rs_is_outbound_hostname("outbound"));
}

/* ── is_dns_stub_hostname ──────────────────────────────────────────────── */

TEST(is_dns_stub_hostname) {
        assert_se(is_dns_stub_hostname("_localdnsstub") == rs_is_dns_stub_hostname("_localdnsstub"));
        assert_se(is_dns_stub_hostname("_localdnsstub.") == rs_is_dns_stub_hostname("_localdnsstub."));
        assert_se(is_dns_stub_hostname("_LocalDNSStub") == rs_is_dns_stub_hostname("_LocalDNSStub"));
        assert_se(is_dns_stub_hostname("localdnsstub") == rs_is_dns_stub_hostname("localdnsstub"));
}

/* ── is_dns_proxy_stub_hostname ────────────────────────────────────────── */

TEST(is_dns_proxy_stub_hostname) {
        assert_se(is_dns_proxy_stub_hostname("_localdnsproxy") == rs_is_dns_proxy_stub_hostname("_localdnsproxy"));
        assert_se(is_dns_proxy_stub_hostname("_localdnsproxy.") == rs_is_dns_proxy_stub_hostname("_localdnsproxy."));
        assert_se(is_dns_proxy_stub_hostname("localdnsproxy") == rs_is_dns_proxy_stub_hostname("localdnsproxy"));
}

TEST(synthetic_hostname_raw_bytes) {
        const char invalid_utf8[] = "_gateway\xFF";

        assert_se(is_gateway_hostname(invalid_utf8) == rs_is_gateway_hostname(invalid_utf8));
        assert_se(is_outbound_hostname(invalid_utf8) == rs_is_outbound_hostname(invalid_utf8));
        assert_se(is_dns_stub_hostname(invalid_utf8) == rs_is_dns_stub_hostname(invalid_utf8));
        assert_se(is_dns_proxy_stub_hostname(invalid_utf8) == rs_is_dns_proxy_stub_hostname(invalid_utf8));
}

/* ── split_user_at_host ─────────────────────────────────────────────────── */

TEST(split_user_at_host_with_user) {
        _cleanup_free_ char *cu = NULL, *ch = NULL;
        _cleanup_free_ char *ru = NULL, *rh = NULL;

        assert_se(split_user_at_host("root@host", &cu, &ch) > 0);
        assert_se(rs_split_user_at_host("root@host", &ru, &rh) > 0);
        assert_se(streq(cu, ru));
        assert_se(streq(ch, rh));
}

TEST(split_user_at_host_no_user) {
        _cleanup_free_ char *ch = NULL, *rh = NULL;

        assert_se(split_user_at_host("myhost", NULL, &ch) == 0);
        assert_se(rs_split_user_at_host("myhost", NULL, &rh) == 0);
        assert_se(streq(ch, rh));
}

TEST(split_user_at_host_empty_user) {
        _cleanup_free_ char *cu = NULL, *ch = NULL;
        _cleanup_free_ char *ru = NULL, *rh = NULL;

        assert_se(split_user_at_host("@host", &cu, &ch) > 0);
        assert_se(rs_split_user_at_host("@host", &ru, &rh) > 0);
        assert_se(cu == NULL && ru == NULL);
        assert_se(streq(ch, rh));
}

TEST(split_user_at_host_empty_host) {
        _cleanup_free_ char *cu = NULL, *ch = NULL;
        _cleanup_free_ char *ru = NULL, *rh = NULL;

        assert_se(split_user_at_host("user@", &cu, &ch) > 0);
        assert_se(rs_split_user_at_host("user@", &ru, &rh) > 0);
        assert_se(streq(cu, ru));
        assert_se(ch == NULL && rh == NULL);
}

TEST(split_user_at_host_invalid) {
        _cleanup_free_ char *cu = NULL, *ch = NULL;
        _cleanup_free_ char *ru = NULL, *rh = NULL;

        assert_se(split_user_at_host("", &cu, &ch) < 0);
        assert_se(rs_split_user_at_host("", &ru, &rh) < 0);
}

TEST(split_user_at_host_first_separator_and_ownership) {
        _cleanup_free_ char *cu = NULL, *ch = NULL;
        _cleanup_free_ char *ru = NULL, *rh = NULL;

        assert_se(split_user_at_host("user@host@tail", &cu, &ch) > 0);
        assert_se(rs_split_user_at_host("user@host@tail", &ru, &rh) > 0);
        assert_se(streq(cu, ru));
        assert_se(streq(ch, rh));
}

/* ── machine_spec_valid ────────────────────────────────────────────────── */

TEST(machine_spec_valid_basic) {
        assert_se(machine_spec_valid("root@host") == rs_machine_spec_valid("root@host"));
        assert_se(machine_spec_valid("myhost") == rs_machine_spec_valid("myhost"));
}

TEST(machine_spec_valid_invalid) {
        assert_se(machine_spec_valid("") == rs_machine_spec_valid(""));
        assert_se(machine_spec_valid("@") == rs_machine_spec_valid("@"));
        assert_se(machine_spec_valid("invalid user@host") == rs_machine_spec_valid("invalid user@host"));
}

TEST(machine_spec_valid_relaxed_user_and_raw_bytes) {
        const char invalid_utf8[] = "\xFF@host";

        assert_se(machine_spec_valid("user.name@host") == rs_machine_spec_valid("user.name@host"));
        assert_se(machine_spec_valid("user name@host") == rs_machine_spec_valid("user name@host"));
        assert_se(machine_spec_valid(invalid_utf8) == rs_machine_spec_valid(invalid_utf8));
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
