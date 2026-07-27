/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hostname-util.h"
#include "string-util.h"
#include "tests.h"

TEST(hostname_is_valid_basic) {
        /* Valid hostnames */
        assert_se(hostname_is_valid("localhost", 0));
        assert_se(hostname_is_valid("myhost", 0));
        assert_se(hostname_is_valid("my-host", 0));
        assert_se(hostname_is_valid("a", 0));
        assert_se(hostname_is_valid("0", 0));
        assert_se(hostname_is_valid("my.host.example.com", 0));
        assert_se(hostname_is_valid("foo-bar.baz", 0));

        /* Invalid hostnames */
        assert_se(!hostname_is_valid("", 0));
        assert_se(!hostname_is_valid(NULL, 0));
        assert_se(!hostname_is_valid(".foobar", 0));
        assert_se(!hostname_is_valid("-foobar", 0));
        assert_se(!hostname_is_valid("foobar-", 0));
        assert_se(!hostname_is_valid("foo..bar", 0));
        assert_se(!hostname_is_valid("foo_bar", 0));
        assert_se(!hostname_is_valid("foo bar", 0));
}

TEST(hostname_is_valid_trailing_dot) {
        /* Trailing dot NOT allowed without flag */
        assert_se(!hostname_is_valid("example.com.", 0));

        /* Trailing dot allowed with flag on multi-label */
        assert_se(hostname_is_valid("example.com.", VALID_HOSTNAME_TRAILING_DOT));

        /* Single label with trailing dot still not valid */
        assert_se(!hostname_is_valid("localhost.", VALID_HOSTNAME_TRAILING_DOT));
}

TEST(valid_ldh_char) {
        assert_se(valid_ldh_char('a'));
        assert_se(valid_ldh_char('Z'));
        assert_se(valid_ldh_char('0'));
        assert_se(valid_ldh_char('9'));
        assert_se(valid_ldh_char('-'));

        assert_se(!valid_ldh_char('_'));
        assert_se(!valid_ldh_char('.'));
        assert_se(!valid_ldh_char(' '));
}

TEST(is_localhost_basic) {
        assert_se(is_localhost("localhost"));
        assert_se(is_localhost("localhost."));
        assert_se(is_localhost("localhost.localdomain"));
        assert_se(is_localhost("localhost.localdomain."));
        assert_se(is_localhost("LOCALHOST"));
        assert_se(is_localhost("LocalHost."));
        assert_se(is_localhost("foo.localhost"));
        assert_se(is_localhost("foo.localhost."));

        assert_se(!is_localhost("myhost"));
        assert_se(!is_localhost("example.com"));
}

TEST(is_gateway_hostname) {
        assert_se(is_gateway_hostname("_gateway"));
        assert_se(is_gateway_hostname("_gateway."));
        assert_se(is_gateway_hostname("_GATEWAY"));
        assert_se(is_gateway_hostname("_Gateway."));

        assert_se(!is_gateway_hostname("gateway"));
        assert_se(!is_gateway_hostname("_gateway.foo"));
}

TEST(is_outbound_hostname) {
        assert_se(is_outbound_hostname("_outbound"));
        assert_se(is_outbound_hostname("_outbound."));
        assert_se(is_outbound_hostname("_OUTBOUND"));

        assert_se(!is_outbound_hostname("outbound"));
}

TEST(is_dns_stub_hostname) {
        assert_se(is_dns_stub_hostname("_localdnsstub"));
        assert_se(is_dns_stub_hostname("_localdnsstub."));
        assert_se(is_dns_stub_hostname("_LOCALDNSSTUB"));

        assert_se(!is_dns_stub_hostname("localdnsstub"));
}

TEST(is_dns_proxy_stub_hostname) {
        assert_se(is_dns_proxy_stub_hostname("_localdnsproxy"));
        assert_se(is_dns_proxy_stub_hostname("_localdnsproxy."));

        assert_se(!is_dns_proxy_stub_hostname("localdnsproxy"));
}

TEST(split_user_at_host) {
        _cleanup_free_ char *user = NULL, *host = NULL;
        int r;

        /* user@host */
        user = host = NULL;
        r = split_user_at_host("root@myhost", &user, &host);
        assert_se(r >= 0);
        assert_se(streq(user, "root"));
        assert_se(streq(host, "myhost"));

        /* @host only → user is NULL */
        user = host = NULL;
        r = split_user_at_host("@myhost", &user, &host);
        assert_se(r >= 0);
        assert_se(user == NULL);
        assert_se(streq(host, "myhost"));

        /* user@ only → host is NULL */
        user = host = NULL;
        r = split_user_at_host("user@", &user, &host);
        assert_se(r >= 0);
        assert_se(streq(user, "user"));
        assert_se(host == NULL);

        /* No @ → user is NULL, host is the whole string */
        user = host = NULL;
        r = split_user_at_host("justastring", &user, &host);
        assert_se(r >= 0);
        assert_se(user == NULL);
        assert_se(streq(host, "justastring"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
