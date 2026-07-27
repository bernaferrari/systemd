/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "pkcs11-util.h"

TEST(pkcs11_uri_valid) {
        /* Valid URIs */
        assert_se(pkcs11_uri_valid("pkcs11:token=Foo"));
        assert_se(pkcs11_uri_valid("pkcs11:token=Foo;object=Bar"));
        assert_se(pkcs11_uri_valid("pkcs11:id=%01%02"));
        assert_se(pkcs11_uri_valid("pkcs11:token=test-token;type=private"));
        assert_se(pkcs11_uri_valid("pkcs11:object=cert;id=%aa%bb"));

        /* Invalid: empty */
        assert_se(!pkcs11_uri_valid(""));
        assert_se(!pkcs11_uri_valid(NULL));

        /* Invalid: no pkcs11: prefix */
        assert_se(!pkcs11_uri_valid("http://example.com"));
        assert_se(!pkcs11_uri_valid("pkcs11"));

        /* Invalid: pkcs11: with nothing after */
        assert_se(!pkcs11_uri_valid("pkcs11:"));

        /* Invalid: bad characters */
        assert_se(!pkcs11_uri_valid("pkcs11:token=foo bar"));
        assert_se(!pkcs11_uri_valid("pkcs11:token=foo@bar"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
