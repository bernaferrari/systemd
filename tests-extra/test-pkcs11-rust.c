/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C pkcs11_uri_valid vs Rust */

#include <assert.h>
#include "tests.h"

/* C header */
#include "pkcs11-util.h"

/* Rust FFI */
#include "rust/shared_facades/validation.h"

static void test_pkcs11_uri_valid(void) {
        /* Valid URIs */
        assert_se(pkcs11_uri_valid("pkcs11:token=mytoken") == rs_pkcs11_uri_valid("pkcs11:token=mytoken"));
        assert_se(pkcs11_uri_valid("pkcs11:token=mytoken") == true);

        assert_se(pkcs11_uri_valid("pkcs11:object=myobj") == rs_pkcs11_uri_valid("pkcs11:object=myobj"));
        assert_se(pkcs11_uri_valid("pkcs11:object=myobj") == true);

        assert_se(pkcs11_uri_valid("pkcs11:pin-value=1234") == rs_pkcs11_uri_valid("pkcs11:pin-value=1234"));
        assert_se(pkcs11_uri_valid("pkcs11:pin-value=1234") == true);

        assert_se(pkcs11_uri_valid("pkcs11:library-manufacturer=Foo;model=Bar") ==
                  rs_pkcs11_uri_valid("pkcs11:library-manufacturer=Foo;model=Bar"));
        assert_se(pkcs11_uri_valid("pkcs11:library-manufacturer=Foo;model=Bar") == true);

        /* With allowed special characters */
        assert_se(pkcs11_uri_valid("pkcs11:a.~_-?;&%=") == rs_pkcs11_uri_valid("pkcs11:a.~_-?;&%="));
        assert_se(pkcs11_uri_valid("pkcs11:a.~_-?;&%=") == true);

        /* Invalid: empty */
        assert_se(pkcs11_uri_valid("") == rs_pkcs11_uri_valid(""));
        assert_se(pkcs11_uri_valid("") == false);

        /* Invalid: no pkcs11: prefix */
        assert_se(pkcs11_uri_valid("http://example.com") == rs_pkcs11_uri_valid("http://example.com"));
        assert_se(pkcs11_uri_valid("http://example.com") == false);

        /* Invalid: pkcs11: prefix only, empty after */
        assert_se(pkcs11_uri_valid("pkcs11:") == rs_pkcs11_uri_valid("pkcs11:"));
        assert_se(pkcs11_uri_valid("pkcs11:") == false);

        /* Invalid: pkcs11: prefix with space */
        assert_se(pkcs11_uri_valid("pkcs11: has space") == rs_pkcs11_uri_valid("pkcs11: has space"));
        assert_se(pkcs11_uri_valid("pkcs11: has space") == false);

        /* Slash test: C accepts / in pkcs11 URI (matches C behavior) */
        assert_se(pkcs11_uri_valid("pkcs11:path/to/thing") == rs_pkcs11_uri_valid("pkcs11:path/to/thing"));

        /* NULL */
        assert_se(pkcs11_uri_valid(NULL) == rs_pkcs11_uri_valid(NULL));
        assert_se(pkcs11_uri_valid(NULL) == false);
}

int main(int argc, char **argv) {
        test_pkcs11_uri_valid();
        return 0;
}
