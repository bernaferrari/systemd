/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C tpm2 hash/asym/pcr functions vs Rust */

#include "tests.h"
#include "tpm2-util.h"
#include "string-util.h"
#include "rust/netdev_str_tables.h"

static void test_tpm2_hash_alg_to_size(void) {
        int cr, rr;

        cr = tpm2_hash_alg_to_size(TPM2_ALG_SHA1);
        rr = rs_tpm2_hash_alg_to_size(TPM2_ALG_SHA1);
        assert_se(cr == rr);
        assert_se(cr == 20);

        cr = tpm2_hash_alg_to_size(TPM2_ALG_SHA256);
        rr = rs_tpm2_hash_alg_to_size(TPM2_ALG_SHA256);
        assert_se(cr == rr);
        assert_se(cr == 32);

        cr = tpm2_hash_alg_to_size(TPM2_ALG_SHA384);
        rr = rs_tpm2_hash_alg_to_size(TPM2_ALG_SHA384);
        assert_se(cr == rr);
        assert_se(cr == 48);

        cr = tpm2_hash_alg_to_size(TPM2_ALG_SHA512);
        rr = rs_tpm2_hash_alg_to_size(TPM2_ALG_SHA512);
        assert_se(cr == rr);
        assert_se(cr == 64);

        /* Invalid algorithm */
        cr = tpm2_hash_alg_to_size(0);
        rr = rs_tpm2_hash_alg_to_size(0);
        assert_se(cr == rr);
        assert_se(cr < 0);

        cr = tpm2_hash_alg_to_size(0xFFFF);
        rr = rs_tpm2_hash_alg_to_size(0xFFFF);
        assert_se(cr == rr);
        assert_se(cr < 0);
}

static void test_tpm2_hash_alg_to_string(void) {
        const char *cr, *rr;

        cr = tpm2_hash_alg_to_string(TPM2_ALG_SHA1);
        rr = rs_tpm2_hash_alg_to_string(TPM2_ALG_SHA1);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "sha1"));

        cr = tpm2_hash_alg_to_string(TPM2_ALG_SHA256);
        rr = rs_tpm2_hash_alg_to_string(TPM2_ALG_SHA256);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "sha256"));

        cr = tpm2_hash_alg_to_string(TPM2_ALG_SHA384);
        rr = rs_tpm2_hash_alg_to_string(TPM2_ALG_SHA384);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = tpm2_hash_alg_to_string(TPM2_ALG_SHA512);
        rr = rs_tpm2_hash_alg_to_string(TPM2_ALG_SHA512);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        /* Invalid */
        cr = tpm2_hash_alg_to_string(0);
        rr = rs_tpm2_hash_alg_to_string(0);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

static void test_tpm2_hash_alg_from_string(void) {
        int cr, rr;

        cr = tpm2_hash_alg_from_string("sha1");
        rr = rs_tpm2_hash_alg_from_string("sha1");
        assert_se(cr == rr);
        assert_se(cr == TPM2_ALG_SHA1);

        cr = tpm2_hash_alg_from_string("SHA256");
        rr = rs_tpm2_hash_alg_from_string("SHA256");
        assert_se(cr == rr);
        assert_se(cr == TPM2_ALG_SHA256);

        cr = tpm2_hash_alg_from_string("Sha384");
        rr = rs_tpm2_hash_alg_from_string("Sha384");
        assert_se(cr == rr);
        assert_se(cr == TPM2_ALG_SHA384);

        cr = tpm2_hash_alg_from_string("SHA512");
        rr = rs_tpm2_hash_alg_from_string("SHA512");
        assert_se(cr == rr);
        assert_se(cr == TPM2_ALG_SHA512);

        /* Invalid */
        cr = tpm2_hash_alg_from_string("bogus");
        rr = rs_tpm2_hash_alg_from_string("bogus");
        assert_se(cr == rr);
        assert_se(cr < 0);

        cr = tpm2_hash_alg_from_string(NULL);
        rr = rs_tpm2_hash_alg_from_string(NULL);
        assert_se(cr == rr);
        assert_se(cr < 0);
}

static void test_tpm2_asym_alg_to_string(void) {
        const char *cr, *rr;

        cr = tpm2_asym_alg_to_string(TPM2_ALG_ECC);
        rr = rs_tpm2_asym_alg_to_string(TPM2_ALG_ECC);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "ecc"));

        cr = tpm2_asym_alg_to_string(TPM2_ALG_RSA);
        rr = rs_tpm2_asym_alg_to_string(TPM2_ALG_RSA);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "rsa"));

        /* Invalid */
        cr = tpm2_asym_alg_to_string(0);
        rr = rs_tpm2_asym_alg_to_string(0);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

static void test_tpm2_asym_alg_from_string(void) {
        int cr, rr;

        cr = tpm2_asym_alg_from_string("ecc");
        rr = rs_tpm2_asym_alg_from_string("ecc");
        assert_se(cr == rr);
        assert_se(cr == TPM2_ALG_ECC);

        cr = tpm2_asym_alg_from_string("RSA");
        rr = rs_tpm2_asym_alg_from_string("RSA");
        assert_se(cr == rr);
        assert_se(cr == TPM2_ALG_RSA);

        /* Invalid */
        cr = tpm2_asym_alg_from_string("bogus");
        rr = rs_tpm2_asym_alg_from_string("bogus");
        assert_se(cr == rr);
        assert_se(cr < 0);

        cr = tpm2_asym_alg_from_string(NULL);
        rr = rs_tpm2_asym_alg_from_string(NULL);
        assert_se(cr == rr);
        assert_se(cr < 0);
}

static void test_tpm2_pcr_mask_to_string(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;

        /* Empty mask */
        cr = tpm2_pcr_mask_to_string(0);
        rr = rs_tpm2_pcr_mask_to_string(0);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, ""));
        cr = mfree(cr);
        rr = mfree(rr);

        /* Single bit */
        cr = tpm2_pcr_mask_to_string(1);
        rr = rs_tpm2_pcr_mask_to_string(1);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "0"));
        cr = mfree(cr);
        rr = mfree(rr);

        /* Multiple bits */
        cr = tpm2_pcr_mask_to_string(0x7);
        rr = rs_tpm2_pcr_mask_to_string(0x7);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "0+1+2"));
        cr = mfree(cr);
        rr = mfree(rr);

        /* Non-contiguous bits */
        cr = tpm2_pcr_mask_to_string(0x100001);
        rr = rs_tpm2_pcr_mask_to_string(0x100001);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "0+20"));
        cr = mfree(cr);
        rr = mfree(rr);

        /* High bit (23) */
        cr = tpm2_pcr_mask_to_string(1u << 23);
        rr = rs_tpm2_pcr_mask_to_string(1u << 23);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));
        assert_se(streq(rr, "23"));
        cr = mfree(cr);
        rr = mfree(rr);
}

static void test_tpm2_nvpcr_name_is_valid(void) {
        bool cr, rr;

        /* Valid name */
        cr = tpm2_nvpcr_name_is_valid("my-nv-pcr");
        rr = rs_tpm2_nvpcr_name_is_valid("my-nv-pcr");
        assert_se(cr == rr);
        assert_se(cr);

        /* Invalid: empty */
        cr = tpm2_nvpcr_name_is_valid("");
        rr = rs_tpm2_nvpcr_name_is_valid("");
        assert_se(cr == rr);
        assert_se(!cr);

        /* Invalid: NULL */
        cr = tpm2_nvpcr_name_is_valid(NULL);
        rr = rs_tpm2_nvpcr_name_is_valid(NULL);
        assert_se(cr == rr);
        assert_se(!cr);

        /* Invalid: has slash (not valid filename) */
        cr = tpm2_nvpcr_name_is_valid("foo/bar");
        rr = rs_tpm2_nvpcr_name_is_valid("foo/bar");
        assert_se(cr == rr);
        assert_se(!cr);

        /* Invalid: is a PCR index name (like "0") */
        cr = tpm2_nvpcr_name_is_valid("0");
        rr = rs_tpm2_nvpcr_name_is_valid("0");
        assert_se(cr == rr);
        assert_se(!cr);

        /* Invalid: is a named PCR index */
        cr = tpm2_nvpcr_name_is_valid("platform-code");
        rr = rs_tpm2_nvpcr_name_is_valid("platform-code");
        assert_se(cr == rr);
        assert_se(!cr);

        cr = tpm2_nvpcr_name_is_valid("ima");
        rr = rs_tpm2_nvpcr_name_is_valid("ima");
        assert_se(cr == rr);
        assert_se(!cr);

        /* Invalid: has unsafe chars (backslash) */
        cr = tpm2_nvpcr_name_is_valid("foo\\bar");
        rr = rs_tpm2_nvpcr_name_is_valid("foo\\bar");
        assert_se(cr == rr);
        assert_se(!cr);
}

int main(int argc, char **argv) {
        test_tpm2_hash_alg_to_size();
        test_tpm2_hash_alg_to_string();
        test_tpm2_hash_alg_from_string();
        test_tpm2_asym_alg_to_string();
        test_tpm2_asym_alg_from_string();
        test_tpm2_pcr_mask_to_string();
        test_tpm2_nvpcr_name_is_valid();
        return 0;
}
