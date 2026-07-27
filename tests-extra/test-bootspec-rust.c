/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C boot_filename_extract_tries vs Rust, bootspec_pick_name_version_sort_key */

#include "tests.h"
#include "bootspec.h"
#include "rust/bootspec_util.h"

static void test_extract_tries_one(
                const char *fname,
                int ret,
                const char *stripped,
                unsigned tries_left,
                unsigned tries_done,
                bool use_rust) {

        _cleanup_free_ char *p = NULL;
        unsigned l, d;

        if (use_rust)
                assert_se(rs_boot_filename_extract_tries(fname, &p, &l, &d) == ret);
        else
                assert_se(boot_filename_extract_tries(fname, &p, &l, &d) == ret);

        if (ret < 0)
                return;

        ASSERT_STREQ(p, stripped);
        assert_se(l == tries_left);
        assert_se(d == tries_done);
}

static void test_extract_both(
                const char *fname,
                int ret,
                const char *stripped,
                unsigned tries_left,
                unsigned tries_done) {

        test_extract_tries_one(fname, ret, stripped, tries_left, tries_done, /* use_rust= */ false);
        test_extract_tries_one(fname, ret, stripped, tries_left, tries_done, /* use_rust= */ true);
}

static void test_boot_filename_extract_tries(void) {
        /* No tries in filename */
        test_extract_both("foo.conf", 0, "foo.conf", UINT_MAX, UINT_MAX);

        /* Single try count */
        test_extract_both("foo+0.conf", 0, "foo.conf", 0, UINT_MAX);
        test_extract_both("foo+1.conf", 0, "foo.conf", 1, UINT_MAX);
        test_extract_both("foo+2.conf", 0, "foo.conf", 2, UINT_MAX);
        test_extract_both("foo+33.conf", 0, "foo.conf", 33, UINT_MAX);

        assert_cc(INT_MAX == INT32_MAX);
        test_extract_both("foo+2147483647.conf", 0, "foo.conf", 2147483647, UINT_MAX);
        test_extract_both("foo+2147483648.conf", -ERANGE, NULL, UINT_MAX, UINT_MAX);

        /* Both try counts */
        test_extract_both("foo+33-0.conf", 0, "foo.conf", 33, 0);
        test_extract_both("foo+33-1.conf", 0, "foo.conf", 33, 1);
        test_extract_both("foo+33-107.conf", 0, "foo.conf", 33, 107);
        test_extract_both("foo+33-107.efi", 0, "foo.efi", 33, 107);
        test_extract_both("foo+33-2147483647.conf", 0, "foo.conf", 33, 2147483647);
        test_extract_both("foo+33-2147483648.conf", -ERANGE, NULL, UINT_MAX, UINT_MAX);

        /* Leading zeros */
        test_extract_both("foo+007-000008.conf", 0, "foo.conf", 7, 8);

        /* No plus before suffix — not a tries filename */
        test_extract_both("foo-1.conf", 0, "foo-1.conf", UINT_MAX, UINT_MAX);
        test_extract_both("foo-999.conf", 0, "foo-999.conf", UINT_MAX, UINT_MAX);
        test_extract_both("foo-.conf", 0, "foo-.conf", UINT_MAX, UINT_MAX);

        /* Plus but no digits */
        test_extract_both("foo+.conf", 0, "foo+.conf", UINT_MAX, UINT_MAX);
        test_extract_both("+.conf", 0, "+.conf", UINT_MAX, UINT_MAX);
        test_extract_both("-.conf", 0, "-.conf", UINT_MAX, UINT_MAX);

        /* Empty filename */
        test_extract_both("", 0, "", UINT_MAX, UINT_MAX);

        /* No suffix (no dot) */
        test_extract_both("+1", 0, "+1", UINT_MAX, UINT_MAX);
        test_extract_both("+1-7", 0, "+1-7", UINT_MAX, UINT_MAX);

        /* Multiple plus signs — uses last one before suffix */
        test_extract_both("some+name+24324-22.efi", 0, "some+name.efi", 24324, 22);
        test_extract_both("sels+2-3+7-6.", 0, "sels+2-3.", 7, 6);

        /* Trailing junk after tries */
        test_extract_both("a+1-2..", 0, "a+1-2..", UINT_MAX, UINT_MAX);

        /* Dots before plus */
        test_extract_both("ses.sgesge.+4-1.efi", 0, "ses.sgesge..efi", 4, 1);

        /* Non-digit after plus */
        test_extract_both("abc+0x4.conf", 0, "abc+0x4.conf", UINT_MAX, UINT_MAX);
        test_extract_both("def+1-0x3.conf", 0, "def+1-0x3.conf", UINT_MAX, UINT_MAX);
}

static void test_bootspec_pick_name_version_sort_key(void) {
        const char *cr_name, *cr_version, *cr_sort_key;
        const char *rr_name, *rr_version, *rr_sort_key;
        bool cr, rr;

        /* All fields present */
        cr = bootspec_pick_name_version_sort_key(
                        "Fedora Linux 40", "fedora", "Fedora", "fedora",
                        "40.1", "40", "40", "20240401",
                        &cr_name, &cr_version, &cr_sort_key);
        rr = rs_bootspec_pick_name_version_sort_key(
                        "Fedora Linux 40", "fedora", "Fedora", "fedora",
                        "40.1", "40", "40", "20240401",
                        &rr_name, &rr_version, &rr_sort_key);
        assert_se(cr == rr && cr == true);
        assert_se(streq(cr_name, rr_name));
        assert_se(streq(cr_name, "Fedora Linux 40"));
        assert_se(streq(cr_version, rr_version));
        assert_se(streq(cr_version, "40.1"));
        assert_se(streq(cr_sort_key, rr_sort_key));
        assert_se(streq(cr_sort_key, "fedora"));

        /* No pretty_name, falls back to image_id */
        cr = bootspec_pick_name_version_sort_key(
                        NULL, "myimage", "Fedora", "fedora",
                        "1.0", "40", "40", "20240401",
                        &cr_name, &cr_version, &cr_sort_key);
        rr = rs_bootspec_pick_name_version_sort_key(
                        NULL, "myimage", "Fedora", "fedora",
                        "1.0", "40", "40", "20240401",
                        &rr_name, &rr_version, &rr_sort_key);
        assert_se(cr == rr && cr == true);
        assert_se(streq(cr_name, rr_name));
        assert_se(streq(cr_name, "myimage"));

        /* Only name and id */
        cr = bootspec_pick_name_version_sort_key(
                        NULL, NULL, "Fedora", "fedora",
                        NULL, "40", "40", "20240401",
                        &cr_name, &cr_version, &cr_sort_key);
        rr = rs_bootspec_pick_name_version_sort_key(
                        NULL, NULL, "Fedora", "fedora",
                        NULL, "40", "40", "20240401",
                        &rr_name, &rr_version, &rr_sort_key);
        assert_se(cr == rr && cr == true);
        assert_se(streq(cr_name, rr_name));
        assert_se(streq(cr_name, "Fedora"));
        assert_se(streq(cr_sort_key, rr_sort_key));
        assert_se(streq(cr_sort_key, "fedora"));

        /* Only id */
        cr = bootspec_pick_name_version_sort_key(
                        NULL, NULL, NULL, "fedora",
                        NULL, NULL, NULL, NULL,
                        &cr_name, &cr_version, &cr_sort_key);
        rr = rs_bootspec_pick_name_version_sort_key(
                        NULL, NULL, NULL, "fedora",
                        NULL, NULL, NULL, NULL,
                        &rr_name, &rr_version, &rr_sort_key);
        assert_se(cr == rr && cr == true);
        assert_se(streq(cr_name, rr_name));
        assert_se(streq(cr_name, "fedora"));

        /* All NULL — returns false */
        cr = bootspec_pick_name_version_sort_key(
                        NULL, NULL, NULL, NULL,
                        NULL, NULL, NULL, NULL,
                        &cr_name, &cr_version, &cr_sort_key);
        rr = rs_bootspec_pick_name_version_sort_key(
                        NULL, NULL, NULL, NULL,
                        NULL, NULL, NULL, NULL,
                        &rr_name, &rr_version, &rr_sort_key);
        assert_se(cr == rr && cr == false);

        /* NULL output pointers */
        cr = bootspec_pick_name_version_sort_key(
                        "Name", "img", "N", "id", "1.0", "1", "1", "b",
                        NULL, NULL, NULL);
        rr = rs_bootspec_pick_name_version_sort_key(
                        "Name", "img", "N", "id", "1.0", "1", "1", "b",
                        NULL, NULL, NULL);
        assert_se(cr == rr && cr == true);

        /* Version fallback chain: image_version → version → version_id → build_id */
        cr = bootspec_pick_name_version_sort_key(
                        "Name", "img", "N", "id",
                        NULL, NULL, "42", NULL,
                        &cr_name, &cr_version, &cr_sort_key);
        rr = rs_bootspec_pick_name_version_sort_key(
                        "Name", "img", "N", "id",
                        NULL, NULL, "42", NULL,
                        &rr_name, &rr_version, &rr_sort_key);
        assert_se(cr == rr);
        assert_se(streq(cr_version, rr_version));
        assert_se(streq(cr_version, "42"));
}

int main(int argc, char **argv) {
        test_boot_filename_extract_tries();
        test_bootspec_pick_name_version_sort_key();
        return 0;
}
