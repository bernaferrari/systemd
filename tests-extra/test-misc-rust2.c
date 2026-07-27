/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C btrfs_might_be_subvol, json_underscorify, json_dashify,
 *             suitable_blob_filename, decode_modhex_char, normalize_recovery_key vs Rust */

#include "tests.h"
#include "stat-util.h"
#include "string-util.h"
#include "btrfs-util.h"
#include "user-record.h"
#include "recovery-key.h"
#include "json-util.h"
#include "rust/stat_util.h"
#include "rust/string_util.h"
#include "rust/shared_facades/validation.h"
#include "rust/recovery_key.h"

static void test_btrfs_might_be_subvol(void) {
        struct stat st;
        bool cr, rr;

        /* Directory with inode 256 = btrfs subvolume */
        zero(st);
        st.st_mode = S_IFDIR;
        st.st_ino = 256;
        cr = btrfs_might_be_subvol(&st);
        rr = rs_btrfs_might_be_subvol(&st);
        assert_se(cr == rr);
        assert_se(cr);

        /* Directory with other inode */
        zero(st);
        st.st_mode = S_IFDIR;
        st.st_ino = 2;
        cr = btrfs_might_be_subvol(&st);
        rr = rs_btrfs_might_be_subvol(&st);
        assert_se(cr == rr);
        assert_se(!cr);

        /* Regular file with inode 256 */
        zero(st);
        st.st_mode = S_IFREG;
        st.st_ino = 256;
        cr = btrfs_might_be_subvol(&st);
        rr = rs_btrfs_might_be_subvol(&st);
        assert_se(cr == rr);
        assert_se(!cr);

        /* NULL */
        cr = btrfs_might_be_subvol(NULL);
        rr = rs_btrfs_might_be_subvol(NULL);
        assert_se(cr == rr);
        assert_se(!cr);
}

static void test_json_underscorify(void) {
        _cleanup_free_ char *c1 = strdup("hello-world+test");
        _cleanup_free_ char *r1 = strdup("hello-world+test");

        assert_se(streq(json_underscorify(c1), "hello_world_test"));
        assert_se(streq(rs_json_underscorify(r1), "hello_world_test"));

        /* Already underscores */
        c1 = mfree(c1);
        r1 = mfree(r1);
        c1 = strdup("hello_world");
        r1 = strdup("hello_world");
        assert_se(streq(json_underscorify(c1), "hello_world"));
        assert_se(streq(rs_json_underscorify(r1), "hello_world"));

        /* NULL */
        assert_se(json_underscorify(NULL) == NULL);
        assert_se(rs_json_underscorify(NULL) == NULL);

        /* Empty */
        c1 = mfree(c1);
        r1 = mfree(r1);
        c1 = strdup("");
        r1 = strdup("");
        assert_se(streq(json_underscorify(c1), ""));
        assert_se(streq(rs_json_underscorify(r1), ""));
}

static void test_json_dashify(void) {
        _cleanup_free_ char *c1 = strdup("hello_world+test");
        _cleanup_free_ char *r1 = strdup("hello_world+test");

        assert_se(streq(json_dashify(c1), "hello-world-test"));
        assert_se(streq(rs_json_dashify(r1), "hello-world-test"));

        /* Already dashes */
        c1 = mfree(c1);
        r1 = mfree(r1);
        c1 = strdup("hello-world");
        r1 = strdup("hello-world");
        assert_se(streq(json_dashify(c1), "hello-world"));
        assert_se(streq(rs_json_dashify(r1), "hello-world"));

        /* NULL */
        assert_se(json_dashify(NULL) == NULL);
        assert_se(rs_json_dashify(NULL) == NULL);
}

static void test_suitable_blob_filename(void) {
        int cr, rr;

        /* Valid: alphanumeric */
        cr = suitable_blob_filename("abc123");
        rr = rs_suitable_blob_filename("abc123");
        assert_se(cr == rr);
        assert_se(cr);

        /* Valid: with dash, dot, tilde */
        cr = suitable_blob_filename("my-file.v2~");
        rr = rs_suitable_blob_filename("my-file.v2~");
        assert_se(cr == rr);
        assert_se(cr);

        /* Invalid: starts with dot */
        cr = suitable_blob_filename(".hidden");
        rr = rs_suitable_blob_filename(".hidden");
        assert_se(cr == rr);
        assert_se(!cr);

        /* Invalid: has space (not in URI_UNRESERVED) */
        cr = suitable_blob_filename("has space");
        rr = rs_suitable_blob_filename("has space");
        assert_se(cr == rr);
        assert_se(!cr);

        /* Invalid: has slash */
        cr = suitable_blob_filename("foo/bar");
        rr = rs_suitable_blob_filename("foo/bar");
        assert_se(cr == rr);
        assert_se(!cr);

        /* Invalid: empty */
        cr = suitable_blob_filename("");
        rr = rs_suitable_blob_filename("");
        assert_se(cr == rr);
        assert_se(!cr);

        /* Invalid: NULL */
        cr = suitable_blob_filename(NULL);
        rr = rs_suitable_blob_filename(NULL);
        assert_se(cr == rr);
        assert_se(!cr);
}

static void test_decode_modhex_char(void) {
        int cr, rr;

        /* Valid lowercase */
        cr = decode_modhex_char('c');
        rr = rs_decode_modhex_char('c');
        assert_se(cr == rr);
        assert_se(cr == 0);

        cr = decode_modhex_char('v');
        rr = rs_decode_modhex_char('v');
        assert_se(cr == rr);
        assert_se(cr == 15);

        /* Valid uppercase */
        cr = decode_modhex_char('C');
        rr = rs_decode_modhex_char('C');
        assert_se(cr == rr);
        assert_se(cr == 0);

        /* Invalid */
        cr = decode_modhex_char('a');
        rr = rs_decode_modhex_char('a');
        assert_se(cr == rr);
        assert_se(cr < 0);

        cr = decode_modhex_char('0');
        rr = rs_decode_modhex_char('0');
        assert_se(cr == rr);
        assert_se(cr < 0);
}

static void test_normalize_recovery_key(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        int rc, rrs;

        /* Valid: without dashes (64 chars) */
        rc = normalize_recovery_key("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", &cr);
        rrs = rs_normalize_recovery_key("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", &rr);
        assert_se(rc == rrs);
        assert_se(rc == 0);
        if (cr && rr) {
                assert_se(streq(cr, rr));
                assert_se(strlen(rr) == RECOVERY_KEY_MODHEX_FORMATTED_LENGTH - 1); /* 71 printable chars */
        }
        cr = mfree(cr);
        rr = mfree(rr);

        /* Invalid: wrong length */
        rc = normalize_recovery_key("short", &cr);
        rrs = rs_normalize_recovery_key("short", &rr);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* Invalid: contains non-modhex chars (64 chars but 'a' is not in modhex) */
        rc = normalize_recovery_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &cr);
        rrs = rs_normalize_recovery_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &rr);
        assert_se(rc == rrs);
        assert_se(rc < 0);

        /* NULL — C asserts on NULL, only test Rust */
        rrs = rs_normalize_recovery_key(NULL, &rr);
        assert_se(rrs < 0);
}

int main(int argc, char **argv) {
        test_btrfs_might_be_subvol();
        test_json_underscorify();
        test_json_dashify();
        test_suitable_blob_filename();
        test_decode_modhex_char();
        test_normalize_recovery_key();
        return 0;
}
