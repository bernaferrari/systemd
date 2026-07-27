/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C fileio/fs-util functions vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "fileio.h"
#include "fs-util.h"

/* Rust FFI forward declarations */
int rs_fopen_mode_to_flags(const char *mode);
int rs_parse_cifs_service(const char *s, char **ret_host, char **ret_service, char **ret_path);

/* -- fopen_mode_to_flags -------------------------------------------------- */

static void test_fopen_mode_to_flags(void) {
        assert_se(fopen_mode_to_flags("r") == rs_fopen_mode_to_flags("r"));
        assert_se(fopen_mode_to_flags("w") == rs_fopen_mode_to_flags("w"));
        assert_se(fopen_mode_to_flags("a") == rs_fopen_mode_to_flags("a"));
        assert_se(fopen_mode_to_flags("r+") == rs_fopen_mode_to_flags("r+"));
        assert_se(fopen_mode_to_flags("w+") == rs_fopen_mode_to_flags("w+"));
        assert_se(fopen_mode_to_flags("a+") == rs_fopen_mode_to_flags("a+"));

        /* With 'e' (O_CLOEXEC) */
        assert_se(fopen_mode_to_flags("re") == rs_fopen_mode_to_flags("re"));
        assert_se(fopen_mode_to_flags("we") == rs_fopen_mode_to_flags("we"));
        assert_se(fopen_mode_to_flags("ae") == rs_fopen_mode_to_flags("ae"));
        assert_se(fopen_mode_to_flags("r+e") == rs_fopen_mode_to_flags("r+e"));
        assert_se(fopen_mode_to_flags("w+e") == rs_fopen_mode_to_flags("w+e"));

        /* With 'x' (O_EXCL) */
        assert_se(fopen_mode_to_flags("wx") == rs_fopen_mode_to_flags("wx"));
        assert_se(fopen_mode_to_flags("rx") == rs_fopen_mode_to_flags("rx"));

        /* With 'm' (ignored) */
        assert_se(fopen_mode_to_flags("rm") == rs_fopen_mode_to_flags("rm"));
        assert_se(fopen_mode_to_flags("rme") == rs_fopen_mode_to_flags("rme"));

        /* Combined */
        assert_se(fopen_mode_to_flags("wxe") == rs_fopen_mode_to_flags("wxe"));
        assert_se(fopen_mode_to_flags("r+xe") == rs_fopen_mode_to_flags("r+xe"));

        /* Invalid */
        assert_se(fopen_mode_to_flags("x") == rs_fopen_mode_to_flags("x"));
        assert_se(fopen_mode_to_flags("c") == rs_fopen_mode_to_flags("c"));
        assert_se(fopen_mode_to_flags("") == rs_fopen_mode_to_flags(""));

        /* Verify specific flag values */
        assert_se(fopen_mode_to_flags("r") >= 0); /* O_RDONLY = 0 */
        assert_se(fopen_mode_to_flags("w") & O_CREAT);
        assert_se(fopen_mode_to_flags("w") & O_TRUNC);
        assert_se(fopen_mode_to_flags("re") & O_CLOEXEC);
        assert_se(fopen_mode_to_flags("wx") & O_EXCL);
}

/* -- parse_cifs_service --------------------------------------------------- */

static void test_parse_cifs_service_basic(void) {
        _cleanup_free_ char *c_host = NULL, *c_service = NULL, *c_path = NULL;
        char *rs_host = NULL, *rs_service = NULL, *rs_path = NULL;
        int cr, rs_r;

        /* Basic //host/service */
        cr = parse_cifs_service("//server/share", &c_host, &c_service, &c_path);
        rs_r = rs_parse_cifs_service("//server/share", &rs_host, &rs_service, &rs_path);
        assert_se(cr == rs_r);
        assert_se(cr >= 0);
        assert_se(streq(c_host, rs_host));
        assert_se(streq(c_service, rs_service));
        assert_se(c_path == NULL && rs_path == NULL);
        free(rs_host);
        free(rs_service);

        /* With path */
        c_host = c_service = c_path = NULL;
        rs_host = rs_service = rs_path = NULL;
        cr = parse_cifs_service("//server/share/dir/file.txt", &c_host, &c_service, &c_path);
        rs_r = rs_parse_cifs_service("//server/share/dir/file.txt", &rs_host, &rs_service, &rs_path);
        assert_se(cr == rs_r);
        assert_se(cr >= 0);
        assert_se(streq(c_host, rs_host));
        assert_se(streq(c_service, rs_service));
        assert_se(streq(c_path, rs_path));
        free(rs_host);
        free(rs_service);
        free(rs_path);

        /* Backslash syntax */
        c_host = c_service = c_path = NULL;
        rs_host = rs_service = rs_path = NULL;
        cr = parse_cifs_service("\\\\server\\share\\dir", &c_host, &c_service, &c_path);
        rs_r = rs_parse_cifs_service("\\\\server\\share\\dir", &rs_host, &rs_service, &rs_path);
        assert_se(cr == rs_r);
        assert_se(cr >= 0);
        assert_se(streq(c_host, rs_host));
        assert_se(streq(c_service, rs_service));
        /* Backslash paths get converted to forward slashes */
        assert_se(streq(c_path, rs_path));
        free(rs_host);
        free(rs_service);
        free(rs_path);

        /* No path component */
        c_host = c_service = c_path = NULL;
        rs_host = rs_service = rs_path = NULL;
        cr = parse_cifs_service("//host/svc", &c_host, &c_service, NULL);
        rs_r = rs_parse_cifs_service("//host/svc", &rs_host, &rs_service, NULL);
        assert_se(cr == rs_r);
        assert_se(cr >= 0);
        assert_se(streq(c_host, rs_host));
        assert_se(streq(c_service, rs_service));
        free(rs_host);
        free(rs_service);

        /* Errors */
        assert_se(parse_cifs_service(NULL, &c_host, &c_service, &c_path) ==
                   rs_parse_cifs_service(NULL, &rs_host, &rs_service, &rs_path));
        assert_se(parse_cifs_service("host/share", &c_host, &c_service, &c_path) ==
                   rs_parse_cifs_service("host/share", &rs_host, &rs_service, &rs_path));
        assert_se(parse_cifs_service("//server", &c_host, &c_service, &c_path) ==
                   rs_parse_cifs_service("//server", &rs_host, &rs_service, &rs_path));
}

int main(int argc, char **argv) {
        test_fopen_mode_to_flags();
        test_parse_cifs_service_basic();
        return 0;
}
