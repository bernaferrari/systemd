/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C user-util validators vs Rust */
/* RUST-CONTRACT: user-name-validation */
/* RUST-CONTRACT: capsule-name-validation */
/* RUST-CONTRACT: uid-validation */
/* RUST-CONTRACT: uid-parsing */
/* RUST-CONTRACT: id128-validation */
/* RUST-CONTRACT: password-lock-predicate */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "user-util.h"
#include "capsule-util.h"
#include "sd-id128.h"
#include "id128-util.h"
#include "strv.h"
#include "rust/user_util.h"

/* ValidUserFlags */
#define RS_VALID_USER_RELAX         1u
#define RS_VALID_USER_WARN          2u
#define RS_VALID_USER_ALLOW_NUMERIC 4u

/* -- valid_user_group_name (strict) --------------------------------------- */

static void test_valid_user_group_name_strict(void) {
        unsigned int flags = 0;

        /* Valid strict names */
        assert_se(valid_user_group_name("root", flags) == rs_valid_user_group_name("root", flags));
        assert_se(valid_user_group_name("root", flags) == true);

        assert_se(valid_user_group_name("_systemd", flags) == rs_valid_user_group_name("_systemd", flags));
        assert_se(valid_user_group_name("_systemd", flags) == true);

        assert_se(valid_user_group_name("my-user", flags) == rs_valid_user_group_name("my-user", flags));
        assert_se(valid_user_group_name("my-user", flags) == true);

        assert_se(valid_user_group_name("user123", flags) == rs_valid_user_group_name("user123", flags));
        assert_se(valid_user_group_name("user123", flags) == true);

        /* Empty */
        assert_se(valid_user_group_name("", flags) == rs_valid_user_group_name("", flags));
        assert_se(valid_user_group_name("", flags) == false);

        /* NULL */
        assert_se(valid_user_group_name(NULL, flags) == rs_valid_user_group_name(NULL, flags));
        assert_se(valid_user_group_name(NULL, flags) == false);

        /* Starts with digit */
        assert_se(valid_user_group_name("0user", flags) == rs_valid_user_group_name("0user", flags));
        assert_se(valid_user_group_name("0user", flags) == false);

        /* Starts with hyphen */
        assert_se(valid_user_group_name("-user", flags) == rs_valid_user_group_name("-user", flags));
        assert_se(valid_user_group_name("-user", flags) == false);

        /* Contains dot */
        assert_se(valid_user_group_name("user.name", flags) == rs_valid_user_group_name("user.name", flags));
        assert_se(valid_user_group_name("user.name", flags) == false);

        /* Contains colon */
        assert_se(valid_user_group_name("user:name", flags) == rs_valid_user_group_name("user:name", flags));
        assert_se(valid_user_group_name("user:name", flags) == false);

        /* Numeric — strict mode rejects */
        assert_se(valid_user_group_name("12345", flags) == rs_valid_user_group_name("12345", flags));
        assert_se(valid_user_group_name("12345", flags) == false);

        /* With ALLOW_NUMERIC flag */
        flags = RS_VALID_USER_ALLOW_NUMERIC;
        assert_se(valid_user_group_name("12345", flags) == rs_valid_user_group_name("12345", flags));
        assert_se(valid_user_group_name("0", flags) == rs_valid_user_group_name("0", flags));
        assert_se(valid_user_group_name("0", flags) == true);

        flags = 0;

        /* Special characters */
        assert_se(valid_user_group_name("user@host", flags) == rs_valid_user_group_name("user@host", flags));
        assert_se(valid_user_group_name("user@host", flags) == false);

        assert_se(valid_user_group_name("user name", flags) == rs_valid_user_group_name("user name", flags));
        assert_se(valid_user_group_name("user name", flags) == false);
}

/* -- valid_user_group_name (relaxed) --------------------------------------- */

static void test_valid_user_group_name_relaxed(void) {
        unsigned int flags = RS_VALID_USER_RELAX;

        /* Valid relaxed names */
        assert_se(valid_user_group_name("user.name", flags) == rs_valid_user_group_name("user.name", flags));
        assert_se(valid_user_group_name("user.name", flags) == true);

        assert_se(valid_user_group_name("User Name", flags) == rs_valid_user_group_name("User Name", flags));
        assert_se(valid_user_group_name("User Name", flags) == true);

        assert_se(valid_user_group_name("user@domain", flags) == rs_valid_user_group_name("user@domain", flags));
        assert_se(valid_user_group_name("user@domain", flags) == true);

        /* C1 control code points are multibyte UTF-8 and are not ASCII CC bytes. */
        assert_se(valid_user_group_name("user\xc2\x85name", flags) ==
                  rs_valid_user_group_name("user\xc2\x85name", flags));
        assert_se(valid_user_group_name("user\xc2\x85name", flags) == true);

        /* Still rejects empty */
        assert_se(valid_user_group_name("", flags) == rs_valid_user_group_name("", flags));
        assert_se(valid_user_group_name("", flags) == false);

        /* Rejects leading/trailing space */
        assert_se(valid_user_group_name(" user", flags) == rs_valid_user_group_name(" user", flags));
        assert_se(valid_user_group_name(" user", flags) == false);

        assert_se(valid_user_group_name("user ", flags) == rs_valid_user_group_name("user ", flags));
        assert_se(valid_user_group_name("user ", flags) == false);

        /* Rejects control chars */
        assert_se(valid_user_group_name("user\nname", flags) == rs_valid_user_group_name("user\nname", flags));
        assert_se(valid_user_group_name("user\nname", flags) == false);

        /* Rejects colons and slashes */
        assert_se(valid_user_group_name("user:name", flags) == rs_valid_user_group_name("user:name", flags));
        assert_se(valid_user_group_name("user:name", flags) == false);

        assert_se(valid_user_group_name("user/name", flags) == rs_valid_user_group_name("user/name", flags));
        assert_se(valid_user_group_name("user/name", flags) == false);

        /* Rejects numeric */
        assert_se(valid_user_group_name("12345", flags) == rs_valid_user_group_name("12345", flags));
        assert_se(valid_user_group_name("12345", flags) == false);

        assert_se(valid_user_group_name("-1", flags) == rs_valid_user_group_name("-1", flags));
        assert_se(valid_user_group_name("-1", flags) == false);

        /* Rejects . and .. */
        assert_se(valid_user_group_name(".", flags) == rs_valid_user_group_name(".", flags));
        assert_se(valid_user_group_name(".", flags) == false);

        assert_se(valid_user_group_name("..", flags) == rs_valid_user_group_name("..", flags));
        assert_se(valid_user_group_name("..", flags) == false);

        /* Whitespace-only is rejected (leading space check) */
        assert_se(valid_user_group_name("   ", flags) == rs_valid_user_group_name("   ", flags));
        assert_se(valid_user_group_name("   ", flags) == false);
}

/* -- capsule_name_is_valid ------------------------------------------------ */

static void test_capsule_name_is_valid(void) {
        /* Valid capsule names (must be valid filename and "c-<name>" must be valid user/group) */
        assert_se(capsule_name_is_valid("mycapsule") == rs_capsule_name_is_valid("mycapsule"));
        assert_se(capsule_name_is_valid("mycapsule") > 0);

        assert_se(capsule_name_is_valid("my-capsule") == rs_capsule_name_is_valid("my-capsule"));
        assert_se(capsule_name_is_valid("my-capsule") > 0);

        /* "c-1bad" is valid in strict mode (first char 'c' is alpha, '-' allowed after) */
        assert_se(capsule_name_is_valid("1bad") == rs_capsule_name_is_valid("1bad"));
        assert_se(capsule_name_is_valid("1bad") > 0);

        /* "c--bad" is valid in strict mode (hyphens allowed after first char) */
        assert_se(capsule_name_is_valid("-bad") == rs_capsule_name_is_valid("-bad"));
        assert_se(capsule_name_is_valid("-bad") > 0);

        /* Invalid: starts with colon → "c-:bad" is not valid */
        assert_se(capsule_name_is_valid(":bad") == rs_capsule_name_is_valid(":bad"));
        assert_se(capsule_name_is_valid(":bad") == 0);

        /* Invalid: empty */
        assert_se(capsule_name_is_valid("") == rs_capsule_name_is_valid(""));
        assert_se(capsule_name_is_valid("") == 0);

        /* Invalid: has slash (not valid filename) */
        assert_se(capsule_name_is_valid("a/b") == rs_capsule_name_is_valid("a/b"));
        assert_se(capsule_name_is_valid("a/b") == 0);

        /* Invalid: dot */
        assert_se(capsule_name_is_valid(".") == rs_capsule_name_is_valid("."));
        assert_se(capsule_name_is_valid(".") == 0);
}

/* -- uid_is_valid -------------------------------------------------------- */

static void test_uid_is_valid(void) {
        assert_se(uid_is_valid(0) == rs_uid_is_valid(0));
        assert_se(uid_is_valid(0) == true);

        assert_se(uid_is_valid(1) == rs_uid_is_valid(1));
        assert_se(uid_is_valid(1) == true);

        assert_se(uid_is_valid(65534) == rs_uid_is_valid(65534));
        assert_se(uid_is_valid(65534) == true);

        assert_se(uid_is_valid(65535) == rs_uid_is_valid(65535));
        assert_se(uid_is_valid(65535) == false); /* old 16-bit -1 */

        assert_se(uid_is_valid(UINT32_MAX) == rs_uid_is_valid(UINT32_MAX));
        assert_se(uid_is_valid(UINT32_MAX) == false); /* UID_INVALID */

        assert_se(uid_is_valid(4294967294u) == rs_uid_is_valid(4294967294u));
        assert_se(uid_is_valid(4294967294u) == true);
}

/* -- parse_uid ------------------------------------------------------------ */

static void test_parse_uid(void) {
        uid_t cv, rv;
        int cr, rr;

        /* Valid UIDs */
        cr = parse_uid("0", &cv);
        rr = rs_parse_uid("0", &rv);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cv == rv);
        assert_se(cv == 0);

        cr = parse_uid("1", &cv);
        rr = rs_parse_uid("1", &rv);
        assert_se(cr == rr);
        assert_se(cr == 0);

        cr = parse_uid("1000", &cv);
        rr = rs_parse_uid("1000", &rv);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cv == rv);
        assert_se(cv == 1000);

        cr = parse_uid("65534", &cv);
        rr = rs_parse_uid("65534", &rv);
        assert_se(cr == rr);
        assert_se(cr == 0);

        /* Invalid: leading zero */
        cr = parse_uid("01", &cv);
        rr = rs_parse_uid("01", &rv);
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Invalid: leading whitespace */
        cr = parse_uid(" 1", &cv);
        rr = rs_parse_uid(" 1", &rv);
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Invalid: plus sign */
        cr = parse_uid("+1", &cv);
        rr = rs_parse_uid("+1", &rv);
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Invalid: minus sign */
        cr = parse_uid("-1", &cv);
        rr = rs_parse_uid("-1", &rv);
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Invalid: empty */
        cr = parse_uid("", &cv);
        rr = rs_parse_uid("", &rv);
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Invalid: non-numeric */
        cr = parse_uid("root", &cv);
        rr = rs_parse_uid("root", &rv);
        assert_se(cr == rr);
        assert_se(cr < 0);

        /* Invalid: 0xFFFF */
        cr = parse_uid("65535", &cv);
        rr = rs_parse_uid("65535", &rv);
        assert_se(cr == rr);
        assert_se(cr == -ENXIO);

        /* Invalid: 0xFFFFFFFF */
        cr = parse_uid("4294967295", &cv);
        rr = rs_parse_uid("4294967295", &rv);
        assert_se(cr == rr);
        assert_se(cr == -ENXIO);

        /* Error returns do not publish a partially parsed UID. */
        cv = 1111;
        rv = 2222;
        cr = parse_uid("not-a-uid", &cv);
        rr = rs_parse_uid("not-a-uid", &rv);
        assert_se(cr == rr);
        assert_se(cr < 0);
        assert_se(cv == 1111);
        assert_se(rv == 2222);

        /* NULL ret pointer */
        cr = parse_uid("0", NULL);
        rr = rs_parse_uid("0", NULL);
        assert_se(cr == rr);
        assert_se(cr == 0);
}

/* -- parse_uid_range ------------------------------------------------------ */

static void test_parse_uid_range(void) {
        uid_t cl, cu, rl, ru;
        int cr, rr;

        FOREACH_STRING(input, "1000", "1000-2000", "1000-", "2000-1000", "01-2") {
                cr = parse_uid_range(input, &cl, &cu);
                rr = rs_parse_uid_range(input, &rl, &ru);
                assert_se(cr == rr);
                if (cr >= 0) {
                        assert_se(cl == rl);
                        assert_se(cu == ru);
                }
        }

        /* Both C and Rust publish range bounds only on success. */
        cl = 1111;
        cu = 2222;
        rl = 3333;
        ru = 4444;
        cr = parse_uid_range("1000-", &cl, &cu);
        rr = rs_parse_uid_range("1000-", &rl, &ru);
        assert_se(cr == rr);
        assert_se(cr < 0);
        assert_se(cl == 1111);
        assert_se(cu == 2222);
        assert_se(rl == 3333);
        assert_se(ru == 4444);

        /* The Rust facade fails closed instead of evaluating C assertions. */
        rl = 3333;
        ru = 4444;
        assert_se(rs_parse_uid(NULL, &rl) == -EINVAL);
        assert_se(rl == 3333);
        assert_se(rs_parse_uid_range(NULL, &rl, &ru) == -EINVAL);
        assert_se(rl == 3333);
        assert_se(ru == 4444);
        assert_se(rs_parse_uid_range("1000", NULL, &ru) == -EINVAL);
        assert_se(ru == 4444);
}

/* -- hashed_password_is_locked_or_invalid -------------------------------- */

static void test_hashed_password_is_locked_or_invalid(void) {
        FOREACH_STRING(password, "$6$salt$hash", "!", "*", "locked", "") {
                assert_se(hashed_password_is_locked_or_invalid(password) ==
                          rs_hashed_password_is_locked_or_invalid(password));
        }
        assert_se(!hashed_password_is_locked_or_invalid(NULL));
        assert_se(!rs_hashed_password_is_locked_or_invalid(NULL));
}

/* -- id128_is_valid ------------------------------------------------------- */

static void test_id128_is_valid(void) {
        bool cv, rv;

        /* Plain 32-char hex string */
        cv = id128_is_valid("c5a4166e3f224932a4987f3a63a18b02");
        rv = rs_id128_is_valid("c5a4166e3f224932a4987f3a63a18b02");
        assert_se(cv == rv);
        assert_se(cv);

        /* UUID format */
        cv = id128_is_valid("c5a4166e-3f22-4932-a498-7f3a63a18b02");
        rv = rs_id128_is_valid("c5a4166e-3f22-4932-a498-7f3a63a18b02");
        assert_se(cv == rv);
        assert_se(cv);

        /* All zeros */
        cv = id128_is_valid("00000000000000000000000000000000");
        rv = rs_id128_is_valid("00000000000000000000000000000000");
        assert_se(cv == rv);
        assert_se(cv);

        /* Empty */
        cv = id128_is_valid("");
        rv = rs_id128_is_valid("");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Wrong length (too short) */
        cv = id128_is_valid("abcdef");
        rv = rs_id128_is_valid("abcdef");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Non-hex chars in plain format */
        cv = id128_is_valid("c5a4166e3f224932a4987f3a63g18b02");
        rv = rs_id128_is_valid("c5a4166e3f224932a4987f3a63g18b02");
        assert_se(cv == rv);
        assert_se(!cv);

        /* Wrong dash positions in UUID */
        cv = id128_is_valid("c5a4166e3f22-4932-a498-7f3a63a18b02");
        rv = rs_id128_is_valid("c5a4166e3f22-4932-a498-7f3a63a18b02");
        assert_se(cv == rv);
        assert_se(!cv);

        /* NULL */
        /* C id128_is_valid asserts on NULL, only test Rust */
        rv = rs_id128_is_valid(NULL);
        assert_se(!rv);
}

int main(int argc, char **argv) {
        test_valid_user_group_name_strict();
        test_valid_user_group_name_relaxed();
        test_capsule_name_is_valid();
        test_uid_is_valid();
        test_parse_uid();
        test_parse_uid_range();
        test_hashed_password_is_locked_or_invalid();
        test_id128_is_valid();
        return 0;
}
