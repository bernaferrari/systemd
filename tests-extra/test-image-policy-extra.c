/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "image-policy.h"
#include "dissect-image.h"
#include "gpt.h"
#include "tests.h"

#include "string-util.h"

#include "alloc-util.h"
TEST(partition_policy_flags_from_string) {
        PartitionPolicyFlags flags;
        /* Empty string/dash returns 0 */
        flags = partition_policy_flags_from_string("", false);
        assert_se(flags == 0);
        flags = partition_policy_flags_from_string("-", false);
        assert_se(flags == 0);
        /* Individual flags */
        flags = partition_policy_flags_from_string("verity", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_VERITY));
        flags = partition_policy_flags_from_string("signed", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_SIGNED));
        flags = partition_policy_flags_from_string("encrypted", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_ENCRYPTED));
        flags = partition_policy_flags_from_string("unprotected", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_UNPROTECTED));
        flags = partition_policy_flags_from_string("unused", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_UNUSED));
        flags = partition_policy_flags_from_string("absent", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_ABSENT));
        /* Combined flags */
        flags = partition_policy_flags_from_string("verity+encrypted", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_VERITY));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_ENCRYPTED));
        flags = partition_policy_flags_from_string("verity+signed", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_VERITY));
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_SIGNED));
        /* Shortcut aliases */
        flags = partition_policy_flags_from_string("open", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_OPEN));
        flags = partition_policy_flags_from_string("ignore", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_IGNORE));
        /* GPT flags */
        flags = partition_policy_flags_from_string("read-only-on", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_READ_ONLY_ON));
        flags = partition_policy_flags_from_string("read-only-off", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_READ_ONLY_OFF));
        flags = partition_policy_flags_from_string("growfs-on", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_GROWFS_ON));
        flags = partition_policy_flags_from_string("growfs-off", false);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_GROWFS_OFF));
        /* Invalid flag */
        flags = partition_policy_flags_from_string("invalidflag", false);
        assert_se(flags == -EBADRQC);
        /* Graceful mode ignores unknown flags */
        flags = partition_policy_flags_from_string("verity+invalidflag", true);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_VERITY));
}
TEST(partition_policy_flags_to_string) {
        _cleanup_free_ char *s = NULL;
        int r;
        /* Single flag */
        r = partition_policy_flags_to_string(PARTITION_POLICY_VERITY, false, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "verity"));
        /* Simplified: OPEN should become "open" */
        r = partition_policy_flags_to_string(PARTITION_POLICY_OPEN, true, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "open"));
        /* Simplified: IGNORE should become "ignore" */
        r = partition_policy_flags_to_string(PARTITION_POLICY_IGNORE, true, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "ignore"));
        /* No flags → "-" */
        r = partition_policy_flags_to_string(0, false, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "-"));
        /* Invalid flags */
        r = partition_policy_flags_to_string(-EINVAL, false, &s);
        assert_se(r < 0);
        /* Combined flags */
        r = partition_policy_flags_to_string(
                        PARTITION_POLICY_VERITY | PARTITION_POLICY_ENCRYPTED, false, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "verity+encrypted"));
        /* Combined with read-only and growfs */
        r = partition_policy_flags_to_string(
                        PARTITION_POLICY_UNPROTECTED | PARTITION_POLICY_READ_ONLY_ON, false, &s);
        assert_se(r >= 0);
        assert_se(endwith(s, "read-only-on"));
}
TEST(partition_policy_flags_extend_reduce) {
        /* No flags set → extend fills in all */
        PartitionPolicyFlags flags = 0;
        flags = partition_policy_flags_extend(flags);
        assert_se(FLAGS_SET(flags, _PARTITION_POLICY_USE_MASK));
        assert_se(FLAGS_SET(flags, _PARTITION_POLICY_READ_ONLY_MASK));
        assert_se(FLAGS_SET(flags, _PARTITION_POLICY_GROWFS_MASK));
        /* Verity only → extend fills read-only and growfs */
        flags = PARTITION_POLICY_VERITY;
        flags = partition_policy_flags_extend(flags);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_VERITY));
        assert_se(FLAGS_SET(flags, _PARTITION_POLICY_READ_ONLY_MASK));
        assert_se(FLAGS_SET(flags, _PARTITION_POLICY_GROWFS_MASK));
        /* Reduce all-open should clear everything */
        flags = PARTITION_POLICY_OPEN | _PARTITION_POLICY_READ_ONLY_MASK | _PARTITION_POLICY_GROWFS_MASK;
        flags = partition_policy_flags_reduce(flags);
        assert_se(flags == 0);
}
TEST(image_policy_from_string_symbolic) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        int r;
        /* "-" means ignore policy */
        r = image_policy_from_string("-", false, &p);
        assert_se(r >= 0);
        assert_se(p);
        assert_se(image_policy_equiv_ignore(p));
        assert_se(image_policy_default(p) == PARTITION_POLICY_IGNORE);
        assert_se(image_policy_n_entries(p) == 0);
        p = image_policy_free(p);
        /* "*" means allow policy */
        r = image_policy_from_string("*", false, &p);
        assert_se(r >= 0);
        assert_se(p);
        assert_se(image_policy_equiv_allow(p));
        assert_se(image_policy_default(p) == PARTITION_POLICY_OPEN);
        assert_se(image_policy_n_entries(p) == 0);
        p = image_policy_free(p);
        /* "~" means deny policy */
        r = image_policy_from_string("~", false, &p);
        assert_se(r >= 0);
        assert_se(p);
        assert_se(image_policy_equiv_deny(p));
        assert_se(image_policy_default(p) == PARTITION_POLICY_ABSENT);
        assert_se(image_policy_n_entries(p) == 0);
        p = image_policy_free(p);
        /* "" also means ignore */
        r = image_policy_from_string("", false, &p);
        assert_se(r >= 0);
        assert_se(p);
        assert_se(image_policy_equiv_ignore(p));
        p = image_policy_free(p);
}
TEST(image_policy_from_string_explicit) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        _cleanup_free_ char *s = NULL;
        int r;
        /* root=verity */
        r = image_policy_from_string("root=verity", false, &p);
        assert_se(r >= 0);
        assert_se(p);
        s = mfree(s);
        r = image_policy_to_string(p, true, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "root=verity"));
        p = image_policy_free(p);
        s = mfree(s);
        /* root=encrypted */
        r = image_policy_from_string("root=encrypted", false, &p);
        assert_se(r >= 0);
        assert_se(p);
        s = mfree(s);
        r = image_policy_to_string(p, true, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "root=encrypted"));
        p = image_policy_free(p);
        s = mfree(s);
        /* root=absent */
        r = image_policy_from_string("root=absent", false, &p);
        assert_se(r >= 0);
        assert_se(p);
        s = mfree(s);
        r = image_policy_to_string(p, true, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "root=absent"));
        p = image_policy_free(p);
        s = mfree(s);
}
TEST(image_policy_from_string_with_default) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        _cleanup_free_ char *s = NULL;
        int r;
        /* "=encrypted means default is encrypted, */
        r = image_policy_from_string("=encrypted", false, &p);
        assert_se(r >= 0);
        assert_se(p);
        assert_se(image_policy_default(p) == PARTITION_POLICY_ENCRYPTED);
        assert_se(image_policy_n_entries(p) == 0);
        s = mfree(s);
        r = image_policy_to_string(p, true, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "=encrypted"));
        p = image_policy_free(p);
        s = mfree(s);
}
TEST(image_policy_from_string_multiple_rules) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        _cleanup_free_ char *s = NULL;
        int r;
        /* Multiple designators */
        r = image_policy_from_string("root=unprotected:usr=verity:home=absent", false, &p);
        assert_se(r >= 0);
        assert_se(p);
        assert_se(image_policy_n_entries(p) == 2);
        s = mfree(s);
        r = image_policy_to_string(p, true, &s);
        assert_se(r >= 0);
        /* Should contain both root and usr */
        assert_se(strstr(s, "root="));
        assert_se(strstr(s, "usr="));
        assert_se(strstr(s, "home="));
        p = image_policy_free(p);
        s = mfree(s);
}
TEST(image_policy_from_string_duplicate) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        int r;
        /* Duplicate designator */
        r = image_policy_from_string("root=verity:root=encrypted", false, &p);
        assert_se(r == -ENOTUNIQ);
}
TEST(image_policy_from_string_unknown_designator) {
        _cleanup_(image_policy_freep) ImagePolicy *p = NULL;
        int r;
        /* Unknown designator, non-graceful */
        r = image_policy_from_string("root=verity:fakedesignator=absent", false, &p);
        assert_se(r == -EBADSLT);
        /* Graceful mode should succeed */
        r = image_policy_from_string("root=verity:fakedesignator=absent", true, &p);
        assert_se(r >= 0);
}
TEST(image_policy_from_string_unknown_flag) {
        int r;
        /* Unknown policy flag */
        r = image_policy_from_string("root=invalidflag", false, NULL);
        assert_se(r == -EBADRQC);
}
TEST(image_policy_equal) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL;
        int r;
        /* Same symbolic policy */
        r = image_policy_from_string("*", false, &a);
        assert_se(r >= 0);
        r = image_policy_from_string("*", false, &b);
        assert_se(r >= 0);
        assert_se(image_policy_equal(a, b));
        /* Different policies */
        r = image_policy_from_string("-", false, &b);
        assert_se(r >= 0);
        assert_se(!image_policy_equal(a, b));
}
TEST(image_policy_equivalent) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL;
        int r;
        /* Equivalent by same outcome */
        r = image_policy_from_string("*", false, &a);
        assert_se(r >= 0);
        r = image_policy_from_string("*", false, &b);
        assert_se(r >= 0);
        assert_se(image_policy_equivalent(a, b));
        /* "-" and "root=verity:...=ignore" are not equivalent */
        r = image_policy_from_string("-", false, &b);
        assert_se(r >= 0);
        assert_se(!image_policy_equivalent(a, b));
}
TEST(image_policy_intersect) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL, *c = NULL;
        int r;
        /* Intersect allow with allow = allow */
        r = image_policy_from_string("*", false, &a);
        assert_se(r >= 0);
        r = image_policy_intersect(a, a, &c);
        assert_se(r >= 0);
        assert_se(c);
        assert_se(image_policy_equiv_allow(c));
        c = image_policy_free(c);
        /* Intersect allow with deny = impossible (-ENAVAIL) */
        r = image_policy_from_string("~", false, &b);
        assert_se(r >= 0);
        r = image_policy_intersect(a, b, &c);
        assert_se(r == -ENAVAIL);
}
TEST(image_policy_union) {
        _cleanup_(image_policy_freep) ImagePolicy *a = NULL, *b = NULL, *c = NULL;
        int r;
        /* Union deny with deny = deny */
        r = image_policy_from_string("~", false, &a);
        assert_se(r >= 0);
        r = image_policy_union(a, a, &c);
        assert_se(r >= 0);
        assert_se(c);
        assert_se(image_policy_equiv_deny(c));
        c = image_policy_free(c);
        /* Union allow with deny = allow */
        r = image_policy_from_string("*", false, &b);
        assert_se(r >= 0);
        r = image_policy_union(a, b, &c);
        assert_se(r >= 0);
        assert_se(image_policy_equiv_allow(c));
        c = image_policy_free(c);
}
TEST(image_policy_get) {
        /* NULL policy means everything allowed */
        PartitionPolicyFlags flags;
        flags = image_policy_get(NULL, PARTITION_ROOT);
        assert_se(flags >= 0);
        assert_se(FLAGS_SET(flags, PARTITION_POLICY_UNPROTECTED));
}
TEST(image_policy_default_inline) {
        assert_se(image_policy_default(NULL) == PARTITION_POLICY_OPEN);
        assert_se(image_policy_n_entries(NULL) == 0);
}
TEST(image_policy_predefined) {
        _cleanup_free_ char *s = NULL;
        int r;
        /* image_policy_allow */
        r = image_policy_to_string(&image_policy_allow, true, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "*"));
        s = mfree(s);
        r = image_policy_to_string(&image_policy_allow, false, &s);
        assert_se(r >= 0);
        /* Without simplify, should be a long form */
        assert_se(strstr(s, "verity") || strstr(s, "signed") || strstr(s, "encrypted"));
        s = mfree(s);
        /* image_policy_deny */
        r = image_policy_to_string(&image_policy_deny, true, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "~"));
        s = mfree(s);
        /* image_policy_ignore */
        r = image_policy_to_string(&image_policy_ignore, true, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "-"));
        s = mfree(s);
}
DEFINE_TEST_MAIN(LOG_DEBUG);
