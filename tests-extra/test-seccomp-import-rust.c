/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for seccomp, import-util, and reboot_parameter_is_valid */

#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "seccomp-util.h"
#include "import-util.h"
#include "reboot-util.h"
#include "rust/import_util.h"

/* Rust FFI forward declarations */
bool rs_seccomp_errno_or_action_is_valid(int n);
int rs_seccomp_parse_errno_or_action(const char *p);
const char *rs_seccomp_errno_or_action_to_string(int num);
const char *rs_seccomp_arch_to_string(uint32_t c);
int rs_seccomp_arch_from_string(const char *n, uint32_t *ret);

/* -- seccomp_errno_or_action ------------------------------------------------ */

static void test_seccomp_errno_or_action_is_valid(void) {
        assert_se(rs_seccomp_errno_or_action_is_valid(SECCOMP_ERROR_NUMBER_KILL) ==
                  seccomp_errno_or_action_is_valid(SECCOMP_ERROR_NUMBER_KILL));
        assert_se(rs_seccomp_errno_or_action_is_valid(SECCOMP_ERROR_NUMBER_KILL) == true);

        assert_se(rs_seccomp_errno_or_action_is_valid(1) ==
                  seccomp_errno_or_action_is_valid(1));
        assert_se(rs_seccomp_errno_or_action_is_valid(1) == true);

        assert_se(rs_seccomp_errno_or_action_is_valid(4095) ==
                  seccomp_errno_or_action_is_valid(4095));
        assert_se(rs_seccomp_errno_or_action_is_valid(4095) == true);

        assert_se(rs_seccomp_errno_or_action_is_valid(4096) ==
                  seccomp_errno_or_action_is_valid(4096));
        assert_se(rs_seccomp_errno_or_action_is_valid(4096) == false);

        assert_se(rs_seccomp_errno_or_action_is_valid(0) ==
                  seccomp_errno_or_action_is_valid(0));
        assert_se(rs_seccomp_errno_or_action_is_valid(0) == false);

        assert_se(rs_seccomp_errno_or_action_is_valid(-1) ==
                  seccomp_errno_or_action_is_valid(-1));
        assert_se(rs_seccomp_errno_or_action_is_valid(-1) == false);
}

static void test_seccomp_parse_errno_or_action(void) {

        assert_se(seccomp_parse_errno_or_action("kill") == SECCOMP_ERROR_NUMBER_KILL);
        assert_se(rs_seccomp_parse_errno_or_action("kill") == SECCOMP_ERROR_NUMBER_KILL);

        assert_se(seccomp_parse_errno_or_action("EPERM") == EPERM);
        assert_se(rs_seccomp_parse_errno_or_action("EPERM") == EPERM);

        assert_se(seccomp_parse_errno_or_action("ENOENT") == ENOENT);
        assert_se(rs_seccomp_parse_errno_or_action("ENOENT") == ENOENT);

        /* Numeric errno */
        assert_se(seccomp_parse_errno_or_action("2") == ENOENT);
        assert_se(rs_seccomp_parse_errno_or_action("2") == ENOENT);

        assert_se(seccomp_parse_errno_or_action("0") == 0);
        assert_se(rs_seccomp_parse_errno_or_action("0") == 0);
}

static void test_seccomp_errno_or_action_to_string(void) {
        const char *c_str, *rs_str;

        c_str = seccomp_errno_or_action_to_string(SECCOMP_ERROR_NUMBER_KILL);
        rs_str = rs_seccomp_errno_or_action_to_string(SECCOMP_ERROR_NUMBER_KILL);
        assert_se(streq(c_str, rs_str));
        assert_se(streq(c_str, "kill"));

        c_str = seccomp_errno_or_action_to_string(EPERM);
        rs_str = rs_seccomp_errno_or_action_to_string(EPERM);
        assert_se(streq_ptr(c_str, rs_str));

        c_str = seccomp_errno_or_action_to_string(ENOENT);
        rs_str = rs_seccomp_errno_or_action_to_string(ENOENT);
        assert_se(streq_ptr(c_str, rs_str));

        /* Invalid */
        c_str = seccomp_errno_or_action_to_string(0);
        rs_str = rs_seccomp_errno_or_action_to_string(0);
        assert_se(c_str == NULL);
        assert_se(rs_str == NULL);
}

/* -- seccomp_arch ----------------------------------------------------------- */

static void test_seccomp_arch(void) {
        const char *c_str, *rs_str;
        uint32_t c_val, rs_val;
        int r;

        /* to_string for common arches */
        c_str = seccomp_arch_to_string(SCMP_ARCH_X86_64);
        rs_str = rs_seccomp_arch_to_string(SCMP_ARCH_X86_64);
        assert_se(streq_ptr(c_str, rs_str));
        assert_se(streq(c_str, "x86-64"));

        c_str = seccomp_arch_to_string(SCMP_ARCH_X86);
        rs_str = rs_seccomp_arch_to_string(SCMP_ARCH_X86);
        assert_se(streq_ptr(c_str, rs_str));

        c_str = seccomp_arch_to_string(SCMP_ARCH_ARM);
        rs_str = rs_seccomp_arch_to_string(SCMP_ARCH_ARM);
        assert_se(streq_ptr(c_str, rs_str));

        c_str = seccomp_arch_to_string(SCMP_ARCH_AARCH64);
        rs_str = rs_seccomp_arch_to_string(SCMP_ARCH_AARCH64);
        assert_se(streq_ptr(c_str, rs_str));

        /* Unknown arch */
        c_str = seccomp_arch_to_string(0xDEAD);
        rs_str = rs_seccomp_arch_to_string(0xDEAD);
        assert_se(c_str == NULL);
        assert_se(rs_str == NULL);

        /* from_string */
        r = seccomp_arch_from_string("x86-64", &c_val);
        assert_se(r == 0);
        r = rs_seccomp_arch_from_string("x86-64", &rs_val);
        assert_se(r == 0);
        assert_se(c_val == rs_val);

        r = seccomp_arch_from_string("arm64", &c_val);
        assert_se(r == 0);
        r = rs_seccomp_arch_from_string("arm64", &rs_val);
        assert_se(r == 0);
        assert_se(c_val == rs_val);

        r = seccomp_arch_from_string("ppc64-le", &c_val);
        assert_se(r == 0);
        r = rs_seccomp_arch_from_string("ppc64-le", &rs_val);
        assert_se(r == 0);
        assert_se(c_val == rs_val);

        /* Invalid name */
        r = seccomp_arch_from_string("bogus", &c_val);
        assert_se(r < 0);
        r = rs_seccomp_arch_from_string("bogus", &rs_val);
        assert_se(r < 0);

        r = seccomp_arch_from_string(NULL, &c_val);
        assert_se(r < 0);
        r = rs_seccomp_arch_from_string(NULL, &rs_val);
        assert_se(r < 0);
}

/* -- import_url_last_component --------------------------------------------- */

static void test_import_url_last_component(void) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;
        static const char non_utf8_url[] = "x://host/\xff.raw";
        int r;

        r = import_url_last_component("https://example.com/image.raw", &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_last_component("https://example.com/image.raw", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image.raw"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = import_url_last_component("https://example.com/path/to/file.tar.xz", &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_last_component("https://example.com/path/to/file.tar.xz", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "file.tar.xz"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = import_url_last_component("https://example.com/file.raw?query=1", &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_last_component("https://example.com/file.raw?query=1", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = import_url_last_component("https://example.com/file.raw#fragment", &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_last_component("https://example.com/file.raw#fragment", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* Trailing slash — still extracts component */
        r = import_url_last_component("https://example.com/path/", &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_last_component("https://example.com/path/", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "path"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* No path after host — empty component */
        r = import_url_last_component("https://example.com", &c_ret);
        assert_se(r == -EADDRNOTAVAIL);
        r = rs_import_url_last_component("https://example.com", &rs_ret);
        assert_se(r == -EADDRNOTAVAIL);

        /* Not a URL */
        r = import_url_last_component("not-a-url", &c_ret);
        assert_se(r < 0);
        r = rs_import_url_last_component("not-a-url", &rs_ret);
        assert_se(r < 0);

        r = import_url_last_component(non_utf8_url, &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_last_component(non_utf8_url, &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
}

/* -- import_url_change_suffix ---------------------------------------------- */

static void test_import_url_change_suffix(void) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;
        int r;

        r = import_url_change_suffix("https://example.com/image.raw", 1, "image.tar", &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_change_suffix("https://example.com/image.raw", 1, "image.tar", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = import_url_change_suffix("https://example.com/path/to/file.raw", 1, "file.tar", &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_change_suffix("https://example.com/path/to/file.raw", 1, "file.tar", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = import_url_change_suffix("https://example.com/path/", 0, "file.raw", &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_change_suffix("https://example.com/path/", 0, "file.raw", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* Drop component, no suffix */
        r = import_url_change_suffix("https://example.com/path/file.raw", 1, NULL, &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_change_suffix("https://example.com/path/file.raw", 1, NULL, &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* With query string */
        r = import_url_change_suffix("https://example.com/file.raw?query=1", 0, "new.raw", &c_ret);
        assert_se(r >= 0);
        r = rs_import_url_change_suffix("https://example.com/file.raw?query=1", 0, "new.raw", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
}

/* -- tar_strip_suffixes ---------------------------------------------------- */

static void test_tar_strip_suffixes(void) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;
        int r;

        r = tar_strip_suffixes("image.tar", &c_ret);
        assert_se(r >= 0);
        r = rs_tar_strip_suffixes("image.tar", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = tar_strip_suffixes("", &c_ret);
        assert_se(r == -EINVAL);
        r = rs_tar_strip_suffixes("", &rs_ret);
        assert_se(r == -EINVAL);

        r = tar_strip_suffixes(".tar", &c_ret);
        assert_se(r == -EINVAL);
        r = rs_tar_strip_suffixes(".tar", &rs_ret);
        assert_se(r == -EINVAL);

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = tar_strip_suffixes("image.tar.xz", &c_ret);
        assert_se(r >= 0);
        r = rs_tar_strip_suffixes("image.tar.xz", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = tar_strip_suffixes("image.tar.gz", &c_ret);
        assert_se(r >= 0);
        r = rs_tar_strip_suffixes("image.tar.gz", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = tar_strip_suffixes("image.tar.bz2", &c_ret);
        assert_se(r >= 0);
        r = rs_tar_strip_suffixes("image.tar.bz2", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = tar_strip_suffixes("image.tar.zst", &c_ret);
        assert_se(r >= 0);
        r = rs_tar_strip_suffixes("image.tar.zst", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = tar_strip_suffixes("image.tgz", &c_ret);
        assert_se(r >= 0);
        r = rs_tar_strip_suffixes("image.tgz", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* No suffix */
        r = tar_strip_suffixes("image", &c_ret);
        assert_se(r >= 0);
        r = rs_tar_strip_suffixes("image", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));
}

/* -- raw_strip_suffixes ---------------------------------------------------- */

static void test_raw_strip_suffixes(void) {
        _cleanup_free_ char *c_ret = NULL;
        _cleanup_free_ char *rs_ret = NULL;
        static const char non_utf8_raw[] = "\xff.raw";
        int r;

        r = raw_strip_suffixes("image.raw", &c_ret);
        assert_se(r >= 0);
        r = rs_raw_strip_suffixes("image.raw", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = raw_strip_suffixes("image.raw.xz", &c_ret);
        assert_se(r >= 0);
        r = rs_raw_strip_suffixes("image.raw.xz", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = raw_strip_suffixes("image.raw.gz", &c_ret);
        assert_se(r >= 0);
        r = rs_raw_strip_suffixes("image.raw.gz", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = raw_strip_suffixes("image.qcow2", &c_ret);
        assert_se(r >= 0);
        r = rs_raw_strip_suffixes("image.qcow2", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = raw_strip_suffixes("image.img", &c_ret);
        assert_se(r >= 0);
        r = rs_raw_strip_suffixes("image.img", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = raw_strip_suffixes("image.bin", &c_ret);
        assert_se(r >= 0);
        r = rs_raw_strip_suffixes("image.bin", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* No suffix */
        r = raw_strip_suffixes("image", &c_ret);
        assert_se(r >= 0);
        r = rs_raw_strip_suffixes("image", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "image"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        /* sysext.raw */
        r = raw_strip_suffixes("foobar.sysext.raw", &c_ret);
        assert_se(r >= 0);
        r = rs_raw_strip_suffixes("foobar.sysext.raw", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(streq(c_ret, "foobar"));

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = raw_strip_suffixes(non_utf8_raw, &c_ret);
        assert_se(r >= 0);
        r = rs_raw_strip_suffixes(non_utf8_raw, &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se((unsigned char) c_ret[0] == 0xff);

        c_ret = mfree(c_ret);
        rs_ret = mfree(rs_ret);

        r = raw_strip_suffixes("", &c_ret);
        assert_se(r >= 0);
        r = rs_raw_strip_suffixes("", &rs_ret);
        assert_se(r >= 0);
        assert_se(streq(c_ret, rs_ret));
        assert_se(isempty(c_ret));
}

/* -- reboot_parameter_is_valid --------------------------------------------- */

static void test_reboot_parameter_is_valid(void) {
        static const char non_ascii[] = "\x80";
        char maximum_length[NAME_MAX + 2];
        assert_se(rs_reboot_parameter_is_valid("halt") == reboot_parameter_is_valid("halt"));
        assert_se(rs_reboot_parameter_is_valid("halt") == true);

        assert_se(rs_reboot_parameter_is_valid("poweroff") == reboot_parameter_is_valid("poweroff"));
        assert_se(rs_reboot_parameter_is_valid("poweroff") == true);

        assert_se(rs_reboot_parameter_is_valid("reboot") == reboot_parameter_is_valid("reboot"));
        assert_se(rs_reboot_parameter_is_valid("reboot") == true);

        assert_se(rs_reboot_parameter_is_valid("") == reboot_parameter_is_valid(""));
        assert_se(rs_reboot_parameter_is_valid("") == true);

        assert_se(rs_reboot_parameter_is_valid(non_ascii) == reboot_parameter_is_valid(non_ascii));
        assert_se(rs_reboot_parameter_is_valid(non_ascii) == false);

        memset(maximum_length, 'x', NAME_MAX);
        maximum_length[NAME_MAX] = 0;
        assert_se(rs_reboot_parameter_is_valid(maximum_length) == reboot_parameter_is_valid(maximum_length));
        assert_se(rs_reboot_parameter_is_valid(maximum_length) == true);

        maximum_length[NAME_MAX] = 'x';
        maximum_length[NAME_MAX + 1] = 0;
        assert_se(rs_reboot_parameter_is_valid(maximum_length) == reboot_parameter_is_valid(maximum_length));
        assert_se(rs_reboot_parameter_is_valid(maximum_length) == false);
}

int main(int argc, char **argv) {
        test_seccomp_errno_or_action_is_valid();
        test_seccomp_parse_errno_or_action();
        test_seccomp_errno_or_action_to_string();
        test_seccomp_arch();
        test_import_url_last_component();
        test_import_url_change_suffix();
        test_tar_strip_suffixes();
        test_raw_strip_suffixes();
        test_reboot_parameter_is_valid();
        return 0;
}
