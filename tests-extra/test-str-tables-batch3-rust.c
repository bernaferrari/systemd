/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "rust/virt.h"
#include "rust/image_class.h"
#include "rust/confidential_virt.h"
#include "rust/log_target.h"

/* C references */
#include "virt.h"
#include "os-util.h"
#include "confidential-virt.h"
#include "log.h"
#include "string-util.h"

/* ── virtualization ───────────────────────────────────────────────────── */

static void test_virtualization_to_string(void) {
        const char *c_ret, *r_ret;

        c_ret = virtualization_to_string(VIRTUALIZATION_NONE);
        r_ret = rs_virtualization_to_string(VIRTUALIZATION_NONE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = virtualization_to_string(VIRTUALIZATION_KVM);
        r_ret = rs_virtualization_to_string(VIRTUALIZATION_KVM);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = virtualization_to_string(VIRTUALIZATION_QEMU);
        r_ret = rs_virtualization_to_string(VIRTUALIZATION_QEMU);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = virtualization_to_string(VIRTUALIZATION_DOCKER);
        r_ret = rs_virtualization_to_string(VIRTUALIZATION_DOCKER);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = virtualization_to_string(VIRTUALIZATION_CONTAINER_OTHER);
        r_ret = rs_virtualization_to_string(VIRTUALIZATION_CONTAINER_OTHER);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Invalid */
        c_ret = virtualization_to_string(-1);
        r_ret = rs_virtualization_to_string(-1);
        assert_se(streq_ptr(c_ret, r_ret));
}

static void test_virtualization_from_string(void) {
        Virtualization c_ret;
        int r_ret;

        c_ret = virtualization_from_string("none");
        r_ret = rs_virtualization_from_string("none");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == VIRTUALIZATION_NONE);

        c_ret = virtualization_from_string("kvm");
        r_ret = rs_virtualization_from_string("kvm");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == VIRTUALIZATION_KVM);

        c_ret = virtualization_from_string("docker");
        r_ret = rs_virtualization_from_string("docker");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == VIRTUALIZATION_DOCKER);

        c_ret = virtualization_from_string("systemd-nspawn");
        r_ret = rs_virtualization_from_string("systemd-nspawn");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == VIRTUALIZATION_SYSTEMD_NSPAWN);

        /* Invalid */
        c_ret = virtualization_from_string("bogus");
        r_ret = rs_virtualization_from_string("bogus");
        assert_se((int)c_ret == r_ret);

        c_ret = virtualization_from_string(NULL);
        r_ret = rs_virtualization_from_string(NULL);
        assert_se((int)c_ret == r_ret);
}

/* ── image_class ──────────────────────────────────────────────────────── */

static void test_image_class_to_string(void) {
        const char *c_ret, *r_ret;

        c_ret = image_class_to_string(IMAGE_MACHINE);
        r_ret = rs_image_class_to_string(IMAGE_MACHINE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = image_class_to_string(IMAGE_PORTABLE);
        r_ret = rs_image_class_to_string(IMAGE_PORTABLE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = image_class_to_string(IMAGE_SYSEXT);
        r_ret = rs_image_class_to_string(IMAGE_SYSEXT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = image_class_to_string(IMAGE_CONFEXT);
        r_ret = rs_image_class_to_string(IMAGE_CONFEXT);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Invalid */
        c_ret = image_class_to_string(-1);
        r_ret = rs_image_class_to_string(-1);
        assert_se(streq_ptr(c_ret, r_ret));
}

static void test_image_class_from_string(void) {
        ImageClass c_ret;
        int r_ret;

        c_ret = image_class_from_string("machine");
        r_ret = rs_image_class_from_string("machine");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == IMAGE_MACHINE);

        c_ret = image_class_from_string("portable");
        r_ret = rs_image_class_from_string("portable");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == IMAGE_PORTABLE);

        c_ret = image_class_from_string("sysext");
        r_ret = rs_image_class_from_string("sysext");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == IMAGE_SYSEXT);

        c_ret = image_class_from_string("confext");
        r_ret = rs_image_class_from_string("confext");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == IMAGE_CONFEXT);

        /* Invalid */
        c_ret = image_class_from_string("bogus");
        r_ret = rs_image_class_from_string("bogus");
        assert_se((int)c_ret == r_ret);

        c_ret = image_class_from_string(NULL);
        r_ret = rs_image_class_from_string(NULL);
        assert_se((int)c_ret == r_ret);
}

/* ── confidential_virtualization ──────────────────────────────────────── */

static void test_confidential_virtualization_to_string(void) {
        const char *c_ret, *r_ret;

        c_ret = confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_NONE);
        r_ret = rs_confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_NONE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_SEV);
        r_ret = rs_confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_SEV);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_SEV_SNP);
        r_ret = rs_confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_SEV_SNP);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_TDX);
        r_ret = rs_confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_TDX);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_CCA);
        r_ret = rs_confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_CCA);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Invalid */
        c_ret = confidential_virtualization_to_string(-1);
        r_ret = rs_confidential_virtualization_to_string(-1);
        assert_se(streq_ptr(c_ret, r_ret));
}

static void test_confidential_virtualization_from_string(void) {
        ConfidentialVirtualization c_ret;
        int r_ret;

        c_ret = confidential_virtualization_from_string("none");
        r_ret = rs_confidential_virtualization_from_string("none");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == CONFIDENTIAL_VIRTUALIZATION_NONE);

        c_ret = confidential_virtualization_from_string("sev");
        r_ret = rs_confidential_virtualization_from_string("sev");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == CONFIDENTIAL_VIRTUALIZATION_SEV);

        c_ret = confidential_virtualization_from_string("sev-snp");
        r_ret = rs_confidential_virtualization_from_string("sev-snp");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == CONFIDENTIAL_VIRTUALIZATION_SEV_SNP);

        c_ret = confidential_virtualization_from_string("tdx");
        r_ret = rs_confidential_virtualization_from_string("tdx");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == CONFIDENTIAL_VIRTUALIZATION_TDX);

        /* Invalid */
        c_ret = confidential_virtualization_from_string("bogus");
        r_ret = rs_confidential_virtualization_from_string("bogus");
        assert_se((int)c_ret == r_ret);

        c_ret = confidential_virtualization_from_string(NULL);
        r_ret = rs_confidential_virtualization_from_string(NULL);
        assert_se((int)c_ret == r_ret);
}

/* ── log_target ────────────────────────────────────────────────────────── */

static void test_log_target_to_string(void) {
        const char *c_ret, *r_ret;

        c_ret = log_target_to_string(LOG_TARGET_CONSOLE);
        r_ret = rs_log_target_to_string(LOG_TARGET_CONSOLE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = log_target_to_string(LOG_TARGET_KMSG);
        r_ret = rs_log_target_to_string(LOG_TARGET_KMSG);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = log_target_to_string(LOG_TARGET_JOURNAL);
        r_ret = rs_log_target_to_string(LOG_TARGET_JOURNAL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = log_target_to_string(LOG_TARGET_CONSOLE_PREFIXED);
        r_ret = rs_log_target_to_string(LOG_TARGET_CONSOLE_PREFIXED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = log_target_to_string(LOG_TARGET_AUTO);
        r_ret = rs_log_target_to_string(LOG_TARGET_AUTO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = log_target_to_string(LOG_TARGET_NULL);
        r_ret = rs_log_target_to_string(LOG_TARGET_NULL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Invalid */
        c_ret = log_target_to_string(-1);
        r_ret = rs_log_target_to_string(-1);
        assert_se(streq_ptr(c_ret, r_ret));
}

static void test_log_target_from_string(void) {
        LogTarget c_ret;
        int r_ret;

        c_ret = log_target_from_string("console");
        r_ret = rs_log_target_from_string("console");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == LOG_TARGET_CONSOLE);

        c_ret = log_target_from_string("kmsg");
        r_ret = rs_log_target_from_string("kmsg");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == LOG_TARGET_KMSG);

        c_ret = log_target_from_string("journal");
        r_ret = rs_log_target_from_string("journal");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == LOG_TARGET_JOURNAL);

        c_ret = log_target_from_string("console-prefixed");
        r_ret = rs_log_target_from_string("console-prefixed");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == LOG_TARGET_CONSOLE_PREFIXED);

        c_ret = log_target_from_string("auto");
        r_ret = rs_log_target_from_string("auto");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == LOG_TARGET_AUTO);

        c_ret = log_target_from_string("null");
        r_ret = rs_log_target_from_string("null");
        assert_se((int)c_ret == r_ret);
        assert_se(c_ret == LOG_TARGET_NULL);

        /* Invalid */
        c_ret = log_target_from_string("bogus");
        r_ret = rs_log_target_from_string("bogus");
        assert_se((int)c_ret == r_ret);

        c_ret = log_target_from_string(NULL);
        r_ret = rs_log_target_from_string(NULL);
        assert_se((int)c_ret == r_ret);
}

int main(int argc, char **argv) {
        test_virtualization_to_string();
        test_virtualization_from_string();
        test_image_class_to_string();
        test_image_class_from_string();
        test_confidential_virtualization_to_string();
        test_confidential_virtualization_from_string();
        test_log_target_to_string();
        test_log_target_from_string();
        return 0;
}
