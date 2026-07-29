/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <string.h>

#include "rust/virt.h"
#include "virt.h"
#include "string-util.h"

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

        c_ret = virtualization_to_string(-1);
        r_ret = rs_virtualization_to_string(-1);
        assert_se(streq_ptr(c_ret, r_ret));
}

static void test_virtualization_from_string(void) {
        Virtualization c_ret;
        int r_ret;

        c_ret = virtualization_from_string("none");
        r_ret = rs_virtualization_from_string("none");
        assert_se((int) c_ret == r_ret);
        assert_se(c_ret == VIRTUALIZATION_NONE);

        c_ret = virtualization_from_string("kvm");
        r_ret = rs_virtualization_from_string("kvm");
        assert_se((int) c_ret == r_ret);
        assert_se(c_ret == VIRTUALIZATION_KVM);

        c_ret = virtualization_from_string("docker");
        r_ret = rs_virtualization_from_string("docker");
        assert_se((int) c_ret == r_ret);
        assert_se(c_ret == VIRTUALIZATION_DOCKER);

        c_ret = virtualization_from_string("systemd-nspawn");
        r_ret = rs_virtualization_from_string("systemd-nspawn");
        assert_se((int) c_ret == r_ret);
        assert_se(c_ret == VIRTUALIZATION_SYSTEMD_NSPAWN);

        c_ret = virtualization_from_string("bogus");
        r_ret = rs_virtualization_from_string("bogus");
        assert_se((int) c_ret == r_ret);

        c_ret = virtualization_from_string(NULL);
        r_ret = rs_virtualization_from_string(NULL);
        assert_se((int) c_ret == r_ret);
}

int main(int argc, char **argv) {
        test_virtualization_to_string();
        test_virtualization_from_string();
        return 0;
}
