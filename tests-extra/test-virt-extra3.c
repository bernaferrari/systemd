/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "virt.h"
#include "tests.h"

TEST(detect_vm_basic) {
        Virtualization v = detect_vm();
        log_debug("detect_vm: %d (%s)", v, virtualization_to_string(v));
}

TEST(detect_container_basic) {
        Virtualization c = detect_container();
        log_debug("detect_container: %d (%s)", c, virtualization_to_string(c));
}

TEST(running_in_userns_basic) {
        int r = running_in_userns();
        if (r >= 0)
                log_debug("running_in_userns: %d", r);
        else
                log_debug("running_in_userns failed: %d", r);
}

TEST(running_in_chroot_basic) {
        int r = running_in_chroot();
        if (r >= 0)
                log_debug("running_in_chroot: %d", r);
        else
                log_debug("running_in_chroot failed: %d", r);
}

TEST(has_cpu_with_flag_basic) {
        bool b = has_cpu_with_flag("vmx");
        log_debug("has_cpu_with_flag(vmx): %d", b);
}

TEST(virtualization_is_vm_container) {
        assert_se(VIRTUALIZATION_IS_VM(VIRTUALIZATION_KVM));
        assert_se(VIRTUALIZATION_IS_VM(VIRTUALIZATION_QEMU));
        assert_se(!VIRTUALIZATION_IS_VM(VIRTUALIZATION_NONE));
        assert_se(!VIRTUALIZATION_IS_VM(VIRTUALIZATION_DOCKER));

        assert_se(VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_DOCKER));
        assert_se(VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_PODMAN));
        assert_se(!VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_NONE));
        assert_se(!VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_KVM));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
