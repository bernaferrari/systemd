/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "virt.h"
#include "tests.h"

TEST(virtualization) {
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_NONE), "none");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_KVM), "kvm");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_QEMU), "qemu");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_XEN), "xen");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_VMWARE), "vmware");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_MICROSOFT), "microsoft");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_DOCKER), "docker");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_PODMAN), "podman");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_SYSTEMD_NSPAWN), "systemd-nspawn");
        ASSERT_EQ(virtualization_from_string("kvm"), VIRTUALIZATION_KVM);
        ASSERT_EQ(virtualization_from_string("qemu"), VIRTUALIZATION_QEMU);
        ASSERT_EQ(virtualization_from_string("docker"), VIRTUALIZATION_DOCKER);
        ASSERT_EQ(virtualization_from_string("invalid"), _VIRTUALIZATION_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
