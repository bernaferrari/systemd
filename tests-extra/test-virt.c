/* SPDX-License-Identifier: LGPL-2.1-or-later */


#include "virt.h"
#include "tests.h"

TEST(virtualization_to_string) {
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_NONE), "none");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_KVM), "kvm");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_QEMU), "qemu");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_XEN), "xen");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_VMWARE), "vmware");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_MICROSOFT), "microsoft");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_ORACLE), "oracle");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_SYSTEMD_NSPAWN), "systemd-nspawn");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_DOCKER), "docker");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_CONTAINER_OTHER), "container-other");
        ASSERT_STREQ(virtualization_to_string(VIRTUALIZATION_VM_OTHER), "vm-other");
}

TEST(virtualization_from_string) {
        ASSERT_EQ(virtualization_from_string("none"), VIRTUALIZATION_NONE);
        ASSERT_EQ(virtualization_from_string("kvm"), VIRTUALIZATION_KVM);
        ASSERT_EQ(virtualization_from_string("qemu"), VIRTUALIZATION_QEMU);
        ASSERT_EQ(virtualization_from_string("xen"), VIRTUALIZATION_XEN);
        ASSERT_EQ(virtualization_from_string("vmware"), VIRTUALIZATION_VMWARE);
        ASSERT_EQ(virtualization_from_string("microsoft"), VIRTUALIZATION_MICROSOFT);
        ASSERT_EQ(virtualization_from_string("oracle"), VIRTUALIZATION_ORACLE);
        ASSERT_EQ(virtualization_from_string("systemd-nspawn"), VIRTUALIZATION_SYSTEMD_NSPAWN);
        ASSERT_EQ(virtualization_from_string("docker"), VIRTUALIZATION_DOCKER);
        ASSERT_EQ(virtualization_from_string("container-other"), VIRTUALIZATION_CONTAINER_OTHER);
        ASSERT_EQ(virtualization_from_string("vm-other"), VIRTUALIZATION_VM_OTHER);
        ASSERT_EQ(virtualization_from_string("invalid"), _VIRTUALIZATION_INVALID);
}

TEST(virtualization_is_vm) {
        ASSERT_TRUE(VIRTUALIZATION_IS_VM(VIRTUALIZATION_KVM));
        ASSERT_TRUE(VIRTUALIZATION_IS_VM(VIRTUALIZATION_QEMU));
        ASSERT_TRUE(VIRTUALIZATION_IS_VM(VIRTUALIZATION_VM_OTHER));
        ASSERT_FALSE(VIRTUALIZATION_IS_VM(VIRTUALIZATION_NONE));
        ASSERT_FALSE(VIRTUALIZATION_IS_VM(VIRTUALIZATION_DOCKER));
}

TEST(virtualization_is_container) {
        ASSERT_TRUE(VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_SYSTEMD_NSPAWN));
        ASSERT_TRUE(VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_DOCKER));
        ASSERT_TRUE(VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_CONTAINER_OTHER));
        ASSERT_FALSE(VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_NONE));
        ASSERT_FALSE(VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_KVM));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
