/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "virt.h"
#include "tests.h"

TEST(virtualization_to_string_basic) {
        assert_se(streq(virtualization_to_string(VIRTUALIZATION_NONE), "none"));
        assert_se(streq(virtualization_to_string(VIRTUALIZATION_KVM), "kvm"));
        assert_se(streq(virtualization_to_string(VIRTUALIZATION_QEMU), "qemu"));
        assert_se(streq(virtualization_to_string(VIRTUALIZATION_VMWARE), "vmware"));
        assert_se(streq(virtualization_to_string(VIRTUALIZATION_ORACLE), "oracle"));
        assert_se(streq(virtualization_to_string(VIRTUALIZATION_XEN), "xen"));
        assert_se(streq(virtualization_to_string(VIRTUALIZATION_SYSTEMD_NSPAWN), "systemd-nspawn"));
        assert_se(streq(virtualization_to_string(VIRTUALIZATION_DOCKER), "docker"));
        assert_se(streq(virtualization_to_string(VIRTUALIZATION_PODMAN), "podman"));
}

TEST(virtualization_from_string_basic) {
        assert_se(virtualization_from_string("none") == VIRTUALIZATION_NONE);
        assert_se(virtualization_from_string("kvm") == VIRTUALIZATION_KVM);
        assert_se(virtualization_from_string("qemu") == VIRTUALIZATION_QEMU);
        assert_se(virtualization_from_string("vmware") == VIRTUALIZATION_VMWARE);
        assert_se(virtualization_from_string("oracle") == VIRTUALIZATION_ORACLE);
        assert_se(virtualization_from_string("xen") == VIRTUALIZATION_XEN);
        assert_se(virtualization_from_string("systemd-nspawn") == VIRTUALIZATION_SYSTEMD_NSPAWN);
        assert_se(virtualization_from_string("docker") == VIRTUALIZATION_DOCKER);
        assert_se(virtualization_from_string("podman") == VIRTUALIZATION_PODMAN);
}

TEST(virtualization_roundtrip) {
        assert_se(virtualization_from_string(virtualization_to_string(VIRTUALIZATION_KVM)) == VIRTUALIZATION_KVM);
        assert_se(virtualization_from_string(virtualization_to_string(VIRTUALIZATION_QEMU)) == VIRTUALIZATION_QEMU);
        assert_se(virtualization_from_string(virtualization_to_string(VIRTUALIZATION_NONE)) == VIRTUALIZATION_NONE);
}

TEST(virtualization_is_vm_macro) {
        assert_se(VIRTUALIZATION_IS_VM(VIRTUALIZATION_KVM));
        assert_se(VIRTUALIZATION_IS_VM(VIRTUALIZATION_QEMU));
        assert_se(VIRTUALIZATION_IS_VM(VIRTUALIZATION_VMWARE));
        assert_se(!VIRTUALIZATION_IS_VM(VIRTUALIZATION_NONE));
        assert_se(!VIRTUALIZATION_IS_VM(VIRTUALIZATION_DOCKER));
        assert_se(!VIRTUALIZATION_IS_VM(VIRTUALIZATION_SYSTEMD_NSPAWN));
}

TEST(virtualization_is_container_macro) {
        assert_se(VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_DOCKER));
        assert_se(VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_PODMAN));
        assert_se(VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_SYSTEMD_NSPAWN));
        assert_se(!VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_NONE));
        assert_se(!VIRTUALIZATION_IS_CONTAINER(VIRTUALIZATION_KVM));
}

TEST(virtualization_detect_basic) {
        int v = detect_virtualization();
        if (VIRTUALIZATION_IS_CONTAINER(v))
                printf("Running in container: %s\n", virtualization_to_string(v));
        else if (VIRTUALIZATION_IS_VM(v))
                printf("Running in VM: %s\n", virtualization_to_string(v));
        else
                printf("No virtualization detected\n");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
