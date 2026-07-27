/* SPDX-License-Identifier: LGPL-2.1-or-later */


#include "cgroup-util.h"
#include "tests.h"

TEST(cgroup_io_limit_type_to_string) {
        ASSERT_STREQ(cgroup_io_limit_type_to_string(CGROUP_IO_RBPS_MAX), "IOReadBandwidthMax");
        ASSERT_STREQ(cgroup_io_limit_type_to_string(CGROUP_IO_WBPS_MAX), "IOWriteBandwidthMax");
        ASSERT_STREQ(cgroup_io_limit_type_to_string(CGROUP_IO_RIOPS_MAX), "IOReadIOPSMax");
        ASSERT_STREQ(cgroup_io_limit_type_to_string(CGROUP_IO_WIOPS_MAX), "IOWriteIOPSMax");
}

TEST(cgroup_io_limit_type_from_string) {
        ASSERT_EQ(cgroup_io_limit_type_from_string("IOReadBandwidthMax"), CGROUP_IO_RBPS_MAX);
        ASSERT_EQ(cgroup_io_limit_type_from_string("IOWriteBandwidthMax"), CGROUP_IO_WBPS_MAX);
        ASSERT_EQ(cgroup_io_limit_type_from_string("IOReadIOPSMax"), CGROUP_IO_RIOPS_MAX);
        ASSERT_EQ(cgroup_io_limit_type_from_string("IOWriteIOPSMax"), CGROUP_IO_WIOPS_MAX);
        ASSERT_EQ(cgroup_io_limit_type_from_string("invalid"), _CGROUP_IO_LIMIT_TYPE_INVALID);
}

TEST(cgroup_controller_to_string) {
        ASSERT_STREQ(cgroup_controller_to_string(CGROUP_CONTROLLER_CPU), "cpu");
        ASSERT_STREQ(cgroup_controller_to_string(CGROUP_CONTROLLER_MEMORY), "memory");
        ASSERT_STREQ(cgroup_controller_to_string(CGROUP_CONTROLLER_IO), "io");
        ASSERT_STREQ(cgroup_controller_to_string(CGROUP_CONTROLLER_PIDS), "pids");
        ASSERT_STREQ(cgroup_controller_to_string(CGROUP_CONTROLLER_BPF_FIREWALL), "bpf-firewall");
}

TEST(cgroup_controller_from_string) {
        ASSERT_EQ(cgroup_controller_from_string("cpu"), CGROUP_CONTROLLER_CPU);
        ASSERT_EQ(cgroup_controller_from_string("cpuacct"), CGROUP_CONTROLLER_CPUACCT);
        ASSERT_EQ(cgroup_controller_from_string("cpuset"), CGROUP_CONTROLLER_CPUSET);
        ASSERT_EQ(cgroup_controller_from_string("io"), CGROUP_CONTROLLER_IO);
        ASSERT_EQ(cgroup_controller_from_string("blkio"), CGROUP_CONTROLLER_BLKIO);
        ASSERT_EQ(cgroup_controller_from_string("memory"), CGROUP_CONTROLLER_MEMORY);
        ASSERT_EQ(cgroup_controller_from_string("devices"), CGROUP_CONTROLLER_DEVICES);
        ASSERT_EQ(cgroup_controller_from_string("pids"), CGROUP_CONTROLLER_PIDS);
        ASSERT_EQ(cgroup_controller_from_string("bpf-firewall"), CGROUP_CONTROLLER_BPF_FIREWALL);
        ASSERT_EQ(cgroup_controller_from_string("bpf-devices"), CGROUP_CONTROLLER_BPF_DEVICES);
        ASSERT_EQ(cgroup_controller_from_string("invalid"), _CGROUP_CONTROLLER_INVALID);
}

TEST(managed_oom_mode_to_string) {
        ASSERT_STREQ(managed_oom_mode_to_string(MANAGED_OOM_AUTO), "auto");
        ASSERT_STREQ(managed_oom_mode_to_string(MANAGED_OOM_KILL), "kill");
}

TEST(managed_oom_mode_from_string) {
        ASSERT_EQ(managed_oom_mode_from_string("auto"), MANAGED_OOM_AUTO);
        ASSERT_EQ(managed_oom_mode_from_string("kill"), MANAGED_OOM_KILL);
        ASSERT_EQ(managed_oom_mode_from_string("invalid"), _MANAGED_OOM_MODE_INVALID);
}

TEST(managed_oom_preference_to_string) {
        ASSERT_STREQ(managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_NONE), "none");
        ASSERT_STREQ(managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_AVOID), "avoid");
        ASSERT_STREQ(managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_OMIT), "omit");
}

TEST(managed_oom_preference_from_string) {
        ASSERT_EQ(managed_oom_preference_from_string("none"), MANAGED_OOM_PREFERENCE_NONE);
        ASSERT_EQ(managed_oom_preference_from_string("avoid"), MANAGED_OOM_PREFERENCE_AVOID);
        ASSERT_EQ(managed_oom_preference_from_string("omit"), MANAGED_OOM_PREFERENCE_OMIT);
        ASSERT_EQ(managed_oom_preference_from_string("invalid"), _MANAGED_OOM_PREFERENCE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
