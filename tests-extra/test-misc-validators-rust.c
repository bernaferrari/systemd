/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C process-util, mountpoint-util, parse-util, os-util validators vs Rust */

#include <assert.h>
#include <string.h>
#include <sched.h>
#include <sys/mount.h>
#include <limits.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "process-util.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "os-util.h"
#include "user-util.h"
#include "syslog-util.h"
#include "socket-util.h"
#include "bus-print-properties.h"
#include "rust/misc_validators.h"
#include "rust/mountpoint_util.h"
#include "rust/socket_util.h"

/* -- nice_is_valid -------------------------------------------------------- */

static void test_nice_is_valid(void) {
        assert_se(nice_is_valid(-20) == rs_nice_is_valid(-20));
        assert_se(nice_is_valid(-20) == true);

        assert_se(nice_is_valid(0) == rs_nice_is_valid(0));
        assert_se(nice_is_valid(0) == true);

        assert_se(nice_is_valid(18) == rs_nice_is_valid(18));
        assert_se(nice_is_valid(18) == true);

        /* PRIO_MAX (20) is NOT valid — C uses < not <= */
        assert_se(nice_is_valid(20) == rs_nice_is_valid(20));
        assert_se(nice_is_valid(20) == false);

        assert_se(nice_is_valid(-21) == rs_nice_is_valid(-21));
        assert_se(nice_is_valid(-21) == false);

        assert_se(nice_is_valid(INT_MAX) == rs_nice_is_valid(INT_MAX));
        assert_se(nice_is_valid(INT_MIN) == rs_nice_is_valid(INT_MIN));
}

/* -- sched_policy_is_valid ------------------------------------------------ */

static void test_sched_policy_is_valid(void) {
        assert_se(sched_policy_is_valid(SCHED_OTHER) == rs_sched_policy_is_valid(SCHED_OTHER));
        assert_se(sched_policy_is_valid(SCHED_OTHER) == true);

        assert_se(sched_policy_is_valid(SCHED_FIFO) == rs_sched_policy_is_valid(SCHED_FIFO));
        assert_se(sched_policy_is_valid(SCHED_FIFO) == true);

        assert_se(sched_policy_is_valid(SCHED_RR) == rs_sched_policy_is_valid(SCHED_RR));
        assert_se(sched_policy_is_valid(SCHED_RR) == true);

        assert_se(sched_policy_is_valid(SCHED_BATCH) == rs_sched_policy_is_valid(SCHED_BATCH));
        assert_se(sched_policy_is_valid(SCHED_BATCH) == true);

        assert_se(sched_policy_is_valid(SCHED_IDLE) == rs_sched_policy_is_valid(SCHED_IDLE));
        assert_se(sched_policy_is_valid(SCHED_IDLE) == true);

        assert_se(sched_policy_is_valid(4) == rs_sched_policy_is_valid(4));
        assert_se(sched_policy_is_valid(4) == false);

        assert_se(sched_policy_is_valid(-1) == rs_sched_policy_is_valid(-1));
        assert_se(sched_policy_is_valid(-1) == false);
}

/* -- oom_score_adjust_is_valid -------------------------------------------- */

static void test_oom_score_adjust_is_valid(void) {
        assert_se(oom_score_adjust_is_valid(-1000) == rs_oom_score_adjust_is_valid(-1000));
        assert_se(oom_score_adjust_is_valid(-1000) == true);

        assert_se(oom_score_adjust_is_valid(0) == rs_oom_score_adjust_is_valid(0));
        assert_se(oom_score_adjust_is_valid(0) == true);

        assert_se(oom_score_adjust_is_valid(1000) == rs_oom_score_adjust_is_valid(1000));
        assert_se(oom_score_adjust_is_valid(1000) == true);

        assert_se(oom_score_adjust_is_valid(-1001) == rs_oom_score_adjust_is_valid(-1001));
        assert_se(oom_score_adjust_is_valid(-1001) == false);

        assert_se(oom_score_adjust_is_valid(1001) == rs_oom_score_adjust_is_valid(1001));
        assert_se(oom_score_adjust_is_valid(1001) == false);
}

/* -- mount_propagation_flag_is_valid -------------------------------------- */

static void test_mount_propagation_flag_is_valid(void) {
        assert_se(mount_propagation_flag_is_valid(0) == rs_mount_propagation_flag_is_valid(0));
        assert_se(mount_propagation_flag_is_valid(0) == true);

        assert_se(mount_propagation_flag_is_valid(MS_SHARED) == rs_mount_propagation_flag_is_valid(MS_SHARED));
        assert_se(mount_propagation_flag_is_valid(MS_SHARED) == true);

        assert_se(mount_propagation_flag_is_valid(MS_PRIVATE) == rs_mount_propagation_flag_is_valid(MS_PRIVATE));
        assert_se(mount_propagation_flag_is_valid(MS_PRIVATE) == true);

        assert_se(mount_propagation_flag_is_valid(MS_SLAVE) == rs_mount_propagation_flag_is_valid(MS_SLAVE));
        assert_se(mount_propagation_flag_is_valid(MS_SLAVE) == true);

        assert_se(mount_propagation_flag_is_valid(MS_UNBINDABLE) == rs_mount_propagation_flag_is_valid(MS_UNBINDABLE));
        assert_se(mount_propagation_flag_is_valid(MS_UNBINDABLE) == false);

        assert_se(mount_propagation_flag_is_valid(0xDEAD) == rs_mount_propagation_flag_is_valid(0xDEAD));
        assert_se(mount_propagation_flag_is_valid(0xDEAD) == false);
}

/* -- nft_identifier_valid ------------------------------------------------- */

static void test_nft_identifier_valid(void) {
        assert_se(nft_identifier_valid("abc") == rs_nft_identifier_valid("abc"));
        assert_se(nft_identifier_valid("abc") == true);

        assert_se(nft_identifier_valid("a1") == rs_nft_identifier_valid("a1"));
        assert_se(nft_identifier_valid("a1") == true);

        assert_se(nft_identifier_valid("a_b.c/d") == rs_nft_identifier_valid("a_b.c/d"));
        assert_se(nft_identifier_valid("a_b.c/d") == true);

        assert_se(nft_identifier_valid("") == rs_nft_identifier_valid(""));
        assert_se(nft_identifier_valid("") == false);

        assert_se(nft_identifier_valid("1abc") == rs_nft_identifier_valid("1abc"));
        assert_se(nft_identifier_valid("1abc") == false);

        assert_se(nft_identifier_valid("_abc") == rs_nft_identifier_valid("_abc"));
        assert_se(nft_identifier_valid("_abc") == false);
}

/* -- image_name_is_valid -------------------------------------------------- */

static void test_image_name_is_valid(void) {
        assert_se(image_name_is_valid("myimage") == rs_image_name_is_valid("myimage"));
        assert_se(image_name_is_valid("myimage") == true);

        assert_se(image_name_is_valid("my.image") == rs_image_name_is_valid("my.image"));
        assert_se(image_name_is_valid("my.image") == true);

        assert_se(image_name_is_valid("my_image-v2") == rs_image_name_is_valid("my_image-v2"));
        assert_se(image_name_is_valid("my_image-v2") == true);

        assert_se(image_name_is_valid("") == rs_image_name_is_valid(""));
        assert_se(image_name_is_valid("") == false);

        assert_se(image_name_is_valid(".#temp") == rs_image_name_is_valid(".#temp"));
        assert_se(image_name_is_valid(".#temp") == false);

        assert_se(image_name_is_valid("image/with/slash") == rs_image_name_is_valid("image/with/slash"));
        assert_se(image_name_is_valid("image/with/slash") == false);

        assert_se(image_name_is_valid("image\x01" "bad") == rs_image_name_is_valid("image\x01" "bad"));
        assert_se(image_name_is_valid("image\x01" "bad") == false);
}

/* -- valid_gecos ---------------------------------------------------------- */

static void test_valid_gecos(void) {
        assert_se(valid_gecos("John Doe") == rs_valid_gecos("John Doe"));
        assert_se(valid_gecos("John Doe") == true);

        assert_se(valid_gecos("") == rs_valid_gecos(""));
        assert_se(valid_gecos("") == true);

        assert_se(valid_gecos(NULL) == rs_valid_gecos(NULL));
        assert_se(valid_gecos(NULL) == false);

        assert_se(valid_gecos("a:b") == rs_valid_gecos("a:b"));
        assert_se(valid_gecos("a:b") == false);

        assert_se(valid_gecos("line1\nline2") == rs_valid_gecos("line1\nline2"));
        assert_se(valid_gecos("line1\nline2") == false);
}

/* -- log_namespace_name_valid --------------------------------------------- */

static void test_log_namespace_name_valid(void) {
        assert_se(log_namespace_name_valid("mylog") == rs_log_namespace_name_valid("mylog"));
        assert_se(log_namespace_name_valid("mylog") == true);

        assert_se(log_namespace_name_valid("") == rs_log_namespace_name_valid(""));
        assert_se(log_namespace_name_valid("") == false);

        /* NULL — C filename_is_valid asserts on NULL, only test Rust side */
        assert_se(rs_log_namespace_name_valid(NULL) == false);

        assert_se(log_namespace_name_valid("log/name") == rs_log_namespace_name_valid("log/name"));
        assert_se(log_namespace_name_valid("log/name") == false);

        assert_se(log_namespace_name_valid("log*glob") == rs_log_namespace_name_valid("log*glob"));
        assert_se(log_namespace_name_valid("log*glob") == false);

        assert_se(log_namespace_name_valid("log\x01ctrl") == rs_log_namespace_name_valid("log\x01ctrl"));
        assert_se(log_namespace_name_valid("log\x01ctrl") == false);
}

/* -- address_label_valid -------------------------------------------------- */

static void test_address_label_valid(void) {
        assert_se(address_label_valid("eth0") == rs_address_label_valid("eth0"));
        assert_se(address_label_valid("eth0") == true);

        assert_se(address_label_valid("my label") == rs_address_label_valid("my label"));
        assert_se(address_label_valid("my label") == true);

        assert_se(address_label_valid("") == rs_address_label_valid(""));
        assert_se(address_label_valid("") == false);

        assert_se(address_label_valid(NULL) == rs_address_label_valid(NULL));
        assert_se(address_label_valid(NULL) == false);

        /* 0x7F is DEL, should be rejected */
        assert_se(address_label_valid("label\x7f") == rs_address_label_valid("label\x7f"));
        assert_se(address_label_valid("label\x7f") == false);
}

/* -- valid_home ------------------------------------------------------------- */

static void test_valid_home(void) {
        assert_se(valid_home("/home/user") == rs_valid_home("/home/user"));
        assert_se(valid_home("/home/user") == true);

        assert_se(valid_home("/bin/bash") == rs_valid_home("/bin/bash"));
        assert_se(valid_home("/bin/bash") == true);

        assert_se(valid_home("") == rs_valid_home(""));
        assert_se(valid_home("") == false);

        assert_se(valid_home(NULL) == rs_valid_home(NULL));
        assert_se(valid_home(NULL) == false);

        assert_se(valid_home("relative/path") == rs_valid_home("relative/path"));
        assert_se(valid_home("relative/path") == false);

        assert_se(valid_home("/path/with:colon") == rs_valid_home("/path/with:colon"));
        assert_se(valid_home("/path/with:colon") == false);

        assert_se(valid_home("/path/with\nnewline") == rs_valid_home("/path/with\nnewline"));
        assert_se(valid_home("/path/with\nnewline") == false);

        assert_se(valid_home("/path/with//double") == rs_valid_home("/path/with//double"));
        assert_se(valid_home("/path/with//double") == false);

        assert_se(valid_home("/path/with/./dot") == rs_valid_home("/path/with/./dot"));
        assert_se(valid_home("/path/with/./dot") == false);

        assert_se(valid_home("/trailing/") == rs_valid_home("/trailing/"));
        assert_se(valid_home("/trailing/") == true);

        assert_se(valid_home("/") == rs_valid_home("/"));
        assert_se(valid_home("/") == true);
}

/* -- valid_shell ------------------------------------------------------------- */

static void test_valid_shell(void) {
        assert_se(valid_shell("/bin/bash") == rs_valid_shell("/bin/bash"));
        assert_se(valid_shell("/bin/bash") == true);

        assert_se(valid_shell("/usr/bin/zsh") == rs_valid_shell("/usr/bin/zsh"));
        assert_se(valid_shell("/usr/bin/zsh") == true);

        assert_se(valid_shell("") == rs_valid_shell(""));
        assert_se(valid_shell("") == false);

        assert_se(valid_shell(NULL) == rs_valid_shell(NULL));
        assert_se(valid_shell(NULL) == false);

        /* Shells may not be directories */
        assert_se(valid_shell("/bin/") == rs_valid_shell("/bin/"));
        assert_se(valid_shell("/bin/") == false);

        assert_se(valid_shell("/home/user/") == rs_valid_shell("/home/user/"));
        assert_se(valid_shell("/home/user/") == false);

        /* Same restrictions as valid_home */
        assert_se(valid_shell("relative/path") == rs_valid_shell("relative/path"));
        assert_se(valid_shell("relative/path") == false);
}

/* -- bus_property_is_timestamp ---------------------------------------------- */

static void test_bus_property_is_timestamp(void) {
        bool cv, rv;

        /* Ends with "Timestamp" */
        cv = bus_property_is_timestamp("InactiveEnterTimestamp");
        rv = rs_bus_property_is_timestamp("InactiveEnterTimestamp");
        assert_se(cv == rv);
        assert_se(cv);

        cv = bus_property_is_timestamp("ActiveExitTimestampMonotonic");
        rv = rs_bus_property_is_timestamp("ActiveExitTimestampMonotonic");
        assert_se(cv == rv);
        assert_se(!cv);  /* ends with "Monotonic", not "Timestamp" */

        /* STR_IN_SET special cases */
        cv = bus_property_is_timestamp("NextElapseUSecRealtime");
        rv = rs_bus_property_is_timestamp("NextElapseUSecRealtime");
        assert_se(cv == rv);
        assert_se(cv);

        cv = bus_property_is_timestamp("LastTriggerUSec");
        rv = rs_bus_property_is_timestamp("LastTriggerUSec");
        assert_se(cv == rv);
        assert_se(cv);

        cv = bus_property_is_timestamp("TimeUSec");
        rv = rs_bus_property_is_timestamp("TimeUSec");
        assert_se(cv == rv);
        assert_se(cv);

        cv = bus_property_is_timestamp("RTCTimeUSec");
        rv = rs_bus_property_is_timestamp("RTCTimeUSec");
        assert_se(cv == rv);
        assert_se(cv);

        /* Not a timestamp */
        cv = bus_property_is_timestamp("Description");
        rv = rs_bus_property_is_timestamp("Description");
        assert_se(cv == rv);
        assert_se(!cv);

        cv = bus_property_is_timestamp("TimestampToo");  /* ends with "Too" not "Timestamp" */
        rv = rs_bus_property_is_timestamp("TimestampToo");
        assert_se(cv == rv);
        assert_se(!cv);

        /* NULL — C asserts on NULL, only test Rust side */
        rv = rs_bus_property_is_timestamp(NULL);
        assert_se(!rv);

        /* "Timestamp" exactly */
        cv = bus_property_is_timestamp("Timestamp");
        rv = rs_bus_property_is_timestamp("Timestamp");
        assert_se(cv == rv);
        assert_se(cv);
}

int main(int argc, char **argv) {
        test_nice_is_valid();
        test_sched_policy_is_valid();
        test_oom_score_adjust_is_valid();
        test_mount_propagation_flag_is_valid();
        test_nft_identifier_valid();
        test_image_name_is_valid();
        test_valid_gecos();
        test_log_namespace_name_valid();
        test_address_label_valid();
        test_valid_home();
        test_valid_shell();
        test_bus_property_is_timestamp();
        return 0;
}
