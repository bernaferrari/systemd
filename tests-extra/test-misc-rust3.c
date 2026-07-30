/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C gpt_header_has_signature and mount-point predicates vs Rust */

#include "tests.h"
#include "gpt.h"
#include "mount-setup.h"
#include "rust/gpt_util.h"
#include "rust/mount_setup.h"

/* RUST-CONTRACT: gpt-header-signature */
/* ── gpt_header_has_signature ────────────────────────────────────────── */

static void test_gpt_header_has_signature_valid(void) {
        /* Build a valid GPT header (92 bytes) */
        uint8_t header[4096];
        zero(header);

        /* Signature "EFI PART" */
        memcpy(header, "EFI PART", 8);

        /* revision at offset 8: 0x00010000 in LE */
        header[8] = 0x00;
        header[9] = 0x00;
        header[10] = 0x01;
        header[11] = 0x00;

        /* header_size at offset 12: 92 (sizeof(GptHeader)) in LE */
        header[12] = 92;
        header[13] = 0;
        header[14] = 0;
        header[15] = 0;

        /* my_lba at offset 24: 1 in LE */
        header[24] = 1;
        header[25] = 0;
        header[26] = 0;
        header[27] = 0;
        header[28] = 0;
        header[29] = 0;
        header[30] = 0;
        header[31] = 0;

        bool cr = gpt_header_has_signature((const GptHeader *)header);
        bool rr = rs_gpt_header_has_signature(header);
        assert_se(cr == rr);
        assert_se(cr);
}

static void test_gpt_header_has_signature_bad_signature(void) {
        uint8_t header[256];
        zero(header);
        memcpy(header, "BAD SIG!", 8);

        bool cr = gpt_header_has_signature((const GptHeader *)header);
        bool rr = rs_gpt_header_has_signature(header);
        assert_se(cr == rr);
        assert_se(!cr);
}

static void test_gpt_header_has_signature_bad_revision(void) {
        uint8_t header[256];
        zero(header);
        memcpy(header, "EFI PART", 8);
        /* revision 0x00020000 (2.0, wrong) */
        header[10] = 0x02;

        bool cr = gpt_header_has_signature((const GptHeader *)header);
        bool rr = rs_gpt_header_has_signature(header);
        assert_se(cr == rr);
        assert_se(!cr);
}

static void test_gpt_header_has_signature_header_too_small(void) {
        uint8_t header[256];
        zero(header);
        memcpy(header, "EFI PART", 8);
        /* revision 1.0 */
        header[10] = 0x01;
        /* header_size = 50 (< 92) */
        header[12] = 50;

        bool cr = gpt_header_has_signature((const GptHeader *)header);
        bool rr = rs_gpt_header_has_signature(header);
        assert_se(cr == rr);
        assert_se(!cr);
}

static void test_gpt_header_has_signature_header_too_large(void) {
        uint8_t header[256];
        zero(header);
        memcpy(header, "EFI PART", 8);
        header[10] = 0x01;
        /* header_size = 5000 (> 4096) */
        header[12] = 0x88;
        header[13] = 0x13;

        bool cr = gpt_header_has_signature((const GptHeader *)header);
        bool rr = rs_gpt_header_has_signature(header);
        assert_se(cr == rr);
        assert_se(!cr);
}

static void test_gpt_header_has_signature_bad_lba(void) {
        uint8_t header[256];
        zero(header);
        memcpy(header, "EFI PART", 8);
        header[10] = 0x01;
        header[12] = 92; /* header_size OK */
        /* my_lba at offset 24: 0 (should be 1) */
        /* already zero */

        bool cr = gpt_header_has_signature((const GptHeader *)header);
        bool rr = rs_gpt_header_has_signature(header);
        assert_se(cr == rr);
        assert_se(!cr);
}

/* ── mount_point_is_api ──────────────────────────────────────────────── */

static void test_mount_point_is_api_known(void) {
        bool cr, rr;

        cr = mount_point_is_api("/proc");
        rr = rs_mount_point_is_api("/proc");
        assert_se(cr == rr);
        assert_se(cr);

        cr = mount_point_is_api("/sys");
        rr = rs_mount_point_is_api("/sys");
        assert_se(cr == rr);
        assert_se(cr);

        cr = mount_point_is_api("/dev");
        rr = rs_mount_point_is_api("/dev");
        assert_se(cr == rr);
        assert_se(cr);

        cr = mount_point_is_api("/run");
        rr = rs_mount_point_is_api("/run");
        assert_se(cr == rr);
        assert_se(cr);

        cr = mount_point_is_api("/sys/fs/cgroup");
        rr = rs_mount_point_is_api("/sys/fs/cgroup");
        assert_se(cr == rr);
        assert_se(cr);
}

static void test_mount_point_is_api_cgroup_subdir(void) {
        bool cr, rr;

        cr = mount_point_is_api("/sys/fs/cgroup/systemd");
        rr = rs_mount_point_is_api("/sys/fs/cgroup/systemd");
        assert_se(cr == rr);
        assert_se(cr);

        cr = mount_point_is_api("/sys/fs/cgroup/cpu,cpuacct");
        rr = rs_mount_point_is_api("/sys/fs/cgroup/cpu,cpuacct");
        assert_se(cr == rr);
        assert_se(cr);
}

static void test_mount_point_is_api_not_api(void) {
        bool cr, rr;

        cr = mount_point_is_api("/home");
        rr = rs_mount_point_is_api("/home");
        assert_se(cr == rr);
        assert_se(!cr);

        cr = mount_point_is_api("/tmp");
        rr = rs_mount_point_is_api("/tmp");
        assert_se(cr == rr);
        assert_se(!cr);

        cr = mount_point_is_api("/var");
        rr = rs_mount_point_is_api("/var");
        assert_se(cr == rr);
        assert_se(!cr);
}

/* ── mount_point_ignore ──────────────────────────────────────────────── */

static void test_mount_point_ignore_known(void) {
        bool cr, rr;

        cr = mount_point_ignore("/sys/fs/selinux");
        rr = rs_mount_point_ignore("/sys/fs/selinux");
        assert_se(cr == rr);
        assert_se(cr);

        cr = mount_point_ignore("/dev/console");
        rr = rs_mount_point_ignore("/dev/console");
        assert_se(cr == rr);
        assert_se(cr);

        cr = mount_point_ignore("/proc/kmsg");
        rr = rs_mount_point_ignore("/proc/kmsg");
        assert_se(cr == rr);
        assert_se(cr);

        cr = mount_point_ignore("/proc/sys");
        rr = rs_mount_point_ignore("/proc/sys");
        assert_se(cr == rr);
        assert_se(cr);
}

static void test_mount_point_ignore_run_host(void) {
        bool cr, rr;

        cr = mount_point_ignore("/run/host");
        rr = rs_mount_point_ignore("/run/host");
        assert_se(cr == rr);
        assert_se(cr);

        cr = mount_point_ignore("/run/host/incoming");
        rr = rs_mount_point_ignore("/run/host/incoming");
        assert_se(cr == rr);
        assert_se(cr);
}

static void test_mount_point_ignore_not_ignored(void) {
        bool cr, rr;

        cr = mount_point_ignore("/home");
        rr = rs_mount_point_ignore("/home");
        assert_se(cr == rr);
        assert_se(!cr);

        cr = mount_point_ignore("/tmp");
        rr = rs_mount_point_ignore("/tmp");
        assert_se(cr == rr);
        assert_se(!cr);

        cr = mount_point_ignore("/run/user");
        rr = rs_mount_point_ignore("/run/user");
        assert_se(cr == rr);
        assert_se(!cr);
}

int main(int argc, char **argv) {
        test_gpt_header_has_signature_valid();
        test_gpt_header_has_signature_bad_signature();
        test_gpt_header_has_signature_bad_revision();
        test_gpt_header_has_signature_header_too_small();
        test_gpt_header_has_signature_header_too_large();
        test_gpt_header_has_signature_bad_lba();
        test_mount_point_is_api_known();
        test_mount_point_is_api_cgroup_subdir();
        test_mount_point_is_api_not_api();
        test_mount_point_ignore_known();
        test_mount_point_ignore_run_host();
        test_mount_point_ignore_not_ignored();
        return 0;
}
