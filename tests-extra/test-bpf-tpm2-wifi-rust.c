/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C bpf_cgroup_attach_type, nl80211_cmd vs Rust.
 * Self-test: Rust tpm2_userspace_event_type, tpm2_pcr_index
 * (C tpm2 functions are behind #if HAVE_TPM2, not available without tpm2 libs) */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* Rust FFI */
#include "rust/netdev_str_tables.h"

/* C function forward declarations (from bpf-program.c, wifi-util.c) */
const char *bpf_cgroup_attach_type_to_string(int i);
int bpf_cgroup_attach_type_from_string(const char *s);
const char *nl80211_cmd_to_string(int i);

/* ── bpf_cgroup_attach_type (shadow) ─────────────────────────────────────── */

static void test_bpf_cgroup_attach_type(void) {
        const char *cr, *rr;
        int cv, rv;

        /* Test all named entries */
        static const struct {
                int val;
                const char *name;
        } entries[] = {
                { 0,  "ingress" },
                { 1,  "egress" },
                { 2,  "sock_create" },
                { 3,  "sock_ops" },
                { 6,  "device" },
                { 8,  "bind4" },
                { 9,  "bind6" },
                { 10, "connect4" },
                { 11, "connect6" },
                { 12, "post_bind4" },
                { 13, "post_bind6" },
                { 14, "sendmsg4" },
                { 15, "sendmsg6" },
                { 18, "sysctl" },
                { 19, "recvmsg4" },
                { 20, "recvmsg6" },
                { 21, "getsockopt" },
                { 22, "setsockopt" },
        };

        for (size_t i = 0; i < ELEMENTSOF(entries); i++) {
                cr = bpf_cgroup_attach_type_to_string(entries[i].val);
                rr = rs_bpf_cgroup_attach_type_to_string(entries[i].val);
                assert_se(cr && rr);
                assert_se(streq(cr, rr));

                cv = bpf_cgroup_attach_type_from_string(entries[i].name);
                rv = rs_bpf_cgroup_attach_type_from_string(entries[i].name);
                assert_se(cv == rv);
                assert_se(cv == entries[i].val);
        }

        /* Gaps return NULL for to_string */
        cr = bpf_cgroup_attach_type_to_string(4);
        rr = rs_bpf_cgroup_attach_type_to_string(4);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = bpf_cgroup_attach_type_to_string(5);
        rr = rs_bpf_cgroup_attach_type_to_string(5);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = bpf_cgroup_attach_type_to_string(7);
        rr = rs_bpf_cgroup_attach_type_to_string(7);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = bpf_cgroup_attach_type_to_string(16);
        rr = rs_bpf_cgroup_attach_type_to_string(16);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = bpf_cgroup_attach_type_to_string(17);
        rr = rs_bpf_cgroup_attach_type_to_string(17);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Invalid from_string */
        cv = bpf_cgroup_attach_type_from_string("nonexistent");
        rv = rs_bpf_cgroup_attach_type_from_string("nonexistent");
        assert_se(cv < 0);
        assert_se(rv < 0);

        cv = bpf_cgroup_attach_type_from_string(NULL);
        rv = rs_bpf_cgroup_attach_type_from_string(NULL);
        assert_se(cv < 0);
        assert_se(rv < 0);
}

/* ── tpm2_userspace_event_type (self-test, C behind #if HAVE_TPM2) ───────── */

static void test_tpm2_userspace_event_type(void) {
        const char *rr;
        int rv;

        /* Test all enum values (0..11) */
        static const struct {
                int val;
                const char *name;
        } entries[] = {
                { 0,  "phase" },
                { 1,  "filesystem" },
                { 2,  "volume-key" },
                { 3,  "machine-id" },
                { 4,  "product-id" },
                { 5,  "keyslot" },
                { 6,  "nvpcr-init" },
                { 7,  "nvpcr-separator" },
                { 8,  "dm-verity" },
                { 9,  "imds-userdata" },
                { 10, "os-separator" },
                { 11, "login" },
        };

        for (size_t i = 0; i < ELEMENTSOF(entries); i++) {
                rr = rs_tpm2_userspace_event_type_to_string(entries[i].val);
                assert_se(rr);
                assert_se(streq(rr, entries[i].name));

                rv = rs_tpm2_userspace_event_type_from_string(entries[i].name);
                assert_se(rv == entries[i].val);
        }

        /* Out of range */
        rr = rs_tpm2_userspace_event_type_to_string(12);
        assert_se(rr == NULL);

        rr = rs_tpm2_userspace_event_type_to_string(-1);
        assert_se(rr == NULL);

        /* Invalid from_string */
        rv = rs_tpm2_userspace_event_type_from_string("nonexistent");
        assert_se(rv < 0);
}

/* ── tpm2_pcr_index (self-test, C behind #if HAVE_TPM2) ──────────────────── */

static void test_tpm2_pcr_index(void) {
        const char *rr;
        int rv;

        /* Test all named entries */
        static const struct {
                int val;
                const char *name;
        } entries[] = {
                { 0,  "platform-code" },
                { 1,  "platform-config" },
                { 2,  "external-code" },
                { 3,  "external-config" },
                { 4,  "boot-loader-code" },
                { 5,  "boot-loader-config" },
                { 6,  "host-platform" },
                { 7,  "secure-boot-policy" },
                { 9,  "kernel-initrd" },
                { 10, "ima" },
                { 11, "kernel-boot" },
                { 12, "kernel-config" },
                { 13, "sysexts" },
                { 14, "shim-policy" },
                { 15, "system-identity" },
                { 16, "debug" },
                { 23, "application-support" },
        };

        for (size_t i = 0; i < ELEMENTSOF(entries); i++) {
                rr = rs_tpm2_pcr_index_to_string(entries[i].val);
                assert_se(rr);
                assert_se(streq(rr, entries[i].name));
        }

        /* Gap at PCR 8 returns NULL */
        rr = rs_tpm2_pcr_index_to_string(8);
        assert_se(rr == NULL);

        /* Gaps at 17-22 return NULL */
        for (int g = 17; g <= 22; g++) {
                rr = rs_tpm2_pcr_index_to_string(g);
                assert_se(rr == NULL);
        }

        /* Out of range */
        rr = rs_tpm2_pcr_index_to_string(-1);
        assert_se(rr == NULL);

        rr = rs_tpm2_pcr_index_to_string(24);
        assert_se(rr == NULL);

        /* from_string with named entries */
        for (size_t i = 0; i < ELEMENTSOF(entries); i++) {
                rv = rs_tpm2_pcr_index_from_string(entries[i].name);
                assert_se(rv == entries[i].val);
        }

        /* from_string with numeric fallback (0..23) */
        rv = rs_tpm2_pcr_index_from_string("8");
        assert_se(rv == 8);

        rv = rs_tpm2_pcr_index_from_string("17");
        assert_se(rv == 17);

        rv = rs_tpm2_pcr_index_from_string("0");
        assert_se(rv == 0);

        rv = rs_tpm2_pcr_index_from_string("23");
        assert_se(rv == 23);

        /* Match safe_atou() numeric syntax used by the C fallback. */
        rv = rs_tpm2_pcr_index_from_string("0x8");
        assert_se(rv == 8);
        rv = rs_tpm2_pcr_index_from_string("0b1000");
        assert_se(rv == 8);
        rv = rs_tpm2_pcr_index_from_string("0o10");
        assert_se(rv == 8);
        rv = rs_tpm2_pcr_index_from_string(" +8");
        assert_se(rv == 8);

        /* from_string out of range */
        rv = rs_tpm2_pcr_index_from_string("24");
        assert_se(rv < 0);

        rv = rs_tpm2_pcr_index_from_string("-1");
        assert_se(rv < 0);

        rv = rs_tpm2_pcr_index_from_string("nonexistent");
        assert_se(rv < 0);

        rv = rs_tpm2_pcr_index_from_string(NULL);
        assert_se(rv < 0);
}

/* ── nl80211_cmd (shadow) ────────────────────────────────────────────────── */

static void test_nl80211_cmd(void) {
        const char *cr, *rr;

        /* Test a representative sample of commands */
        static const struct {
                int val;
                const char *name;
        } entries[] = {
                { 1,   "get_wiphy" },
                { 2,   "set_wiphy" },
                { 5,   "get_interface" },
                { 15,  "start_ap" },
                { 16,  "stop_ap" },
                { 33,  "trigger_scan" },
                { 46,  "connect" },
                { 48,  "disconnect" },
                { 68,  "join_mesh" },
                { 89,  "start_p2p_device" },
                { 103, "vendor" },
                { 115, "start_nan" },
                { 128, "sta_opmode_changed" },
                { 145, "color_change_completed" },
        };

        for (size_t i = 0; i < ELEMENTSOF(entries); i++) {
                cr = nl80211_cmd_to_string(entries[i].val);
                rr = rs_nl80211_cmd_to_string(entries[i].val);
                assert_se(cr && rr);
                assert_se(streq(cr, rr));
        }

        /* Invalid values return NULL */
        cr = nl80211_cmd_to_string(0);
        rr = rs_nl80211_cmd_to_string(0);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = nl80211_cmd_to_string(-1);
        rr = rs_nl80211_cmd_to_string(-1);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = nl80211_cmd_to_string(200);
        rr = rs_nl80211_cmd_to_string(200);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

int main(int argc, char **argv) {
        test_bpf_cgroup_attach_type();
        test_tpm2_userspace_event_type();
        test_tpm2_pcr_index();
        test_nl80211_cmd();
        return 0;
}
