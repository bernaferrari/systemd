/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C cgroup-util string tables vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"

/* C headers */
#include "cgroup-util.h"
#include "rust/unit_def.h"

/* Allocation-owning mask helpers are declared by the Rust-owned ABI header. */

/* ── cgroup_io_limit_type ──────────────────────────────────────────────── */

static void test_cgroup_io_limit_type(void) {
        const char *cr, *rr;
        int cv, rv;

        cr = cgroup_io_limit_type_to_string(0);
        rr = rs_cgroup_io_limit_type_to_string(0);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = cgroup_io_limit_type_to_string(3);
        rr = rs_cgroup_io_limit_type_to_string(3);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = cgroup_io_limit_type_to_string(99);
        rr = rs_cgroup_io_limit_type_to_string(99);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cv = cgroup_io_limit_type_from_string("IOReadBandwidthMax");
        rv = rs_cgroup_io_limit_type_from_string("IOReadBandwidthMax");
        assert_se(cv == rv);
        assert_se(cv == 0);

        cv = cgroup_io_limit_type_from_string("bogus");
        rv = rs_cgroup_io_limit_type_from_string("bogus");
        assert_se(cv < 0);
        assert_se(rv < 0);

        for (int value = -1; value <= _CGROUP_IO_LIMIT_TYPE_MAX; value++) {
                cr = cgroup_io_limit_type_to_string(value);
                rr = rs_cgroup_io_limit_type_to_string(value);
                assert_se((cr == NULL) == (rr == NULL));
                if (cr) {
                        assert_se(streq(cr, rr));
                        assert_se(cgroup_io_limit_type_from_string(cr) ==
                                  rs_cgroup_io_limit_type_from_string(cr));
                }
        }
}

/* ── cgroup_controller ─────────────────────────────────────────────────── */

static void test_cgroup_controller(void) {
        const char *cr, *rr;
        int cv, rv;

        cr = cgroup_controller_to_string(CGROUP_CONTROLLER_CPU);
        rr = rs_cgroup_controller_to_string(CGROUP_CONTROLLER_CPU);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = cgroup_controller_to_string(CGROUP_CONTROLLER_MEMORY);
        rr = rs_cgroup_controller_to_string(CGROUP_CONTROLLER_MEMORY);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = cgroup_controller_to_string(CGROUP_CONTROLLER_BPF_FIREWALL);
        rr = rs_cgroup_controller_to_string(CGROUP_CONTROLLER_BPF_FIREWALL);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = cgroup_controller_to_string(CGROUP_CONTROLLER_BPF_BIND_NETWORK_INTERFACE);
        rr = rs_cgroup_controller_to_string(CGROUP_CONTROLLER_BPF_BIND_NETWORK_INTERFACE);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = cgroup_controller_to_string(_CGROUP_CONTROLLER_MAX);
        rr = rs_cgroup_controller_to_string(_CGROUP_CONTROLLER_MAX);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cv = cgroup_controller_from_string("cpu");
        rv = rs_cgroup_controller_from_string("cpu");
        assert_se(cv == rv);
        assert_se(cv == CGROUP_CONTROLLER_CPU);

        cv = cgroup_controller_from_string("memory");
        rv = rs_cgroup_controller_from_string("memory");
        assert_se(cv == rv);
        assert_se(cv == CGROUP_CONTROLLER_MEMORY);

        cv = cgroup_controller_from_string("bpf-firewall");
        rv = rs_cgroup_controller_from_string("bpf-firewall");
        assert_se(cv == rv);
        assert_se(cv == CGROUP_CONTROLLER_BPF_FIREWALL);

        cv = cgroup_controller_from_string("bogus");
        rv = rs_cgroup_controller_from_string("bogus");
        assert_se(cv < 0);
        assert_se(rv < 0);

        for (int value = -1; value <= _CGROUP_CONTROLLER_MAX; value++) {
                cr = cgroup_controller_to_string(value);
                rr = rs_cgroup_controller_to_string(value);
                assert_se((cr == NULL) == (rr == NULL));
                if (cr) {
                        assert_se(streq(cr, rr));
                        assert_se(cgroup_controller_from_string(cr) ==
                                  rs_cgroup_controller_from_string(cr));
                }
        }
}

/* ── managed_oom_mode ──────────────────────────────────────────────────── */

static void test_managed_oom_mode(void) {
        const char *cr, *rr;
        int cv, rv;

        cr = managed_oom_mode_to_string(MANAGED_OOM_AUTO);
        rr = rs_managed_oom_mode_to_string(MANAGED_OOM_AUTO);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = managed_oom_mode_to_string(MANAGED_OOM_KILL);
        rr = rs_managed_oom_mode_to_string(MANAGED_OOM_KILL);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cv = managed_oom_mode_from_string("auto");
        rv = rs_managed_oom_mode_from_string("auto");
        assert_se(cv == rv);
        assert_se(cv == MANAGED_OOM_AUTO);

        cv = managed_oom_mode_from_string("bogus");
        rv = rs_managed_oom_mode_from_string("bogus");
        assert_se(cv < 0);
        assert_se(rv < 0);

        for (int value = -1; value <= _MANAGED_OOM_MODE_MAX; value++) {
                cr = managed_oom_mode_to_string(value);
                rr = rs_managed_oom_mode_to_string(value);
                assert_se((cr == NULL) == (rr == NULL));
                if (cr) {
                        assert_se(streq(cr, rr));
                        assert_se(managed_oom_mode_from_string(cr) ==
                                  rs_managed_oom_mode_from_string(cr));
                }
        }
}

/* ── managed_oom_preference ─────────────────────────────────────────────── */

static void test_managed_oom_preference(void) {
        const char *cr, *rr;
        int cv, rv;

        cr = managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_NONE);
        rr = rs_managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_NONE);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_AVOID);
        rr = rs_managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_AVOID);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cr = managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_OMIT);
        rr = rs_managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_OMIT);
        assert_se(cr && rr);
        assert_se(streq(cr, rr));

        cv = managed_oom_preference_from_string("none");
        rv = rs_managed_oom_preference_from_string("none");
        assert_se(cv == rv);

        cv = managed_oom_preference_from_string("bogus");
        rv = rs_managed_oom_preference_from_string("bogus");
        assert_se(cv < 0);
        assert_se(rv < 0);

        for (int value = -1; value <= _MANAGED_OOM_PREFERENCE_MAX; value++) {
                cr = managed_oom_preference_to_string(value);
                rr = rs_managed_oom_preference_to_string(value);
                assert_se((cr == NULL) == (rr == NULL));
                if (cr) {
                        assert_se(streq(cr, rr));
                        assert_se(managed_oom_preference_from_string(cr) ==
                                  rs_managed_oom_preference_from_string(cr));
                }
        }
}

static void test_cgroup_escape_predicates(void) {
        static const char *const names[] = {
                "demo.service",
                "_escaped",
                ".hidden",
                "notify_on_release",
                "release_agent",
                "tasks",
                "cgroup.procs",
                "cpu.weight",
                "memory.low",
                "ordinary",
                "",
                ".",
                "..",
                "contains/slash",
        };

        FOREACH_ELEMENT(name, names) {
                assert_se(cg_needs_escape(*name) == rs_cg_needs_escape(*name));
                assert_se(streq(cg_unescape(*name), rs_cg_unescape(*name)));
        }

        assert_se(rs_cg_needs_escape(NULL));
        assert_se(rs_cg_unescape(NULL) == NULL);
}

/* ── cg_mask_to_string / cg_mask_from_string ────────────────────────────── */

static void test_cg_mask(void) {
        _cleanup_free_ char *cr = NULL, *rr = NULL;
        unsigned int cm, rm;
        int c_ret, r_ret;

        /* Single controller */
        c_ret = cg_mask_to_string(CGROUP_MASK_CPU, &cr);
        r_ret = rs_cg_mask_to_string(CGROUP_MASK_CPU, &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));

        free(cr); cr = NULL;
        free(rr); rr = NULL;

        /* Multiple controllers */
        c_ret = cg_mask_to_string(CGROUP_MASK_CPU | CGROUP_MASK_MEMORY, &cr);
        r_ret = rs_cg_mask_to_string(CGROUP_MASK_CPU | CGROUP_MASK_MEMORY, &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));

        free(cr); cr = NULL;
        free(rr); rr = NULL;

        /* Zero mask */
        c_ret = cg_mask_to_string(0, &cr);
        r_ret = rs_cg_mask_to_string(0, &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* All controllers */
        c_ret = cg_mask_to_string(CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_CPUSET |
                                      CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY |
                                      CGROUP_MASK_DEVICES | CGROUP_MASK_PIDS |
                                      CGROUP_MASK_BPF_FIREWALL | CGROUP_MASK_BPF_DEVICES |
                                      CGROUP_MASK_BPF_FOREIGN | CGROUP_MASK_BPF_SOCKET_BIND |
                                      CGROUP_MASK_BPF_RESTRICT_NETWORK_INTERFACES |
                                      CGROUP_MASK_BPF_BIND_NETWORK_INTERFACE, &cr);
        r_ret = rs_cg_mask_to_string(CGROUP_MASK_CPU | CGROUP_MASK_CPUACCT | CGROUP_MASK_CPUSET |
                                      CGROUP_MASK_IO | CGROUP_MASK_BLKIO | CGROUP_MASK_MEMORY |
                                      CGROUP_MASK_DEVICES | CGROUP_MASK_PIDS |
                                      CGROUP_MASK_BPF_FIREWALL | CGROUP_MASK_BPF_DEVICES |
                                      CGROUP_MASK_BPF_FOREIGN | CGROUP_MASK_BPF_SOCKET_BIND |
                                      CGROUP_MASK_BPF_RESTRICT_NETWORK_INTERFACES |
                                      CGROUP_MASK_BPF_BIND_NETWORK_INTERFACE, &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(streq(cr, rr));

        free(cr); cr = NULL;
        free(rr); rr = NULL;

        /* from_string roundtrip: single */
        c_ret = cg_mask_from_string("cpu", &cm);
        r_ret = rs_cg_mask_from_string("cpu", &rm);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cm == rm);
        assert_se(cm == CGROUP_MASK_CPU);

        /* from_string: multiple */
        c_ret = cg_mask_from_string("cpu memory io", &cm);
        r_ret = rs_cg_mask_from_string("cpu memory io", &rm);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cm == rm);

        /* from_string: empty string */
        c_ret = cg_mask_from_string("", &cm);
        r_ret = rs_cg_mask_from_string("", &rm);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cm == 0);
        assert_se(rm == 0);

        /* from_string: unknown names silently ignored */
        c_ret = cg_mask_from_string("cpu bogus memory", &cm);
        r_ret = rs_cg_mask_from_string("cpu bogus memory", &rm);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cm == rm);
        assert_se((cm & CGROUP_MASK_CPU) != 0);
        assert_se((cm & CGROUP_MASK_MEMORY) != 0);
}

int main(int argc, char **argv) {
        test_cgroup_io_limit_type();
        test_cgroup_controller();
        test_managed_oom_mode();
        test_managed_oom_preference();
        test_cgroup_escape_predicates();
        test_cg_mask();
        return 0;
}
