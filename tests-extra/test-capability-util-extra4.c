/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/capability.h>

#include "capability-util.h"
#include "tests.h"

TEST(drop_capability_basic) {
        /* Dropping a capability we likely don't have */
        int r = drop_capability(CAP_SYS_BOOT);
        /* May succeed or fail depending on privileges */
        log_debug("drop_capability(SYS_BOOT): %d", r);
}

TEST(keep_capability_basic) {
        int r = keep_capability(CAP_CHOWN);
        log_debug("keep_capability(CHOWN): %d", r);
}

TEST(have_inheritable_cap_basic) {
        int r = have_inheritable_cap(CAP_CHOWN);
        log_debug("have_inheritable_cap(CHOWN): %d", r);
}

TEST(capability_gain_cap_setpcap_basic) {
        /* This requires privileges, will likely fail in test env */
        int r = capability_gain_cap_setpcap();
        log_debug("capability_gain_cap_setpcap: %d", r);
}

TEST(capability_bounding_set_drop_basic) {
        /* Keep all capabilities — no-op */
        int r = capability_bounding_set_drop(UINT64_MAX, false);
        log_debug("capability_bounding_set_drop(ALL): %d", r);
}

TEST(capability_quintet_enforce_basic) {
        /* Enforce with all ambient — may fail without privileges */
        CapabilityQuintet q = {
                .ambient = 0,
                .bounding = UINT64_MAX,
                .effective = 0,
                .inheritable = 0,
                .permitted = 0,
        };
        int r = capability_quintet_enforce(&q);
        log_debug("capability_quintet_enforce: %d", r);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
