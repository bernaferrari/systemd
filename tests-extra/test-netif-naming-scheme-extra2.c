/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netif-naming-scheme.h"
#include "tests.h"

TEST(name_policy_to_from_string) {
        assert_se(streq(name_policy_to_string(NAMEPOLICY_KERNEL), "kernel"));
        assert_se(streq(name_policy_to_string(NAMEPOLICY_KEEP), "keep"));
        assert_se(streq(name_policy_to_string(NAMEPOLICY_DATABASE), "database"));
        assert_se(streq(name_policy_to_string(NAMEPOLICY_ONBOARD), "onboard"));
        assert_se(streq(name_policy_to_string(NAMEPOLICY_SLOT), "slot"));
        assert_se(streq(name_policy_to_string(NAMEPOLICY_PATH), "path"));
        assert_se(streq(name_policy_to_string(NAMEPOLICY_MAC), "mac"));

        assert_se(name_policy_from_string("kernel") == NAMEPOLICY_KERNEL);
        assert_se(name_policy_from_string("keep") == NAMEPOLICY_KEEP);
        assert_se(name_policy_from_string("database") == NAMEPOLICY_DATABASE);
        assert_se(name_policy_from_string("onboard") == NAMEPOLICY_ONBOARD);
        assert_se(name_policy_from_string("slot") == NAMEPOLICY_SLOT);
        assert_se(name_policy_from_string("path") == NAMEPOLICY_PATH);
        assert_se(name_policy_from_string("mac") == NAMEPOLICY_MAC);
        assert_se(name_policy_from_string("invalid") < 0);
}

TEST(alternative_names_policy_to_from_string) {
        assert_se(streq(alternative_names_policy_to_string(NAMEPOLICY_DATABASE), "database"));
        assert_se(streq(alternative_names_policy_to_string(NAMEPOLICY_ONBOARD), "onboard"));
        assert_se(streq(alternative_names_policy_to_string(NAMEPOLICY_SLOT), "slot"));
        assert_se(streq(alternative_names_policy_to_string(NAMEPOLICY_PATH), "path"));
        assert_se(streq(alternative_names_policy_to_string(NAMEPOLICY_MAC), "mac"));

        assert_se(alternative_names_policy_from_string("database") == NAMEPOLICY_DATABASE);
        assert_se(alternative_names_policy_from_string("onboard") == NAMEPOLICY_ONBOARD);
        assert_se(alternative_names_policy_from_string("slot") == NAMEPOLICY_SLOT);
        assert_se(alternative_names_policy_from_string("path") == NAMEPOLICY_PATH);
        assert_se(alternative_names_policy_from_string("mac") == NAMEPOLICY_MAC);
        assert_se(alternative_names_policy_from_string("invalid") < 0);
}

TEST(naming_scheme_from_name) {
        const NamingScheme *ns;

        ns = naming_scheme_from_name("v238");
        assert_se(ns && streq(ns->name, "v238"));

        ns = naming_scheme_from_name("v260");
        assert_se(ns && streq(ns->name, "v260"));

        ns = naming_scheme_from_name("latest");
        assert_se(ns);

        ns = naming_scheme_from_name("nonexistent");
        assert_se(!ns);
}

TEST(naming_scheme_basic) {
        const NamingScheme *ns = naming_scheme();
        assert_se(ns);
        assert_se(ns->name);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
