/* SPDX-License-Identifier: LGPL-2.1-or-later */


#include "confidential-virt.h"
#include "tests.h"

TEST(confidential_virtualization_to_string) {
        ASSERT_STREQ(confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_NONE), "none");
        ASSERT_STREQ(confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_SEV), "sev");
        ASSERT_STREQ(confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_SEV_ES), "sev-es");
        ASSERT_STREQ(confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_SEV_SNP), "sev-snp");
        ASSERT_STREQ(confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_TDX), "tdx");
        ASSERT_STREQ(confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_PROTVIRT), "protvirt");
        ASSERT_STREQ(confidential_virtualization_to_string(CONFIDENTIAL_VIRTUALIZATION_CCA), "cca");
}

TEST(confidential_virtualization_from_string) {
        ASSERT_EQ(confidential_virtualization_from_string("none"), CONFIDENTIAL_VIRTUALIZATION_NONE);
        ASSERT_EQ(confidential_virtualization_from_string("sev"), CONFIDENTIAL_VIRTUALIZATION_SEV);
        ASSERT_EQ(confidential_virtualization_from_string("sev-es"), CONFIDENTIAL_VIRTUALIZATION_SEV_ES);
        ASSERT_EQ(confidential_virtualization_from_string("sev-snp"), CONFIDENTIAL_VIRTUALIZATION_SEV_SNP);
        ASSERT_EQ(confidential_virtualization_from_string("tdx"), CONFIDENTIAL_VIRTUALIZATION_TDX);
        ASSERT_EQ(confidential_virtualization_from_string("protvirt"), CONFIDENTIAL_VIRTUALIZATION_PROTVIRT);
        ASSERT_EQ(confidential_virtualization_from_string("cca"), CONFIDENTIAL_VIRTUALIZATION_CCA);
        ASSERT_EQ(confidential_virtualization_from_string("invalid"), _CONFIDENTIAL_VIRTUALIZATION_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
