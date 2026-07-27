/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pe-binary.h"
#include "tests.h"

TEST(pe_header_is_64bit) {
        PeHeader h = {};

        /* PE32: Magic = 0x010B in little-endian */
        h.optional.Magic = 0x010B;
        ASSERT_FALSE(pe_header_is_64bit(&h));

        /* PE32+: Magic = 0x020B in little-endian */
        h.optional.Magic = 0x020B;
        ASSERT_TRUE(pe_header_is_64bit(&h));
}

TEST(pe_section_table_find) {
        IMAGE_SECTION_HEADER sections[3] = {};
        memcpy(sections[0].Name, ".text\0\0\0", 8);
        memcpy(sections[1].Name, ".data\0\0\0", 8);
        memcpy(sections[2].Name, ".rdata\0\0", 8);

        assert_se(pe_section_table_find(sections, 3, ".text") == &sections[0]);
        assert_se(pe_section_table_find(sections, 3, ".data") == &sections[1]);
        assert_se(pe_section_table_find(sections, 3, ".bss") == NULL);
        assert_se(pe_section_table_find(sections, 0, ".text") == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
