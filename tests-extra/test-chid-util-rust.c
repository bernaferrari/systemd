/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Shadow test for CHID (Hardware ID) calculation ported from
 * src/fundamental/chid.c (chid_calculate)
 * to src/basic/rust/chid_util.rs
 *
 * Note: Expected values from fwupdtool hwids output, same as src/test/test-chid.c.
 * This test only runs on little-endian machines. */

#include <assert.h>
#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <uchar.h>

#include "tests.h"

#include "rust/chid_util.h"

#define CHID_TYPES_MAX 18
#define _CHID_SMBIOS_FIELDS_MAX 12

#define CHID_SMBIOS_MANUFACTURER           0
#define CHID_SMBIOS_FAMILY                 1
#define CHID_SMBIOS_PRODUCT_NAME           2
#define CHID_SMBIOS_PRODUCT_SKU            3
#define CHID_SMBIOS_BASEBOARD_MANUFACTURER 4
#define CHID_SMBIOS_BASEBOARD_PRODUCT      5
#define CHID_SMBIOS_BIOS_VENDOR            6
#define CHID_SMBIOS_BIOS_VERSION           7
#define CHID_SMBIOS_BIOS_MAJOR             8
#define CHID_SMBIOS_BIOS_MINOR             9
#define CHID_SMBIOS_ENCLOSURE_TYPE         10
#define CHID_EDID_PANEL                    11

static const char16_t *const test_fields[_CHID_SMBIOS_FIELDS_MAX] = {
        [CHID_SMBIOS_MANUFACTURER]           = u"Micro-Star International Co., Ltd.",
        [CHID_SMBIOS_PRODUCT_NAME]           = u"MS-7D70",
        [CHID_SMBIOS_PRODUCT_SKU]            = u"To be filled by O.E.M.",
        [CHID_SMBIOS_FAMILY]                 = u"To be filled by O.E.M.",
        [CHID_SMBIOS_BASEBOARD_PRODUCT]      = u"MPG X670E CARBON WIFI (MS-7D70)",
        [CHID_SMBIOS_BASEBOARD_MANUFACTURER] = u"Micro-Star International Co., Ltd.",
        [CHID_SMBIOS_ENCLOSURE_TYPE]         = u"3",
};

static void test_chid_known_values(void) {
        uint8_t chids[CHID_TYPES_MAX * 16];
        rs_chid_calculate(test_fields, chids);

        /* [0-2] require BIOS fields (missing) → all zeros */
        assert_se(memcmp(&chids[0 * 16], (uint8_t[16]){}, 16) == 0);
        assert_se(memcmp(&chids[1 * 16], (uint8_t[16]){}, 16) == 0);
        assert_se(memcmp(&chids[2 * 16], (uint8_t[16]){}, 16) == 0);

        /* [3] Manufacturer + Family + ProductName + ProductSku + BaseboardManufacturer + BaseboardProduct */
        assert_se(chids[3 * 16 + 0] == 0x32 && chids[3 * 16 + 1] == 0x9b && chids[3 * 16 + 2] == 0xe0 && chids[3 * 16 + 3] == 0x01);
        assert_se(chids[3 * 16 + 7] == 0x56);

        /* [5] Manufacturer + Family + ProductName */
        assert_se(chids[5 * 16 + 0] == 0x3d && chids[5 * 16 + 1] == 0x82 && chids[5 * 16 + 2] == 0x7c && chids[5 * 16 + 3] == 0x37);
        assert_se(chids[5 * 16 + 7] == 0x55);

        /* [9] Manufacturer + ProductName */
        assert_se(chids[9 * 16 + 0] == 0x4a && chids[9 * 16 + 1] == 0x1f && chids[9 * 16 + 2] == 0x2c && chids[9 * 16 + 3] == 0xc1);
        assert_se(chids[9 * 16 + 7] == 0x5d);

        /* [14] Manufacturer */
        assert_se(chids[14 * 16 + 0] == 0x97 && chids[14 * 16 + 1] == 0x57 && chids[14 * 16 + 2] == 0xaf && chids[14 * 16 + 3] == 0x50);
        assert_se(chids[14 * 16 + 7] == 0x58);
}

static void test_chid_rfc4122_bits(void) {
        uint8_t chids[CHID_TYPES_MAX * 16];
        rs_chid_calculate(test_fields, chids);

        /* Check non-zero CHIDs have RFC4122 bits set */
        for (size_t i = 0; i < CHID_TYPES_MAX; i++) {
                uint8_t *c = &chids[i * 16];
                /* Skip zero CHIDs */
                bool is_zero = true;
                for (size_t j = 0; j < 16; j++) {
                        if (c[j] != 0) {
                                is_zero = false;
                                break;
                        }
                }
                if (is_zero)
                        continue;

                /* Data3 byte[7]: version 5 → upper nibble = 0x5 */
                assert_se((c[7] & 0xf0) == 0x50);
                /* Data4[0] byte[8]: variant → upper 2 bits = 0x2 */
                assert_se((c[8] & 0xc0) == 0x80);
        }
}

static void test_chid_null(void) {
        /* Should not crash */
        rs_chid_calculate(NULL, NULL);

        uint8_t chids[CHID_TYPES_MAX * 16];
        rs_chid_calculate(NULL, chids);
}

int main(int argc, char *argv[]) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        test_chid_known_values();
        test_chid_rfc4122_bits();
        test_chid_null();
#else
        return 77; /* SKIP on big-endian */
#endif
        return 0;
}
