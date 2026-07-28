/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* RUST-CONTRACT: edid-parse-blob */
/* RUST-CONTRACT: edid-panel-id */

#include "edid.h"
#include "rust/edid.h"
#include "tests.h"

assert_cc(sizeof(EdidHeader) == 20);
assert_cc(alignof(EdidHeader) == 1);
assert_cc(sizeof(char16_t) == 2);

static void make_valid_edid_blob(uint8_t blob[128], uint16_t manufacturer_id, uint16_t product_code) {
        memset(blob, 0, 128);
        /* Fixed header pattern: \x00\xFF\xFF\xFF\xFF\xFF\xFF\x00 (8 bytes, includes NUL) */
        blob[0] = 0x00;
        blob[1] = blob[2] = blob[3] = blob[4] = blob[5] = blob[6] = 0xFF;
        blob[7] = 0x00;
        /* manufacturer_id: big-endian in blob */
        blob[8] = (manufacturer_id >> 8) & 0xFF;
        blob[9] = manufacturer_id & 0xFF;
        /* manufacturer_product_code: little-endian in blob */
        blob[10] = product_code & 0xFF;
        blob[11] = (product_code >> 8) & 0xFF;
        /* serial_number: little-endian */
        blob[12] = 0x78;
        blob[13] = 0x56;
        blob[14] = 0x34;
        blob[15] = 0x12;
        /* week/year */
        blob[16] = 42;
        blob[17] = 33; /* 2023 */
        blob[18] = 0x01; /* version */
        blob[19] = 0x04; /* revision */
}

TEST(edid_parse_blob_too_small) {
        EdidHeader ch, rh;
        uint8_t blob[64];

        memset(&ch, 0xa5, sizeof(ch));
        memcpy(&rh, &ch, sizeof(rh));

        assert_se(edid_parse_blob(blob, 64, &ch) == -EINVAL);
        assert_se(rs_edid_parse_blob(blob, 64, &rh) == -EINVAL);
        assert_se(memcmp(&ch, &rh, sizeof(ch)) == 0);

        assert_se(edid_parse_blob(NULL, 0, &ch) == -EINVAL);
        assert_se(rs_edid_parse_blob(NULL, 0, &rh) == -EINVAL);
}

TEST(edid_parse_blob_bad_pattern) {
        EdidHeader ch, rh;
        uint8_t blob[128];

        memset(blob, 0x01, 128);
        memset(&ch, 0xa5, sizeof(ch));
        memcpy(&rh, &ch, sizeof(rh));

        assert_se(edid_parse_blob(blob, 128, &ch) == -EINVAL);
        assert_se(rs_edid_parse_blob(blob, 128, &rh) == -EINVAL);
        assert_se(memcmp(&ch, &rh, sizeof(ch)) == 0);
}

TEST(edid_parse_blob_valid) {
        EdidHeader ch, rh;
        uint8_t blob[128];

        /* SAM manufacturer: S=19, A=1, M=13 → (19<<10)|(1<<5)|13 = 0x4C2D */
        make_valid_edid_blob(blob, 0x4C2D, 0x1234);

        assert_se(edid_parse_blob(blob, 128, &ch) == 0);
        assert_se(rs_edid_parse_blob(blob, 128, &rh) == 0);

        assert_se(memcmp(&ch, &rh, sizeof(ch)) == 0);
        assert_se(memcmp(rh.pattern,
                         (const uint8_t[]) { 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0 },
                         8) == 0);
        assert_se(ch.manufacturer_id == rh.manufacturer_id);
        assert_se(ch.manufacturer_product_code == rh.manufacturer_product_code);
        assert_se(ch.serial_number == rh.serial_number);
        assert_se(ch.week_of_manufacture == rh.week_of_manufacture);
        assert_se(ch.year_of_manufacture == rh.year_of_manufacture);
        assert_se(ch.edid_version == rh.edid_version);
        assert_se(ch.edid_revision == rh.edid_revision);

        assert_se(rh.manufacturer_id == 0x4C2D);
        assert_se(rh.manufacturer_product_code == 0x1234);
}

TEST(edid_parse_blob_unaligned) {
        uint8_t storage[129];
        uint8_t c_header_storage[sizeof(EdidHeader) + 1];
        uint8_t r_header_storage[sizeof(EdidHeader) + 1];
        uint8_t *blob = storage + 1;
        EdidHeader *ch = (EdidHeader*) (c_header_storage + 1);
        EdidHeader *rh = (EdidHeader*) (r_header_storage + 1);

        make_valid_edid_blob(blob, 0x244D, 0x5600);

        assert_se(edid_parse_blob(blob, 128, ch) == 0);
        assert_se(rs_edid_parse_blob(blob, 128, rh) == 0);
        assert_se(memcmp(ch, rh, sizeof(*ch)) == 0);
}

TEST(edid_get_panel_id) {
        EdidHeader header;
        char16_t cpanel[8];
        char16_t rpanel[8];

        memset(&header, 0, sizeof(header));
        header.manufacturer_id = 0x4C2D; /* SAM */
        header.manufacturer_product_code = 0x1234;

        assert_se(edid_get_panel_id(&header, cpanel) == 0);
        assert_se(rs_edid_get_panel_id(&header, rpanel) == 0);

        for (int i = 0; i < 8; i++)
                assert_se(cpanel[i] == rpanel[i]);

        /* S=19→'S', A=1→'A', M=13→'M' */
        assert_se(cpanel[0] == 'S');
        assert_se(cpanel[1] == 'A');
        assert_se(cpanel[2] == 'M');
        /* product code nibbles: 1, 2, 3, 4 */
        assert_se(cpanel[3] == '1');
        assert_se(cpanel[4] == '2');
        assert_se(cpanel[5] == '3');
        assert_se(cpanel[6] == '4');
        assert_se(cpanel[7] == 0);
}

TEST(edid_get_panel_id_invalid) {
        EdidHeader header;
        char16_t cpanel[8];
        char16_t rpanel[8];

        memset(&header, 0, sizeof(header));
        memset(cpanel, 0xa5, sizeof(cpanel));
        memcpy(rpanel, cpanel, sizeof(rpanel));
        /* The first loop iteration writes panel[2], then the second
         * manufacturer letter (27) fails. This proves C's partial publication
         * contract rather than only checking a first-letter failure. */
        header.manufacturer_id = (0x1B << 5) | 1;

        assert_se(edid_get_panel_id(&header, cpanel) == -EINVAL);
        assert_se(rs_edid_get_panel_id(&header, rpanel) == -EINVAL);
        assert_se(memcmp(cpanel, rpanel, sizeof(cpanel)) == 0);
        assert_se(cpanel[2] == 'A');
        assert_se(cpanel[0] == 0xa5a5);
        assert_se(cpanel[1] == 0xa5a5);
}

TEST(edid_get_panel_id_zero_letters) {
        EdidHeader header = {};
        char16_t cpanel[8], rpanel[8];

        assert_se(edid_get_panel_id(&header, cpanel) == 0);
        assert_se(rs_edid_get_panel_id(&header, rpanel) == 0);
        assert_se(memcmp(cpanel, rpanel, sizeof(cpanel)) == 0);
        assert_se(cpanel[0] == '@');
        assert_se(cpanel[1] == '@');
        assert_se(cpanel[2] == '@');
        assert_se(cpanel[3] == '0');
        assert_se(cpanel[6] == '0');
        assert_se(cpanel[7] == 0);
}

TEST(edid_rust_null_extension) {
        EdidHeader header = {};
        char16_t panel[8];
        uint8_t blob[128] = {};

        assert_se(rs_edid_parse_blob(blob, sizeof(blob), NULL) == -EINVAL);
        assert_se(rs_edid_parse_blob(NULL, sizeof(blob), &header) == -EINVAL);
        assert_se(rs_edid_get_panel_id(NULL, panel) == -EINVAL);
        assert_se(rs_edid_get_panel_id(&header, NULL) == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
