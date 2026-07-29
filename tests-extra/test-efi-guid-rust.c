/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for EFI GUID <-> sd_id128 conversion */

#include <string.h>

#include "tests.h"
#include "efi-api.h"
#include "rust/efivars_util.h"

/* ── efi_guid_to_id128 ────────────────────────────────────────────── */
/* RUST-CONTRACT: efi-guid-to-id128 */

static void test_efi_guid_to_id128_null_guid(void) {
        uint8_t r_out[16] = {};

        /* C has ASSERT_PTR(guid) — only test Rust with NULL */
        int r = rs_efi_guid_to_id128(NULL, r_out);
        assert_se(r < 0);
}

static void test_efi_guid_to_id128_null_ret(void) {
        uint8_t buf[16] = {};

        /* C has ASSERT_PTR(guid) but ret is a pointer — Rust checks it */
        int r = rs_efi_guid_to_id128(buf, NULL);
        assert_se(r < 0);
}

static void test_efi_guid_to_id128_zero(void) {
        uint8_t guid[16] = {};
        sd_id128_t c_out;
        uint8_t r_out[16] = {};

        c_out = efi_guid_to_id128(guid);
        int r = rs_efi_guid_to_id128(guid, r_out);
        assert_se(r == 0);

        /* Compare C result (sd_id128_t.bytes) with Rust result */
        assert_se(memcmp(c_out.bytes, r_out, 16) == 0);
}

static void test_efi_guid_to_id128_known(void) {
        /* EFI GUID bytes: 8b f0 6e 4f 34 12 78 56 9a bc de f0 12 34 56 78 */
        uint8_t guid[16] = {
                0x8b, 0xf0, 0x6e, 0x4f, 0x34, 0x12, 0x78, 0x56,
                0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78
        };
        sd_id128_t c_out;
        uint8_t r_out[16] = {};

        c_out = efi_guid_to_id128(guid);
        int r = rs_efi_guid_to_id128(guid, r_out);
        assert_se(r == 0);

        /* C and Rust should produce identical output */
        assert_se(memcmp(c_out.bytes, r_out, 16) == 0);

        /* Verify C output matches expected UUID text format */
        assert_se(c_out.bytes[0] == 0x4f);
        assert_se(c_out.bytes[3] == 0x8b);
        assert_se(c_out.bytes[4] == 0x12);
        assert_se(c_out.bytes[5] == 0x34);
        assert_se(memcmp(&c_out.bytes[8], &guid[8], 8) == 0);
}

/* ── efi_id128_to_guid ────────────────────────────────────────────── */
/* RUST-CONTRACT: id128-to-efi-guid */

static void test_efi_id128_to_guid_null_id(void) {
        uint8_t r_out[16] = {};

        /* C takes sd_id128_t by value (no NULL possible) — only test Rust */
        rs_efi_id128_to_guid(NULL, r_out);
}

static void test_efi_id128_to_guid_null_ret(void) {
        uint8_t id[16] = {};

        /* C has assert(ret_guid) — only test Rust */
        rs_efi_id128_to_guid(id, NULL);
}

static void test_efi_id128_to_guid_zero(void) {
        sd_id128_t c_id = SD_ID128_NULL;
        uint8_t c_out[16] = {}, r_out[16] = {};

        efi_id128_to_guid(c_id, c_out);
        rs_efi_id128_to_guid(c_id.bytes, r_out);

        assert_se(memcmp(c_out, r_out, 16) == 0);
}

static void test_efi_id128_to_guid_roundtrip(void) {
        uint8_t id_bytes[16] = {
                0x8b, 0xf0, 0x6e, 0x4f, 0x34, 0x12, 0x78, 0x56,
                0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78
        };
        sd_id128_t id;
        memcpy(id.bytes, id_bytes, 16);

        uint8_t c_guid[16] = {}, r_guid[16] = {};

        efi_id128_to_guid(id, c_guid);
        rs_efi_id128_to_guid(id.bytes, r_guid);
        assert_se(memcmp(c_guid, r_guid, 16) == 0);

        /* Convert GUID back to id128 and verify roundtrip */
        sd_id128_t c_rt = efi_guid_to_id128(c_guid);
        uint8_t r_rt[16] = {};
        int r = rs_efi_guid_to_id128(r_guid, r_rt);
        assert_se(r == 0);

        assert_se(memcmp(c_rt.bytes, r_rt, 16) == 0);
        assert_se(memcmp(id.bytes, c_rt.bytes, 16) == 0);
        assert_se(memcmp(id.bytes, r_rt, 16) == 0);
}

int main(int argc, char *argv[]) {
        test_efi_guid_to_id128_null_guid();
        test_efi_guid_to_id128_null_ret();
        test_efi_guid_to_id128_zero();
        test_efi_guid_to_id128_known();
        test_efi_id128_to_guid_null_id();
        test_efi_id128_to_guid_null_ret();
        test_efi_id128_to_guid_zero();
        test_efi_id128_to_guid_roundtrip();

        return 0;
}
