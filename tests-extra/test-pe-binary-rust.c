/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C PE binary functions vs Rust */

#include "tests.h"
#include "pe-binary.h"
#include "uki.h"

/* Rust FFI */
#include "rust/pe_binary.h"

/* ── helpers ─────────────────────────────────────────────────────────────── */

/* Build a minimal PeHeader in a byte buffer.
 * Layout: signature(4) + IMAGE_FILE_HEADER(20) + IMAGE_OPTIONAL_HEADER prefix(70)
 * Total: 94 bytes minimum. We allocate 256 for safety. */
static void build_pe_header(
                uint8_t *buf,
                uint16_t magic,
                uint16_t num_sections,
                uint16_t subsystem) {

        memset(buf, 0, 256);

        /* signature: "PE\0\0" in LE */
        buf[0] = 'P'; buf[1] = 'E'; buf[2] = 0; buf[3] = 0;

        /* IMAGE_FILE_HEADER at offset 4 */
        /* Machine at offset 4 */
        buf[4] = 0x64; buf[5] = 0x86; /* IMAGE_FILE_MACHINE_ARM64 */
        /* NumberOfSections at offset 6 */
        memcpy(buf + 6, &num_sections, 2);
        /* SizeOfOptionalHeader at offset 16 */
        uint16_t opt_hdr_size = 70; /* minimal */
        memcpy(buf + 16, &opt_hdr_size, 2);

        /* IMAGE_OPTIONAL_HEADER at offset 24 */
        /* Magic at offset 24 */
        memcpy(buf + 24, &magic, 2);
        /* Subsystem at offset 92 (24 + 68) */
        memcpy(buf + 92, &subsystem, 2);
}

/* Build IMAGE_SECTION_HEADER array */
static void build_section(uint8_t *buf, const char *name) {
        memset(buf, 0, 40);
        strncpy((char *)buf, name, 8);
}

/* ── pe_header_is_64bit ──────────────────────────────────────────────────── */

static void test_pe_header_is_64bit(void) {
        uint8_t buf[256];
        bool cb, rb;

        /* PE32 (Magic = 0x010B) */
        build_pe_header(buf, 0x010B, 0, 0);
        cb = pe_header_is_64bit((const PeHeader *)buf);
        rb = rs_pe_header_is_64bit(buf);
        assert_se(cb == rb);
        assert_se(cb == false);

        /* PE32+ (Magic = 0x020B) */
        build_pe_header(buf, 0x020B, 0, 0);
        cb = pe_header_is_64bit((const PeHeader *)buf);
        rb = rs_pe_header_is_64bit(buf);
        assert_se(cb == rb);
        assert_se(cb == true);
}

/* ── pe_section_table_find / pe_header_find_section ─────────────────────── */

static void test_pe_section_find(void) {
        uint8_t hdr[256];
        uint8_t sections[120]; /* room for 3 sections (40 bytes each) */
        const IMAGE_SECTION_HEADER *cr, *rr;

        /* Build header with 3 sections */
        build_pe_header(hdr, 0x020B, 3, 10);

        /* Section 0: ".osrel" */
        build_section(sections + 0, ".osrel");
        /* Section 1: ".linux" */
        build_section(sections + 40, ".linux");
        /* Section 2: ".initrd" */
        build_section(sections + 80, ".initrd");

        /* Find .osrel */
        cr = pe_section_table_find((const IMAGE_SECTION_HEADER *)sections, 3, ".osrel");
        rr = rs_pe_section_table_find(sections, 3, ".osrel");
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(cr == (const IMAGE_SECTION_HEADER *)sections);
        assert_se(rr == (const IMAGE_SECTION_HEADER *)sections);

        /* Find .linux */
        cr = pe_section_table_find((const IMAGE_SECTION_HEADER *)sections, 3, ".linux");
        rr = rs_pe_section_table_find(sections, 3, ".linux");
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(cr == (const IMAGE_SECTION_HEADER *)(sections + 40));
        assert_se(rr == (const IMAGE_SECTION_HEADER *)(sections + 40));

        /* Find via pe_header_find_section */
        cr = pe_header_find_section((const PeHeader *)hdr, (const IMAGE_SECTION_HEADER *)sections, ".linux");
        rr = rs_pe_header_find_section(hdr, sections, ".linux");
        assert_se(cr != NULL);
        assert_se(rr != NULL);

        /* Not found */
        cr = pe_section_table_find((const IMAGE_SECTION_HEADER *)sections, 3, ".nonexistent");
        rr = rs_pe_section_table_find(sections, 3, ".nonexistent");
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Name too long (>8 chars) */
        cr = pe_section_table_find((const IMAGE_SECTION_HEADER *)sections, 3, ".toolongname");
        rr = rs_pe_section_table_find(sections, 3, ".toolongname");
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* NULL sections with 0 count */
        cr = pe_section_table_find(NULL, 0, ".osrel");
        rr = rs_pe_section_table_find(NULL, 0, ".osrel");
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

/* ── pe_is_uki / pe_is_addon ─────────────────────────────────────────────── */

static void test_pe_is_uki_addon(void) {
        uint8_t hdr[256];
        uint8_t sections[120];
        bool cb, rb;

        /* UKI: EFI subsystem + .osrel + .linux */
        build_pe_header(hdr, 0x020B, 3, 10);
        build_section(sections + 0, ".osrel");
        build_section(sections + 40, ".linux");
        build_section(sections + 80, ".initrd");

        cb = pe_is_uki((const PeHeader *)hdr, (const IMAGE_SECTION_HEADER *)sections);
        rb = rs_pe_is_uki(hdr, sections);
        assert_se(cb == rb);
        assert_se(cb == true);

        /* Not UKI: missing .osrel */
        build_pe_header(hdr, 0x020B, 2, 10);
        build_section(sections + 0, ".linux");
        build_section(sections + 40, ".initrd");

        cb = pe_is_uki((const PeHeader *)hdr, (const IMAGE_SECTION_HEADER *)sections);
        rb = rs_pe_is_uki(hdr, sections);
        assert_se(cb == rb);
        assert_se(cb == false);

        /* Not UKI: wrong subsystem */
        build_pe_header(hdr, 0x020B, 2, 3); /* subsystem=3 (console) */
        build_section(sections + 0, ".osrel");
        build_section(sections + 40, ".linux");

        cb = pe_is_uki((const PeHeader *)hdr, (const IMAGE_SECTION_HEADER *)sections);
        rb = rs_pe_is_uki(hdr, sections);
        assert_se(cb == rb);
        assert_se(cb == false);

        /* Addon: EFI + no .linux + has .cmdline */
        build_pe_header(hdr, 0x020B, 2, 10);
        build_section(sections + 0, ".cmdline");
        build_section(sections + 40, ".dtb");

        cb = pe_is_addon((const PeHeader *)hdr, (const IMAGE_SECTION_HEADER *)sections);
        rb = rs_pe_is_addon(hdr, sections);
        assert_se(cb == rb);
        assert_se(cb == true);

        /* Not addon: has .linux */
        build_pe_header(hdr, 0x020B, 3, 10);
        build_section(sections + 0, ".cmdline");
        build_section(sections + 40, ".linux");
        build_section(sections + 80, ".initrd");

        cb = pe_is_addon((const PeHeader *)hdr, (const IMAGE_SECTION_HEADER *)sections);
        rb = rs_pe_is_addon(hdr, sections);
        assert_se(cb == rb);
        assert_se(cb == false);

        /* Not addon: no recognized sections */
        build_pe_header(hdr, 0x020B, 1, 10);
        build_section(sections + 0, ".text");

        cb = pe_is_addon((const PeHeader *)hdr, (const IMAGE_SECTION_HEADER *)sections);
        rb = rs_pe_is_addon(hdr, sections);
        assert_se(cb == rb);
        assert_se(cb == false);

}

/* ── pe_is_native ──────────────────────────────────────────────────────── */

static void build_pe_header_machine(
                uint8_t *buf,
                uint16_t magic,
                uint16_t machine) {

        memset(buf, 0, 256);

        /* signature: "PE\0\0" in LE */
        buf[0] = 'P'; buf[1] = 'E'; buf[2] = 0; buf[3] = 0;

        /* Machine at offset 4 */
        memcpy(buf + 4, &machine, 2);

        /* SizeOfOptionalHeader at offset 16 */
        uint16_t opt_hdr_size = 70;
        memcpy(buf + 16, &opt_hdr_size, 2);

        /* Magic at offset 24 */
        memcpy(buf + 24, &magic, 2);
}

static void test_pe_is_native(void) {
        uint8_t buf[256];
        bool cb, rb;

#ifdef _IMAGE_FILE_MACHINE_NATIVE
        /* Native machine type should match */
        build_pe_header_machine(buf, 0x020B, _IMAGE_FILE_MACHINE_NATIVE);
        cb = pe_is_native((const PeHeader *)buf);
        rb = rs_pe_is_native(buf);
        assert_se(cb == rb);
        assert_se(cb == true);
#endif

        /* Non-native machine (x86_64 = 0x8664) */
        build_pe_header_machine(buf, 0x020B, 0x8664);
        cb = pe_is_native((const PeHeader *)buf);
        rb = rs_pe_is_native(buf);
        assert_se(cb == rb);
#ifdef _IMAGE_FILE_MACHINE_NATIVE
        assert_se(cb == false);
#endif
}

/* ── pe_header_get_data_directory ──────────────────────────────────────── */

static void build_pe_header_with_dd(
                uint8_t *buf,
                uint16_t magic,
                uint16_t subsystem,
                uint32_t num_rva_and_sizes) {

        build_pe_header(buf, magic, 0, subsystem);

        /* NumberOfRvaAndSizes at different offsets for PE32 vs PE32+ */
        size_t nrva_offset;
        if (magic == 0x020B) /* PE32+ */
                nrva_offset = 132;
        else /* PE32 */
                nrva_offset = 116;

        memcpy(buf + nrva_offset, &num_rva_and_sizes, 4);
}

static void test_pe_header_get_data_directory(void) {
        uint8_t buf[256];
        const IMAGE_DATA_DIRECTORY *cr;
        const void *rr;

        /* PE32+ with 16 data directory entries */
        build_pe_header_with_dd(buf, 0x020B, 10, 16);

        /* Entry 0 should be valid */
        cr = pe_header_get_data_directory((const PeHeader *)buf, 0);
        rr = rs_pe_header_get_data_directory(buf, 0);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(cr == (const IMAGE_DATA_DIRECTORY *)rr);

        /* Entry 4 (certification table) should be valid */
        cr = pe_header_get_data_directory((const PeHeader *)buf, 4);
        rr = rs_pe_header_get_data_directory(buf, 4);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(cr == (const IMAGE_DATA_DIRECTORY *)rr);

        /* Entry 15 should be valid (last one) */
        cr = pe_header_get_data_directory((const PeHeader *)buf, 15);
        rr = rs_pe_header_get_data_directory(buf, 15);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(cr == (const IMAGE_DATA_DIRECTORY *)rr);

        /* Entry 16 should be out of bounds */
        cr = pe_header_get_data_directory((const PeHeader *)buf, 16);
        rr = rs_pe_header_get_data_directory(buf, 16);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* PE32 with 16 data directory entries */
        build_pe_header_with_dd(buf, 0x010B, 10, 16);

        /* Entry 0 should be valid */
        cr = pe_header_get_data_directory((const PeHeader *)buf, 0);
        rr = rs_pe_header_get_data_directory(buf, 0);
        assert_se(cr != NULL);
        assert_se(rr != NULL);
        assert_se(cr == (const IMAGE_DATA_DIRECTORY *)rr);

        /* Entry 16 should be out of bounds */
        cr = pe_header_get_data_directory((const PeHeader *)buf, 16);
        rr = rs_pe_header_get_data_directory(buf, 16);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Zero entries */
        build_pe_header_with_dd(buf, 0x020B, 10, 0);
        cr = pe_header_get_data_directory((const PeHeader *)buf, 0);
        rr = rs_pe_header_get_data_directory(buf, 0);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

int main(int argc, char **argv) {
        test_pe_header_is_64bit();
        test_pe_section_find();
        test_pe_is_uki_addon();
        test_pe_is_native();
        test_pe_header_get_data_directory();
        return 0;
}
