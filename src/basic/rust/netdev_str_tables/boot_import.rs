// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/boot-entry.c, import-util.c

use super::*;

static BOOT_ENTRY_TOKEN_TYPE_TABLE: &[(i32, &[u8])] = &[
    (0, b"machine-id\0"),
    (1, b"os-image-id\0"),
    (2, b"os-id\0"),
    (3, b"literal\0"),
    (4, b"auto\0"),
];
string_table!(
    rs_boot_entry_token_type_to_string,
    rs_boot_entry_token_type_from_string,
    BOOT_ENTRY_TOKEN_TYPE_TABLE
);

static IMPORT_TYPE_TABLE: &[(i32, &[u8])] = &[(0, b"raw\0"), (1, b"tar\0"), (2, b"oci\0")];
string_table!(
    rs_import_type_to_string,
    rs_import_type_from_string,
    IMPORT_TYPE_TABLE
);

static IMPORT_VERIFY_TABLE: &[(i32, &[u8])] =
    &[(0, b"no\0"), (1, b"checksum\0"), (2, b"signature\0")];
string_table!(
    rs_import_verify_to_string,
    rs_import_verify_from_string,
    IMPORT_VERIFY_TABLE
);
