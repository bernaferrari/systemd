// SPDX-License-Identifier: LGPL-2.1-or-later

use super::lookup::parse_id128_string;
use super::*;

fn id(value: &str) -> Id128 {
    parse_id128_string(value).unwrap()
}

fn partition_type(designator: PartitionDesignator) -> GptPartitionType {
    GptPartitionType {
        designator,
        ..GptPartitionType::INVALID
    }
}

#[test]
fn canonical_uuid_bytes_match_sd_gpt_header_examples() {
    assert_eq!(
        gpt_partition_type_uuid_to_string(id("6523f8ae-3eb1-4e2a-a05a-18b695ae656f")),
        Some("root-alpha".to_owned())
    );
    assert_eq!(
        gpt_partition_type_uuid_to_string(id("fc56d9e9-e6e5-4c06-be32-e74407ce09a5")),
        Some("root-alpha-verity".to_owned())
    );
    assert_eq!(
        gpt_partition_type_uuid_to_string(id("5c6e1c76-076a-457a-a0fe-f3b4cd21ce6e")),
        Some("usr-alpha-verity-sig".to_owned())
    );
    assert_eq!(
        gpt_partition_type_uuid_to_string(id("4f68bce3-e8cd-4db1-96e7-fbcaf984b709")),
        Some("root-x86-64".to_owned())
    );
}

#[test]
fn aliases_resolve_to_first_canonical_entry() {
    assert_eq!(
        gpt_partition_type_from_string("root-aarch64").unwrap().name,
        "root-arm64"
    );
    assert_eq!(
        gpt_partition_type_from_string("usr-amd64").unwrap().name,
        "usr-x86-64"
    );
    assert_eq!(
        gpt_partition_type_from_string("root-i686").unwrap().name,
        "root-x86"
    );
}

#[test]
fn names_are_exact_and_not_implicitly_prefixed() {
    assert!(gpt_partition_type_from_string("aarch64").is_none());
    assert!(gpt_partition_type_from_string("root-aarch64").is_some());
    assert!(gpt_partition_type_from_string("ROOT-ARM64").is_none());
}

#[test]
fn both_sd_id128_string_forms_are_accepted() {
    let uuid = gpt_partition_type_from_string("4f68bce3-e8cd-4db1-96e7-fbcaf984b709").unwrap();
    let plain = gpt_partition_type_from_string("4f68bce3e8cd4db196e7fbcaf984b709").unwrap();
    assert_eq!(uuid, plain);
    assert_eq!(uuid.name, "root-x86-64");

    assert!(gpt_partition_type_from_string("4f68bce3-e8cd4db1-96e7-fbcaf984b709").is_none());
    assert!(gpt_partition_type_from_string("{4f68bce3-e8cd-4db1-96e7-fbcaf984b709}").is_none());
}

#[test]
fn unknown_uuid_is_preserved_and_formatted() {
    let unknown = id("aabbccdd-eeff-0011-2233-445566778899");
    let resolved = gpt_partition_type_from_uuid(unknown);
    assert_eq!(resolved.uuid, unknown);
    assert_eq!(resolved.arch, Architecture::Invalid);
    assert_eq!(resolved.designator, PartitionDesignator::Invalid);
    assert_eq!(resolved.name, "");
    assert_eq!(
        gpt_partition_type_uuid_to_string_harder(unknown),
        "aabbccdd-eeff-0011-2233-445566778899"
    );
}

#[test]
fn architecture_override_uses_canonical_entry() {
    let esp = gpt_partition_type_from_string("esp").unwrap();
    let root_x86_64 = gpt_partition_type_override_architecture(
        partition_type(PartitionDesignator::Root),
        Architecture::X86_64,
    );
    assert_eq!(root_x86_64.name, "root-x86-64");
    assert_eq!(
        gpt_partition_type_override_architecture(esp, Architecture::X86_64),
        esp
    );
    assert_eq!(
        gpt_partition_type_override_architecture(esp, Architecture::Invalid),
        esp
    );
}

#[test]
fn generic_partition_types_match_canonical_header() {
    let cases = [
        (
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            "esp",
            PartitionDesignator::Esp,
        ),
        (
            "bc13c2ff-59e6-4262-a352-b275fd6f7172",
            "xbootldr",
            PartitionDesignator::XBootldr,
        ),
        (
            "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f",
            "swap",
            PartitionDesignator::Swap,
        ),
        (
            "933ac7e1-2eb4-4f13-b844-0e14e2aef915",
            "home",
            PartitionDesignator::Home,
        ),
        (
            "4d21b016-b534-45c2-a9fb-5c16e091fd2d",
            "var",
            PartitionDesignator::Var,
        ),
    ];
    for (uuid, name, designator) in cases {
        let value = gpt_partition_type_from_uuid(id(uuid));
        assert_eq!(value.name, name);
        assert_eq!(value.designator, designator);
    }
}

#[test]
fn designator_strings_and_mountpoints_match_c() {
    for designator in [
        PartitionDesignator::Root,
        PartitionDesignator::Usr,
        PartitionDesignator::Home,
        PartitionDesignator::Srv,
        PartitionDesignator::Esp,
        PartitionDesignator::XBootldr,
        PartitionDesignator::Swap,
        PartitionDesignator::RootVerity,
        PartitionDesignator::UsrVerity,
        PartitionDesignator::RootVeritySig,
        PartitionDesignator::UsrVeritySig,
        PartitionDesignator::Tmp,
        PartitionDesignator::Var,
    ] {
        assert_eq!(
            PartitionDesignator::from_str_name(designator.as_str()),
            Some(designator)
        );
    }
    assert_eq!(PartitionDesignator::Root.mountpoint_nulstr(), Some("/\0"));
    assert_eq!(
        PartitionDesignator::Esp.mountpoint_nulstr(),
        Some("/efi\0/boot\0")
    );
    assert_eq!(PartitionDesignator::Swap.mountpoint_nulstr(), None);
}

#[test]
fn verity_designator_relationships_match_c() {
    assert_eq!(
        partition_verity_hash_of(PartitionDesignator::Root),
        PartitionDesignator::RootVerity
    );
    assert_eq!(
        partition_verity_sig_of(PartitionDesignator::Usr),
        PartitionDesignator::UsrVeritySig
    );
    assert_eq!(
        partition_verity_hash_to_data(PartitionDesignator::UsrVerity),
        PartitionDesignator::Usr
    );
    assert_eq!(
        partition_verity_sig_to_data(PartitionDesignator::RootVeritySig),
        PartitionDesignator::Root
    );
    assert_eq!(
        partition_verity_to_data(PartitionDesignator::Esp),
        PartitionDesignator::Invalid
    );
    assert!(partition_designator_is_verity(
        PartitionDesignator::RootVeritySig
    ));
    assert!(!partition_designator_is_verity(PartitionDesignator::Root));
}

#[test]
fn partition_attribute_knowledge_matches_c() {
    assert!(gpt_partition_type_knows_read_only(partition_type(
        PartitionDesignator::RootVeritySig
    )));
    assert!(!gpt_partition_type_knows_read_only(partition_type(
        PartitionDesignator::Esp
    )));
    assert!(gpt_partition_type_knows_growfs(partition_type(
        PartitionDesignator::XBootldr
    )));
    assert!(!gpt_partition_type_knows_growfs(partition_type(
        PartitionDesignator::Swap
    )));
    assert!(gpt_partition_type_knows_no_auto(partition_type(
        PartitionDesignator::Swap
    )));
    assert!(gpt_partition_type_has_filesystem(partition_type(
        PartitionDesignator::Esp
    )));
    assert!(!gpt_partition_type_has_filesystem(partition_type(
        PartitionDesignator::RootVerity
    )));
}

#[test]
fn label_length_is_counted_in_utf16_code_units() {
    assert!(gpt_partition_label_valid(&"a".repeat(GPT_LABEL_MAX)));
    assert!(!gpt_partition_label_valid(&"a".repeat(GPT_LABEL_MAX + 1)));
    assert!(gpt_partition_label_valid(&"😀".repeat(GPT_LABEL_MAX / 2)));
    assert!(!gpt_partition_label_valid(
        &"😀".repeat(GPT_LABEL_MAX / 2 + 1)
    ));
}

fn valid_header() -> [u8; 128] {
    let mut header = [0; 128];
    header[..8].copy_from_slice(GPT_HEADER_SIGNATURE);
    header[8..12].copy_from_slice(&GPT_HEADER_REVISION.to_le_bytes());
    header[12..16].copy_from_slice(&(GPT_HEADER_BASE_SIZE as u32).to_le_bytes());
    header[24..32].copy_from_slice(&1_u64.to_le_bytes());
    header
}

#[test]
fn header_validation_matches_all_c_checks() {
    let header = valid_header();
    assert!(gpt_header_has_signature(&header));
    assert!(!gpt_header_has_signature(
        &header[..GPT_HEADER_BASE_SIZE - 1]
    ));

    let mut wrong_signature = header;
    wrong_signature[0] = b'X';
    assert!(!gpt_header_has_signature(&wrong_signature));

    let mut wrong_revision = header;
    wrong_revision[8..12].copy_from_slice(&0_u32.to_le_bytes());
    assert!(!gpt_header_has_signature(&wrong_revision));

    let mut short_header = header;
    short_header[12..16].copy_from_slice(&(GPT_HEADER_BASE_SIZE as u32 - 1).to_le_bytes());
    assert!(!gpt_header_has_signature(&short_header));

    let mut oversized_header = header;
    oversized_header[12..16].copy_from_slice(&4097_u32.to_le_bytes());
    assert!(!gpt_header_has_signature(&oversized_header));

    let mut wrong_lba = header;
    wrong_lba[24..32].copy_from_slice(&2_u64.to_le_bytes());
    assert!(!gpt_header_has_signature(&wrong_lba));
}
