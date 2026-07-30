// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/varlink-execute.c
//

use std::collections::BTreeMap;

use crate::ffi::Errno;

pub type Result<T> = std::result::Result<T, VarlinkExecuteError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarlinkExecuteError {
    MissingField(&'static str),
    InvalidName(&'static str),
}

impl VarlinkExecuteError {
    pub const fn errno(&self) -> i32 {
        match self {
            Self::MissingField(_) | Self::InvalidName(_) => Errno::EINVAL.to_neg_errno(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Integer(i64),
    Unsigned(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    fn object(entries: impl IntoIterator<Item = (impl Into<String>, JsonValue)>) -> Self {
        Self::Object(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkingDirectory {
    pub path: Option<String>,
    pub use_home: bool,
    pub missing_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionMountOption {
    pub partition_designator: String,
    pub options: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: String,
    pub destination: String,
    pub read_only: bool,
    pub ignore_enoent: bool,
    pub recursive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedImage {
    pub source: String,
    pub destination: Option<String>,
    pub ignore_enoent: bool,
    pub mount_options: Vec<PartitionMountOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RLimit {
    pub soft: Option<u64>,
    pub hard: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecDirectoryItem {
    pub path: String,
    pub symlinks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecDirectory {
    pub items: Vec<ExecDirectoryItem>,
    pub mode: u32,
    pub quota_accounting: bool,
    pub quota_enforce: bool,
    pub quota_absolute: u64,
    pub quota_scale: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLoad {
    pub id: String,
    pub path: String,
    pub encrypted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialImport {
    pub glob: String,
    pub rename: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSet {
    pub id: String,
    pub value: Vec<u8>,
    pub encrypted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecContext {
    pub exec_search_path: Vec<String>,
    pub working_directory: WorkingDirectory,
    pub root_directory: Option<String>,
    pub root_image: Option<String>,
    pub root_image_options: Vec<PartitionMountOption>,
    pub root_image_policy: Option<String>,
    pub bind_mounts: Vec<BindMount>,
    pub mount_images: Vec<MountedImage>,
    pub extension_images: Vec<MountedImage>,
    pub capability_sets: BTreeMap<String, Vec<String>>,
    pub secure_bits: Vec<String>,
    pub limits: BTreeMap<String, RLimit>,
    pub default_limits: BTreeMap<String, RLimit>,
    pub cpu_sched_policy: Option<String>,
    pub cpu_affinity: Vec<u8>,
    pub cpu_affinity_from_numa: bool,
    pub numa_policy: Option<String>,
    pub numa_mask: Vec<u8>,
    pub io_sched_class: Option<String>,
    pub temporary_filesystems: Vec<(String, Option<String>)>,
    pub address_families_allow_list: bool,
    pub address_families: Vec<String>,
    pub restrict_filesystems_allow_list: bool,
    pub restrict_filesystems: Vec<String>,
    pub namespace_flags: Vec<String>,
    pub delegate_namespace_flags: Vec<String>,
    pub bpf_delegate_commands: Option<String>,
    pub bpf_delegate_maps: Option<String>,
    pub bpf_delegate_programs: Option<String>,
    pub bpf_delegate_attachments: Option<String>,
    pub syscall_allow_list: bool,
    pub syscall_filter: Vec<String>,
    pub syscall_errno: Option<String>,
    pub syscall_archs: Vec<String>,
    pub syscall_log: Vec<String>,
    pub environment_files: Vec<String>,
    pub log_level_max: Option<String>,
    pub log_extra_fields: Vec<String>,
    pub allowed_log_patterns: Vec<String>,
    pub denied_log_patterns: Vec<String>,
    pub syslog_facility: Option<String>,
    pub load_credentials: Vec<CredentialLoad>,
    pub import_credentials: Vec<CredentialImport>,
    pub set_credentials: Vec<CredentialSet>,
    pub runtime_directory: ExecDirectory,
}

fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();

    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        let n = ((a as u32) << 16) | ((b as u32) << 8) | c as u32;

        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }

    out
}

pub fn working_directory_build_json(ctx: &WorkingDirectory) -> Result<Option<JsonValue>> {
    let wd = if ctx.use_home {
        Some("~".to_string())
    } else {
        ctx.path.clone()
    };

    Ok(wd.map(|path| {
        JsonValue::object([
            ("path", JsonValue::String(path)),
            ("missingOK", JsonValue::Bool(ctx.missing_ok)),
        ])
    }))
}

pub fn json_append_mount_options(options: &[PartitionMountOption]) -> Result<Option<JsonValue>> {
    if options.is_empty() {
        return Ok(None);
    }

    Ok(Some(JsonValue::Array(
        options
            .iter()
            .filter(|entry| !entry.options.is_empty())
            .map(|entry| {
                JsonValue::object([
                    (
                        "partitionDesignator",
                        JsonValue::String(entry.partition_designator.clone()),
                    ),
                    ("options", JsonValue::String(entry.options.clone())),
                ])
            })
            .collect(),
    )))
}

pub fn root_image_options_build_json(
    options: &[PartitionMountOption],
) -> Result<Option<JsonValue>> {
    json_append_mount_options(options)
}

pub fn image_policy_build_json(policy: Option<&str>) -> Result<Option<JsonValue>> {
    Ok(policy.map(|value| JsonValue::String(value.to_string())))
}

pub fn bind_paths_build_json(name: &str, ctx: &ExecContext) -> Result<Option<JsonValue>> {
    let read_only = name.contains("ReadOnly");
    let mut out = Vec::new();

    for mount in &ctx.bind_mounts {
        if mount.read_only != read_only {
            continue;
        }

        out.push(JsonValue::object([
            ("source", JsonValue::String(mount.source.clone())),
            ("destination", JsonValue::String(mount.destination.clone())),
            ("ignoreEnoent", JsonValue::Bool(mount.ignore_enoent)),
            (
                "options",
                JsonValue::Array(vec![JsonValue::String(
                    if mount.recursive { "rbind" } else { "norbind" }.to_string(),
                )]),
            ),
        ]));
    }

    Ok((!out.is_empty()).then_some(JsonValue::Array(out)))
}

fn mounted_images_to_json(
    images: &[MountedImage],
    include_destination: bool,
) -> Result<Option<JsonValue>> {
    let mut out = Vec::new();

    for image in images {
        let mut object = BTreeMap::from([
            (
                "source".to_string(),
                JsonValue::String(image.source.clone()),
            ),
            (
                "ignoreEnoent".to_string(),
                JsonValue::Bool(image.ignore_enoent),
            ),
        ]);

        if include_destination {
            let destination = image
                .destination
                .clone()
                .ok_or(VarlinkExecuteError::MissingField("destination"))?;
            object.insert("destination".into(), JsonValue::String(destination));
        }

        if let Some(mount_options) = json_append_mount_options(&image.mount_options)? {
            object.insert("mountOptions".into(), mount_options);
        }

        out.push(JsonValue::Object(object));
    }

    Ok((!out.is_empty()).then_some(JsonValue::Array(out)))
}

pub fn mount_images_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    mounted_images_to_json(&ctx.mount_images, true)
}

pub fn extension_images_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    mounted_images_to_json(&ctx.extension_images, false)
}

pub fn capability_set_build_json(values: &[String]) -> Result<Option<JsonValue>> {
    Ok((!values.is_empty()).then_some(JsonValue::Array(
        values.iter().cloned().map(JsonValue::String).collect(),
    )))
}

pub fn secure_bits_build_json(values: &[String]) -> Result<Option<JsonValue>> {
    capability_set_build_json(values)
}

pub fn rlimit_table_with_defaults_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    let mut object = BTreeMap::new();

    for name in ctx.limits.keys().chain(ctx.default_limits.keys()) {
        if object.contains_key(name) {
            continue;
        }

        let limit = ctx
            .limits
            .get(name)
            .or_else(|| ctx.default_limits.get(name));
        if let Some(limit) = limit {
            let mut fields = BTreeMap::new();
            if let Some(soft) = limit.soft {
                fields.insert("soft".into(), JsonValue::Unsigned(soft));
            }
            if let Some(hard) = limit.hard {
                fields.insert("hard".into(), JsonValue::Unsigned(hard));
            }
            if !fields.is_empty() {
                object.insert(name.clone(), JsonValue::Object(fields));
            }
        }
    }

    Ok((!object.is_empty()).then_some(JsonValue::Object(object)))
}

pub fn cpu_sched_class_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    Ok(ctx.cpu_sched_policy.clone().map(JsonValue::String))
}

pub fn cpu_affinity_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    if ctx.cpu_affinity.is_empty() {
        return Ok(None);
    }

    Ok(Some(JsonValue::object([
        (
            "affinity",
            JsonValue::Array(
                ctx.cpu_affinity
                    .iter()
                    .copied()
                    .map(|b| JsonValue::Unsigned(b as u64))
                    .collect(),
            ),
        ),
        ("fromNUMA", JsonValue::Bool(ctx.cpu_affinity_from_numa)),
    ])))
}

pub fn numa_policy_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    Ok(ctx.numa_policy.clone().map(JsonValue::String))
}

pub fn numa_mask_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    Ok((!ctx.numa_mask.is_empty()).then_some(JsonValue::Array(
        ctx.numa_mask
            .iter()
            .copied()
            .map(|b| JsonValue::Unsigned(b as u64))
            .collect(),
    )))
}

pub fn ioprio_class_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    Ok(ctx.io_sched_class.clone().map(JsonValue::String))
}

pub fn exec_dir_build_json(dir: &ExecDirectory) -> Result<Option<JsonValue>> {
    if dir.items.is_empty() {
        return Ok(None);
    }

    let paths = dir
        .items
        .iter()
        .map(|item| {
            JsonValue::object([
                ("path", JsonValue::String(item.path.clone())),
                (
                    "symlinks",
                    JsonValue::Array(
                        item.symlinks
                            .iter()
                            .cloned()
                            .map(JsonValue::String)
                            .collect(),
                    ),
                ),
            ])
        })
        .collect::<Vec<_>>();

    Ok(Some(JsonValue::object([
        ("paths", JsonValue::Array(paths)),
        ("mode", JsonValue::Unsigned(dir.mode as u64)),
        (
            "quota",
            JsonValue::object([
                ("accounting", JsonValue::Bool(dir.quota_accounting)),
                ("enforce", JsonValue::Bool(dir.quota_enforce)),
                ("quotaAbsolute", JsonValue::Unsigned(dir.quota_absolute)),
                ("quotaScale", JsonValue::Unsigned(dir.quota_scale)),
            ]),
        ),
    ])))
}

pub fn temporary_filesystems_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    Ok(
        (!ctx.temporary_filesystems.is_empty()).then_some(JsonValue::Array(
            ctx.temporary_filesystems
                .iter()
                .map(|(path, options)| {
                    let mut object =
                        BTreeMap::from([("path".into(), JsonValue::String(path.clone()))]);
                    if let Some(options) = options {
                        object.insert("options".into(), JsonValue::String(options.clone()));
                    }
                    JsonValue::Object(object)
                })
                .collect(),
        )),
    )
}

fn allow_list_object(flag: bool, key: &str, values: &[String]) -> Option<JsonValue> {
    (!values.is_empty()).then_some(JsonValue::object([
        ("isAllowList", JsonValue::Bool(flag)),
        (
            key,
            JsonValue::Array(values.iter().cloned().map(JsonValue::String).collect()),
        ),
    ]))
}

pub fn address_families_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    Ok(allow_list_object(
        ctx.address_families_allow_list,
        "addressFamilies",
        &ctx.address_families,
    ))
}

pub fn restrict_filesystems_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    Ok(allow_list_object(
        ctx.restrict_filesystems_allow_list,
        "filesystems",
        &ctx.restrict_filesystems,
    ))
}

pub fn namespace_flags_build_json(values: &[String]) -> Result<Option<JsonValue>> {
    capability_set_build_json(values)
}

pub fn environment_files_build_json(files: &[String]) -> Result<Option<JsonValue>> {
    Ok((!files.is_empty()).then_some(JsonValue::Array(
        files
            .iter()
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                JsonValue::object([
                    (
                        "path",
                        JsonValue::String(entry.strip_prefix('-').unwrap_or(entry).to_string()),
                    ),
                    ("graceful", JsonValue::Bool(entry.starts_with('-'))),
                ])
            })
            .collect(),
    )))
}

pub fn log_filter_patterns_build_json(ctx: &ExecContext) -> Result<Option<JsonValue>> {
    let mut patterns = Vec::new();

    for pattern in &ctx.allowed_log_patterns {
        patterns.push(JsonValue::object([
            ("isAllowList", JsonValue::Bool(true)),
            ("pattern", JsonValue::String(pattern.clone())),
        ]));
    }

    for pattern in &ctx.denied_log_patterns {
        patterns.push(JsonValue::object([
            ("isAllowList", JsonValue::Bool(false)),
            ("pattern", JsonValue::String(pattern.clone())),
        ]));
    }

    Ok((!patterns.is_empty()).then_some(JsonValue::Array(patterns)))
}

pub fn load_credential_build_json(
    entries: &[CredentialLoad],
    encrypted: bool,
) -> Result<Option<JsonValue>> {
    Ok((!entries.is_empty()).then_some(JsonValue::Array(
        entries
            .iter()
            .filter(|entry| entry.encrypted == encrypted)
            .map(|entry| {
                JsonValue::object([
                    ("id", JsonValue::String(entry.id.clone())),
                    ("path", JsonValue::String(entry.path.clone())),
                ])
            })
            .collect(),
    )))
}

pub fn import_credential_build_json(entries: &[CredentialImport]) -> Result<Option<JsonValue>> {
    Ok((!entries.is_empty()).then_some(JsonValue::Array(
        entries
            .iter()
            .map(|entry| {
                let mut object =
                    BTreeMap::from([("glob".into(), JsonValue::String(entry.glob.clone()))]);
                if let Some(rename) = &entry.rename {
                    object.insert("rename".into(), JsonValue::String(rename.clone()));
                }
                JsonValue::Object(object)
            })
            .collect(),
    )))
}

pub fn set_credential_build_json(
    entries: &[CredentialSet],
    encrypted: bool,
) -> Result<Option<JsonValue>> {
    Ok((!entries.is_empty()).then_some(JsonValue::Array(
        entries
            .iter()
            .filter(|entry| entry.encrypted == encrypted)
            .map(|entry| {
                JsonValue::object([
                    ("id", JsonValue::String(entry.id.clone())),
                    ("value", JsonValue::String(encode_base64(&entry.value))),
                ])
            })
            .collect(),
    )))
}

pub fn unit_exec_context_build_json(ctx: &ExecContext) -> Result<JsonValue> {
    let mut object = BTreeMap::new();

    if !ctx.exec_search_path.is_empty() {
        object.insert(
            "ExecSearchPath".into(),
            JsonValue::Array(
                ctx.exec_search_path
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
    }
    if let Some(v) = working_directory_build_json(&ctx.working_directory)? {
        object.insert("WorkingDirectory".into(), v);
    }
    if let Some(v) = root_image_options_build_json(&ctx.root_image_options)? {
        object.insert("RootImageOptions".into(), v);
    }
    if let Some(v) = image_policy_build_json(ctx.root_image_policy.as_deref())? {
        object.insert("RootImagePolicy".into(), v);
    }
    if let Some(v) = bind_paths_build_json("BindPaths", ctx)? {
        object.insert("BindPaths".into(), v);
    }
    if let Some(v) = bind_paths_build_json("BindReadOnlyPaths", ctx)? {
        object.insert("BindReadOnlyPaths".into(), v);
    }
    if let Some(v) = mount_images_build_json(ctx)? {
        object.insert("MountImages".into(), v);
    }
    if let Some(v) = extension_images_build_json(ctx)? {
        object.insert("ExtensionImages".into(), v);
    }
    if let Some(v) = capability_set_build_json(
        ctx.capability_sets
            .get("CapabilityBoundingSet")
            .map(Vec::as_slice)
            .unwrap_or(&[]),
    )? {
        object.insert("CapabilityBoundingSet".into(), v);
    }
    if let Some(v) = secure_bits_build_json(&ctx.secure_bits)? {
        object.insert("SecureBits".into(), v);
    }
    if let Some(v) = rlimit_table_with_defaults_build_json(ctx)? {
        object.insert("Limits".into(), v);
    }
    if let Some(v) = cpu_affinity_build_json(ctx)? {
        object.insert("CPUAffinity".into(), v);
    }
    if let Some(v) = temporary_filesystems_build_json(ctx)? {
        object.insert("TemporaryFileSystem".into(), v);
    }
    if let Some(v) = address_families_build_json(ctx)? {
        object.insert("RestrictAddressFamilies".into(), v);
    }
    if let Some(v) = restrict_filesystems_build_json(ctx)? {
        object.insert("RestrictFileSystems".into(), v);
    }
    if let Some(v) = namespace_flags_build_json(&ctx.namespace_flags)? {
        object.insert("RestrictNamespaces".into(), v);
    }
    if let Some(v) = environment_files_build_json(&ctx.environment_files)? {
        object.insert("EnvironmentFiles".into(), v);
    }
    if let Some(v) = log_filter_patterns_build_json(ctx)? {
        object.insert("LogFilterPatterns".into(), v);
    }
    if let Some(v) = exec_dir_build_json(&ctx.runtime_directory)? {
        object.insert("RuntimeDirectory".into(), v);
    }
    if let Some(v) = set_credential_build_json(&ctx.set_credentials, false)? {
        object.insert("SetCredential".into(), v);
    }

    Ok(JsonValue::Object(object))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn working_directory_uses_home_marker() {
        let json = working_directory_build_json(&WorkingDirectory {
            path: Some("/srv".into()),
            use_home: true,
            missing_ok: true,
        })
        .unwrap()
        .unwrap();

        let JsonValue::Object(object) = json else {
            panic!("expected object")
        };
        assert_eq!(object.get("path"), Some(&JsonValue::String("~".into())));
        assert_eq!(object.get("missingOK"), Some(&JsonValue::Bool(true)));
    }

    #[test]
    fn mount_options_skip_empty_entries() {
        let json = json_append_mount_options(&[
            PartitionMountOption {
                partition_designator: "root".into(),
                options: "rw".into(),
            },
            PartitionMountOption {
                partition_designator: "home".into(),
                options: String::new(),
            },
        ])
        .unwrap()
        .unwrap();

        let JsonValue::Array(entries) = json else {
            panic!("expected array")
        };
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn bind_paths_filter_read_only_variant_by_name() {
        let ctx = ExecContext {
            bind_mounts: vec![
                BindMount {
                    source: "/a".into(),
                    destination: "/b".into(),
                    read_only: false,
                    ignore_enoent: false,
                    recursive: true,
                },
                BindMount {
                    source: "/c".into(),
                    destination: "/d".into(),
                    read_only: true,
                    ignore_enoent: true,
                    recursive: false,
                },
            ],
            ..Default::default()
        };

        let JsonValue::Array(rw) = bind_paths_build_json("BindPaths", &ctx).unwrap().unwrap()
        else {
            panic!()
        };
        let JsonValue::Array(ro) = bind_paths_build_json("BindReadOnlyPaths", &ctx)
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(rw.len(), 1);
        assert_eq!(ro.len(), 1);
    }

    #[test]
    fn rlimit_builder_prefers_explicit_value_then_defaults() {
        let mut ctx = ExecContext::default();
        ctx.limits.insert(
            "LimitNOFILE".into(),
            RLimit {
                soft: Some(1),
                hard: Some(2),
            },
        );
        ctx.default_limits.insert(
            "LimitCPU".into(),
            RLimit {
                soft: Some(3),
                hard: None,
            },
        );

        let JsonValue::Object(object) = rlimit_table_with_defaults_build_json(&ctx)
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        assert!(object.contains_key("LimitNOFILE"));
        assert!(object.contains_key("LimitCPU"));
    }

    #[test]
    fn cpu_affinity_embeds_bytes_and_numa_flag() {
        let ctx = ExecContext {
            cpu_affinity: vec![1, 2],
            cpu_affinity_from_numa: true,
            ..Default::default()
        };

        let JsonValue::Object(object) = cpu_affinity_build_json(&ctx).unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(object.get("fromNUMA"), Some(&JsonValue::Bool(true)));
    }

    #[test]
    fn environment_files_preserve_graceful_prefix() {
        let JsonValue::Array(entries) =
            environment_files_build_json(&["-/etc/default/a".into(), "/etc/default/b".into()])
                .unwrap()
                .unwrap()
        else {
            panic!()
        };
        let JsonValue::Object(first) = &entries[0] else {
            panic!()
        };
        assert_eq!(first.get("graceful"), Some(&JsonValue::Bool(true)));
    }

    #[test]
    fn set_credentials_are_base64_encoded() {
        let json = set_credential_build_json(
            &[CredentialSet {
                id: "db".into(),
                value: b"hi".to_vec(),
                encrypted: false,
            }],
            false,
        )
        .unwrap()
        .unwrap();

        let JsonValue::Array(entries) = json else {
            panic!()
        };
        let JsonValue::Object(first) = &entries[0] else {
            panic!()
        };
        assert_eq!(first.get("value"), Some(&JsonValue::String("aGk=".into())));
    }

    #[test]
    fn log_filter_patterns_keep_allow_and_deny_markers() {
        let ctx = ExecContext {
            allowed_log_patterns: vec!["foo*".into()],
            denied_log_patterns: vec!["bar*".into()],
            ..Default::default()
        };

        let JsonValue::Array(entries) = log_filter_patterns_build_json(&ctx).unwrap().unwrap()
        else {
            panic!()
        };
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn unit_exec_context_aggregates_non_empty_sections() {
        let ctx = ExecContext {
            exec_search_path: vec!["/usr/bin".into()],
            working_directory: WorkingDirectory {
                path: Some("/work".into()),
                use_home: false,
                missing_ok: false,
            },
            environment_files: vec!["/etc/default/demo".into()],
            runtime_directory: ExecDirectory {
                items: vec![ExecDirectoryItem {
                    path: "/run/demo".into(),
                    symlinks: vec![],
                }],
                mode: 0o755,
                quota_accounting: true,
                quota_enforce: false,
                quota_absolute: 10,
                quota_scale: 20,
            },
            ..Default::default()
        };

        let JsonValue::Object(object) = unit_exec_context_build_json(&ctx).unwrap() else {
            panic!()
        };
        assert!(object.contains_key("ExecSearchPath"));
        assert!(object.contains_key("WorkingDirectory"));
        assert!(object.contains_key("EnvironmentFiles"));
        assert!(object.contains_key("RuntimeDirectory"));
    }
}
