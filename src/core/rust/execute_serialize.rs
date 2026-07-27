// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/execute-serialize.c, src/core/execute-serialize.h
//

use std::collections::BTreeMap;

use crate::ffi::Errno;

pub const SOURCE_PATHS: &[&str] = &[
    "src/core/execute-serialize.c",
    "src/core/execute-serialize.h",
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MountOptions {
    pub by_partition: BTreeMap<String, String>,
}

pub fn serialize_mount_options(mount_options: &MountOptions) -> Result<String, Errno> {
    let mut rendered = String::new();
    for (partition, options) in &mount_options.by_partition {
        if partition.is_empty() {
            return Err(Errno::EINVAL);
        }
        if options.is_empty() {
            continue;
        }

        rendered.push(' ');
        rendered.push_str(partition);
        rendered.push(':');
        rendered.push_str(&escape_word(options));
    }
    Ok(rendered)
}

pub fn deserialize_mount_options(input: &str) -> Result<MountOptions, Errno> {
    let mut out = MountOptions::default();
    for word in split_words(input)? {
        let Some((partition, options)) = split_partition_word(&word)? else {
            continue;
        };
        out.by_partition.insert(partition, options);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecContext {
    pub environment: Vec<String>,
    pub working_directory: Option<String>,
    pub root_directory: Option<String>,
    pub root_image_options: Option<MountOptions>,
    pub std_input: Option<String>,
    pub std_output: Option<String>,
    pub private_tmp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecCommand {
    pub path: Option<String>,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecParameters {
    pub idle_pipe_set: bool,
    pub socket_fds: Vec<i32>,
    pub stashed_fds: Vec<i32>,
}

impl ExecParameters {
    pub fn is_idle_pipe_set(&self) -> bool {
        self.idle_pipe_set
    }

    pub fn validate(&self) -> Result<(), Errno> {
        if self.socket_fds.iter().any(|fd| *fd < 0) || self.stashed_fds.iter().any(|fd| *fd < 0) {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecRuntime {
    pub cgroup_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CGroupContext {
    pub delegated_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub context: ExecContext,
    pub command: ExecCommand,
    pub parameters: ExecParameters,
    pub runtime: ExecRuntime,
    pub cgroup: CGroupContext,
}

pub fn exec_serialize_invocation(invocation: &Invocation) -> Result<String, Errno> {
    invocation.parameters.validate()?;

    let mut lines = Vec::new();
    if !invocation.context.environment.is_empty() {
        lines.push(format!(
            "exec-context-environment={}",
            invocation.context.environment.join(" ")
        ));
    }
    if let Some(value) = &invocation.context.working_directory {
        lines.push(format!(
            "exec-context-working-directory={}",
            escape_word(value)
        ));
    }
    if let Some(value) = &invocation.context.root_directory {
        lines.push(format!(
            "exec-context-root-directory={}",
            escape_word(value)
        ));
    }
    if let Some(value) = &invocation.context.root_image_options {
        lines.push(format!(
            "exec-context-root-image-options={}",
            serialize_mount_options(value)?.trim_start()
        ));
    }
    if let Some(value) = &invocation.context.std_input {
        lines.push(format!("exec-context-std-input={value}"));
    }
    if let Some(value) = &invocation.context.std_output {
        lines.push(format!("exec-context-std-output={value}"));
    }
    if let Some(value) = &invocation.context.private_tmp {
        lines.push(format!("exec-context-private-tmp={value}"));
    }
    if let Some(path) = &invocation.command.path {
        lines.push(format!("exec-command-path={}", escape_word(path)));
    }
    if !invocation.command.argv.is_empty() {
        lines.push(format!(
            "exec-command-argv={}",
            invocation.command.argv.join("\u{1f}")
        ));
    }
    lines.push(format!(
        "exec-parameters-idle-pipe-set={}",
        u8::from(invocation.parameters.idle_pipe_set)
    ));
    if !invocation.parameters.socket_fds.is_empty() {
        lines.push(format!(
            "exec-parameters-socket-fds={}",
            invocation
                .parameters
                .socket_fds
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if !invocation.parameters.stashed_fds.is_empty() {
        lines.push(format!(
            "exec-parameters-stashed-fds={}",
            invocation
                .parameters
                .stashed_fds
                .iter()
                .map(i32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if let Some(value) = &invocation.runtime.cgroup_path {
        lines.push(format!("exec-runtime-cgroup-path={}", escape_word(value)));
    }
    if let Some(value) = &invocation.cgroup.delegated_path {
        lines.push(format!("exec-cgroup-delegated-path={}", escape_word(value)));
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

pub fn exec_deserialize_invocation(serialized: &str) -> Result<Invocation, Errno> {
    let mut invocation = Invocation {
        context: ExecContext::default(),
        command: ExecCommand::default(),
        parameters: ExecParameters::default(),
        runtime: ExecRuntime::default(),
        cgroup: CGroupContext::default(),
    };

    for line in serialized.lines() {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(Errno::EINVAL);
        };
        match key {
            "exec-context-environment" => invocation.context.environment = split_words(value)?,
            "exec-context-working-directory" => {
                invocation.context.working_directory = Some(unescape_word(value)?)
            }
            "exec-context-root-directory" => {
                invocation.context.root_directory = Some(unescape_word(value)?)
            }
            "exec-context-root-image-options" => {
                invocation.context.root_image_options = Some(deserialize_mount_options(value)?);
            }
            "exec-context-std-input" => invocation.context.std_input = Some(value.into()),
            "exec-context-std-output" => invocation.context.std_output = Some(value.into()),
            "exec-context-private-tmp" => invocation.context.private_tmp = Some(value.into()),
            "exec-command-path" => invocation.command.path = Some(unescape_word(value)?),
            "exec-command-argv" => {
                invocation.command.argv = if value.is_empty() {
                    Vec::new()
                } else {
                    value.split('\u{1f}').map(str::to_string).collect()
                }
            }
            "exec-parameters-idle-pipe-set" => {
                invocation.parameters.idle_pipe_set = parse_bool01(value)?
            }
            "exec-parameters-socket-fds" => {
                invocation.parameters.socket_fds = parse_fd_list(value)?
            }
            "exec-parameters-stashed-fds" => {
                invocation.parameters.stashed_fds = parse_fd_list(value)?
            }
            "exec-runtime-cgroup-path" => {
                invocation.runtime.cgroup_path = Some(unescape_word(value)?)
            }
            "exec-cgroup-delegated-path" => {
                invocation.cgroup.delegated_path = Some(unescape_word(value)?)
            }
            _ => return Err(Errno::EINVAL),
        }
    }

    invocation.parameters.validate()?;
    Ok(invocation)
}

fn parse_bool01(value: &str) -> Result<bool, Errno> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(Errno::EINVAL),
    }
}

fn parse_fd_list(value: &str) -> Result<Vec<i32>, Errno> {
    if value.is_empty() {
        return Ok(Vec::new());
    }

    value
        .split(',')
        .map(|part| part.parse::<i32>().map_err(|_| Errno::EINVAL))
        .collect()
}

fn escape_word(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, ' ' | ':' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

fn unescape_word(value: &str) -> Result<String, Errno> {
    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    if escaped {
        return Err(Errno::EINVAL);
    }
    Ok(out)
}

fn split_words(input: &str) -> Result<Vec<String>, Errno> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in input.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if escaped {
        return Err(Errno::EINVAL);
    }
    if !current.is_empty() {
        words.push(current);
    }
    Ok(words)
}

fn split_partition_word(word: &str) -> Result<Option<(String, String)>, Errno> {
    let mut escaped = false;
    for (idx, ch) in word.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == ':' {
            let partition = &word[..idx];
            let options = &word[idx + 1..];
            if partition.is_empty() {
                return Ok(None);
            }
            return Ok(Some((partition.to_string(), unescape_word(options)?)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_options_roundtrip_with_escaping() {
        let options = MountOptions {
            by_partition: BTreeMap::from([("root".into(), "rw:nodev".into())]),
        };
        let serialized = serialize_mount_options(&options).unwrap();
        assert_eq!(serialized, " root:rw\\:nodev");
        assert_eq!(deserialize_mount_options(&serialized).unwrap(), options);
    }

    #[test]
    fn parameters_idle_pipe_tracks_boolean() {
        let parameters = ExecParameters {
            idle_pipe_set: true,
            ..Default::default()
        };
        assert!(parameters.is_idle_pipe_set());
    }

    #[test]
    fn parameters_reject_negative_fds() {
        let parameters = ExecParameters {
            socket_fds: vec![-1],
            ..Default::default()
        };
        assert_eq!(parameters.validate(), Err(Errno::EINVAL));
    }

    #[test]
    fn invocation_roundtrip_preserves_subset() {
        let invocation = Invocation {
            context: ExecContext {
                environment: vec!["A=1".into(), "B=2".into()],
                working_directory: Some("/srv/app".into()),
                root_directory: Some("/root dir".into()),
                root_image_options: Some(MountOptions {
                    by_partition: BTreeMap::from([("root".into(), "rw:nodev".into())]),
                }),
                std_input: Some("tty".into()),
                std_output: Some("journal".into()),
                private_tmp: Some("connected".into()),
            },
            command: ExecCommand {
                path: Some("/usr/bin/test".into()),
                argv: vec!["test".into(), "--flag".into()],
            },
            parameters: ExecParameters {
                idle_pipe_set: true,
                socket_fds: vec![3, 4],
                stashed_fds: vec![5],
            },
            runtime: ExecRuntime {
                cgroup_path: Some("/sys/fs/cgroup/demo".into()),
            },
            cgroup: CGroupContext {
                delegated_path: Some("/delegated".into()),
            },
        };

        let serialized = exec_serialize_invocation(&invocation).unwrap();
        let parsed = exec_deserialize_invocation(&serialized).unwrap();
        assert_eq!(parsed, invocation);
    }

    #[test]
    fn deserializer_rejects_unknown_key() {
        assert_eq!(
            exec_deserialize_invocation("unknown=value\n\n"),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn split_words_respects_backslash_escaping() {
        let words = split_words("one two\\ three four").unwrap();
        assert_eq!(words, vec!["one", "two three", "four"]);
    }

    #[test]
    fn split_partition_word_requires_partition() {
        assert_eq!(split_partition_word(":rw").unwrap(), None);
    }

    #[test]
    fn unescape_rejects_dangling_escape() {
        assert_eq!(unescape_word("abc\\"), Err(Errno::EINVAL));
    }
}
