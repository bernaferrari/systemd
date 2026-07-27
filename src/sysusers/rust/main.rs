// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-sysusers

use systemd_sysusers_rs::{
    backup_path, group_path, parse_config_line, passwd_path, Item, ItemType, GSHADOW_PATH,
    PASSWORD_LOCKED_AND_INVALID, PASSWORD_SEE_SHADOW, SHADOW_PATH,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const SYSUSERS_DIRS: &[&str] = &[
    "/etc/sysusers.d",
    "/run/sysusers.d",
    "/usr/local/lib/sysusers.d",
    "/usr/lib/sysusers.d",
    "/lib/sysusers.d",
];

fn print_help() {
    println!("systemd-sysusers [OPTIONS...] [CONFIGFILE...]");
    println!();
    println!("Create system users and groups.");
    println!();
    println!("  -h --help           Show this help");
    println!("     --version        Show package version");
    println!("     --root=PATH      Operate on root directory");
    println!("     --image=IMAGE    Operate on disk image");
    println!("     --replace=PATH   Replace configuration file");
    println!("     --no-pager       Do not pipe output into pager");
}

fn print_version() {
    println!("systemd-sysusers {}", VERSION);
}

fn existing_users(passwd: &str) -> std::collections::HashSet<String> {
    let mut users = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(passwd) {
        for line in content.lines() {
            if let Some(name) = line.split(':').next() {
                users.insert(name.to_string());
            }
        }
    }
    users
}

fn existing_groups(group_file: &str) -> std::collections::HashSet<String> {
    let mut groups = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(group_file) {
        for line in content.lines() {
            if let Some(name) = line.split(':').next() {
                groups.insert(name.to_string());
            }
        }
    }
    groups
}

fn next_available_uid(passwd: &str, min: u32, max: u32) -> u32 {
    let mut used = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(passwd) {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                if let Ok(uid) = fields[2].parse::<u32>() {
                    used.insert(uid);
                }
            }
        }
    }
    for uid in min..=max {
        if !used.contains(&uid) {
            return uid;
        }
    }
    min
}

fn next_available_gid(group_file: &str, min: u32, max: u32) -> u32 {
    let mut used = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(group_file) {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                if let Ok(gid) = fields[2].parse::<u32>() {
                    used.insert(gid);
                }
            }
        }
    }
    for gid in min..=max {
        if !used.contains(&gid) {
            return gid;
        }
    }
    min
}

fn append_line(path: &str, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
    writeln!(file, "{}", line)
}

fn add_user_to_passwd(passwd: &str, item: &Item, uid: u32, gid: u32) -> std::io::Result<()> {
    let shell = item
        .pick_shell("/bin/bash")
        .unwrap_or_else(|| "/sbin/nologin".to_string());
    let home = item.home_dir();
    let gecos = item.description.as_deref().unwrap_or("");
    let line = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        item.name, PASSWORD_SEE_SHADOW, uid, gid, gecos, home, shell
    );
    append_line(passwd, &line)
}

fn add_user_to_shadow(shadow: &str, name: &str) -> std::io::Result<()> {
    let line = format!("{}:{}:0:0:99999:7:::", name, PASSWORD_LOCKED_AND_INVALID);
    append_line(shadow, &line)
}

fn add_group(group_file: &str, name: &str, gid: u32) -> std::io::Result<()> {
    let line = format!("{}:x:{}:", name, gid);
    append_line(group_file, &line)
}

fn add_group_member(group_file: &str, group_name: &str, user_name: &str) -> std::io::Result<()> {
    let content = std::fs::read_to_string(group_file)?;
    let mut new_content = String::new();
    let mut found = false;

    for line in content.lines() {
        let mut fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 4 && fields[0] == group_name {
            found = true;
            let members = fields[3];
            if members.is_empty() {
                fields[3] = user_name;
            } else if !members.split(',').any(|m| m == user_name) {
                let new_members = format!("{},{}", members, user_name);
                fields[3] = &new_members;
                new_content.push_str(&format!(
                    "{}:{}:{}:{}\n",
                    fields[0], fields[1], fields[2], new_members
                ));
                continue;
            }
            new_content.push_str(&fields.join(":"));
            new_content.push('\n');
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    if found {
        std::fs::write(group_file, &new_content)?;
    }
    Ok(())
}

fn apply_item(item: &Item, root: &Option<String>) -> Result<(), String> {
    let passwd = passwd_path(root.as_deref());
    let group_file = group_path(root.as_deref());
    let shadow = root.as_deref().map_or_else(
        || SHADOW_PATH.to_string(),
        |r| format!("{}{}", r, SHADOW_PATH),
    );

    match item.item_type {
        ItemType::AddUser => {
            let existing = existing_users(&passwd);
            if existing.contains(&item.name) {
                return Ok(());
            }

            let uid = if item.uid_set {
                item.uid
            } else {
                next_available_uid(&passwd, 1, 999)
            };

            let gid = if item.gid_set {
                item.gid
            } else {
                let existing_groups = existing_groups(&group_file);
                if existing_groups.contains(&item.name) {
                    next_available_gid(&group_file, 1, 999)
                } else {
                    let g = next_available_gid(&group_file, 1, 999);
                    let _ = add_group(&group_file, &item.name, g);
                    g
                }
            };

            add_user_to_passwd(&passwd, item, uid, gid)
                .map_err(|e| format!("add user {} to passwd: {}", item.name, e))?;
            let _ = add_user_to_shadow(&shadow, &item.name);

            eprintln!("sysusers: created user {} (uid={})", item.name, uid);
            Ok(())
        }
        ItemType::AddGroup => {
            let existing = existing_groups(&group_file);
            if existing.contains(&item.name) {
                return Ok(());
            }

            let gid = if item.gid_set {
                item.gid
            } else {
                next_available_gid(&group_file, 1, 999)
            };

            add_group(&group_file, &item.name, gid)
                .map_err(|e| format!("add group {} to group: {}", item.name, e))?;

            eprintln!("sysusers: created group {} (gid={})", item.name, gid);
            Ok(())
        }
        ItemType::AddMember => {
            let group_name = item.group_name.as_deref().unwrap_or(&item.name);
            add_group_member(&group_file, group_name, &item.name)
                .map_err(|e| format!("add member {} to {}: {}", item.name, group_name, e))?;
            eprintln!("sysusers: added {} to group {}", item.name, group_name);
            Ok(())
        }
        ItemType::AddRange => {
            eprintln!("sysusers: range {} (not yet applied)", item.name);
            Ok(())
        }
    }
}

fn process_config_file(path: &str, root: &Option<String>) -> (usize, usize) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sysusers: cannot read {}: {}", path, e);
            return (0, 0);
        }
    };

    let mut ok = 0usize;
    let mut fail = 0usize;
    for (i, line) in content.lines().enumerate() {
        let item = match parse_config_line(line, path, i as u32 + 1) {
            Ok(item) => item,
            Err(_) => continue,
        };
        match apply_item(&item, root) {
            Ok(()) => ok += 1,
            Err(e) => {
                eprintln!("sysusers: {} line {}: {}", path, i + 1, e);
                fail += 1;
            }
        }
    }
    (ok, fail)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut root: Option<String> = None;
    let mut config_files: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--version" => {
                print_version();
                return;
            }
            "--root" => {
                i += 1;
                if i < args.len() {
                    root = Some(args[i].clone());
                }
            }
            s if s.starts_with("--root=") => {
                root = Some(s[7..].to_string());
            }
            "--no-pager" | "--inline" => {}
            s if s.starts_with('-') => {
                eprintln!("Unknown option: {}", s);
            }
            other => {
                config_files.push(other.to_string());
            }
        }
        i += 1;
    }

    let mut total_ok = 0usize;
    let mut total_fail = 0usize;

    if config_files.is_empty() {
        for dir in SYSUSERS_DIRS {
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let mut conf_files: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "conf")
                        .unwrap_or(false)
                })
                .collect();
            conf_files.sort_by_key(|e| e.file_name());

            for entry in conf_files {
                let path = entry.path().display().to_string();
                let (ok, fail) = process_config_file(&path, &root);
                total_ok += ok;
                total_fail += fail;
            }
        }
    } else {
        for config_file in &config_files {
            let (ok, fail) = process_config_file(config_file, &root);
            total_ok += ok;
            total_fail += fail;
        }
    }

    eprintln!(
        "sysusers: {} items processed, {} failed",
        total_ok, total_fail
    );
    if total_fail > 0 {
        std::process::exit(1);
    }
}
