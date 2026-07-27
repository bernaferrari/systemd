// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-machine-id-setup

use systemd_machine_id_setup_rs::{MachineIdAction, MachineIdSetupArgs};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MACHINE_ID_PATH: &str = "/etc/machine-id";
const MACHINE_ID_LEN: usize = 32;

fn print_help() {
    println!("systemd-machine-id-setup [OPTIONS...]");
    println!("Initialize /etc/machine-id from a random source.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
    println!("     --root=PATH         Operate on alternate root");
    println!("     --image=PATH        Operate on disk image");
    println!("     --commit            Commit a transient ID");
    println!("     --print             Print the resulting ID");
}

fn machine_id_path(root: &Option<String>) -> String {
    match root {
        Some(r) if !r.is_empty() => {
            let r = r.trim_end_matches('/');
            format!("{}/etc/machine-id", r)
        }
        _ => MACHINE_ID_PATH.to_string(),
    }
}

fn generate_machine_id() -> Result<String, String> {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).map_err(|e| format!("random read failed: {}", e))?;
    let hex: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(hex)
}

fn write_machine_id(path: &str) -> Result<String, String> {
    let id = generate_machine_id()?;
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create_dir {} failed: {}", parent.display(), e))?;
    }
    std::fs::write(path, format!("{}\n", id))
        .map_err(|e| format!("write {} failed: {}", path, e))?;
    Ok(id)
}

fn read_existing_id(path: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.len() == MACHINE_ID_LEN && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    if refs.contains(&"--help") || refs.contains(&"-h") {
        print_help();
        return;
    }
    if refs.contains(&"--version") {
        println!("systemd-machine-id-setup {}", VERSION);
        return;
    }

    let mut setup_args = MachineIdSetupArgs::new();
    let mut i = 0;
    while i < refs.len() {
        match refs[i] {
            "--commit" => setup_args.commit = true,
            "--print" => setup_args.print = true,
            s if s.starts_with("--root=") => setup_args.root = Some(s[7..].to_string()),
            "--root" => {
                i += 1;
                if i < refs.len() {
                    setup_args.root = Some(refs[i].to_string());
                }
            }
            s if s.starts_with("--image=") => setup_args.image = Some(s[8..].to_string()),
            "--image" => {
                i += 1;
                if i < refs.len() {
                    setup_args.image = Some(refs[i].to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }

    if let Err(e) = setup_args.validate() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    let path = machine_id_path(&setup_args.root);

    match setup_args.determine_action() {
        MachineIdAction::Commit => {
            let transient = format!(
                "{}/etc/machine-id",
                setup_args
                    .root
                    .as_deref()
                    .unwrap_or("")
                    .trim_end_matches('/')
            );
            let uncommitted = format!(
                "{}/run/machine-id",
                setup_args
                    .root
                    .as_deref()
                    .unwrap_or("")
                    .trim_end_matches('/')
            );
            if let Ok(content) = std::fs::read_to_string(&uncommitted) {
                if let Some(parent) = std::path::Path::new(&transient).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&transient, &content) {
                    Ok(()) => {
                        let id = content.trim().to_string();
                        eprintln!("machine-id-setup: committed {}", id);
                        if setup_args.print {
                            println!("{}", id);
                        }
                    }
                    Err(e) => {
                        eprintln!("machine-id-setup: commit failed: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("machine-id-setup: no transient machine-id to commit");
                std::process::exit(1);
            }
        }
        MachineIdAction::Initialize => {
            if let Some(existing) = read_existing_id(&path) {
                eprintln!("machine-id-setup: {} already initialized", path);
                if setup_args.print {
                    println!("{}", existing);
                }
                return;
            }

            match write_machine_id(&path) {
                Ok(id) => {
                    eprintln!("machine-id-setup: initialized {}", path);
                    if setup_args.print {
                        println!("{}", id);
                    }
                }
                Err(e) => {
                    eprintln!("machine-id-setup: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
