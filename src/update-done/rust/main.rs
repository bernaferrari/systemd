// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-update-done

use systemd_update_done_rs::{
    generate_updated_content, Timespec, UpdateDoneArgs, UPDATE_DIRS, USR_PATH,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const UPDATED_FILE: &str = "/etc/.updated";
const USR_UPDATED_FILE: &str = "/usr/.updated";

fn print_help() {
    println!("systemd-update-done [OPTIONS...]");
    println!("Mark OS updates as complete.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
}

fn write_updated_file(path: &str, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refs: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    for a in &refs {
        match *a {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--version" => {
                println!("systemd-update-done {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let _ = UpdateDoneArgs::parse(&refs).unwrap_or_else(|_| {
        eprintln!("Invalid arguments. Try --help.");
        std::process::exit(1);
    });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ts = Timespec {
        sec: now.as_secs() as i64,
        nsec: now.subsec_nanos() as i64,
    };

    for dir in UPDATE_DIRS {
        let content = generate_updated_content(dir, &ts);
        let file_path = format!("{}/.updated", dir.trim_end_matches('/'));

        match write_updated_file(&file_path, &content) {
            Ok(()) => eprintln!("update-done: wrote {}", file_path),
            Err(e) => eprintln!("update-done: failed to write {}: {}", file_path, e),
        }
    }
}
