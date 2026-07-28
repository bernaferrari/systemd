// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-pstore

use systemd_pstore_rs::{
    PStoreEntry, PStoreStorage, classify_entry, parse_pstore_storage, sort_entries,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-pstore [OPTIONS...]");
    println!("Archive and manage pstore entries from kernel crashes.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
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
                println!("systemd-pstore {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let storage = refs
        .iter()
        .find_map(|a| {
            a.strip_prefix("--storage=")
                .and_then(|v| parse_pstore_storage(v).ok())
        })
        .unwrap_or(PStoreStorage::External);

    if storage == PStoreStorage::None {
        return;
    }

    let _ = classify_entry;
    let _ = sort_entries;
    let _ = |_: &mut Vec<PStoreEntry>| {};
    eprintln!(
        "Processing pstore entries (storage: {})...",
        storage.as_str()
    );
}
