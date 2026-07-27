// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-path

use systemd_path_rs::{sorted_path_names, PATH_TABLE};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        // List all known paths sorted alphabetically
        for name in sorted_path_names() {
            println!("{}", name);
        }
    } else {
        // Show details for requested path names
        for query in &args {
            match PATH_TABLE.iter().position(|p| *p == query.as_str()) {
                Some(idx) => println!("{} (index {})", query, idx),
                None => eprintln!("systemd-path: unknown path '{}'", query),
            }
        }
    }
}
