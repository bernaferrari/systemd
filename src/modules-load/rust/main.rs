// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-modules-load

use systemd_modules_load_rs::{
    is_module_name_valid, load_module_best_effort, load_modules_from_conf_dirs,
    normalize_module_name, parse_proc_cmdline_modules, read_proc_cmdline, ModuleSet,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-modules-load [OPTIONS...] [MODULE...]");
    println!("Load statically configured kernel modules.");
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
                println!("systemd-modules-load {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let mut modules = ModuleSet::new();

    for arg in &refs {
        if arg.starts_with('-') {
            eprintln!("Unknown option '{}'. Try --help.", arg);
            std::process::exit(1);
        }
        let name = normalize_module_name(arg);
        if !is_module_name_valid(&name) {
            eprintln!("Invalid module name '{}'.", arg);
            std::process::exit(1);
        }
        modules.append(&name).unwrap();
    }

    let _ = load_modules_from_conf_dirs(&mut modules);

    if let Some(cmdline) = read_proc_cmdline() {
        parse_proc_cmdline_modules("modules_load", Some(cmdline.as_str()), &mut modules).ok();
    }

    let loaded = modules.to_sorted_vec();
    if loaded.is_empty() {
        eprintln!("systemd-modules-load: no modules to load");
        return;
    }

    let mut ok = 0usize;
    let mut fail = 0usize;
    for m in &loaded {
        match load_module_best_effort(m) {
            Ok(()) => {
                eprintln!("systemd-modules-load: loaded {}", m);
                ok += 1;
            }
            Err(e) => {
                eprintln!("systemd-modules-load: failed to load {}: {}", m, e);
                fail += 1;
            }
        }
    }
    eprintln!(
        "systemd-modules-load: {} modules loaded, {} failed",
        ok, fail
    );
}
