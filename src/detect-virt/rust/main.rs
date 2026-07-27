// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-detect-virt

use systemd_detect_virt_rs::detect_virt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-detect-virt [OPTIONS...]");
    println!();
    println!("Detect execution in a virtualized environment.");
    println!();
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
    println!("  -q --quiet             Suppress output");
    println!("  -v --vm                Only detect VMs");
    println!("  -c --container         Only detect containers");
    println!("  -r --chroot            Detect chroot");
    println!("     --private-users     Detect private users");
    println!("     --cvm               Detect confidential VMs");
}

fn print_version() {
    println!("systemd-detect-virt {}", VERSION);
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
                print_version();
                return;
            }
            _ => {}
        }
    }

    let (quiet, mode) = match detect_virt::parse_args(&refs) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Invalid argument. Try --help.");
            std::process::exit(1);
        }
    };

    let detected = detect_virt::detect();
    match mode {
        detect_virt::Mode::Vm if !detect_virt::is_vm(detected) => std::process::exit(1),
        detect_virt::Mode::Container if !detect_virt::is_container(detected) => {
            std::process::exit(1)
        }
        detect_virt::Mode::Chroot if detected != detect_virt::Virtualization::Chroot => {
            std::process::exit(1)
        }
        detect_virt::Mode::PrivateUsers
            if detected != detect_virt::Virtualization::PrivateUsers =>
        {
            std::process::exit(1)
        }
        detect_virt::Mode::Cvm if detected != detect_virt::Virtualization::Sev => {
            std::process::exit(1)
        }
        _ => {}
    }

    if !quiet {
        println!("{}", detect_virt::name(detected));
    }
    std::process::exit(detect_virt::exit_code(detected));
}
