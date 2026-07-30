// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-storagetm
//
// PORT-SYNC: src/storagetm/storagetm.c

use systemd_storagetm_rs::{
    IpFamily, NVME_PORTS_PATH, NVME_SUBSYSTEMS_PATH, build_subsystem_name, calculate_start_port,
    should_ignore_sysname, truncate_for_nvme,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!("systemd-storagetm [OPTIONS...] [DEVICE...]");
    println!();
    println!("  -h --help             Show this help");
    println!("     --version          Show package version");
    println!("     --backing-file=PATH  Set backing file");
    println!("  -a --all              Expose all block devices");
    println!("  -p --port=PORT        Set NVMe port number");
    println!("     --nqn=NQN          Set NVMe Qualified Name");
    println!("     --list-devices     List exposed devices");
}

fn print_version() {
    println!("systemd-storagetm {}", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut devices: Vec<String> = Vec::new();
    let mut all_count = 0;
    let mut nqn: Option<String> = None;
    let mut list_devices = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--version" => {
                print_version();
                return;
            }
            "-a" | "--all" => all_count += 1,
            "--list-devices" => list_devices = true,
            s if s.starts_with("--backing-file=") => {
                devices.push(s[15..].to_string());
            }
            s if s.starts_with("--nqn=") => {
                nqn = Some(s[6..].to_string());
            }
            s if s.starts_with("--port=") => {}
            s if s.starts_with('-') => {
                eprintln!("storagetm: unknown option: {}", s);
                std::process::exit(1);
            }
            other => devices.push(other.to_string()),
        }
        i += 1;
    }

    if !std::path::Path::new(NVME_SUBSYSTEMS_PATH).exists() {
        eprintln!(
            "storagetm: configfs not mounted at /sys/kernel/config/ (need CONFIG_NVME_TARGET)"
        );
        std::process::exit(1);
    }

    if list_devices {
        let subsystems_path = NVME_SUBSYSTEMS_PATH;
        if let Ok(entries) = std::fs::read_dir(subsystems_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let ns_path = entry.path().join("namespaces");
                if let Ok(ns_entries) = std::fs::read_dir(&ns_path) {
                    for ns in ns_entries.flatten() {
                        let device_path = ns.path().join("device_path");
                        if let Ok(dev) = std::fs::read_to_string(&device_path) {
                            println!("{}\t{}", name, dev.trim());
                        }
                    }
                }
            }
        }
        return;
    }

    if all_count > 0
        && devices.is_empty()
        && let Ok(entries) = std::fs::read_dir("/sys/class/block")
    {
        for entry in entries.flatten() {
            let sysname = entry.file_name().to_string_lossy().to_string();
            if should_ignore_sysname(&sysname) {
                continue;
            }
            let dev_path = format!("/dev/{}", sysname);
            if std::path::Path::new(&dev_path).exists() {
                devices.push(dev_path);
            }
        }
    }

    if devices.is_empty() {
        eprintln!("storagetm: no devices specified. Use --all or provide device paths.");
        std::process::exit(1);
    }

    let default_nqn = format!(
        "nqn.2023-10.io.systemd:storagetm.{}",
        std::env::var("MACHINE_ID")
            .or_else(|_| std::fs::read_to_string("/etc/machine-id").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string())
    );
    let nqn = nqn.as_deref().unwrap_or(&default_nqn);

    #[cfg(target_os = "linux")]
    {
        let _ = std::fs::create_dir_all(NVME_PORTS_PATH);

        let notify_socket = std::env::var("NOTIFY_SOCKET").unwrap_or_default();
        if !notify_socket.is_empty()
            && let Ok(sock) = std::os::unix::net::UnixDatagram::unbound()
        {
            let _ = sock.send_to(b"READY=1", notify_socket.trim_start_matches('@'));
        }

        for device in &devices {
            let subsys_name = build_subsystem_name(nqn, device);
            let subsys_dir = format!("{}/{}", NVME_SUBSYSTEMS_PATH, subsys_name);

            if std::path::Path::new(&subsys_dir).exists() {
                continue;
            }

            if let Err(e) = std::fs::create_dir_all(&subsys_dir) {
                eprintln!(
                    "storagetm: failed to create subsystem {}: {}",
                    subsys_name, e
                );
                continue;
            }

            let model = truncate_for_nvme("systemd-storagetm", 40);
            let _ = std::fs::write(format!("{}/attr/model", subsys_dir), model);
            let _ = std::fs::write(format!("{}/attr/serial", subsys_dir), "SN_STM001");
            let _ = std::fs::write(format!("{}/attr/firmware", subsys_dir), "00100001");

            let ns_dir = format!("{}/namespaces/1", subsys_dir);
            if std::fs::create_dir_all(&ns_dir).is_ok() {
                let _ = std::fs::write(format!("{}/device_path", ns_dir), device);
                let _ = std::fs::write(format!("{}/enable", ns_dir), "1");
            }

            for family in &[IpFamily::V4, IpFamily::V6] {
                let port = calculate_start_port(&subsys_name, *family);
                let port_dir = format!("{}/{}", NVME_PORTS_PATH, port);

                if !std::path::Path::new(&port_dir).exists()
                    && std::fs::create_dir_all(&port_dir).is_ok()
                {
                    let _ = std::fs::write(format!("{}/addr_trtype", port_dir), "tcp");
                    let _ = std::fs::write(format!("{}/addr_adrfam", port_dir), family.adrfam());
                    let _ =
                        std::fs::write(format!("{}/addr_traddr", port_dir), family.wildcard_addr());
                    let _ =
                        std::fs::write(format!("{}/addr_trsvcid", port_dir), format!("{}", port));
                    let _ = std::fs::write(format!("{}/addr_treq", port_dir), "not specified");
                }

                let link_dir = format!("{}/subsystems/{}", port_dir, subsys_name);
                if !std::path::Path::new(&link_dir).exists() {
                    if let Some(parent) = std::path::Path::new(&link_dir).parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::os::unix::fs::symlink(&subsys_dir, &link_dir);
                }
            }

            eprintln!("storagetm: exposed {} as {}", device, subsys_name);
            for family in &[IpFamily::V4, IpFamily::V6] {
                let port = calculate_start_port(&subsys_name, *family);
                eprintln!(
                    "  nvme connect -t tcp -n '{}' -a {} -s {}",
                    subsys_name,
                    family.wildcard_addr(),
                    port
                );
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("storagetm: NVMe target requires Linux");
        for device in &devices {
            eprintln!("  device: {}", device);
        }
        std::process::exit(1);
    }
}
