// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/random-seed/random-seed-tool.c
#![deny(unsafe_op_in_unsafe_fn)]
//
// Binary entry point for systemd-random-seed

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use systemd_random_seed_rs::{SeedAction, seed_file_path};

#[cfg(target_os = "linux")]
use systemd_random_seed_rs::{CreditContext, CreditEntropy, may_credit};

const VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(target_os = "linux")]
const POOL_SIZE: usize = 512;
#[cfg(target_os = "linux")]
const URANDOM_PATH: &str = "/dev/urandom";

fn print_help() {
    println!("systemd-random-seed [OPTIONS...] {{load|save}}");
    println!("Load or save the system random seed.");
    println!("  -h --help              Show this help");
    println!("     --version           Show package version");
}

#[cfg(target_os = "linux")]
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
};

#[cfg(target_os = "linux")]
const RNDADDENTROPY_HEADER_SIZE: usize = std::mem::size_of::<RandPoolInfoHeader>();

/// Linux's `RNDADDENTROPY` `_IOW('R', 0x03, int[2])` request number.
///
/// libc does not export this UAPI constant. Deriving it through nix's
/// target-aware ioctl encoder preserves the distinct encodings used by Linux
/// architectures instead of hard-coding the generic 0x4008_5203 value.
#[cfg(target_os = "linux")]
const RNDADDENTROPY: libc::c_ulong =
    nix::request_code_write!(b'R', 0x03, RNDADDENTROPY_HEADER_SIZE) as libc::c_ulong;

/// The fixed-size prefix of Linux's `struct rand_pool_info` UAPI request.
///
/// `buf` is a flexible array member, so `libc::rand_pool_info` alone is not a
/// complete ioctl request. The request constructed below is this C-layout
/// prefix immediately followed by the seed bytes.
#[cfg(target_os = "linux")]
#[repr(C)]
struct RandPoolInfoHeader {
    entropy_count: libc::c_int,
    buf_size: libc::c_int,
}

#[cfg(target_os = "linux")]
fn entropy_credit_requested() -> bool {
    let env_value = std::env::var("SYSTEMD_RANDOM_SEED_CREDIT").ok();
    match may_credit(CreditContext {
        env_value: env_value.as_deref(),
        // Automatic crediting requires a persisted xattr and a first-boot
        // check. This small Rust port does not yet implement either check, so
        // it must not claim that a seed is creditable.
        seed_marked_creditable: false,
        first_boot: false,
    }) {
        Ok(CreditEntropy::YesForced) => true,
        Ok(_) => false,
        Err(error) => {
            eprintln!(
                "random-seed: invalid $SYSTEMD_RANDOM_SEED_CREDIT ({error}), not crediting entropy"
            );
            false
        }
    }
}

/// Submit seed bytes through the Linux `RNDADDENTROPY` UAPI.
///
/// The only unsafe operation in this program is confined here. The vector is
/// a contiguous C-compatible request: two native-endian C `int` fields then
/// `data.len()` bytes. It remains alive for the duration of `ioctl`, which
/// synchronously copies the request from userspace.
#[cfg(target_os = "linux")]
fn add_entropy(urandom: &File, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    if data.len() > (libc::c_int::MAX as usize) / 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "seed is too large for RNDADDENTROPY",
        ));
    }

    // Linux defines this UAPI prefix as two C ints. Keep the check adjacent
    // to the marshalling so an ABI change cannot silently alter the request.
    debug_assert_eq!(
        RNDADDENTROPY_HEADER_SIZE,
        2 * std::mem::size_of::<libc::c_int>()
    );

    let entropy_count = (data.len() * 8) as libc::c_int;
    let buf_size = data.len() as libc::c_int;
    let request_size = RNDADDENTROPY_HEADER_SIZE
        .checked_add(data.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seed request is too large"))?;
    let mut request = Vec::new();
    request
        .try_reserve_exact(request_size)
        .map_err(|_| io::Error::other("unable to allocate RNDADDENTROPY request"))?;
    request.extend_from_slice(&entropy_count.to_ne_bytes());
    request.extend_from_slice(&buf_size.to_ne_bytes());
    debug_assert_eq!(request.len(), RNDADDENTROPY_HEADER_SIZE);
    request.extend_from_slice(data);

    // SAFETY: `request` is a live contiguous Linux UAPI request as described
    // above; `ioctl` copies it before returning and the descriptor is an open
    // /dev/urandom file owned by `urandom`.
    let result = unsafe_ffi!(libc::ioctl(
        urandom.as_raw_fd(),
        RNDADDENTROPY,
        request.as_ptr()
    ));
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn write_seed_to_kernel(data: &[u8]) -> io::Result<()> {
    let mut urandom = OpenOptions::new()
        .read(true)
        .write(true)
        .open(URANDOM_PATH)?;

    if entropy_credit_requested() {
        add_entropy(&urandom, data)
    } else {
        urandom.write_all(data)
    }
}

#[cfg(target_os = "linux")]
fn load_seed(seed_path: &str) -> std::io::Result<()> {
    let seed_data = match File::open(seed_path) {
        Ok(seed_file) => {
            let mut data = Vec::with_capacity(POOL_SIZE);
            seed_file.take(POOL_SIZE as u64).read_to_end(&mut data)?;
            data
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "random-seed: no seed file at {}, generating fresh",
                seed_path
            );
            return write_new_seed(seed_path);
        }
        Err(e) => return Err(e),
    };

    if seed_data.is_empty() {
        eprintln!("random-seed: seed file is empty");
        return write_new_seed(seed_path);
    }

    write_seed_to_kernel(&seed_data)?;
    eprintln!(
        "random-seed: loaded {} bytes from {}",
        seed_data.len(),
        seed_path
    );

    write_new_seed(seed_path)
}

#[cfg(not(target_os = "linux"))]
fn load_seed(seed_path: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("load is only supported on Linux (seed path {seed_path})"),
    ))
}

#[cfg(target_os = "linux")]
fn save_seed(seed_path: &str) -> std::io::Result<()> {
    write_new_seed(seed_path)
}

#[cfg(not(target_os = "linux"))]
fn save_seed(seed_path: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("save is only supported on Linux (seed path {seed_path})"),
    ))
}

#[cfg(target_os = "linux")]
fn write_new_seed(seed_path: &str) -> std::io::Result<()> {
    let mut buf = vec![0u8; POOL_SIZE];
    getrandom::fill(&mut buf).map_err(std::io::Error::other)?;

    if let Some(parent) = std::path::Path::new(seed_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut seed_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(seed_path)?;
    seed_file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    seed_file.write_all(&buf)?;
    seed_file.sync_all()?;
    eprintln!("random-seed: saved {} bytes to {}", POOL_SIZE, seed_path);
    Ok(())
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
                println!("systemd-random-seed {}", VERSION);
                return;
            }
            _ => {}
        }
    }

    let action = match refs.as_slice() {
        ["load"] => SeedAction::Load,
        ["save"] => SeedAction::Save,
        _ => {
            eprintln!("Usage: systemd-random-seed load|save. Try --help.");
            std::process::exit(1);
        }
    };

    let seed_path = seed_file_path(None);

    let result = match action {
        SeedAction::Load => load_seed(&seed_path),
        SeedAction::Save => save_seed(&seed_path),
    };

    if let Err(e) = result {
        eprintln!("random-seed: operation failed: {}", e);
        std::process::exit(1);
    }
}
