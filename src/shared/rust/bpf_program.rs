// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bpf-program.c, src/shared/bpf-program.h
//
// BPF program management - loading, attaching, and controlling BPF programs.
//
// Provides safe Rust wrappers around BPF program lifecycle: creation,
// instruction management, kernel loading, and cgroup attachment/detachment.
// The unsafe `extern "C"` bpf() syscall is confined to private helper
// functions; all public APIs are safe Rust.

use std::ffi::{CStr, CString};
use std::fmt;
use std::path::Path;

use crate::ffi::Errno;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum BPF object name length (kernel constant BPF_OBJ_NAME_LEN).
pub const BPF_OBJ_NAME_LEN: usize = 16;

/// BPF attach flag: allow override of existing program.
pub const BPF_F_ALLOW_OVERRIDE: u32 = 1;

/// BPF attach flag: allow multiple programs at same attach point.
pub const BPF_F_ALLOW_MULTI: u32 = 2;

// ── Enums ─────────────────────────────────────────────────────────────────

/// BPF cgroup attach types.
///
/// Maps to the kernel's `enum bpf_attach_type` for cgroup-related types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum BpfCgroupAttachType {
    /// BPF_CGROUP_INET_INGRESS
    InetIngress = 0,
    /// BPF_CGROUP_INET_EGRESS
    InetEgress = 1,
    /// BPF_CGROUP_INET_SOCK_CREATE
    InetSockCreate = 2,
    /// BPF_CGROUP_SOCK_OPS
    SockOps = 3,
    /// BPF_CGROUP_DEVICE
    Device = 6,
    /// BPF_CGROUP_INET4_BIND
    Inet4Bind = 8,
    /// BPF_CGROUP_INET6_BIND
    Inet6Bind = 9,
    /// BPF_CGROUP_INET4_CONNECT
    Inet4Connect = 10,
    /// BPF_CGROUP_INET6_CONNECT
    Inet6Connect = 11,
    /// BPF_CGROUP_INET4_POST_BIND
    Inet4PostBind = 12,
    /// BPF_CGROUP_INET6_POST_BIND
    Inet6PostBind = 13,
    /// BPF_CGROUP_UDP4_SENDMSG
    Udp4Sendmsg = 14,
    /// BPF_CGROUP_UDP6_SENDMSG
    Udp6Sendmsg = 15,
    /// BPF_CGROUP_SYSCTL
    Sysctl = 16,
    /// BPF_CGROUP_UDP4_RECVMSG
    Udp4Recvmsg = 17,
    /// BPF_CGROUP_UDP6_RECVMSG
    Udp6Recvmsg = 18,
    /// BPF_CGROUP_GETSOCKOPT
    Getsockopt = 19,
    /// BPF_CGROUP_SETSOCKOPT
    Setsockopt = 20,
}

impl BpfCgroupAttachType {
    /// All valid cgroup attach type discriminants, for iteration.
    const ALL_DISCRIMINANTS: &'static [i32] = &[
        0, 1, 2, 3, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    ];

    /// Convert a raw kernel attach type integer to an enum variant.
    /// Returns `None` for unrecognized values.
    pub fn from_discriminant_raw(val: i32) -> Option<Self> {
        match val {
            0 => Some(Self::InetIngress),
            1 => Some(Self::InetEgress),
            2 => Some(Self::InetSockCreate),
            3 => Some(Self::SockOps),
            6 => Some(Self::Device),
            8 => Some(Self::Inet4Bind),
            9 => Some(Self::Inet6Bind),
            10 => Some(Self::Inet4Connect),
            11 => Some(Self::Inet6Connect),
            12 => Some(Self::Inet4PostBind),
            13 => Some(Self::Inet6PostBind),
            14 => Some(Self::Udp4Sendmsg),
            15 => Some(Self::Udp6Sendmsg),
            16 => Some(Self::Sysctl),
            17 => Some(Self::Udp4Recvmsg),
            18 => Some(Self::Udp6Recvmsg),
            19 => Some(Self::Getsockopt),
            20 => Some(Self::Setsockopt),
            _ => None,
        }
    }
}

impl fmt::Display for BpfCgroupAttachType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InetIngress => "ingress",
            Self::InetEgress => "egress",
            Self::InetSockCreate => "sock_create",
            Self::SockOps => "sock_ops",
            Self::Device => "device",
            Self::Inet4Bind => "bind4",
            Self::Inet6Bind => "bind6",
            Self::Inet4Connect => "connect4",
            Self::Inet6Connect => "connect6",
            Self::Inet4PostBind => "post_bind4",
            Self::Inet6PostBind => "post_bind6",
            Self::Udp4Sendmsg => "sendmsg4",
            Self::Udp6Sendmsg => "sendmsg6",
            Self::Sysctl => "sysctl",
            Self::Udp4Recvmsg => "recvmsg4",
            Self::Udp6Recvmsg => "recvmsg6",
            Self::Getsockopt => "getsockopt",
            Self::Setsockopt => "setsockopt",
        };
        f.write_str(s)
    }
}

// ── BpfCgroupAttachType string conversion ─────────────────────────────────

/// Convert a cgroup attach type integer to its string name.
/// Returns `None` for unrecognized values.
pub fn bpf_cgroup_attach_type_to_string(val: i32) -> Option<&'static str> {
    BpfCgroupAttachType::from_discriminant_raw(val).map(|t| match t {
        BpfCgroupAttachType::InetIngress => "ingress",
        BpfCgroupAttachType::InetEgress => "egress",
        BpfCgroupAttachType::InetSockCreate => "sock_create",
        BpfCgroupAttachType::SockOps => "sock_ops",
        BpfCgroupAttachType::Device => "device",
        BpfCgroupAttachType::Inet4Bind => "bind4",
        BpfCgroupAttachType::Inet6Bind => "bind6",
        BpfCgroupAttachType::Inet4Connect => "connect4",
        BpfCgroupAttachType::Inet6Connect => "connect6",
        BpfCgroupAttachType::Inet4PostBind => "post_bind4",
        BpfCgroupAttachType::Inet6PostBind => "post_bind6",
        BpfCgroupAttachType::Udp4Sendmsg => "sendmsg4",
        BpfCgroupAttachType::Udp6Sendmsg => "sendmsg6",
        BpfCgroupAttachType::Sysctl => "sysctl",
        BpfCgroupAttachType::Udp4Recvmsg => "recvmsg4",
        BpfCgroupAttachType::Udp6Recvmsg => "recvmsg6",
        BpfCgroupAttachType::Getsockopt => "getsockopt",
        BpfCgroupAttachType::Setsockopt => "setsockopt",
    })
}

/// Parse a cgroup attach type from its string name.
/// Returns `None` for unrecognized strings.
pub fn bpf_cgroup_attach_type_from_string(s: &str) -> Option<BpfCgroupAttachType> {
    let t = match s {
        "ingress" => BpfCgroupAttachType::InetIngress,
        "egress" => BpfCgroupAttachType::InetEgress,
        "sock_create" => BpfCgroupAttachType::InetSockCreate,
        "sock_ops" => BpfCgroupAttachType::SockOps,
        "device" => BpfCgroupAttachType::Device,
        "bind4" => BpfCgroupAttachType::Inet4Bind,
        "bind6" => BpfCgroupAttachType::Inet6Bind,
        "connect4" => BpfCgroupAttachType::Inet4Connect,
        "connect6" => BpfCgroupAttachType::Inet6Connect,
        "post_bind4" => BpfCgroupAttachType::Inet4PostBind,
        "post_bind6" => BpfCgroupAttachType::Inet6PostBind,
        "sendmsg4" => BpfCgroupAttachType::Udp4Sendmsg,
        "sendmsg6" => BpfCgroupAttachType::Udp6Sendmsg,
        "sysctl" => BpfCgroupAttachType::Sysctl,
        "recvmsg4" => BpfCgroupAttachType::Udp4Recvmsg,
        "recvmsg6" => BpfCgroupAttachType::Udp6Recvmsg,
        "getsockopt" => BpfCgroupAttachType::Getsockopt,
        "setsockopt" => BpfCgroupAttachType::Setsockopt,
        _ => return None,
    };
    Some(t)
}

// ── BpfInstruction ────────────────────────────────────────────────────────

/// A single BPF instruction (simplified representation).
///
/// In the kernel, this is `struct bpf_insn` (16 bytes: opcode, regs, offset, imm).
/// We use a raw byte representation here for flexibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfInstruction {
    /// Raw 16-byte instruction data.
    pub data: [u8; 16],
}

impl BpfInstruction {
    /// Create a BPF instruction from raw bytes.
    /// Panics if `data.len() != 16`.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != 16 {
            return None;
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(data);
        Some(Self { data: buf })
    }

    /// Create a trivial `BPF_MOV64_IMM(BPF_REG_0, imm)` + `BPF_EXIT_INSN()`
    /// pair that returns the given immediate value. This is the simplest
    /// valid BPF program (2 instructions).
    pub fn trivial_return(imm: u64) -> [Self; 2] {
        // BPF_MOV64_IMM(BPF_REG_0, imm): opcode=0xb7, dst_reg=0, src_reg=0, off=0, imm=imm
        let mut mov = [0u8; 16];
        mov[0] = 0xb7; // BPF_ALU64 | BPF_MOV | BPF_K
        mov[..16].copy_from_slice(&[
            0xb7,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            imm as u8,
            (imm >> 8) as u8,
            (imm >> 16) as u8,
            (imm >> 24) as u8,
            (imm >> 32) as u8,
            (imm >> 40) as u8,
            (imm >> 48) as u8,
            (imm >> 56) as u8,
        ]);

        // BPF_EXIT_INSN(): opcode=0x95
        let mut exit = [0u8; 16];
        exit[0] = 0x95;

        [Self { data: mov }, Self { data: exit }]
    }
}

// ── BpfProgram ────────────────────────────────────────────────────────────

/// A BPF program encapsulating code, kernel state, and cgroup attachment.
///
/// This mirrors the C `BPFProgram` struct, encapsulating three concepts:
/// - The loaded BPF program (if loaded into the kernel)
/// - The BPF code/instructions (if known)
/// - The cgroup attachment (if attached)
///
/// Uses RAII: on drop, the program is detached from its cgroup and the
/// kernel fd is closed.
pub struct BpfProgram {
    /// Kernel file descriptor for the loaded program, or -1 if not loaded.
    kernel_fd: i32,
    /// BPF program type (e.g., `BPF_PROG_TYPE_CGROUP_SKB`).
    prog_type: u32,
    /// Optional program name (max `BPF_OBJ_NAME_LEN - 1` chars).
    prog_name: Option<CString>,
    /// BPF instructions (code).
    instructions: Vec<BpfInstruction>,
    /// Cgroup path the program is attached to, if attached.
    attached_path: Option<CString>,
    /// Attach type used when attaching to cgroup.
    attached_type: Option<BpfCgroupAttachType>,
    /// Attach flags used (0, BPF_F_ALLOW_OVERRIDE, or BPF_F_ALLOW_MULTI).
    attached_flags: u32,
}

impl fmt::Debug for BpfProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BpfProgram")
            .field("kernel_fd", &self.kernel_fd)
            .field("prog_type", &self.prog_type)
            .field("prog_name", &self.prog_name)
            .field("n_instructions", &self.instructions.len())
            .field("attached_path", &self.attached_path)
            .field("attached_type", &self.attached_type)
            .field("attached_flags", &self.attached_flags)
            .finish()
    }
}

impl Drop for BpfProgram {
    fn drop(&mut self) {
        // Detach from cgroup if attached (ignore errors on drop).
        let _ = self.cgroup_detach_inner();
        // Close kernel fd if valid.
        if self.kernel_fd >= 0 {
            unsafe {
                libc::close(self.kernel_fd);
            }
        }
    }
}

impl BpfProgram {
    /// Create a new BPF program of the given type with an optional name.
    ///
    /// # Errors
    ///
    /// Returns `Err(Errno::ENAMETOOLONG)` if `prog_name` is >= `BPF_OBJ_NAME_LEN` bytes.
    /// Returns `Err(Errno::EINVAL)` if `prog_name` contains a NUL byte.
    pub fn new(prog_type: u32, prog_name: Option<&str>) -> Result<Self, Errno> {
        let name = match prog_name {
            Some(name) => {
                if name.len() >= BPF_OBJ_NAME_LEN {
                    return Err(Errno::ENAMETOOLONG);
                }
                Some(CString::new(name).map_err(|_| Errno::EINVAL)?)
            }
            None => None,
        };

        Ok(Self {
            kernel_fd: -9, // -EBADF sentinel
            prog_type,
            prog_name: name,
            instructions: Vec::new(),
            attached_path: None,
            attached_type: None,
            attached_flags: 0,
        })
    }

    /// Add BPF instructions to the program.
    ///
    /// # Errors
    ///
    /// Returns `Err(Errno::EBUSY)` if the program has already been loaded
    /// into the kernel (instructions cannot be modified after loading).
    pub fn add_instructions(&mut self, instructions: &[BpfInstruction]) -> Result<(), Errno> {
        if self.kernel_fd >= 0 {
            return Err(Errno::EBUSY);
        }
        self.instructions.extend_from_slice(instructions);
        Ok(())
    }

    /// Number of instructions currently in the program.
    pub fn n_instructions(&self) -> usize {
        self.instructions.len()
    }

    /// Whether the program has been loaded into the kernel.
    pub fn is_loaded(&self) -> bool {
        self.kernel_fd >= 0
    }

    /// Whether the program is currently attached to a cgroup.
    pub fn is_attached(&self) -> bool {
        self.attached_path.is_some()
    }

    /// The kernel file descriptor, or -1 if not loaded.
    pub fn kernel_fd(&self) -> i32 {
        self.kernel_fd
    }

    /// The program type.
    pub fn prog_type(&self) -> u32 {
        self.prog_type
    }

    /// The program name, if set.
    pub fn prog_name(&self) -> Option<&CStr> {
        self.prog_name.as_deref()
    }

    /// The attached cgroup path, if attached.
    pub fn attached_path(&self) -> Option<&CStr> {
        self.attached_path.as_deref()
    }

    /// The attach type, if attached.
    pub fn attached_type(&self) -> Option<BpfCgroupAttachType> {
        self.attached_type
    }

    /// The attach flags used.
    pub fn attached_flags(&self) -> u32 {
        self.attached_flags
    }

    /// Load the BPF program into the kernel.
    ///
    /// This is idempotent: if already loaded, it returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns an error if the BPF_PROG_LOAD syscall fails.
    pub fn load_kernel(&mut self) -> Result<(), Errno> {
        if self.kernel_fd >= 0 {
            return Ok(());
        }

        // BPF_PROG_LOAD syscall
        let fd = bpf_prog_load(self);
        match fd {
            Ok(f) => {
                self.kernel_fd = f;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Attach the BPF program to a cgroup.
    ///
    /// If already attached to the same path/type/flags, this is a no-op
    /// (unless `BPF_F_ALLOW_OVERRIDE` is set, in which case it re-attaches).
    ///
    /// # Errors
    ///
    /// - `Err(Errno::EINVAL)` if flags are invalid or path is empty
    /// - `Err(Errno::EBUSY)` if attached to a different cgroup
    /// - Other errors from the BPF_PROG_ATTACH syscall
    pub fn cgroup_attach(
        &mut self,
        attach_type: BpfCgroupAttachType,
        path: &str,
        flags: u32,
    ) -> Result<(), Errno> {
        // Validate flags
        if !matches!(flags, 0 | BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI) {
            return Err(Errno::EINVAL);
        }

        if path.is_empty() {
            return Err(Errno::EINVAL);
        }

        // Check if already attached
        if let Some(ref cur_path) = self.attached_path {
            let cur_path_str = cur_path.to_str().unwrap_or("");
            if cur_path_str == path
                && self.attached_type == Some(attach_type)
                && self.attached_flags == flags
            {
                // Already attached to same target. Re-attach only for ALLOW_OVERRIDE.
                if flags != BPF_F_ALLOW_OVERRIDE {
                    return Ok(());
                }
            } else {
                return Err(Errno::EBUSY);
            }
        }

        // Ensure kernel object exists
        self.load_kernel()?;

        let path_cstr = CString::new(path).map_err(|_| Errno::EINVAL)?;

        // Open cgroup directory fd
        let cgroup_fd = unsafe {
            libc::open(
                path_cstr.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if cgroup_fd < 0 {
            return Err(Errno::from_errno(crate::ffi::get_errno()));
        }

        // BPF_PROG_ATTACH syscall
        let result = bpf_prog_attach(self.kernel_fd, attach_type as i32, cgroup_fd, flags);

        // Close the cgroup fd regardless
        unsafe {
            libc::close(cgroup_fd);
        }

        result?;

        // Track attachment
        self.attached_path = Some(path_cstr);
        self.attached_type = Some(attach_type);
        self.attached_flags = flags;

        Ok(())
    }

    /// Detach the BPF program from its cgroup.
    ///
    /// # Errors
    ///
    /// - `Err(Errno::ENOLINK)` if the program is not currently attached
    /// - Other errors from the BPF_PROG_DETACH syscall
    pub fn cgroup_detach(&mut self) -> Result<(), Errno> {
        self.cgroup_detach_inner()
    }

    /// Inner detach implementation (used by both `cgroup_detach` and `Drop`).
    fn cgroup_detach_inner(&mut self) -> Result<(), Errno> {
        let path = match self.attached_path.take() {
            Some(p) => p,
            None => return Err(Errno::ENOLINK),
        };

        let attach_type = self
            .attached_type
            .unwrap_or(BpfCgroupAttachType::InetEgress);
        let path_str = path.to_str().unwrap_or("");

        let cgroup_fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };

        if cgroup_fd < 0 {
            let err = crate::ffi::get_errno();
            if err != libc::ENOENT {
                return Err(Errno::from_errno(err));
            }
            // Cgroup no longer exists — implicitly detached, don't complain.
            self.attached_type = None;
            return Ok(());
        }

        let result = bpf_prog_detach(self.kernel_fd, attach_type as i32, cgroup_fd);

        unsafe {
            libc::close(cgroup_fd);
        }

        if result.is_ok() {
            self.attached_type = None;
        } else {
            // Restore attached_path on failure
            self.attached_path = Some(path);
        }

        result
    }
}

// ── Errno extension ───────────────────────────────────────────────────────

trait ErrnoExt {
    fn from_errno(errno: i32) -> Self;
}

impl ErrnoExt for Errno {
    /// Convert a raw errno value to our `Errno` enum.
    /// Falls back to `EINVAL` for unrecognized values.
    fn from_errno(errno: i32) -> Self {
        match errno {
            1 => Errno::EPERM,
            2 => Errno::ENOENT,
            9 => Errno::EBADF,
            11 => Errno::EAGAIN,
            12 => Errno::ENOMEM,
            14 => Errno::EFAULT,
            16 => Errno::EBUSY,
            22 => Errno::EINVAL,
            36 => Errno::ENAMETOOLONG,
            38 => Errno::ENOSYS,
            95 => Errno::EOPNOTSUPP,
            150 => Errno::ENOLINK,
            _ => Errno::EINVAL,
        }
    }
}

// ── Private unsafe syscall wrappers ───────────────────────────────────────

/// BPF syscall number (x86_64).
const SYS_BPF: i32 = 321;

/// Issue the `bpf()` syscall with the given command and attribute.
///
/// # Safety
/// This is a raw syscall wrapper. The caller must ensure `attr` is valid
/// for the given `cmd`.
unsafe fn bpf_syscall(cmd: i32, attr: *const libc::c_void, size: usize) -> std::os::raw::c_long {
    // SAFETY: the caller guarantees attr describes the command-specific bpf_attr range.
    unsafe { libc::syscall(SYS_BPF, cmd, attr, size) as std::os::raw::c_long }
}

/// Wrapper for BPF_PROG_LOAD syscall.
///
/// # Safety
/// Calls the bpf() syscall.
fn bpf_prog_load(prog: &BpfProgram) -> Result<i32, Errno> {
    // bpf_attr layout for PROG_LOAD (simplified for our needs).
    // The attr union is large; we use a zeroed buffer and write fields at
    // their known offsets.
    let mut attr = [0u8; 176]; // sufficient for bpf_attr prog_load

    // prog_type at offset 0 (u32)
    attr[0..4].copy_from_slice(&prog.prog_type.to_le_bytes());

    // insn_cnt at offset 8 (u32)
    let insn_cnt = prog.instructions.len() as u32;
    attr[8..12].copy_from_slice(&insn_cnt.to_le_bytes());

    // insns at offset 16 (u64, pointer to instructions)
    let insns_ptr = prog.instructions.as_ptr() as u64;
    attr[16..24].copy_from_slice(&insns_ptr.to_le_bytes());

    // license at offset 24 (u64, pointer to "GPL")
    // Use a static string so the pointer remains valid.
    let license = b"GPL\0";
    let license_ptr = license.as_ptr() as u64;
    attr[24..32].copy_from_slice(&license_ptr.to_le_bytes());

    // prog_name at offset 56 (char[16])
    if let Some(ref name) = prog.prog_name {
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        attr[56..56 + copy_len].copy_from_slice(&name_bytes[..copy_len]);
        // NUL terminator
        attr[56 + copy_len] = 0;
    }

    // log_level = 0 (no logging)
    // Already zeroed.

    // SAFETY: attr is a live command-specific byte buffer for the duration of the syscall.
    let fd = unsafe { bpf_syscall(5, attr.as_ptr() as *const _, attr.len()) }; // BPF_PROG_LOAD = 5
    if fd < 0 {
        return Err(Errno::from_errno(crate::ffi::get_errno()));
    }
    Ok(fd as i32)
}

/// Wrapper for BPF_PROG_ATTACH syscall.
///
/// # Safety
/// Calls the bpf() syscall.
fn bpf_prog_attach(
    prog_fd: i32,
    attach_type: i32,
    target_fd: i32,
    flags: u32,
) -> Result<(), Errno> {
    let mut attr = [0u8; 48]; // sufficient for bpf_attr attach

    // attach_type at offset 0 (u32)
    attr[0..4].copy_from_slice(&(attach_type as u32).to_le_bytes());
    // target_fd at offset 4 (u32)
    attr[4..8].copy_from_slice(&(target_fd as u32).to_le_bytes());
    // attach_bpf_fd at offset 8 (u32)
    attr[8..12].copy_from_slice(&(prog_fd as u32).to_le_bytes());
    // attach_flags at offset 12 (u32)
    attr[12..16].copy_from_slice(&flags.to_le_bytes());

    // SAFETY: attr is a live command-specific byte buffer for the duration of the syscall.
    let ret = unsafe { bpf_syscall(8, attr.as_ptr() as *const _, attr.len()) }; // BPF_PROG_ATTACH = 8
    if ret < 0 {
        return Err(Errno::from_errno(crate::ffi::get_errno()));
    }
    Ok(())
}

/// Wrapper for BPF_PROG_DETACH syscall.
///
/// # Safety
/// Calls the bpf() syscall.
fn bpf_prog_detach(prog_fd: i32, attach_type: i32, target_fd: i32) -> Result<(), Errno> {
    let mut attr = [0u8; 48];

    attr[0..4].copy_from_slice(&(attach_type as u32).to_le_bytes());
    attr[4..8].copy_from_slice(&(target_fd as u32).to_le_bytes());
    attr[8..12].copy_from_slice(&(prog_fd as u32).to_le_bytes());

    // SAFETY: attr is a live command-specific byte buffer for the duration of the syscall.
    let ret = unsafe { bpf_syscall(9, attr.as_ptr() as *const _, attr.len()) }; // BPF_PROG_DETACH = 9
    if ret < 0 {
        return Err(Errno::from_errno(crate::ffi::get_errno()));
    }
    Ok(())
}

// ── BpfProgram support check ──────────────────────────────────────────────

/// Check if BPF is supported on this system.
///
/// This performs a lightweight check: it verifies the bpf() syscall is
/// functional by issuing a BPF_PROG_DETACH with invalid fds. If the kernel
/// returns EBADF, the syscall works. Other errors indicate BPF is broken.
///
/// Returns `true` if BPF is supported, `false` otherwise.
pub fn bpf_program_supported() -> bool {
    // Quick check: /sys/fs/bpf mount point existence
    if !Path::new("/sys/fs/bpf").exists() {
        return false;
    }

    // Verify the bpf() syscall actually works by issuing a deliberately
    // invalid BPF_PROG_DETACH. If CONFIG_CGROUP_BPF is on, the kernel
    // validates fd parameters and returns EBADF. If it's off, it fails
    // early with EINVAL.
    // SAFETY: attr remains live through the syscall and has the layout expected
    // for the deliberately invalid BPF_PROG_DETACH probe.
    unsafe {
        let mut attr = [0u8; 48];
        // attach_type = BPF_CGROUP_INET_EGRESS (1)
        attr[0..4].copy_from_slice(&1u32.to_le_bytes());
        // target_fd = -EBADF
        attr[4..8].copy_from_slice(&(-9i32 as u32).to_le_bytes());
        // attach_bpf_fd = -EBADF
        attr[8..12].copy_from_slice(&(-9i32 as u32).to_le_bytes());

        let ret = bpf_syscall(9, attr.as_ptr() as *const _, attr.len()); // BPF_PROG_DETACH
        if ret < 0 {
            let err = crate::ffi::get_errno();
            return err == libc::EBADF;
        }
        // Kernel accepted invalid params — something is wrong
        false
    }
}

/// Validate BPF attach flags.
///
/// Valid flags are: 0, `BPF_F_ALLOW_OVERRIDE`, `BPF_F_ALLOW_MULTI`.
pub fn bpf_attach_flags_valid(flags: u32) -> bool {
    matches!(flags, 0 | BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI)
}

/// Validate a BPF program name.
///
/// Returns `Ok(())` if the name is valid (non-empty, no NUL bytes,
/// shorter than `BPF_OBJ_NAME_LEN`), or an appropriate error.
pub fn bpf_validate_prog_name(name: &str) -> Result<(), Errno> {
    if name.is_empty() {
        return Err(Errno::EINVAL);
    }
    if name.len() >= BPF_OBJ_NAME_LEN {
        return Err(Errno::ENAMETOOLONG);
    }
    if name.contains('\0') {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_cgroup_attach_type_to_string_all() {
        let expected = [
            (0, "ingress"),
            (1, "egress"),
            (2, "sock_create"),
            (3, "sock_ops"),
            (6, "device"),
            (8, "bind4"),
            (9, "bind6"),
            (10, "connect4"),
            (11, "connect6"),
            (12, "post_bind4"),
            (13, "post_bind6"),
            (14, "sendmsg4"),
            (15, "sendmsg6"),
            (16, "sysctl"),
            (17, "recvmsg4"),
            (18, "recvmsg6"),
            (19, "getsockopt"),
            (20, "setsockopt"),
        ];
        for (val, name) in &expected {
            assert_eq!(bpf_cgroup_attach_type_to_string(*val), Some(*name));
        }
    }

    #[test]
    fn test_bpf_cgroup_attach_type_to_string_invalid() {
        assert_eq!(bpf_cgroup_attach_type_to_string(4), None);
        assert_eq!(bpf_cgroup_attach_type_to_string(5), None);
        assert_eq!(bpf_cgroup_attach_type_to_string(7), None);
        assert_eq!(bpf_cgroup_attach_type_to_string(99), None);
        assert_eq!(bpf_cgroup_attach_type_to_string(-1), None);
    }

    #[test]
    fn test_bpf_cgroup_attach_type_from_string_all() {
        let expected = [
            ("ingress", 0),
            ("egress", 1),
            ("sock_create", 2),
            ("sock_ops", 3),
            ("device", 6),
            ("bind4", 8),
            ("bind6", 9),
            ("connect4", 10),
            ("connect6", 11),
            ("post_bind4", 12),
            ("post_bind6", 13),
            ("sendmsg4", 14),
            ("sendmsg6", 15),
            ("sysctl", 16),
            ("recvmsg4", 17),
            ("recvmsg6", 18),
            ("getsockopt", 19),
            ("setsockopt", 20),
        ];
        for (name, val) in &expected {
            let t = bpf_cgroup_attach_type_from_string(name).unwrap();
            assert_eq!(t as i32, *val);
        }
    }

    #[test]
    fn test_bpf_cgroup_attach_type_from_string_invalid() {
        assert!(bpf_cgroup_attach_type_from_string("invalid").is_none());
        assert!(bpf_cgroup_attach_type_from_string("").is_none());
        assert!(bpf_cgroup_attach_type_from_string("Ingress").is_none());
        assert!(bpf_cgroup_attach_type_from_string("INGRESS").is_none());
    }

    #[test]
    fn test_bpf_cgroup_attach_type_roundtrip() {
        for &val in BpfCgroupAttachType::ALL_DISCRIMINANTS {
            let s = bpf_cgroup_attach_type_to_string(val).unwrap();
            let parsed = bpf_cgroup_attach_type_from_string(s).unwrap();
            assert_eq!(parsed as i32, val);
        }
    }

    #[test]
    fn test_bpf_cgroup_attach_type_display() {
        assert_eq!(format!("{}", BpfCgroupAttachType::InetIngress), "ingress");
        assert_eq!(format!("{}", BpfCgroupAttachType::Device), "device");
        assert_eq!(format!("{}", BpfCgroupAttachType::Sysctl), "sysctl");
        assert_eq!(format!("{}", BpfCgroupAttachType::Setsockopt), "setsockopt");
    }

    #[test]
    fn test_bpf_program_new_with_name() {
        let prog = BpfProgram::new(1, Some("test_prog")).unwrap();
        assert_eq!(prog.prog_type(), 1);
        assert_eq!(prog.prog_name().unwrap().to_str().unwrap(), "test_prog");
        assert!(!prog.is_loaded());
        assert!(!prog.is_attached());
        assert_eq!(prog.n_instructions(), 0);
    }

    #[test]
    fn test_bpf_program_new_without_name() {
        let prog = BpfProgram::new(1, None).unwrap();
        assert!(prog.prog_name().is_none());
    }

    #[test]
    fn test_bpf_program_new_name_too_long() {
        let long_name = "a".repeat(BPF_OBJ_NAME_LEN);
        let result = BpfProgram::new(1, Some(&long_name));
        assert_eq!(result.unwrap_err(), Errno::ENAMETOOLONG);
    }

    #[test]
    fn test_bpf_program_new_name_with_nul() {
        let result = BpfProgram::new(1, Some("foo\0bar"));
        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn test_bpf_program_add_instructions() {
        let mut prog = BpfProgram::new(1, Some("test")).unwrap();
        let trivial = BpfInstruction::trivial_return(1);
        prog.add_instructions(&trivial).unwrap();
        assert_eq!(prog.n_instructions(), 2);
    }

    #[test]
    fn test_bpf_instruction_from_bytes() {
        let data = [0u8; 16];
        let insn = BpfInstruction::from_bytes(&data).unwrap();
        assert_eq!(insn.data, [0u8; 16]);

        // Wrong length
        assert!(BpfInstruction::from_bytes(&[0; 15]).is_none());
        assert!(BpfInstruction::from_bytes(&[0; 17]).is_none());
    }

    #[test]
    fn test_bpf_instruction_trivial_return() {
        let insns = BpfInstruction::trivial_return(1);
        assert_eq!(insns.len(), 2);
        // First instruction: BPF_MOV64_IMM(BPF_REG_0, 1)
        assert_eq!(insns[0].data[0], 0xb7);
        // Second instruction: BPF_EXIT_INSN
        assert_eq!(insns[1].data[0], 0x95);
    }

    #[test]
    fn test_bpf_attach_flags_valid() {
        assert!(bpf_attach_flags_valid(0));
        assert!(bpf_attach_flags_valid(BPF_F_ALLOW_OVERRIDE));
        assert!(bpf_attach_flags_valid(BPF_F_ALLOW_MULTI));
        assert!(!bpf_attach_flags_valid(3));
        assert!(!bpf_attach_flags_valid(4));
        assert!(!bpf_attach_flags_valid(255));
    }

    #[test]
    fn test_bpf_validate_prog_name() {
        assert!(bpf_validate_prog_name("test").is_ok());
        assert!(bpf_validate_prog_name("a").is_ok());
        assert_eq!(bpf_validate_prog_name(""), Err(Errno::EINVAL));
        let long = "a".repeat(BPF_OBJ_NAME_LEN);
        assert_eq!(bpf_validate_prog_name(&long), Err(Errno::ENAMETOOLONG));
        assert_eq!(bpf_validate_prog_name("foo\0bar"), Err(Errno::EINVAL));
    }

    #[test]
    fn test_bpf_program_debug_format() {
        let prog = BpfProgram::new(1, Some("my_prog")).unwrap();
        let debug_str = format!("{:?}", prog);
        assert!(debug_str.contains("BpfProgram"));
        assert!(debug_str.contains("my_prog"));
        assert!(debug_str.contains("kernel_fd"));
    }

    #[test]
    fn test_bpf_cgroup_attach_ebusy_wrong_path() {
        let mut prog = BpfProgram::new(1, Some("test")).unwrap();
        let trivial = BpfInstruction::trivial_return(1);
        prog.add_instructions(&trivial).unwrap();

        // We can't actually attach without kernel BPF support, but we can
        // test the EBUSY logic by manually setting attached_path.
        prog.attached_path = Some(CString::new("/sys/fs/cgroup/test").unwrap());
        prog.attached_type = Some(BpfCgroupAttachType::InetEgress);
        prog.attached_flags = 0;

        // Attaching to a different path should fail with EBUSY
        let result = prog.cgroup_attach(BpfCgroupAttachType::InetIngress, "/other/path", 0);
        assert_eq!(result.unwrap_err(), Errno::EBUSY);
    }

    #[test]
    fn test_bpf_cgroup_attach_ebusy_wrong_type() {
        let mut prog = BpfProgram::new(1, Some("test")).unwrap();
        prog.attached_path = Some(CString::new("/sys/fs/cgroup/test").unwrap());
        prog.attached_type = Some(BpfCgroupAttachType::InetEgress);
        prog.attached_flags = 0;

        // Same path but different type should fail with EBUSY
        let result = prog.cgroup_attach(BpfCgroupAttachType::InetIngress, "/sys/fs/cgroup/test", 0);
        assert_eq!(result.unwrap_err(), Errno::EBUSY);
    }

    #[test]
    fn test_bpf_cgroup_detach_not_attached() {
        let mut prog = BpfProgram::new(1, None).unwrap();
        let result = prog.cgroup_detach();
        assert_eq!(result.unwrap_err(), Errno::ENOLINK);
    }

    #[test]
    fn test_bpf_cgroup_attach_invalid_flags() {
        let mut prog = BpfProgram::new(1, None).unwrap();
        let result = prog.cgroup_attach(BpfCgroupAttachType::InetIngress, "/path", 3);
        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn test_bpf_cgroup_attach_empty_path() {
        let mut prog = BpfProgram::new(1, None).unwrap();
        let result = prog.cgroup_attach(BpfCgroupAttachType::InetIngress, "", 0);
        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn test_errno_from_errno() {
        assert_eq!(Errno::from_errno(9), Errno::EBADF);
        assert_eq!(Errno::from_errno(22), Errno::EINVAL);
        assert_eq!(Errno::from_errno(12), Errno::ENOMEM);
        assert_eq!(Errno::from_errno(16), Errno::EBUSY);
        assert_eq!(Errno::from_errno(36), Errno::ENAMETOOLONG);
        assert_eq!(Errno::from_errno(95), Errno::EOPNOTSUPP);
        assert_eq!(Errno::from_errno(150), Errno::ENOLINK);
        // Unknown errno falls back to EINVAL
        assert_eq!(Errno::from_errno(999), Errno::EINVAL);
    }
}
