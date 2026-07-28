// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/bpf-devices.c
//
// Device-controller BPF program construction in safe, testable Rust.

use crate::ffi::Errno;

pub const PASS_JUMP_OFF: i16 = 4096;

pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_ALU64: u8 = 0x07;
pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;
pub const BPF_AND: u8 = 0x50;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_JA: u8 = 0x00;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_W: u8 = 0x00;
pub const BPF_MEM: u8 = 0x60;
pub const BPF_EXIT: u8 = 0x90;

pub const BPF_REG_0: u8 = 0;
pub const BPF_REG_1: u8 = 1;
pub const BPF_REG_2: u8 = 2;
pub const BPF_REG_3: u8 = 3;
pub const BPF_REG_4: u8 = 4;
pub const BPF_REG_5: u8 = 5;

pub const BPF_DEVCG_DEV_CHAR: u32 = 1;
pub const BPF_DEVCG_DEV_BLOCK: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CGroupDevicePolicy {
    Auto,
    Closed,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevicePermissions(u32);

impl DevicePermissions {
    pub const MKNOD: Self = Self(1 << 0);
    pub const READ: Self = Self(1 << 1);
    pub const WRITE: Self = Self(1 << 2);
    pub const ALL: Self = Self(Self::MKNOD.0 | Self::READ.0 | Self::WRITE.0);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn is_valid(self) -> bool {
        self.0 > 0 && self.0 < (1 << 3)
    }
}

impl std::ops::BitOr for DevicePermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    pub code: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (src << 4) | (dst & 0x0f),
            off,
            imm,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfProgram {
    pub name: String,
    pub instructions: Vec<BpfInsn>,
    pub attached_cgroup: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BpfDevicesError {
    InvalidPermissions,
    InvalidDeviceType,
}

impl BpfDevicesError {
    pub const fn errno(&self) -> i32 {
        match self {
            Self::InvalidPermissions | Self::InvalidDeviceType => Errno::EINVAL.to_neg_errno(),
        }
    }
}

pub mod ctx_offset {
    pub const ACCESS_TYPE: i16 = 0;
    pub const MAJOR: i16 = 4;
    pub const MINOR: i16 = 8;
}

const fn mov32_reg(dst: u8, src: u8) -> BpfInsn {
    BpfInsn::new(BPF_ALU | BPF_MOV | BPF_X, dst, src, 0, 0)
}

const fn mov64_imm(dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
}

const fn alu32_imm(op: u8, dst: u8, imm: i32) -> BpfInsn {
    BpfInsn::new(BPF_ALU | op | BPF_K, dst, 0, 0, imm)
}

const fn jmp_reg(op: u8, dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | op | BPF_X, dst, src, off, 0)
}

const fn jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | op | BPF_K, dst, 0, off, imm)
}

const fn jmp_a(off: i16) -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, off, 0)
}

const fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> BpfInsn {
    BpfInsn::new(BPF_LDX | size | BPF_MEM, dst, src, off, 0)
}

const fn exit_insn() -> BpfInsn {
    BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
}

impl BpfProgram {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            instructions: Vec::new(),
            attached_cgroup: None,
        }
    }

    pub fn add_instructions(&mut self, instructions: &[BpfInsn]) {
        self.instructions.extend_from_slice(instructions);
    }

    pub fn fixup_pass_jumps(&mut self) {
        let total = self.instructions.len() as i16;
        for (index, instruction) in self.instructions.iter_mut().enumerate() {
            if instruction.code == (BPF_JMP | BPF_JA) && instruction.off == PASS_JUMP_OFF {
                instruction.off = total - index as i16 - 1;
            }
        }
    }
}

fn encode_device_type(device_type: char) -> Result<u32, BpfDevicesError> {
    match device_type {
        'c' => Ok(BPF_DEVCG_DEV_CHAR),
        'b' => Ok(BPF_DEVCG_DEV_BLOCK),
        _ => Err(BpfDevicesError::InvalidDeviceType),
    }
}

fn validate_permissions(permissions: DevicePermissions) -> Result<(), BpfDevicesError> {
    if permissions.is_valid() {
        Ok(())
    } else {
        Err(BpfDevicesError::InvalidPermissions)
    }
}

pub fn allow_list_device(
    program: &mut BpfProgram,
    device_type: char,
    major: u32,
    minor: u32,
    permissions: DevicePermissions,
) -> Result<bool, BpfDevicesError> {
    validate_permissions(permissions)?;
    let bpf_type = encode_device_type(device_type)?;

    let full = [
        mov32_reg(BPF_REG_1, BPF_REG_3),
        alu32_imm(BPF_AND, BPF_REG_1, permissions.bits() as i32),
        jmp_reg(BPF_JNE, BPF_REG_1, BPF_REG_3, 4),
        jmp_imm(BPF_JNE, BPF_REG_2, bpf_type as i32, 3),
        jmp_imm(BPF_JNE, BPF_REG_4, major as i32, 2),
        jmp_imm(BPF_JNE, BPF_REG_5, minor as i32, 1),
        jmp_a(PASS_JUMP_OFF),
    ];

    if permissions == DevicePermissions::ALL {
        program.add_instructions(&full[3..]);
    } else {
        program.add_instructions(&full);
    }
    Ok(true)
}

pub fn allow_list_major(
    program: &mut BpfProgram,
    device_type: char,
    major: u32,
    permissions: DevicePermissions,
) -> Result<bool, BpfDevicesError> {
    validate_permissions(permissions)?;
    let bpf_type = encode_device_type(device_type)?;

    let full = [
        mov32_reg(BPF_REG_1, BPF_REG_3),
        alu32_imm(BPF_AND, BPF_REG_1, permissions.bits() as i32),
        jmp_reg(BPF_JNE, BPF_REG_1, BPF_REG_3, 3),
        jmp_imm(BPF_JNE, BPF_REG_2, bpf_type as i32, 2),
        jmp_imm(BPF_JNE, BPF_REG_4, major as i32, 1),
        jmp_a(PASS_JUMP_OFF),
    ];

    if permissions == DevicePermissions::ALL {
        program.add_instructions(&full[3..]);
    } else {
        program.add_instructions(&full);
    }
    Ok(true)
}

pub fn allow_list_class(
    program: &mut BpfProgram,
    device_type: char,
    permissions: DevicePermissions,
) -> Result<bool, BpfDevicesError> {
    validate_permissions(permissions)?;
    let bpf_type = encode_device_type(device_type)?;

    let full = [
        mov32_reg(BPF_REG_1, BPF_REG_3),
        alu32_imm(BPF_AND, BPF_REG_1, permissions.bits() as i32),
        jmp_reg(BPF_JNE, BPF_REG_1, BPF_REG_3, 2),
        jmp_imm(BPF_JNE, BPF_REG_2, bpf_type as i32, 1),
        jmp_a(PASS_JUMP_OFF),
    ];

    if permissions == DevicePermissions::ALL {
        program.add_instructions(&full[3..]);
    } else {
        program.add_instructions(&full);
    }
    Ok(true)
}

pub fn bpf_devices_cgroup_init(
    policy: CGroupDevicePolicy,
    allow_list: bool,
) -> Result<Option<BpfProgram>, BpfDevicesError> {
    if policy == CGroupDevicePolicy::Auto && !allow_list {
        return Ok(None);
    }

    let mut program = BpfProgram::new("sd_devices");
    if matches!(policy, CGroupDevicePolicy::Closed) || allow_list {
        program.add_instructions(&[
            ldx_mem(BPF_W, BPF_REG_2, BPF_REG_1, ctx_offset::ACCESS_TYPE),
            alu32_imm(BPF_AND, BPF_REG_2, 0xffff),
            ldx_mem(BPF_W, BPF_REG_3, BPF_REG_1, ctx_offset::ACCESS_TYPE),
            alu32_imm(BPF_RSH, BPF_REG_3, 16),
            ldx_mem(BPF_W, BPF_REG_4, BPF_REG_1, ctx_offset::MAJOR),
            ldx_mem(BPF_W, BPF_REG_5, BPF_REG_1, ctx_offset::MINOR),
        ]);
    }

    Ok(Some(program))
}

pub fn bpf_devices_apply_policy(
    program: Option<&mut BpfProgram>,
    policy: CGroupDevicePolicy,
    allow_list: bool,
    cgroup_path: &str,
) -> Result<(), BpfDevicesError> {
    let Some(program) = program else {
        return Ok(());
    };

    let deny_everything = policy == CGroupDevicePolicy::Strict && !allow_list;

    if !deny_everything {
        program.add_instructions(&[mov64_imm(BPF_REG_0, 0), jmp_a(1)]);
        program.fixup_pass_jumps();
    }

    program.add_instructions(&[
        mov64_imm(BPF_REG_0, if deny_everything { 0 } else { 1 }),
        exit_insn(),
    ]);
    program.attached_cgroup = Some(cgroup_path.to_string());
    Ok(())
}

pub fn bpf_devices_allow_list_static(program: &mut BpfProgram) -> Result<(), BpfDevicesError> {
    for (device_type, major, minor, permissions) in [
        ('c', 1, 3, DevicePermissions::ALL),
        ('c', 1, 5, DevicePermissions::ALL),
        ('c', 1, 7, DevicePermissions::ALL),
        ('c', 1, 8, DevicePermissions::ALL),
        ('c', 5, 0, DevicePermissions::ALL),
        ('c', 5, 2, DevicePermissions::ALL),
        ('c', 5, 1, DevicePermissions::ALL),
        ('c', 0, 0, DevicePermissions::ALL),
        ('b', 0, 0, DevicePermissions::ALL),
    ] {
        let _ = allow_list_device(program, device_type, major, minor, permissions)?;
    }
    let _ = allow_list_major(
        program,
        'c',
        136,
        DevicePermissions::READ | DevicePermissions::WRITE,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_rule_emits_full_sequence() {
        let mut program = BpfProgram::new("test");
        allow_list_device(&mut program, 'c', 1, 3, DevicePermissions::READ).unwrap();
        assert_eq!(program.instructions.len(), 7);
        assert_eq!(program.instructions.last().unwrap().off, PASS_JUMP_OFF);
    }

    #[test]
    fn all_permissions_skip_access_mask_prelude() {
        let mut program = BpfProgram::new("test");
        allow_list_device(&mut program, 'c', 1, 3, DevicePermissions::ALL).unwrap();
        assert_eq!(program.instructions.len(), 4);
    }

    #[test]
    fn major_rule_uses_expected_length() {
        let mut program = BpfProgram::new("test");
        allow_list_major(&mut program, 'b', 8, DevicePermissions::WRITE).unwrap();
        assert_eq!(program.instructions.len(), 6);
    }

    #[test]
    fn class_rule_uses_expected_length() {
        let mut program = BpfProgram::new("test");
        allow_list_class(
            &mut program,
            'c',
            DevicePermissions::READ | DevicePermissions::WRITE,
        )
        .unwrap();
        assert_eq!(program.instructions.len(), 5);
    }

    #[test]
    fn invalid_permissions_fail() {
        let err =
            allow_list_class(&mut BpfProgram::new("test"), 'c', DevicePermissions(0)).unwrap_err();
        assert_eq!(err, BpfDevicesError::InvalidPermissions);
        assert_eq!(err.errno(), Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn invalid_device_type_fails() {
        let err = allow_list_class(&mut BpfProgram::new("test"), 'x', DevicePermissions::READ)
            .unwrap_err();
        assert_eq!(err, BpfDevicesError::InvalidDeviceType);
    }

    #[test]
    fn init_auto_without_allow_list_returns_none() {
        assert_eq!(
            bpf_devices_cgroup_init(CGroupDevicePolicy::Auto, false).unwrap(),
            None
        );
    }

    #[test]
    fn apply_policy_fixes_pass_jumps_and_attaches() {
        let mut program = bpf_devices_cgroup_init(CGroupDevicePolicy::Closed, true)
            .unwrap()
            .unwrap();
        allow_list_device(&mut program, 'c', 1, 3, DevicePermissions::READ).unwrap();
        bpf_devices_apply_policy(
            Some(&mut program),
            CGroupDevicePolicy::Closed,
            true,
            "/sys/fs/cgroup/test",
        )
        .unwrap();
        assert_eq!(
            program.attached_cgroup.as_deref(),
            Some("/sys/fs/cgroup/test")
        );
        assert!(
            program
                .instructions
                .iter()
                .all(|insn| insn.off != PASS_JUMP_OFF)
        );
    }

    #[test]
    fn static_allow_list_adds_multiple_rules() {
        let mut program = BpfProgram::new("test");
        bpf_devices_allow_list_static(&mut program).unwrap();
        assert!(program.instructions.len() > 10);
    }
}
