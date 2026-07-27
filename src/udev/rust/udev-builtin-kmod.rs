// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/udev/udev-builtin-kmod.c
//
// Kernel module command planning.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmodRequest {
    pub module: String,
    pub builtin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmodError { EmptyModule }
pub type Result<T> = std::result::Result<T, KmodError>;

pub fn plan_kmod_load(module: &str, builtin_modules: &[&str]) -> Result<KmodRequest> {
    let module = module.trim();
    if module.is_empty() { return Err(KmodError::EmptyModule); }
    Ok(KmodRequest { module: module.into(), builtin: builtin_modules.iter().any(|candidate| *candidate == module) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn marks_builtin_module() { let request = plan_kmod_load("loop", &["loop", "vfat"]).unwrap(); assert!(request.builtin); }
    #[test] fn rejects_empty_module() { assert_eq!(plan_kmod_load("", &[]), Err(KmodError::EmptyModule)); }
}
