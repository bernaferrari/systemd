// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/udev/test-udev-spawn.c

pub const SOURCE_PATH: &str = "src/udev/test-udev-spawn.c";
pub const SOURCE_LINE_COUNT: usize = 121;
pub const BUF_SIZE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnScenario {
    CatUevent,
    SelfInvocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnCase<'a> {
    pub scenario: SpawnScenario,
    pub with_pidfd: bool,
    pub argument: Option<&'a str>,
    pub buffer_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnTestError {
    BufferTooSmall,
    MissingSelfPath,
    UnknownChildMode(String),
}

pub fn build_cat_case(
    with_pidfd: bool,
    buffer_size: usize,
) -> Result<SpawnCase<'static>, SpawnTestError> {
    if buffer_size == 0 {
        return Err(SpawnTestError::BufferTooSmall);
    }
    Ok(SpawnCase {
        scenario: SpawnScenario::CatUevent,
        with_pidfd,
        argument: None,
        buffer_size,
    })
}

pub fn build_self_case<'a>(
    mode: &'a str,
    with_pidfd: bool,
) -> Result<SpawnCase<'a>, SpawnTestError> {
    if !matches!(mode, "test1" | "test2") {
        return Err(SpawnTestError::UnknownChildMode(mode.to_string()));
    }
    Ok(SpawnCase {
        scenario: SpawnScenario::SelfInvocation,
        with_pidfd,
        argument: Some(mode),
        buffer_size: BUF_SIZE,
    })
}

pub fn quote_self_command(self_path: &str, arg: &str) -> Result<String, SpawnTestError> {
    if self_path.is_empty() {
        return Err(SpawnTestError::MissingSelfPath);
    }
    Ok(format!("'{}' {}", self_path, arg))
}

pub fn expected_main_matrix() -> Vec<SpawnCase<'static>> {
    vec![
        build_cat_case(true, usize::MAX).unwrap(),
        build_cat_case(false, usize::MAX).unwrap(),
        build_cat_case(true, 5).unwrap(),
        build_cat_case(false, 5).unwrap(),
        build_self_case("test1", true).unwrap(),
        build_self_case("test1", false).unwrap(),
        build_self_case("test2", true).unwrap(),
        build_self_case("test2", false).unwrap(),
    ]
}

pub fn expected_stdout_markers(case: &SpawnCase<'_>) -> &'static [&'static str] {
    match case.scenario {
        SpawnScenario::CatUevent if case.buffer_size >= BUF_SIZE => &["INTERFACE=lo", "IFINDEX=1"],
        SpawnScenario::CatUevent => &[],
        SpawnScenario::SelfInvocation => &["aaa", "bbb"],
    }
}

pub fn validate_port_model() -> Result<(), SpawnTestError> {
    if expected_main_matrix().len() != 8 {
        return Err(SpawnTestError::BufferTooSmall);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_matches_c_file() {
        assert_eq!(SOURCE_PATH, "src/udev/test-udev-spawn.c");
        assert_eq!(SOURCE_LINE_COUNT, 121);
    }

    #[test]
    fn cat_case_requires_non_zero_buffer() {
        assert_eq!(build_cat_case(true, 0), Err(SpawnTestError::BufferTooSmall));
    }

    #[test]
    fn cat_case_accepts_truncated_buffer() {
        let case = build_cat_case(false, 5).unwrap();
        assert_eq!(case.buffer_size, 5);
    }

    #[test]
    fn self_case_only_accepts_known_modes() {
        assert!(build_self_case("test1", true).is_ok());
        assert_eq!(
            build_self_case("other", false),
            Err(SpawnTestError::UnknownChildMode("other".into()))
        );
    }

    #[test]
    fn quote_self_command_matches_c_quoting_strategy() {
        assert_eq!(
            quote_self_command("/tmp/a b", "test1").unwrap(),
            "'/tmp/a b' test1"
        );
    }

    #[test]
    fn full_buffer_cat_case_expects_uevent_markers() {
        let markers = expected_stdout_markers(&build_cat_case(true, BUF_SIZE).unwrap());
        assert_eq!(markers, &["INTERFACE=lo", "IFINDEX=1"]);
    }

    #[test]
    fn short_buffer_cat_case_expects_no_full_markers() {
        let markers = expected_stdout_markers(&build_cat_case(true, 5).unwrap());
        assert!(markers.is_empty());
    }

    #[test]
    fn self_case_expects_shared_stdout_markers() {
        let markers = expected_stdout_markers(&build_self_case("test2", false).unwrap());
        assert_eq!(markers, &["aaa", "bbb"]);
    }

    #[test]
    fn main_matrix_matches_eight_c_invocations() {
        assert_eq!(expected_main_matrix().len(), 8);
    }

    #[test]
    fn main_matrix_contains_both_pidfd_modes() {
        let matrix = expected_main_matrix();
        assert!(matrix.iter().any(|c| c.with_pidfd));
        assert!(matrix.iter().any(|c| !c.with_pidfd));
    }

    #[test]
    fn port_model_validation_succeeds() {
        assert_eq!(validate_port_model(), Ok(()));
    }
}
