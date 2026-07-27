// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homed-operation.c, src/home/homed-operation.h

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    Acquire,
    Release,
    Activate,
    Deactivate,
    Remove,
    LockAll,
    DeactivateAll,
    PipeEof,
    DeactivateForce,
    Immediate,
}

impl OperationType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acquire => "acquire",
            Self::Release => "release",
            Self::Activate => "activate",
            Self::Deactivate => "deactivate",
            Self::Remove => "remove",
            Self::LockAll => "lock-all",
            Self::DeactivateAll => "deactivate-all",
            Self::PipeEof => "pipe-eof",
            Self::DeactivateForce => "deactivate-force",
            Self::Immediate => "immediate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OperationError {
    pub name: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    pub n_ref: usize,
    pub kind: OperationType,
    pub send_fd: i32,
    pub result: Option<bool>,
    pub ret: i32,
    pub error: OperationError,
}

impl Operation {
    pub fn new(kind: OperationType) -> Self {
        Self {
            n_ref: 1,
            kind,
            send_fd: -1,
            result: None,
            ret: 0,
            error: OperationError::default(),
        }
    }

    pub fn ref_op(&mut self) {
        self.n_ref += 1;
    }

    pub fn unref_op(&mut self) -> bool {
        if self.n_ref == 0 {
            return false;
        }
        self.n_ref -= 1;
        self.n_ref == 0
    }
}

pub fn operation_result(operation: &mut Operation, ret: i32, error: Option<OperationError>) {
    if ret >= 0 {
        operation.result = Some(true);
        operation.ret = ret;
        operation.error = OperationError::default();
    } else {
        operation.result = Some(false);
        operation.ret = ret;
        operation.error = error.unwrap_or_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_operation_has_initial_state() {
        let operation = Operation::new(OperationType::Acquire);
        assert_eq!(operation.n_ref, 1);
        assert_eq!(operation.send_fd, -1);
        assert_eq!(operation.result, None);
    }

    #[test]
    fn type_strings_match_expected_names() {
        assert_eq!(OperationType::Acquire.as_str(), "acquire");
        assert_eq!(OperationType::Immediate.as_str(), "immediate");
    }

    #[test]
    fn ref_increments_reference_count() {
        let mut operation = Operation::new(OperationType::Release);
        operation.ref_op();
        assert_eq!(operation.n_ref, 2);
    }

    #[test]
    fn unref_returns_false_until_last_reference() {
        let mut operation = Operation::new(OperationType::LockAll);
        operation.ref_op();
        assert!(!operation.unref_op());
        assert_eq!(operation.n_ref, 1);
    }

    #[test]
    fn unref_returns_true_for_last_reference() {
        let mut operation = Operation::new(OperationType::LockAll);
        assert!(operation.unref_op());
        assert_eq!(operation.n_ref, 0);
    }

    #[test]
    fn success_result_clears_error() {
        let mut operation = Operation::new(OperationType::PipeEof);
        operation.error = OperationError {
            name: Some("x".into()),
            message: Some("y".into()),
        };
        operation_result(&mut operation, 0, None);
        assert_eq!(operation.result, Some(true));
        assert_eq!(operation.error, OperationError::default());
    }

    #[test]
    fn failure_result_stores_error() {
        let mut operation = Operation::new(OperationType::DeactivateAll);
        operation_result(
            &mut operation,
            -5,
            Some(OperationError {
                name: Some("org.test".into()),
                message: Some("boom".into()),
            }),
        );
        assert_eq!(operation.result, Some(false));
        assert_eq!(operation.ret, -5);
    }

    #[test]
    fn failure_without_error_uses_default_error() {
        let mut operation = Operation::new(OperationType::DeactivateForce);
        operation_result(&mut operation, -1, None);
        assert_eq!(operation.error, OperationError::default());
    }

    #[test]
    fn extra_unref_after_zero_is_ignored() {
        let mut operation = Operation::new(OperationType::Immediate);
        assert!(operation.unref_op());
        assert!(!operation.unref_op());
        assert_eq!(operation.n_ref, 0);
    }
}
