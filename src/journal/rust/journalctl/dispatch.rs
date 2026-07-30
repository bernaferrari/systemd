// SPDX-License-Identifier: LGPL-2.1-or-later

use super::arguments::parse_argv;
use super::filter::{
    FilterBackendOp, FilterPlan, build_filter_plan, map_filter_apply_error, map_filter_build_error,
    replay_filter_plan,
};
use super::model::{JournalctlAction, JournalctlArgs, ParseArgvError, ParseArgvResult};
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchTarget {
    ActionShow,
    Id128PrintNew,
    ActionSetupKeys,
    ActionListCatalog,
    ActionDumpCatalog,
    ActionUpdateCatalog,
    ActionPrintHeader,
    ActionVerify,
    ActionDiskUsage,
    ActionListBoots,
    ActionListFields,
    ActionListFieldNames,
    ActionListInvocations,
    ActionListNamespaces,
    ActionFlushToVar,
    ActionRelinquishVar,
    ActionSync,
    ActionRotate,
    ActionVacuum,
    ActionRotateAndVacuum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchPlan {
    pub target: DispatchTarget,
    pub matches: Vec<String>,
    pub filter_plan: Option<FilterPlan>,
    pub filter_backend_ops: Option<Vec<FilterBackendOp>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// PORT-RATIONALE: this public C-shaped control-flow result is matched directly
// by callers and tests; boxing DispatchPlan would create allocation and API
// churn without reducing the plan's owned data.
#[allow(clippy::large_enum_variant)]
pub enum RunOutcome {
    HelpRequested,
    VersionRequested,
    OutputModeHelpRequested,
    FacilitiesHelpRequested,
    Noop,
    Dispatch(DispatchPlan),
}

pub(crate) fn should_relinquish_var_from_dev_ids(
    root_dev: Option<u64>,
    log_dev: Option<u64>,
) -> bool {
    match (root_dev, log_dev) {
        (Some(root), Some(log)) => root != log,
        _ => true,
    }
}

#[cfg(any(test, target_os = "linux"))]
fn normalize_mount_lookup_path(path: &str) -> &str {
    if path == "/" {
        "/"
    } else {
        path.trim_end_matches('/')
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn mount_id_from_mountinfo(mountinfo: &str, path: &str) -> Option<u64> {
    let wanted = normalize_mount_lookup_path(path);

    for line in mountinfo.lines() {
        let mut fields = line.split_whitespace();
        let Some(mount_id_raw) = fields.next() else {
            continue;
        };
        let Some(_parent_id) = fields.next() else {
            continue;
        };
        let Some(_major_minor) = fields.next() else {
            continue;
        };
        let Some(_root) = fields.next() else {
            continue;
        };
        let Some(mount_point) = fields.next() else {
            continue;
        };
        let Some(mount_id) = mount_id_raw.parse::<u64>().ok() else {
            continue;
        };

        if mount_point == wanted {
            return Some(mount_id);
        }
    }

    None
}

fn path_mount_id(path: &str) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        mount_id_from_mountinfo(&mountinfo, path)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

fn should_relinquish_var_smart() -> bool {
    let root_mount_id = path_mount_id("/");
    let log_mount_id = path_mount_id("/var/log/journal/");
    if let (Some(root), Some(log)) = (root_mount_id, log_mount_id) {
        return root != log;
    }

    let root_dev = std::fs::metadata("/").ok().map(|m| m.dev());
    let log_dev = std::fs::metadata("/var/log/journal/").ok().map(|m| m.dev());
    should_relinquish_var_from_dev_ids(root_dev, log_dev)
}

// Mirrors switch(arg_action) in src/journal/journalctl.c:run().
pub fn plan_dispatch(parsed: &JournalctlArgs) -> DispatchPlan {
    let target = match parsed.action {
        JournalctlAction::Show => DispatchTarget::ActionShow,
        JournalctlAction::NewId128 => DispatchTarget::Id128PrintNew,
        JournalctlAction::SetupKeys => DispatchTarget::ActionSetupKeys,
        JournalctlAction::ListCatalog => DispatchTarget::ActionListCatalog,
        JournalctlAction::DumpCatalog => DispatchTarget::ActionDumpCatalog,
        JournalctlAction::UpdateCatalog => DispatchTarget::ActionUpdateCatalog,
        JournalctlAction::PrintHeader => DispatchTarget::ActionPrintHeader,
        JournalctlAction::Verify => DispatchTarget::ActionVerify,
        JournalctlAction::DiskUsage => DispatchTarget::ActionDiskUsage,
        JournalctlAction::ListBoots => DispatchTarget::ActionListBoots,
        JournalctlAction::ListFields => DispatchTarget::ActionListFields,
        JournalctlAction::ListFieldNames => DispatchTarget::ActionListFieldNames,
        JournalctlAction::ListInvocations => DispatchTarget::ActionListInvocations,
        JournalctlAction::ListNamespaces => DispatchTarget::ActionListNamespaces,
        JournalctlAction::Flush => DispatchTarget::ActionFlushToVar,
        JournalctlAction::RelinquishVar => DispatchTarget::ActionRelinquishVar,
        JournalctlAction::Sync => DispatchTarget::ActionSync,
        JournalctlAction::Rotate => DispatchTarget::ActionRotate,
        JournalctlAction::Vacuum => DispatchTarget::ActionVacuum,
        JournalctlAction::RotateAndVacuum => DispatchTarget::ActionRotateAndVacuum,
    };

    let matches = if matches!(
        parsed.action,
        JournalctlAction::Show | JournalctlAction::ListCatalog | JournalctlAction::DumpCatalog
    ) {
        parsed.positional_matches.clone()
    } else {
        Vec::new()
    };

    DispatchPlan {
        target,
        matches,
        filter_plan: None,
        filter_backend_ops: None,
    }
}

// Mirrors parse_argv() + run() dispatch flow in src/journal/journalctl.c.
pub fn run(argv: &[&str]) -> Result<RunOutcome, ParseArgvError> {
    match parse_argv(argv)? {
        ParseArgvResult::HelpRequested => Ok(RunOutcome::HelpRequested),
        ParseArgvResult::VersionRequested => Ok(RunOutcome::VersionRequested),
        ParseArgvResult::OutputModeHelpRequested => Ok(RunOutcome::OutputModeHelpRequested),
        ParseArgvResult::FacilitiesHelpRequested => Ok(RunOutcome::FacilitiesHelpRequested),
        ParseArgvResult::Parsed(parsed) => {
            if parsed.action == JournalctlAction::RelinquishVar
                && parsed.smart_relinquish_var
                && !should_relinquish_var_smart()
            {
                return Ok(RunOutcome::Noop);
            }

            let mut plan = plan_dispatch(&parsed);
            if parsed.action == JournalctlAction::Show {
                let filter_plan = build_filter_plan(&parsed).map_err(map_filter_build_error)?;
                let filter_backend_ops =
                    replay_filter_plan(&filter_plan).map_err(map_filter_apply_error)?;
                plan.filter_plan = Some(filter_plan);
                plan.filter_backend_ops = Some(filter_backend_ops);
            }
            Ok(RunOutcome::Dispatch(plan))
        }
    }
}
