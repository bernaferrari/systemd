#!/usr/bin/env python3
"""Statically review PID1's cgroup capability and process-identity boundary.

The gate pins descriptor-confined hierarchy operations, clone3 placement,
pidfd ownership/signaling, and their reviewed C-compatible fallback classes.
It rejects regressions to pathname-based cgroup access or unclassified numeric
process identity.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "src/core/rust/runtime_manager/linux_cgroup.rs"
CGROUP_RUNTIME = ROOT / "src/core/rust/runtime_manager/cgroup_runtime.rs"
RUNTIME_MANAGER = ROOT / "src/core/rust/runtime_manager.rs"
PID1_MANAGER_RUNTIME = ROOT / "src/core/rust/pid1_manager_runtime.rs"
SERVICE_RUNTIME = ROOT / "src/core/rust/runtime_manager/service_runtime.rs"
SERVICE_SHUTDOWN = ROOT / "src/core/rust/runtime_manager/service_shutdown.rs"
HANDOFF = ROOT / "src/core/rust/runtime_manager/handoff.rs"
SPAWN = ROOT / "src/platform/rust/spawn.rs"
LINUX_SPAWN = ROOT / "src/platform/rust/spawn/linux.rs"
LINUX_CGROUP = ROOT / "src/platform/rust/spawn/linux_cgroup.rs"
LINUX_PROCESS = ROOT / "src/platform/rust/spawn/linux_process.rs"
CHASE_C = ROOT / "src/basic/chase.c"
INOTIFY_C = ROOT / "src/basic/inotify-util.c"
PROCESS_C = ROOT / "src/basic/process-util.c"
PIDREF_C = ROOT / "src/basic/pidref.c"
CGROUP_UTIL_C = ROOT / "src/basic/cgroup-util.c"
CORE_CGROUP_C = ROOT / "src/core/cgroup.c"
EXECUTE_C = ROOT / "src/core/execute.c"
LOAD_FRAGMENT_C = ROOT / "src/core/load-fragment.c"
CGROUP_SETUP_C = ROOT / "src/shared/cgroup-setup.c"
REACHABILITY_BASELINE = ROOT / "tools/rust-port/core-runtime-reachability-baseline.json"
UNSAFE_GATE = ROOT / "tools/rust-port/unsafe-safety-gate.py"


def fail(message: str) -> int:
    print(f"core cgroup capability gate failed: {message}", file=sys.stderr)
    return 1


def unsafe_metrics(path: Path) -> tuple[int, int]:
    spec = importlib.util.spec_from_file_location("unsafe_safety_gate", UNSAFE_GATE)
    if not spec or not spec.loader:
        raise ValueError(f"cannot load {UNSAFE_GATE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    metrics = module.collect_metrics(ROOT, 3)
    adapter = metrics.get(path.relative_to(ROOT).as_posix())
    if adapter is None:
        return 0, 0
    return adapter.unsafe_sites, adapter.missing_safety


def main() -> int:
    adapter = ADAPTER.read_text()
    cgroup = CGROUP_RUNTIME.read_text()
    manager = RUNTIME_MANAGER.read_text()
    pid1_manager = PID1_MANAGER_RUNTIME.read_text()
    service = SERVICE_RUNTIME.read_text()
    shutdown = SERVICE_SHUTDOWN.read_text()
    handoff = HANDOFF.read_text()
    spawn = SPAWN.read_text()
    linux_spawn = LINUX_SPAWN.read_text()
    linux_cgroup = LINUX_CGROUP.read_text()
    linux_process = LINUX_PROCESS.read_text()
    chase_c = CHASE_C.read_text()
    inotify_c = INOTIFY_C.read_text()
    process_c = PROCESS_C.read_text()
    pidref_c = PIDREF_C.read_text()
    cgroup_util_c = CGROUP_UTIL_C.read_text()
    core_cgroup_c = CORE_CGROUP_C.read_text()
    execute_c = EXECUTE_C.read_text()
    load_fragment_c = LOAD_FRAGMENT_C.read_text()
    cgroup_setup_c = CGROUP_SETUP_C.read_text()
    reachability = REACHABILITY_BASELINE.read_text()

    required_adapter = (
        "nix::fcntl::OpenHow::new()",
        "nix::fcntl::ResolveFlag::RESOLVE_BENEATH",
        "nix_openat2(parent, component, how)",
        "OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW",
        "Err(nix::errno::Errno::ENOSYS)",
        "Err(nix::errno::Errno::EPERM | nix::errno::Errno::EAGAIN)",
        "OPENAT2_AVAILABLE.store(false",
        "bytes == b\".\"",
        "bytes == b\"..\"",
        "bytes.contains(&b'/')",
        "nix_mkdirat(parent, component",
        "nix_openat(parent, component",
        "nix_unlinkat(parent, component",
        'format!("/proc/self/fd/{}"',
        "pub(super) struct CgroupRoot",
        "pub(super) struct CgroupDirectory",
        "pub(super) fn write_control_file",
        "pub(super) fn read_processes_recursive",
        "MAX_RECURSIVE_DEPTH",
        "libc::O_WRONLY | libc::O_NONBLOCK",
        "pub(super) fn handoff_fd(&self)",
    )
    missing = [token for token in required_adapter if token not in adapter]
    if missing:
        return fail(f"Linux adapter lost reviewed confinement tokens: {missing}")

    required_runtime = (
        "mod linux_cgroup;",
        "use linux_cgroup::CgroupRoot;",
        "cgroup_root: CgroupRoot,",
        "cgroup_root: CgroupRoot::new(cgroup_root),",
    )
    missing = [token for token in required_runtime if token not in manager]
    if missing:
        return fail(f"RuntimeManager no longer owns the preopened root capability: {missing}")

    required_cgroup = (
        r"self\s*\.\s*cgroup_root\s*\.\s*ensure_directory\s*\(",
        r"directory\s*\.\s*write_control_file\s*\(",
        r'directory\s*\.\s*open_file\s*\(\s*"cgroup\.procs"\s*,\s*libc::O_WRONLY\s*\)',
        r'directory\s*\.\s*open_file\s*\(\s*"cgroup\.events"\s*,\s*libc::O_RDONLY\s*\)',
        r"cgroup\s*\.\s*events_fd\s*\(\s*\)",
        r"linux_cgroup::inotify_add_watch_fd\s*\(",
        r"self\s*\.\s*cgroup_root\s*\.\s*remove_directory\s*\(\s*&components\s*\)",
    )
    missing = [pattern for pattern in required_cgroup if not re.search(pattern, cgroup)]
    if missing:
        return fail(f"cgroup runtime lost descriptor-owned operations: {missing}")
    for token in (
        "WatchEvents",
        "PublishRealization",
        "self.prepare_unit_cgroup_watch(unit_name, &realized)?;",
        "All fallible realization work",
        "cgroup.events capability is already owned by",
        "inotify_remove_watch(inotify.as_fd(), wd)",
        "pub(super) struct BorrowedCgroupSpawnFds",
        'path.join(".control")',
        "delegate_subgroup",
        "recursive_target_access",
        ".read_processes_recursive(Self::MAX_PROCESSES_BYTES)",
        "self.control.as_ref().ok_or_else",
        "normalized_cpu_max",
        'CpuSet::parse_full(&words.join(" "), true)',
        "normalized_io_limits",
        "canonical_block_device",
        "is_char_device()",
        "physical_memory_bytes",
        "prepare_delegated_cgroup_start",
        "Never enable them in",
    ):
        if token not in cgroup:
            return fail(f"cgroup realization lost reviewed ownership/normalization invariant: {token}")
    if "let final_depth = components.len().saturating_sub(1);" not in cgroup:
        return fail("unit leaf may be turned into an internal cgroup before initial placement")

    if (
        "WRITE_STRING_FILE_DISABLE_BUFFER|WRITE_STRING_FILE_OPEN_NONBLOCKING"
        not in cgroup_util_c
    ):
        return fail("C authority no longer requires nonblocking cgroup control writes")

    forbidden_cgroup = (
        "fs::create_dir_all(",
        "fs::write(",
        "fs::remove_dir(",
        "fs::remove_dir_all(",
        "OpenOptions::new()",
        "libc::inotify_add_watch(",
        "libc::openat(",
        "libc::open(",
        "libc::read(",
    )
    present = [token for token in forbidden_cgroup if token in cgroup]
    if present:
        return fail(f"cgroup runtime bypasses its audited Linux adapter: {present}")
    if re.search(r"\bunsafe\s*\{", cgroup):
        return fail("unsafe execution escaped the audited Linux adapter")

    required_spawn = (
        "#[repr(C)]\n#[derive(Default)]\nstruct CloneArgs",
        "libc::SYS_clone3",
        "CLONE_PIDFD_FLAG",
        "CLONE_INTO_CGROUP_FLAG",
        "CLONE3_FALLBACK",
        "CLONE_INTO_CGROUP_FALLBACK",
        "FALLBACK_UNSUPPORTED",
        "FALLBACK_PRIVILEGE",
        "raw_clone3(Some(cgroup_directory.as_raw_fd()))",
        "libc::SYS_pidfd_open",
        "libc::SYS_pidfd_send_signal",
        "matches!(errno, libc::EMFILE | libc::ENFILE | libc::ENOMEM)",
        "failed without a permitted numeric fallback",
        "clone_fallback_class(errno) != Some(FALLBACK_UNSUPPORTED)",
    )
    missing = [token for token in required_spawn if token not in linux_process]
    if missing:
        return fail(f"Linux spawn adapter lost clone3/pidfd invariants: {missing}")
    required_launch = (
        "cgroup_directory_fd",
        "child_write_cgroup_procs",
        "parent_place_child_best_effort",
        "identity: Some(identity)",
        "delegate_root",
        "target_directory",
        "target_procs",
        "delegate_cgroup_access",
    )
    missing = [token for token in required_launch if token not in linux_spawn]
    if missing:
        return fail(f"Linux launch path lost cgroup/identity integration: {missing}")
    required_delegation = (
        "chown_access_recursive",
        "Permissions::from_mode",
        "libc::AT_EMPTY_PATH",
        'c"cgroup.subtree_control"',
    )
    missing = [token for token in required_delegation if token not in linux_cgroup]
    if missing:
        return fail(f"Linux delegated-access adapter lost reviewed invariants: {missing}")
    if "raw_clone3(Some(cgroup_procs" in linux_process:
        return fail("CLONE_INTO_CGROUP targets cgroup.procs instead of the directory capability")

    required_identity = (
        "pub struct ProcessIdentity",
        "pidfd: Option<OwnedFd>",
        "struct TrackedProcess",
        "identity: ProcessIdentity",
        "child: Option<ChildProcess>",
        "processes: HashMap<u32, TrackedProcess>",
        "pub fn insert_with_identity",
        "pub fn adopt_identity",
        "pub fn remove_adopted",
        "Some(process) => process.identity.signal(signal)",
        "refusing to signal PID {pid} without a tracked process identity",
    )
    missing = [token for token in required_identity if token not in spawn]
    if missing:
        return fail(f"process tracker lost owned pidfd identity: {missing}")
    if "pub fn insert(&mut self, child: ChildProcess)" in spawn:
        return fail("process tracker permits identityless child insertion")
    if "children: HashMap<u32, ChildProcess>" in spawn or "identities: HashMap<u32, ProcessIdentity>" in spawn:
        return fail("process tracker split one PID lifecycle across parallel maps")
    if re.search(r"None\s*=>\s*kill_process\s*\(", spawn):
        return fail("process tracker silently falls back to an unproven numeric PID")

    required_service = (
        "unit_cgroup_spawn_fds(name, cursor.phase)",
        "self.prepare_delegated_cgroup_start(unit_name);",
        "cgroup.delegate_root",
        "cgroup.target_directory",
        "cgroup.target_processes",
        "cgroup.delegated",
        "cgroup.recursive_target_access",
        "launch.take_process_identity()",
        "process_tracker.insert_with_identity",
        "ProcessTracker::acquire_identity(pid)",
        "if !identity.has_pidfd()",
        "process_tracker.adopt_identity(identity)",
    )
    missing = [token for token in required_service if token not in service]
    if missing:
        return fail(f"service runtime lost pidfd-backed launch/adoption: {missing}")
    if "self.process_tracker.signal(*pid, signal)" not in manager:
        return fail("manager tracked-PID signaling no longer prefers pidfds")
    if "self.process_tracker.signal(*pid, signal)" not in shutdown:
        return fail("service shutdown no longer prefers pidfds for tracked targets")
    for token in (
        "DescriptorRole::CgroupRoot",
        ".handoff_fd()",
        "bundle.insert(role, descriptor)",
        "cgroup_watch_by_unit.len() == unit_cgroups.len()",
    ):
        if token not in handoff:
            return fail(f"handoff inventory lost the manager root capability: {token}")
    if not re.search(r"runtime\s*\.\s*cgroup_root\s*\.\s*handoff_fd", handoff):
        return fail("handoff inventory no longer borrows the manager root capability")
    if "runtime.prepare_live_handoff" in pid1_manager:
        # Production may duplicate capabilities only as a rollback-safe
        # precommit transaction. It must still round-trip the bounded image,
        # reject incomplete coverage, and return the original owner unchanged.
        required_handoff_boundary = (
            "prepared.rollback()",
            "HandoffPrecommitImage::decode",
            "validate_for_adoption(HandoffPurpose::ReloadInProcess",
            "ReloadPreparationResult::FailedBeforePointOfNoReturn",
            "ReloadPreparationError::VersionedAdopterUnavailable",
        )
    else:
        required_handoff_boundary = (
            "runtime.assess_live_handoff(HandoffPurpose::ReloadInProcess)",
            "ReloadPreparationResult::FailedBeforePointOfNoReturn",
            "ReloadPreparationError::VersionedAdopterUnavailable",
        )
    missing = [token for token in required_handoff_boundary if token not in pid1_manager]
    if missing:
        return fail(f"reload/handoff fail-early boundary lost: {missing}")
    if "mod handoff;" not in manager:
        return fail("RuntimeManager no longer compiles the shared handoff inventory module")

    c_authority = (
        "if (errno == ENOSYS)\n                        can_openat2 = false;" in chase_c
        and "IN_SET(errno, ENOSYS, EPERM, EAGAIN)" in chase_c
        and "FORMAT_PROC_FD_PATH(what)" in inotify_c
        and "POSIX_SPAWN_SETCGROUP" in process_c
        and "have_clone_into_cgroup = false;" in process_c
        and "if (!ERRNO_IS_RESOURCE(errno))" in pidref_c
        and "fd = -EBADF;" in pidref_c
        and 'subgroup = ".control";' in execute_c
        and "subgroup = c->delegate_subgroup;" in execute_c
        and "cgroup_cpu_adjust_period(period, quota, USEC_PER_MSEC, USEC_PER_SEC)" in core_cgroup_c
        and "cpu_set_to_range_string(cpus)" in core_cgroup_c
        and "DEVNUM_FORMAT_STR \" rbps=%s wbps=%s riops=%s wiops=%s" in core_cgroup_c
        and "parse_size(rvalue, 1024, &bytes)" in load_fragment_c
        and "parse_size(p, 1000, &num)" in load_fragment_c
        and "unit_cgroup_disable_all_controllers(Unit *u)" in core_cgroup_c
        and "cg_enable(u->manager->cgroup_supported, /* mask= */ 0" in core_cgroup_c
        and '{ "cgroup.subtree_control", true  }' in cgroup_setup_c
    )
    if not c_authority:
        return fail("current C openat2/clone3/pidfd fallback authority changed")

    # Keep hierarchy traversal and process creation in separate audited ABI
    # adapters; broad cgroup runtime code must own neither raw interface.
    if "clone3" in adapter or "pidfd" in adapter:
        return fail("hierarchy adapter improperly claims clone3 or pidfd ownership")
    if "src/core/rust/runtime_manager/linux_cgroup.rs" not in reachability:
        return fail("reachable Linux capability adapter is absent from the reviewed inventory")

    hierarchy_unsafe, hierarchy_missing = unsafe_metrics(ADAPTER)
    delegation_unsafe, delegation_missing = unsafe_metrics(LINUX_CGROUP)
    process_unsafe, process_missing = unsafe_metrics(LINUX_PROCESS)
    if (
        hierarchy_unsafe == 0
        or delegation_unsafe == 0
        or process_unsafe == 0
        or hierarchy_missing != 0
        or delegation_missing != 0
        or process_missing != 0
    ):
        return fail(
            "audited adapter unsafe inventory is invalid: "
            f"hierarchy-sites={hierarchy_unsafe} hierarchy-missing={hierarchy_missing} "
            f"delegation-sites={delegation_unsafe} delegation-missing={delegation_missing} "
            f"process-sites={process_unsafe} process-missing={process_missing}"
        )

    print(
        "core cgroup capability gate OK: "
        f"unsafe-adapter-sites={hierarchy_unsafe + delegation_unsafe + process_unsafe} missing-safety=0 "
        "root=preopened traversal=openat2/openat-component "
        "controls=descriptor-nonblocking inotify=descriptor "
        "delegation=root/payload/control-descriptors normalization=cpu/cpuset/io/memory "
        "clone3=directory-capability pidfd=owned resource-fallback=direct-child-only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
