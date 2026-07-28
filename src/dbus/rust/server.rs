// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use zbus::interface;
use zbus::zvariant::OwnedObjectPath;

use crate::constants::DBUS_PATH;
use crate::proxy::{JobStatusWire, UnitStatus, UnitStatusWire};

fn encode_unit_name(name: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    if name.is_empty() {
        return "_".to_string();
    }

    let mut encoded = String::with_capacity(name.len().saturating_mul(3));
    for (index, byte) in name.bytes().enumerate() {
        if byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit()) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('_');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn object_path(path: &str) -> zbus::fdo::Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(path).map_err(|error| {
        zbus::fdo::Error::Failed(format!(
            "invalid object path in runtime state {path:?}: {error}"
        ))
    })
}

fn wire_error(error: zbus::zvariant::Error) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(format!("invalid D-Bus value in runtime state: {error}"))
}

#[derive(Debug, Clone)]
struct UnitRecord {
    name: String,
    description: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    unit_path: String,
    enabled: bool,
    job_id: u32,
    job_type: String,
    job_path: String,
}

impl UnitRecord {
    fn from_status(status: UnitStatus) -> Self {
        Self {
            name: status.name,
            description: status.description,
            load_state: status.load_state,
            active_state: status.active_state,
            sub_state: status.sub_state,
            unit_path: status.path,
            enabled: false,
            job_id: status.job_id,
            job_type: status.job_type,
            job_path: status.job_path,
        }
    }

    fn to_status(&self) -> UnitStatus {
        UnitStatus {
            name: self.name.clone(),
            description: self.description.clone(),
            load_state: self.load_state.clone(),
            active_state: self.active_state.clone(),
            sub_state: self.sub_state.clone(),
            followed: String::new(),
            path: self.unit_path.clone(),
            job_id: self.job_id,
            job_type: self.job_type.clone(),
            job_path: self.job_path.clone(),
        }
    }

    fn file_state(&self) -> String {
        if self.enabled {
            "enabled".to_string()
        } else {
            match self.load_state.as_str() {
                "static" | "masked" | "indirect" | "generated" | "transient" => {
                    self.load_state.clone()
                }
                _ => "disabled".to_string(),
            }
        }
    }
}

#[derive(Debug, Clone)]
struct JobRecord {
    id: u32,
    unit_name: String,
    job_type: String,
    job_state: String,
    job_path: String,
    unit_path: String,
}

#[derive(Debug, Default)]
struct RuntimeState {
    units: BTreeMap<String, UnitRecord>,
    jobs: Vec<JobRecord>,
    next_job_id: u32,
}

impl RuntimeState {
    fn from_units(units: Vec<UnitStatus>) -> Self {
        let mut state = Self::default();
        for unit in units {
            let record = UnitRecord::from_status(unit);
            state.units.insert(record.name.clone(), record);
        }
        state
    }

    fn unit(&self, name: &str) -> Option<&UnitRecord> {
        self.units.get(name)
    }

    fn unit_mut(&mut self, name: &str) -> Option<&mut UnitRecord> {
        self.units.get_mut(name)
    }

    fn is_known_unit(&self, name: &str) -> bool {
        self.units.contains_key(name)
    }

    fn update_unit_state(
        &mut self,
        name: &str,
        active_state: &str,
        sub_state: &str,
        job_type: &str,
    ) -> zbus::fdo::Result<String> {
        if !self.is_known_unit(name) {
            return Err(zbus::fdo::Error::FileNotFound(format!(
                "unit {name} not found"
            )));
        }

        self.next_job_id = self.next_job_id.saturating_add(1).max(1);
        let job_id = self.next_job_id;
        let job_path = format!("/org/freedesktop/systemd1/job/{job_id}");

        let unit = self.unit_mut(name).expect("unit existence checked above");
        let unit_path = unit.unit_path.clone();

        unit.active_state = active_state.to_string();
        unit.sub_state = sub_state.to_string();
        unit.job_id = job_id;
        unit.job_type = job_type.to_string();
        unit.job_path = job_path.clone();

        self.jobs.push(JobRecord {
            id: job_id,
            unit_name: name.to_string(),
            job_type: job_type.to_string(),
            job_state: "running".to_string(),
            job_path: job_path.clone(),
            unit_path,
        });

        Ok(job_path)
    }

    fn enqueue_job_without_state_change(
        &mut self,
        name: &str,
        job_type: &str,
        job_state: &str,
    ) -> zbus::fdo::Result<String> {
        let unit_path = self
            .unit(name)
            .map(|unit| unit.unit_path.clone())
            .ok_or_else(|| zbus::fdo::Error::FileNotFound(format!("unit {name} not found")))?;

        self.next_job_id = self.next_job_id.saturating_add(1).max(1);
        let job_id = self.next_job_id;
        let job_path = format!("/org/freedesktop/systemd1/job/{job_id}");

        let unit = self
            .unit_mut(name)
            .expect("unit existence checked while collecting unit path");

        unit.job_id = job_id;
        unit.job_type = job_type.to_string();
        unit.job_path = job_path.clone();

        self.jobs.push(JobRecord {
            id: job_id,
            unit_name: name.to_string(),
            job_type: job_type.to_string(),
            job_state: job_state.to_string(),
            job_path: job_path.clone(),
            unit_path,
        });

        Ok(job_path)
    }

    fn get_job_path(&self, id: u32) -> zbus::fdo::Result<String> {
        self.jobs
            .iter()
            .find(|job| job.id == id)
            .map(|job| job.job_path.clone())
            .ok_or_else(|| zbus::fdo::Error::FileNotFound(format!("job {id} not found")))
    }

    fn cancel_job(&mut self, id: u32) -> zbus::fdo::Result<()> {
        let index = self
            .jobs
            .iter()
            .position(|job| job.id == id)
            .ok_or_else(|| zbus::fdo::Error::FileNotFound(format!("job {id} not found")))?;

        let job = self.jobs.remove(index);
        if let Some(unit) = self.unit_mut(&job.unit_name) {
            if unit.job_id == id {
                unit.job_id = 0;
                unit.job_type.clear();
                unit.job_path.clear();
            }
        }

        Ok(())
    }

    fn set_enabled(
        &mut self,
        name: &str,
        enabled: bool,
    ) -> zbus::fdo::Result<Option<(String, String, String)>> {
        let unit = self
            .unit_mut(name)
            .ok_or_else(|| zbus::fdo::Error::FileNotFound(format!("unit {name} not found")))?;

        let old_state = unit.file_state();
        unit.enabled = enabled;
        let new_state = unit.file_state();

        if old_state == new_state {
            Ok(None)
        } else {
            Ok(Some((unit.name.clone(), old_state, new_state)))
        }
    }

    fn unit_file_state(&self, name: &str) -> zbus::fdo::Result<String> {
        self.unit(name)
            .map(|unit| unit.file_state())
            .ok_or_else(|| zbus::fdo::Error::FileNotFound(format!("unit {name} not found")))
    }
}

#[derive(Debug, Clone)]
struct ManagerState {
    version: String,
    state: Arc<Mutex<RuntimeState>>,
    tainted: String,
    subscribed: Arc<Mutex<bool>>,
}

#[interface(name = "org.freedesktop.systemd1.Manager")]
impl ManagerState {
    #[zbus(name = "ListUnits")]
    async fn list_units(&self) -> zbus::fdo::Result<Vec<UnitStatusWire>> {
        let state = self.state.lock().expect("runtime state poisoned");
        state
            .units
            .values()
            .map(UnitRecord::to_status)
            .map(UnitStatusWire::from_status)
            .collect()
            .map_err(wire_error)
    }

    #[zbus(name = "GetUnit")]
    async fn get_unit(&self, name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        if name.trim().is_empty() {
            return Err(zbus::fdo::Error::InvalidArgs(
                "unit name must not be empty".to_string(),
            ));
        }

        let state = self.state.lock().expect("runtime state poisoned");
        if !state.is_known_unit(name) {
            return Err(zbus::fdo::Error::FileNotFound(format!(
                "unit {name} not found"
            )));
        }

        let encoded = encode_unit_name(name);
        object_path(&format!("/org/freedesktop/systemd1/unit/{encoded}"))
    }

    #[zbus(name = "StartUnit")]
    async fn start_unit(&self, name: &str, mode: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        ManagerState::require_mode(mode)?;
        object_path(&self.transition_unit(name, "active", "running", "start")?)
    }

    #[zbus(name = "StopUnit")]
    async fn stop_unit(&self, name: &str, mode: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        ManagerState::require_mode(mode)?;
        object_path(&self.transition_unit(name, "inactive", "dead", "stop")?)
    }

    #[zbus(name = "RestartUnit")]
    async fn restart_unit(&self, name: &str, mode: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        ManagerState::require_mode(mode)?;
        object_path(&self.transition_unit(name, "active", "running", "restart")?)
    }

    #[zbus(name = "TryRestartUnit")]
    async fn try_restart_unit(&self, name: &str, mode: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        ManagerState::require_mode(mode)?;
        let mut state = self.state.lock().expect("runtime state poisoned");
        let active = state
            .unit(name)
            .ok_or_else(|| zbus::fdo::Error::FileNotFound(format!("unit {name} not found")))?
            .active_state
            == "active";

        let path = if active {
            state.update_unit_state(name, "active", "running", "try-restart")
        } else {
            state.enqueue_job_without_state_change(name, "try-restart", "done")
        }?;
        object_path(&path)
    }

    #[zbus(name = "ReloadOrRestartUnit")]
    async fn reload_or_restart_unit(
        &self,
        name: &str,
        mode: &str,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        ManagerState::require_mode(mode)?;
        let mut state = self.state.lock().expect("runtime state poisoned");
        let active = state
            .unit(name)
            .ok_or_else(|| zbus::fdo::Error::FileNotFound(format!("unit {name} not found")))?
            .active_state
            == "active";

        let path = if active {
            state.update_unit_state(name, "active", "reloading", "reload")
        } else {
            state.update_unit_state(name, "active", "running", "restart")
        }?;
        object_path(&path)
    }

    #[zbus(name = "ReloadOrTryRestartUnit")]
    async fn reload_or_try_restart_unit(
        &self,
        name: &str,
        mode: &str,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        ManagerState::require_mode(mode)?;
        let mut state = self.state.lock().expect("runtime state poisoned");
        let active = state
            .unit(name)
            .ok_or_else(|| zbus::fdo::Error::FileNotFound(format!("unit {name} not found")))?
            .active_state
            == "active";

        let path = if active {
            state.update_unit_state(name, "active", "reloading", "reload")
        } else {
            state.enqueue_job_without_state_change(name, "reload-or-try-restart", "done")
        }?;
        object_path(&path)
    }

    #[zbus(name = "Reload")]
    async fn reload(&self) -> zbus::fdo::Result<()> {
        Ok(())
    }

    #[zbus(name = "ListJobs")]
    async fn list_jobs(&self) -> zbus::fdo::Result<Vec<JobStatusWire>> {
        let state = self.state.lock().expect("runtime state poisoned");
        state
            .jobs
            .iter()
            .map(|job| {
                JobStatusWire::new(
                    job.id,
                    job.unit_name.clone(),
                    job.job_type.clone(),
                    job.job_state.clone(),
                    job.job_path.clone(),
                    job.unit_path.clone(),
                )
            })
            .collect()
            .map_err(wire_error)
    }

    #[zbus(name = "GetJob")]
    async fn get_job(&self, id: u32) -> zbus::fdo::Result<OwnedObjectPath> {
        let state = self.state.lock().expect("runtime state poisoned");
        object_path(&state.get_job_path(id)?)
    }

    #[zbus(name = "CancelJob")]
    async fn cancel_job(&self, id: u32) -> zbus::fdo::Result<()> {
        let mut state = self.state.lock().expect("runtime state poisoned");
        state.cancel_job(id)
    }

    #[zbus(name = "Subscribe")]
    async fn subscribe(&self) -> zbus::fdo::Result<()> {
        *self.subscribed.lock().expect("subscription state poisoned") = true;
        Ok(())
    }

    #[zbus(name = "Unsubscribe")]
    async fn unsubscribe(&self) -> zbus::fdo::Result<()> {
        *self.subscribed.lock().expect("subscription state poisoned") = false;
        Ok(())
    }

    #[zbus(name = "EnableUnitFiles")]
    async fn enable_unit_files(
        &self,
        units: Vec<&str>,
        _runtime: bool,
        _force: bool,
    ) -> zbus::fdo::Result<(bool, Vec<(String, String, String)>)> {
        let changes = self.change_unit_files(units, true)?;

        // This simplified state model only accepts units it can enable, so all
        // successful requests carry install information.
        Ok((true, changes))
    }

    #[zbus(name = "DisableUnitFiles")]
    async fn disable_unit_files(
        &self,
        units: Vec<&str>,
        _runtime: bool,
    ) -> zbus::fdo::Result<Vec<(String, String, String)>> {
        self.change_unit_files(units, false)
    }

    #[zbus(name = "ListUnitFiles")]
    async fn list_unit_files(&self) -> Vec<(String, String)> {
        let state = self.state.lock().expect("runtime state poisoned");
        state
            .units
            .values()
            .map(|unit| (unit.name.clone(), unit.file_state()))
            .collect()
    }

    #[zbus(name = "GetUnitFileState")]
    async fn get_unit_file_state(&self, name: &str) -> zbus::fdo::Result<String> {
        if name.trim().is_empty() {
            return Err(zbus::fdo::Error::InvalidArgs(
                "unit name must not be empty".to_string(),
            ));
        }

        let state = self.state.lock().expect("runtime state poisoned");
        state.unit_file_state(name)
    }

    #[zbus(property)]
    fn version(&self) -> &str {
        &self.version
    }

    #[zbus(property)]
    fn n_failed_units(&self) -> u32 {
        let state = self.state.lock().expect("runtime state poisoned");
        state
            .units
            .values()
            .filter(|unit| unit.active_state == "failed")
            .count() as u32
    }

    #[zbus(property)]
    fn n_installed_jobs(&self) -> u32 {
        let state = self.state.lock().expect("runtime state poisoned");
        state.jobs.len() as u32
    }

    #[zbus(property)]
    fn n_names(&self) -> u32 {
        let state = self.state.lock().expect("runtime state poisoned");
        state.units.len() as u32
    }

    #[zbus(property)]
    fn tainted(&self) -> &str {
        &self.tainted
    }

    #[zbus(property)]
    fn virtualization(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn architecture(&self) -> &str {
        std::env::consts::ARCH
    }
}

impl ManagerState {
    fn require_mode(mode: &str) -> zbus::fdo::Result<()> {
        match mode {
            "replace"
            | "fail"
            | "isolate"
            | "ignore-dependencies"
            | "ignore-requirements"
            | "replace-irreversibly"
            | "trigger"
            | "flush" => Ok(()),
            _ => Err(zbus::fdo::Error::InvalidArgs(format!(
                "unsupported job mode {mode}"
            ))),
        }
    }

    fn transition_unit(
        &self,
        name: &str,
        active_state: &str,
        sub_state: &str,
        job_type: &str,
    ) -> zbus::fdo::Result<String> {
        if name.trim().is_empty() {
            return Err(zbus::fdo::Error::InvalidArgs(
                "unit name must not be empty".to_string(),
            ));
        }

        let mut state = self.state.lock().expect("runtime state poisoned");
        state.update_unit_state(name, active_state, sub_state, job_type)
    }

    fn change_unit_files(
        &self,
        units: Vec<&str>,
        enable: bool,
    ) -> zbus::fdo::Result<Vec<(String, String, String)>> {
        if units.is_empty() {
            return Err(zbus::fdo::Error::InvalidArgs(
                "at least one unit must be provided".to_string(),
            ));
        }

        let mut state = self.state.lock().expect("runtime state poisoned");
        let mut changes = Vec::new();

        for name in &units {
            if name.trim().is_empty() {
                return Err(zbus::fdo::Error::InvalidArgs(
                    "unit name must not be empty".to_string(),
                ));
            }

            if !state.is_known_unit(name) {
                return Err(zbus::fdo::Error::FileNotFound(format!(
                    "unit {name} not found"
                )));
            }
        }

        for name in units {
            match state.set_enabled(name, enable)? {
                Some(change) => changes.push(change),
                None => {}
            }
        }

        Ok(changes)
    }
}

#[derive(Debug, Clone)]
struct UnitIface {
    name: String,
    description: String,
    state: Arc<Mutex<RuntimeState>>,
    unit_path: String,
}

impl UnitIface {
    fn snapshot(&self) -> Option<UnitRecord> {
        let state = self.state.lock().expect("runtime state poisoned");
        state.unit(&self.name).cloned()
    }
}

#[interface(name = "org.freedesktop.systemd1.Unit")]
impl UnitIface {
    #[zbus(property)]
    fn id(&self) -> &str {
        &self.name
    }

    #[zbus(property)]
    fn description(&self) -> &str {
        &self.description
    }

    #[zbus(property)]
    fn load_state(&self) -> String {
        self.snapshot()
            .map(|unit| unit.load_state)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn active_state(&self) -> String {
        self.snapshot()
            .map(|unit| unit.active_state)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn sub_state(&self) -> String {
        self.snapshot()
            .map(|unit| unit.sub_state)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn following(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn unit_path(&self) -> &str {
        &self.unit_path
    }

    #[zbus(property)]
    fn job_id(&self) -> u32 {
        self.snapshot().map(|unit| unit.job_id).unwrap_or(0)
    }

    #[zbus(property)]
    fn job_type(&self) -> String {
        self.snapshot()
            .map(|unit| unit.job_type)
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn job_path(&self) -> String {
        self.snapshot()
            .map(|unit| unit.job_path)
            .unwrap_or_default()
    }

    #[zbus(name = "Start")]
    async fn start(&self, mode: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        Self::require_mode(mode)?;
        self.transition("active", "running", "start")
    }

    #[zbus(name = "Stop")]
    async fn stop(&self, mode: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        Self::require_mode(mode)?;
        self.transition("inactive", "dead", "stop")
    }

    #[zbus(name = "Restart")]
    async fn restart(&self, mode: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        Self::require_mode(mode)?;
        self.transition("active", "running", "restart")
    }

    #[zbus(name = "Reload")]
    async fn reload(&self, mode: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        Self::require_mode(mode)?;
        self.transition("active", "reloading", "reload")
    }
}

impl UnitIface {
    fn require_mode(mode: &str) -> zbus::fdo::Result<()> {
        ManagerState::require_mode(mode)
    }

    fn transition(
        &self,
        active_state: &str,
        sub_state: &str,
        job_type: &str,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let manager = ManagerState {
            version: String::new(),
            state: self.state.clone(),
            tainted: String::new(),
            subscribed: Arc::new(Mutex::new(false)),
        };
        object_path(&manager.transition_unit(&self.name, active_state, sub_state, job_type)?)
    }
}

pub async fn start_systemd_dbus_server(
    version: String,
    units: Vec<UnitStatus>,
) -> zbus::Result<()> {
    let runtime_state = Arc::new(Mutex::new(RuntimeState::from_units(units.clone())));

    let manager = ManagerState {
        version,
        state: runtime_state.clone(),
        tainted: String::new(),
        subscribed: Arc::new(Mutex::new(false)),
    };

    let conn = zbus::Connection::system().await?;

    if !conn.object_server().at(DBUS_PATH, manager).await? {
        return Err(zbus::Error::Failure(format!(
            "manager interface is already registered at {DBUS_PATH}"
        )));
    }

    for unit in &units {
        let encoded = encode_unit_name(&unit.name);
        let path = format!("/org/freedesktop/systemd1/unit/{encoded}");

        let iface = UnitIface {
            name: unit.name.clone(),
            description: unit.description.clone(),
            state: runtime_state.clone(),
            unit_path: path.clone(),
        };

        if !conn.object_server().at(path.as_str(), iface).await? {
            return Err(zbus::Error::Failure(format!(
                "unit interface is already registered at {path}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(future);

        loop {
            match Pin::as_mut(&mut future).poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn unit_status(
        name: &str,
        load_state: &str,
        active_state: &str,
        sub_state: &str,
    ) -> UnitStatus {
        UnitStatus {
            name: name.to_string(),
            description: format!("{name} service"),
            load_state: load_state.to_string(),
            active_state: active_state.to_string(),
            sub_state: sub_state.to_string(),
            followed: String::new(),
            path: format!("/org/freedesktop/systemd1/unit/{}", encode_unit_name(name)),
            job_id: 0,
            job_type: String::new(),
            job_path: String::new(),
        }
    }

    fn manager_with_units() -> ManagerState {
        ManagerState {
            version: "254".to_string(),
            state: Arc::new(Mutex::new(RuntimeState::from_units(vec![
                unit_status("alpha.service", "loaded", "inactive", "dead"),
                unit_status("beta.service", "static", "active", "running"),
            ]))),
            tainted: String::new(),
            subscribed: Arc::new(Mutex::new(false)),
        }
    }

    #[test]
    fn unit_name_encoding_matches_bus_label_escape() {
        assert_eq!(encode_unit_name("alpha.service"), "alpha_2eservice");
        assert_eq!(encode_unit_name("demo@one.service"), "demo_40one_2eservice");
        assert_eq!(
            encode_unit_name("with_under.service"),
            "with_5funder_2eservice"
        );
        assert_eq!(encode_unit_name("123.service"), "_3123_2eservice");
    }

    #[test]
    fn start_stop_restart_update_unit_state_and_jobs() {
        let manager = manager_with_units();

        let start_job = block_on(manager.start_unit("alpha.service", "replace")).unwrap();
        assert_eq!(start_job.as_str(), "/org/freedesktop/systemd1/job/1");
        assert_eq!(
            block_on(manager.get_unit_file_state("alpha.service")).unwrap(),
            "disabled"
        );

        {
            let unit = manager
                .state
                .lock()
                .expect("runtime state poisoned")
                .unit("alpha.service")
                .cloned()
                .expect("unit exists");
            assert_eq!(unit.active_state, "active");
            assert_eq!(unit.sub_state, "running");
            assert_eq!(unit.job_id, 1);
            assert_eq!(unit.job_type, "start");
        }

        let stop_job = block_on(manager.stop_unit("alpha.service", "replace")).unwrap();
        assert_eq!(stop_job.as_str(), "/org/freedesktop/systemd1/job/2");

        let restart_job = block_on(manager.restart_unit("alpha.service", "replace")).unwrap();
        assert_eq!(restart_job.as_str(), "/org/freedesktop/systemd1/job/3");

        let jobs = block_on(manager.list_jobs()).unwrap();
        assert_eq!(jobs.len(), 3);
        assert_eq!(jobs[0].unit_name, "alpha.service");
        assert_eq!(jobs[0].job_type, "start");
        assert_eq!(jobs[0].job_state, "running");
        assert_eq!(jobs[1].job_type, "stop");
        assert_eq!(jobs[2].job_type, "restart");
        assert_eq!(jobs[2].job_path.as_str(), "/org/freedesktop/systemd1/job/3");
    }

    #[test]
    fn invalid_args_and_not_found_are_reported() {
        let manager = manager_with_units();

        let err = block_on(manager.start_unit("missing.service", "replace")).unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::FileNotFound(_)));

        let err = block_on(manager.start_unit("alpha.service", "bogus")).unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));

        let err = block_on(manager.get_unit("missing.service")).unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::FileNotFound(_)));

        let err = block_on(manager.get_job(404)).unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::FileNotFound(_)));

        let err = block_on(manager.get_unit_file_state("missing.service")).unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::FileNotFound(_)));

        let err = block_on(manager.enable_unit_files(Vec::new(), false, false)).unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));

        let err = block_on(manager.disable_unit_files(vec![""], false)).unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
    }

    #[test]
    fn enable_disable_and_list_unit_files_track_state() {
        let manager = manager_with_units();

        let (carries_install_info, changes) =
            block_on(manager.enable_unit_files(vec!["alpha.service"], false, false)).unwrap();
        assert!(carries_install_info);
        assert_eq!(
            changes,
            vec![(
                "alpha.service".to_string(),
                "disabled".to_string(),
                "enabled".to_string()
            )]
        );
        assert_eq!(
            block_on(manager.get_unit_file_state("alpha.service")).unwrap(),
            "enabled"
        );

        let files = block_on(manager.list_unit_files());
        assert_eq!(
            files,
            vec![
                ("alpha.service".to_string(), "enabled".to_string()),
                ("beta.service".to_string(), "static".to_string())
            ]
        );

        let changes = block_on(manager.disable_unit_files(vec!["alpha.service"], false)).unwrap();
        assert_eq!(
            changes,
            vec![(
                "alpha.service".to_string(),
                "enabled".to_string(),
                "disabled".to_string()
            )]
        );
        assert_eq!(
            block_on(manager.get_unit_file_state("alpha.service")).unwrap(),
            "disabled"
        );
    }

    #[test]
    fn unit_iface_reads_shared_state() {
        let manager = manager_with_units();
        let iface = UnitIface {
            name: "alpha.service".to_string(),
            description: "alpha service".to_string(),
            state: manager.state.clone(),
            unit_path: "/org/freedesktop/systemd1/unit/alpha_2eservice".to_string(),
        };

        assert_eq!(iface.active_state(), "inactive");
        assert_eq!(iface.load_state(), "loaded");

        block_on(iface.start("replace")).unwrap();
        block_on(iface.reload("replace")).unwrap();

        assert_eq!(iface.active_state(), "active");
        assert_eq!(iface.sub_state(), "reloading");
        assert_eq!(iface.job_id(), 2);
        assert_eq!(iface.job_type(), "reload");
        assert_eq!(iface.job_path(), "/org/freedesktop/systemd1/job/2");
    }

    #[test]
    fn get_cancel_and_subscribe_roundtrip() {
        let manager = manager_with_units();

        let path = block_on(manager.start_unit("alpha.service", "replace")).unwrap();
        assert_eq!(path.as_str(), "/org/freedesktop/systemd1/job/1");
        assert_eq!(block_on(manager.get_job(1)).unwrap(), path);

        block_on(manager.subscribe()).unwrap();
        assert!(
            *manager
                .subscribed
                .lock()
                .expect("subscription state poisoned")
        );

        block_on(manager.cancel_job(1)).unwrap();
        let err = block_on(manager.get_job(1)).unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::FileNotFound(_)));

        block_on(manager.unsubscribe()).unwrap();
        assert!(
            !*manager
                .subscribed
                .lock()
                .expect("subscription state poisoned")
        );
    }

    #[test]
    fn restart_variants_create_expected_jobs() {
        let manager = manager_with_units();

        let try_restart_inactive = block_on(manager.try_restart_unit("alpha.service", "replace"))
            .expect("try restart on inactive should be accepted");
        assert_eq!(
            try_restart_inactive.as_str(),
            "/org/freedesktop/systemd1/job/1"
        );

        let reload_or_restart =
            block_on(manager.reload_or_restart_unit("alpha.service", "replace")).unwrap();
        assert_eq!(
            reload_or_restart.as_str(),
            "/org/freedesktop/systemd1/job/2"
        );

        let reload_or_try_restart_active =
            block_on(manager.reload_or_try_restart_unit("beta.service", "replace")).unwrap();
        assert_eq!(
            reload_or_try_restart_active.as_str(),
            "/org/freedesktop/systemd1/job/3"
        );
    }
}
