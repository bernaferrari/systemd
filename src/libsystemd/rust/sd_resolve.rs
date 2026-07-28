// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-resolve/sd-resolve.c
//
// Asynchronous getaddrinfo/getnameinfo backed by blocking resolver workers.
// Worker completion is signalled through a pollable Unix datagram socket.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::ptr;
use std::rc::Rc;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const WORKERS_MIN: u32 = 1;
pub const WORKERS_MAX: u32 = 16;
pub const QUERIES_MAX: u32 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    InvalidArgument,
    BadFileDescriptor,
    OutOfMemory,
    Io(String),
    DnsError(i32),
    Canceled,
    TimedOut,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::InvalidArgument => write!(f, "Invalid argument"),
            ResolveError::BadFileDescriptor => write!(f, "Bad file descriptor"),
            ResolveError::OutOfMemory => write!(f, "Out of memory"),
            ResolveError::Io(s) => write!(f, "I/O: {s}"),
            ResolveError::DnsError(n) => write!(f, "DNS error: {n}"),
            ResolveError::Canceled => write!(f, "Canceled"),
            ResolveError::TimedOut => write!(f, "Timed out"),
        }
    }
}

impl std::error::Error for ResolveError {}

pub type Result<T> = std::result::Result<T, ResolveError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    AddrInfo,
    NameInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrInfo {
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
    pub address: Option<SocketAddr>,
    pub canonname: Option<String>,
}

impl AddrInfo {
    pub fn new(family: i32, socktype: i32, protocol: i32) -> Self {
        Self {
            family,
            socktype,
            protocol,
            address: None,
            canonname: None,
        }
    }

    pub fn with_address(mut self, addr: SocketAddr) -> Self {
        self.address = Some(addr);
        self
    }

    pub fn with_canonname(mut self, name: &str) -> Self {
        self.canonname = Some(name.to_string());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameInfo {
    pub host: String,
    pub service: String,
}

#[derive(Debug)]
pub struct ResolveQuery {
    id: u32,
    done: bool,
    cancelled: bool,
    query_type: QueryType,
    host: Option<String>,
    service: Option<String>,
    result_addrinfo: Vec<AddrInfo>,
    result_nameinfo: Option<NameInfo>,
    ret_code: i32,
}

impl ResolveQuery {
    fn new(id: u32, query_type: QueryType) -> Self {
        Self {
            id,
            done: false,
            cancelled: false,
            query_type,
            host: None,
            service: None,
            result_addrinfo: Vec::new(),
            result_nameinfo: None,
            ret_code: 0,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn query_type(&self) -> QueryType {
        self.query_type
    }

    pub fn addrinfo_results(&self) -> &[AddrInfo] {
        &self.result_addrinfo
    }

    pub fn nameinfo_result(&self) -> Option<&NameInfo> {
        self.result_nameinfo.as_ref()
    }

    pub fn ret_code(&self) -> i32 {
        self.ret_code
    }
}

#[derive(Debug)]
enum Job {
    AddrInfo {
        id: u32,
        host: Option<String>,
        service: Option<String>,
    },
    NameInfo {
        id: u32,
        address: SocketAddr,
    },
}

#[derive(Debug)]
enum LookupResult {
    AddrInfo {
        ret_code: i32,
        entries: Vec<AddrInfo>,
    },
    NameInfo {
        ret_code: i32,
        entry: Option<NameInfo>,
    },
}

#[derive(Debug)]
struct Completion {
    id: u32,
    result: LookupResult,
}

/// An asynchronous resolver handle.
///
/// `event_fd()` may be registered for readable events. After readiness, callers
/// invoke `process()` to transfer worker results into their `ResolveQuery`.
#[derive(Debug)]
pub struct Resolve {
    queries: HashMap<u32, Rc<RefCell<ResolveQuery>>>,
    next_id: u32,
    jobs_tx: Option<mpsc::Sender<Job>>,
    jobs_rx: Arc<Mutex<mpsc::Receiver<Job>>>,
    completions_tx: mpsc::Sender<Completion>,
    completions_rx: mpsc::Receiver<Completion>,
    readiness_tx: UnixDatagram,
    readiness_rx: UnixDatagram,
    workers: Vec<JoinHandle<()>>,
}

impl Resolve {
    /// Create a resolver without starting worker threads. Thread creation is
    /// deferred until the first query and failures are returned to the caller.
    pub fn new() -> Result<Self> {
        let (jobs_tx, jobs_rx) = mpsc::channel();
        let (completions_tx, completions_rx) = mpsc::channel();
        let (readiness_tx, readiness_rx) =
            UnixDatagram::pair().map_err(|e| ResolveError::Io(e.to_string()))?;
        readiness_rx
            .set_nonblocking(true)
            .map_err(|e| ResolveError::Io(e.to_string()))?;

        Ok(Self {
            queries: HashMap::new(),
            next_id: 1,
            jobs_tx: Some(jobs_tx),
            jobs_rx: Arc::new(Mutex::new(jobs_rx)),
            completions_tx,
            completions_rx,
            readiness_tx,
            readiness_rx,
            workers: Vec::new(),
        })
    }

    pub fn query_count(&self) -> usize {
        self.queries.len()
    }

    pub fn done_count(&self) -> usize {
        self.queries.values().filter(|q| q.borrow().done).count()
    }

    /// Return the fd which becomes readable when worker results are available.
    pub fn event_fd(&self) -> RawFd {
        self.readiness_rx.as_raw_fd()
    }

    /// Return whether the completion fd is currently readable.
    pub fn has_pending(&self) -> bool {
        let mut poll_fd = libc::pollfd {
            fd: self.event_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll_fd points to one initialized pollfd for the duration of
        // this non-blocking poll, and poll does not retain the pointer.
        unsafe { libc::poll(&mut poll_fd, 1, 0) > 0 && poll_fd.revents & libc::POLLIN != 0 }
    }

    pub fn getaddrinfo(
        &mut self,
        host: Option<&str>,
        service: Option<&str>,
    ) -> Result<Rc<RefCell<ResolveQuery>>> {
        if host.is_none() && service.is_none() {
            return Err(ResolveError::InvalidArgument);
        }
        if host.is_some_and(|s| s.as_bytes().contains(&0))
            || service.is_some_and(|s| s.as_bytes().contains(&0))
        {
            return Err(ResolveError::InvalidArgument);
        }

        self.prepare_query_slot()?;
        let id = self.allocate_id();
        let mut query = ResolveQuery::new(id, QueryType::AddrInfo);
        query.host = host.map(str::to_owned);
        query.service = service.map(str::to_owned);
        let query = Rc::new(RefCell::new(query));
        self.queries.insert(id, Rc::clone(&query));

        let job = Job::AddrInfo {
            id,
            host: host.map(str::to_owned),
            service: service.map(str::to_owned),
        };
        if let Err(error) = self.send_job(job) {
            self.queries.remove(&id);
            return Err(error);
        }

        Ok(query)
    }

    pub fn getnameinfo(&mut self, address: SocketAddr) -> Result<Rc<RefCell<ResolveQuery>>> {
        self.prepare_query_slot()?;
        let id = self.allocate_id();
        let query = Rc::new(RefCell::new(ResolveQuery::new(id, QueryType::NameInfo)));
        self.queries.insert(id, Rc::clone(&query));

        if let Err(error) = self.send_job(Job::NameInfo { id, address }) {
            self.queries.remove(&id);
            return Err(error);
        }

        Ok(query)
    }

    pub fn cancel(&mut self, query_id: u32) -> Result<()> {
        let query = self
            .queries
            .get(&query_id)
            .ok_or(ResolveError::InvalidArgument)?;
        query.borrow_mut().cancelled = true;
        Ok(())
    }

    /// Consume all currently queued worker results.
    pub fn process(&mut self) -> Result<usize> {
        self.drain_readiness();
        let mut processed = 0;

        loop {
            match self.completions_rx.try_recv() {
                Ok(completion) => {
                    processed += 1;
                    self.complete(completion);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if self.has_outstanding_queries() {
                        return Err(ResolveError::Io(
                            "all resolver workers disconnected".to_string(),
                        ));
                    }
                    break;
                }
            }
        }

        self.queries.retain(|_, query| !query.borrow().cancelled);
        if processed == 0 && self.has_outstanding_queries() && !self.has_live_worker() {
            return Err(ResolveError::Io(
                "all resolver workers terminated with queries outstanding".to_string(),
            ));
        }
        Ok(processed)
    }

    /// Wait until at least one result is processed, or until the timeout.
    pub fn wait(&mut self, timeout_usec: u64) -> Result<()> {
        if self.process()? > 0 || !self.has_outstanding_queries() {
            return Ok(());
        }
        if timeout_usec == 0 {
            return Err(ResolveError::TimedOut);
        }

        self.readiness_rx
            .set_nonblocking(false)
            .map_err(|e| ResolveError::Io(e.to_string()))?;
        let timeout = if timeout_usec == u64::MAX {
            None
        } else {
            Some(Duration::from_micros(timeout_usec))
        };
        let timeout_result = self.readiness_rx.set_read_timeout(timeout);
        if let Err(error) = timeout_result {
            let _ = self.readiness_rx.set_nonblocking(true);
            return Err(ResolveError::Io(error.to_string()));
        }

        let receive_result = self.readiness_rx.recv(&mut [0_u8; 1]);
        let restore_result = self.readiness_rx.set_nonblocking(true);
        if let Err(error) = restore_result {
            return Err(ResolveError::Io(error.to_string()));
        }

        match receive_result {
            Ok(_) => {
                if self.process()? == 0 && self.has_outstanding_queries() {
                    Err(ResolveError::Io(
                        "resolver readiness without a completion".to_string(),
                    ))
                } else {
                    Ok(())
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Err(ResolveError::TimedOut)
            }
            Err(error) => Err(ResolveError::Io(error.to_string())),
        }
    }

    pub fn getaddrinfo_done(&self, query_id: u32) -> Result<Vec<AddrInfo>> {
        let query = self
            .queries
            .get(&query_id)
            .ok_or(ResolveError::InvalidArgument)?;
        let query = query.borrow();
        validate_completed_query(&query, QueryType::AddrInfo)?;
        if query.ret_code != 0 {
            return Err(ResolveError::DnsError(query.ret_code));
        }
        Ok(query.result_addrinfo.clone())
    }

    pub fn getnameinfo_done(&self, query_id: u32) -> Result<NameInfo> {
        let query = self
            .queries
            .get(&query_id)
            .ok_or(ResolveError::InvalidArgument)?;
        let query = query.borrow();
        validate_completed_query(&query, QueryType::NameInfo)?;
        if query.ret_code != 0 {
            return Err(ResolveError::DnsError(query.ret_code));
        }
        query
            .result_nameinfo
            .clone()
            .ok_or(ResolveError::InvalidArgument)
    }

    fn prepare_query_slot(&mut self) -> Result<()> {
        if self.queries.len() >= QUERIES_MAX as usize {
            return Err(ResolveError::OutOfMemory);
        }

        self.workers.retain(|worker| !worker.is_finished());
        let outstanding = self
            .queries
            .values()
            .filter(|query| {
                let query = query.borrow();
                !query.done && !query.cancelled
            })
            .count();
        let wanted = (outstanding + 1).clamp(WORKERS_MIN as usize, WORKERS_MAX as usize);
        while self.workers.len() < wanted {
            self.spawn_worker()?;
        }
        Ok(())
    }

    fn spawn_worker(&mut self) -> Result<()> {
        let jobs = Arc::clone(&self.jobs_rx);
        let completions = self.completions_tx.clone();
        let readiness = self
            .readiness_tx
            .try_clone()
            .map_err(|e| ResolveError::Io(e.to_string()))?;
        let worker_number = self.workers.len();
        let handle = thread::Builder::new()
            .name(format!("sd-resolve-{worker_number}"))
            .spawn(move || resolver_worker(jobs, completions, readiness))
            .map_err(|e| ResolveError::Io(format!("failed to start resolver worker: {e}")))?;
        self.workers.push(handle);
        Ok(())
    }

    fn send_job(&self, job: Job) -> Result<()> {
        self.jobs_tx
            .as_ref()
            .ok_or_else(|| ResolveError::Io("resolver is shutting down".to_string()))?
            .send(job)
            .map_err(|_| ResolveError::Io("resolver worker queue is disconnected".to_string()))
    }

    fn allocate_id(&mut self) -> u32 {
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id == 0 {
                self.next_id = 1;
            }
            if !self.queries.contains_key(&id) {
                return id;
            }
        }
    }

    fn has_outstanding_queries(&self) -> bool {
        self.queries.values().any(|query| {
            let query = query.borrow();
            !query.done && !query.cancelled
        })
    }

    fn has_live_worker(&self) -> bool {
        self.workers.iter().any(|worker| !worker.is_finished())
    }

    fn drain_readiness(&self) {
        let mut buffer = [0_u8; 64];
        loop {
            match self.readiness_rx.recv(&mut buffer) {
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn complete(&mut self, completion: Completion) {
        let Some(query) = self.queries.get(&completion.id) else {
            return;
        };
        let mut query = query.borrow_mut();
        if query.cancelled || query.done {
            return;
        }

        match completion.result {
            LookupResult::AddrInfo { ret_code, entries }
                if query.query_type == QueryType::AddrInfo =>
            {
                query.ret_code = ret_code;
                query.result_addrinfo = entries;
                query.done = true;
            }
            LookupResult::NameInfo { ret_code, entry }
                if query.query_type == QueryType::NameInfo =>
            {
                query.ret_code = ret_code;
                query.result_nameinfo = entry;
                query.done = true;
            }
            _ => {
                query.ret_code = libc::EAI_SYSTEM;
                query.done = true;
            }
        }
    }
}

impl Drop for Resolve {
    fn drop(&mut self) {
        self.jobs_tx.take();
        // Detached workers finish any libc resolver call already in progress and
        // then observe the disconnected job channel. Joining here could make
        // destruction block indefinitely in a broken NSS module.
        self.workers.clear();
    }
}

fn validate_completed_query(query: &ResolveQuery, expected: QueryType) -> Result<()> {
    if query.cancelled {
        return Err(ResolveError::Canceled);
    }
    if !query.done || query.query_type != expected {
        return Err(ResolveError::InvalidArgument);
    }
    Ok(())
}

fn resolver_worker(
    jobs: Arc<Mutex<mpsc::Receiver<Job>>>,
    completions: mpsc::Sender<Completion>,
    readiness: UnixDatagram,
) {
    loop {
        let job = {
            let receiver = match jobs.lock() {
                Ok(receiver) => receiver,
                Err(_) => return,
            };
            match receiver.recv() {
                Ok(job) => job,
                Err(_) => return,
            }
        };

        let completion = match job {
            Job::AddrInfo { id, host, service } => Completion {
                id,
                result: lookup_addrinfo(host.as_deref(), service.as_deref()),
            },
            Job::NameInfo { id, address } => Completion {
                id,
                result: lookup_nameinfo(address),
            },
        };

        if completions.send(completion).is_err() {
            return;
        }
        if readiness.send(&[1]).is_err() {
            return;
        }
    }
}

struct AddrInfoList(*mut libc::addrinfo);

impl Drop for AddrInfoList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 is the untouched list head returned by a successful
            // getaddrinfo call and is freed exactly once here.
            unsafe { libc::freeaddrinfo(self.0) };
        }
    }
}

fn lookup_addrinfo(host: Option<&str>, service: Option<&str>) -> LookupResult {
    let host = host.and_then(|value| CString::new(value).ok());
    let service = service.and_then(|value| CString::new(value).ok());
    let host_ptr = host.as_ref().map_or(ptr::null(), |value| value.as_ptr());
    let service_ptr = service.as_ref().map_or(ptr::null(), |value| value.as_ptr());
    let mut raw_result = ptr::null_mut();

    // SAFETY: the optional C strings are NUL-terminated and live through the call;
    // raw_result is an initialized out-pointer, and libc permits null hints.
    let ret_code =
        unsafe { libc::getaddrinfo(host_ptr, service_ptr, ptr::null(), &mut raw_result) };
    if ret_code != 0 {
        return LookupResult::AddrInfo {
            ret_code,
            entries: Vec::new(),
        };
    }

    let list = AddrInfoList(raw_result);
    let mut entries = Vec::new();
    let mut current = list.0;
    while !current.is_null() {
        // SAFETY: current traverses the getaddrinfo-owned linked list until null.
        let raw = unsafe { &*current };
        let mut entry = AddrInfo::new(raw.ai_family, raw.ai_socktype, raw.ai_protocol);
        entry.address = sockaddr_to_socket_addr(raw.ai_addr, raw.ai_addrlen);
        if !raw.ai_canonname.is_null() {
            // SAFETY: libc guarantees ai_canonname is NUL-terminated when set.
            entry.canonname = Some(
                unsafe { CStr::from_ptr(raw.ai_canonname) }
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        entries.push(entry);
        current = raw.ai_next;
    }

    LookupResult::AddrInfo {
        ret_code: 0,
        entries,
    }
}

fn sockaddr_to_socket_addr(
    address: *const libc::sockaddr,
    length: libc::socklen_t,
) -> Option<SocketAddr> {
    if address.is_null() {
        return None;
    }

    // SAFETY: callers provide ai_addr and ai_addrlen from a live getaddrinfo
    // node. Each cast is guarded by both family and minimum structure length.
    unsafe {
        match i32::from((*address).sa_family) {
            libc::AF_INET if (length as usize) >= std::mem::size_of::<libc::sockaddr_in>() => {
                let address = &*address.cast::<libc::sockaddr_in>();
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(address.sin_port),
                )))
            }
            libc::AF_INET6 if (length as usize) >= std::mem::size_of::<libc::sockaddr_in6>() => {
                let address = &*address.cast::<libc::sockaddr_in6>();
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(address.sin6_addr.s6_addr),
                    u16::from_be(address.sin6_port),
                    // libc and SocketAddrV6 both expose flowinfo in host order.
                    address.sin6_flowinfo,
                    address.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

fn lookup_nameinfo(address: SocketAddr) -> LookupResult {
    match address {
        SocketAddr::V4(address) => {
            // SAFETY: zero is a valid base representation for sockaddr_in; all
            // fields consumed by getnameinfo are assigned below.
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            raw.sin_family = libc::AF_INET as libc::sa_family_t;
            raw.sin_port = address.port().to_be();
            raw.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
            call_getnameinfo(
                (&raw as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(address) => {
            // SAFETY: zero is a valid base representation for sockaddr_in6; all
            // fields consumed by getnameinfo are assigned below.
            let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            raw.sin6_port = address.port().to_be();
            // Unlike sin6_port, libc defines sin6_flowinfo in host byte order.
            raw.sin6_flowinfo = address.flowinfo();
            raw.sin6_addr.s6_addr = address.ip().octets();
            raw.sin6_scope_id = address.scope_id();
            call_getnameinfo(
                (&raw as *const libc::sockaddr_in6).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

fn call_getnameinfo(address: *const libc::sockaddr, length: libc::socklen_t) -> LookupResult {
    let mut host = [0_i8; 1025];
    let mut service = [0_i8; 32];
    // SAFETY: address points to a fully initialized sockaddr of length bytes;
    // both output arrays are writable for the lengths passed to libc.
    let ret_code = unsafe {
        libc::getnameinfo(
            address,
            length,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            service.as_mut_ptr(),
            service.len() as libc::socklen_t,
            0,
        )
    };
    if ret_code != 0 {
        return LookupResult::NameInfo {
            ret_code,
            entry: None,
        };
    }

    // SAFETY: successful getnameinfo writes NUL-terminated strings into both
    // buffers because their capacities are non-zero.
    let host = unsafe { CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: same successful getnameinfo contract as the host buffer above.
    let service = unsafe { CStr::from_ptr(service.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    LookupResult::NameInfo {
        ret_code: 0,
        entry: Some(NameInfo { host, service }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_resolution_is_real_and_asynchronous() {
        let mut resolver = Resolve::new().unwrap();
        let query = resolver.getaddrinfo(Some("localhost"), Some("80")).unwrap();
        let id = query.borrow().id();
        resolver.wait(5_000_000).unwrap();
        let entries = resolver.getaddrinfo_done(id).unwrap();
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|entry| {
            entry
                .address
                .is_some_and(|address| address.ip().is_loopback() && address.port() == 80)
        }));
    }

    #[test]
    fn invalid_domain_is_not_fabricated() {
        let mut resolver = Resolve::new().unwrap();
        let query = resolver
            .getaddrinfo(Some("does-not-exist.invalid"), None)
            .unwrap();
        let id = query.borrow().id();
        resolver.wait(5_000_000).unwrap();
        assert!(matches!(
            resolver.getaddrinfo_done(id),
            Err(ResolveError::DnsError(_))
        ));
    }

    #[test]
    fn cancellation_discards_worker_result() {
        let mut resolver = Resolve::new().unwrap();
        let query = resolver.getaddrinfo(Some("localhost"), None).unwrap();
        let id = query.borrow().id();
        resolver.cancel(id).unwrap();
        assert!(query.borrow().is_cancelled());
        assert!(matches!(
            resolver.getaddrinfo_done(id),
            Err(ResolveError::Canceled)
        ));
    }

    #[test]
    fn empty_query_is_rejected() {
        let mut resolver = Resolve::new().unwrap();
        assert!(matches!(
            resolver.getaddrinfo(None, None),
            Err(ResolveError::InvalidArgument)
        ));
    }
}
