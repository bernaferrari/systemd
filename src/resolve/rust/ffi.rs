// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: N/A (FFI conventions)
//
// FFI boundary helpers and type declarations for Rust↔C interop in systemd-resolve-rs.

use std::ffi::c_void;
use std::os::raw::{c_char, c_int, c_uint, c_ushort};

#[cfg(not(feature = "meson"))]
pub use self::local_ffi::*;

#[cfg(feature = "meson")]
pub use systemd_basic_rs::ffi::*;

// ── Errno / Error Types (local fallback when not building with meson) ─────────

#[cfg(not(feature = "meson"))]
mod local_ffi {
    use std::ffi::c_void;
    use std::os::raw::{c_char, c_int};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(i32)]
    pub enum Errno {
        EPERM = 1,
        ENOENT = 2,
        ESRCH = 3,
        EINTR = 4,
        EIO = 5,
        ENXIO = 6,
        E2BIG = 7,
        ENOEXEC = 8,
        EBADF = 9,
        ECHILD = 10,
        EAGAIN = 11,
        ENOMEM = 12,
        EACCES = 13,
        EFAULT = 14,
        EBUSY = 16,
        EEXIST = 17,
        EXDEV = 18,
        ENODEV = 19,
        ENOTDIR = 20,
        EISDIR = 21,
        EINVAL = 22,
        ENFILE = 23,
        EMFILE = 24,
        ENOTTY = 25,
        EFBIG = 27,
        ENOSPC = 28,
        EROFS = 30,
        EMLINK = 31,
        EPIPE = 32,
        EDOM = 33,
        ERANGE = 34,
        ENAMETOOLONG = 36,
        ENOLCK = 37,
        ENOSYS = 38,
        ENOTEMPTY = 39,
        ELOOP = 40,
        ENOMSG = 42,
        EIDRM = 43,
        EADDRINUSE = 98,
        EADDRNOTAVAIL = 99,
        ENETDOWN = 100,
        ENETUNREACH = 101,
        ENETRESET = 102,
        ECONNABORTED = 103,
        ECONNRESET = 104,
        ENOBUFS = 105,
        EISCONN = 106,
        ENOTCONN = 107,
        ETIMEDOUT = 110,
        ECONNREFUSED = 111,
        EHOSTDOWN = 112,
        EHOSTUNREACH = 113,
        EALREADY = 114,
        EINPROGRESS = 115,
        ECANCELED = 125,
        EAFNOSUPPORT = 97,
        EOPNOTSUPP = 95,
        EPROTO = 71,
        EBADMSG = 74,
        EOVERFLOW = 75,
        ENODATA = 61,
        ENOLINK = 67,
        ENOKEY = 126,
        EBADR = 53,
        EUCLEAN = 117,
        EDEADLK = 35,
        EUNATCH = 49,
    }

    impl Errno {
        #[inline(always)]
        pub const fn to_neg_errno(self) -> c_int {
            -(self as i32)
        }
    }

    // ── External C functions ──────────────────────────────────────────────

    // SAFETY: these declarations mirror the target libc allocation, C-string,
    // and byte-memory ABIs. Callers retain the individual pointer obligations.
    unsafe extern "C" {
        pub fn malloc(size: usize) -> *mut c_void;
        pub fn calloc(nmemb: usize, size: usize) -> *mut c_void;
        pub fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
        pub fn free(ptr: *mut c_void);
        pub fn strlen(s: *const c_char) -> usize;
        pub fn strdup(s: *const c_char) -> *mut c_char;
        pub fn strcmp(a: *const c_char, b: *const c_char) -> c_int;
        pub fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int;
        pub fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        pub fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        pub fn memset(s: *mut c_void, c: c_int, n: usize) -> *mut c_void;
        pub fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
        pub fn mempcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    }
}

// ── Opaque struct declarations ──────────────────────────────────────────────
//
// These types are defined in C and are opaque from Rust's perspective.
// They are passed around as raw pointers across FFI boundaries.

macro_rules! opaque_type {
    ($(#[$meta:meta])* $name:ident) => {
        #[repr(C)]
        $(#[$meta])*
        pub struct $name {
            _private: [u8; 0],
        }
        impl $name {
            #[inline(always)]
            pub const fn as_ptr(&self) -> *const Self {
                self as *const Self
            }
        }
    };
}

opaque_type!(Manager);
opaque_type!(Link);
opaque_type!(LinkAddress);
opaque_type!(DnsAnswer);
opaque_type!(DnsAnswerItem);
opaque_type!(DnsPacket);
opaque_type!(DnsQuery);
opaque_type!(DnsQueryCandidate);
opaque_type!(DnsQuestion);
opaque_type!(DnsResourceKey);
opaque_type!(DnsResourceRecord);
opaque_type!(DnsScope);
opaque_type!(DnsServer);
opaque_type!(DnsSearchDomain);
opaque_type!(DnsStream);
opaque_type!(DnsStubListenerExtra);
opaque_type!(DnsTransaction);
opaque_type!(DnsTrustAnchor);
opaque_type!(DnsZone);
opaque_type!(DnsZoneItem);
opaque_type!(DnsDelegate);
opaque_type!(DnsServiceBrowser);
opaque_type!(DnssdService);
opaque_type!(DnssdDiscoveredService);
opaque_type!(DnssdTxtData);
opaque_type!(DnsTxtItem);
opaque_type!(DnsSvcParam);
opaque_type!(HookQuery);
opaque_type!(SocketGraveyard);
opaque_type!(EtcHosts);
opaque_type!(EtcHostsItemByAddress);
opaque_type!(EtcHostsItemByName);
opaque_type!(DnsCache);
opaque_type!(DnsTlsServerData);
opaque_type!(DnsTlsStreamData);
opaque_type!(DnsTlsManagerData);
opaque_type!(DnssdRegisteredService);

// ── C enum re-definitions ──────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsProtocol {
    Dns = 0,
    Llmnr = 1,
    Mdns = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsAnswerFlags {
    Authenticated = 1 << 0,
    Cacheable = 1 << 1,
    Shareable = 1 << 2,
    Conflicted = 1 << 3,
    Expired = 1 << 4,
    RcodeOnly = 1 << 5,
    Private = 1 << 6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsCacheMode {
    No = 0,
    Yes = 1,
    NoNegative = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsTransactionState {
    Null = 0,
    Pending = 1,
    Validating = 2,
    RcodeFailure = 3,
    Success = 4,
    NoServers = 5,
    Timeout = 6,
    AttemptsMaxReached = 7,
    InvalidReply = 8,
    Errno = 9,
    Aborted = 10,
    DnssecFailed = 11,
    NoTrustAnchor = 12,
    RrTypeUnsupported = 13,
    NetworkDown = 14,
    NotFound = 15,
    NoSource = 16,
    StubLoop = 17,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsTransactionSource {
    Network = 0,
    Cache = 1,
    Zone = 2,
    TrustAnchor = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecResult {
    Validated = 0,
    ValidatedWildcard = 1,
    Invalid = 2,
    SignatureExpired = 3,
    UnsupportedAlgorithm = 4,
    TooManyValidations = 5,
    NoSignature = 6,
    MissingKey = 7,
    Unsigned = 8,
    FailedAuxiliary = 9,
    NsecMismatch = 10,
    IncompatibleServer = 11,
    UpstreamFailure = 12,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecVerdict {
    Secure = 0,
    Insecure = 1,
    Bogus = 2,
    Indeterminate = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsScopeOrigin {
    Global = 0,
    Link = 1,
    Delegate = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolveConfigSource {
    File = 0,
    Networkd = 1,
    Dbus = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsSearchDomainType {
    System = 0,
    Link = 1,
    Delegate = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsServerType {
    System = 0,
    Fallback = 1,
    Link = 2,
    Delegate = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsServerFeatureLevel {
    Tcp = 0,
    Udp = 1,
    Edns0 = 2,
    TlsPlain = 3,
    Do = 4,
    TlsDo = 5,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsStreamType {
    Lookup = 0,
    LlmnrSend = 1,
    LlmnrRecv = 2,
    Stub = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsStubListenerMode {
    No = 0,
    Udp = 1 << 0,
    Tcp = 1 << 1,
    Yes = 3, // UDP | TCP
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsZoneItemState {
    Probing = 0,
    Established = 1,
    Verifying = 2,
    Withdrawn = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordTTLState {
    Percent80 = 0,
    Percent85 = 1,
    Percent90 = 2,
    Percent95 = 3,
    Percent100 = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsScopeMatch {
    No = 0,
    LastResort = 1,
    Maybe = 2,
    YesBase = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecNsecResult {
    NoRr = 0,
    Cname = 1,
    UnsupportedAlgorithm = 2,
    Nxdomain = 3,
    Nodata = 4,
    Found = 5,
    Optout = 6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolveSupport {
    No = 0,
    Yes = 1,
    Resolve = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnssecMode {
    No = 0,
    AllowDowngrade = 1,
    Yes = 2,
    Process = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsOverTlsMode {
    No = 0,
    Opportunistic = 1,
    Yes = 2,
}

// ── Network address types ───────────────────────────────────────────────────

/// C `union in_addr_union` — must match the C layout exactly.
#[repr(C)]
#[derive(Clone, Copy)]
pub union in_addr_union {
    pub in_addr: std::ffi::c_uint, // struct in_addr.s_addr (u32)
    pub in6_addr: [u8; 16],        // struct in6_addr (16 bytes)
    pub bytes: [u8; 16],
}

// ── DNS type constants ─────────────────────────────────────────────────────

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_ANY: u16 = 255;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_DNAME: u16 = 39;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_SRV: u16 = 33;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_DS: u16 = 43;
pub const DNS_TYPE_DNSKEY: u16 = 48;
pub const DNS_TYPE_RRSIG: u16 = 46;
pub const DNS_TYPE_NSEC: u16 = 47;
pub const DNS_TYPE_NSEC3: u16 = 50;

pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_CLASS_ANY: u16 = 255;

pub const DNS_RCODE_SUCCESS: c_int = 0;
pub const DNS_RCODE_NXDOMAIN: c_int = 3;
pub const DNS_RCODE_SERVFAIL: c_int = 2;

// ── SD_RESOLVED flags ──────────────────────────────────────────────────────

pub const SD_RESOLVED_DNS: u64 = 1 << 0;
pub const SD_RESOLVED_LLMNR: u64 = 1 << 1;
pub const SD_RESOLVED_MDNS: u64 = 1 << 2;
pub const SD_RESOLVED_LLMNR_IPV4: u64 = 1 << 3;
pub const SD_RESOLVED_LLMNR_IPV6: u64 = 1 << 4;
pub const SD_RESOLVED_MDNS_IPV4: u64 = 1 << 5;
pub const SD_RESOLVED_MDNS_IPV6: u64 = 1 << 6;
pub const SD_RESOLVED_AUTHENTICATED: u64 = 1 << 7;
pub const SD_RESOLVED_CONFIDENTIAL: u64 = 1 << 8;
pub const SD_RESOLVED_FROM_NETWORK: u64 = 1 << 9;
pub const SD_RESOLVED_FROM_CACHE: u64 = 1 << 10;
pub const SD_RESOLVED_FROM_ZONE: u64 = 1 << 11;
pub const SD_RESOLVED_FROM_TRUST_ANCHOR: u64 = 1 << 12;
pub const SD_RESOLVED_NO_CNAME: u64 = 1 << 13;
pub const SD_RESOLVED_NO_VALIDATE: u64 = 1 << 14;
pub const SD_RESOLVED_NO_CACHE: u64 = 1 << 15;
pub const SD_RESOLVED_NO_SEARCH: u64 = 1 << 16;
pub const SD_RESOLVED_NO_ZONE: u64 = 1 << 17;
pub const SD_RESOLVED_RR_TYPE_SRV: u64 = 1 << 18;
pub const SD_RESOLVED_RR_TYPE_MX: u64 = 1 << 19;
pub const SD_RESOLVED_RR_TYPE_TXT: u64 = 1 << 20;

// ── Address family constants ───────────────────────────────────────────────

pub const AF_UNSPEC: c_int = 0;
pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 10;

// ── Special addresses ──────────────────────────────────────────────────────

pub const INADDR_LOOPBACK: u32 = 0x7F000001;
pub const INADDR_LOCALADDRESS: u32 = 0x7F000002;
pub const INADDR_DNS_STUB: u32 = 0x7F000035; // 127.0.0.53
pub const INADDR_DNS_PROXY_STUB: u32 = 0x7F000036; // 127.0.0.54
pub const LOOPBACK_IFINDEX: c_int = 1;

// ── Misc constants ─────────────────────────────────────────────────────────

pub const DNS_N_LABELS_MAX: usize = 127;
pub const DNS_LABEL_MAX: usize = 63;
pub const DNS_HOSTNAME_MAX: usize = 253;

pub const USEC_INFINITY: u64 = u64::MAX;
pub const USEC_PER_SEC: u64 = 1_000_000;
pub const USEC_PER_MSEC: u64 = 1_000;

pub const IN_SET_VALUE: u8 = 1;
