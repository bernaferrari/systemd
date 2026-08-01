// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/osc-context.c,src/shared/osc-context.h

//! Safe ownership-preserving wrappers for the OSC 3008 context API.
//!
//! `osc-context.c` deliberately owns identity collection, process-stable
//! context IDs, escaping, and the associated platform feature detection.  In
//! particular, it uses systemd's configured ID and digest implementation, not
//! an independently linked crypto backend.  Keep this module at that C seam
//! instead of duplicating the protocol or its configuration decisions here.

use std::ffi::{CStr, CString, c_char};
use std::fmt;
use std::io;
use std::ptr::NonNull;
use systemd_basic_rs::id128_util::SdId128;

/// The ABI-compatible `sd_id128_t` used by `osc-context.h`.
pub type Id128 = SdId128;

/// Failure returned by an OSC context operation.
#[derive(Debug)]
pub enum OscContextError {
    Io(io::Error),
    InvalidUtf8(std::string::FromUtf8Error),
}

impl fmt::Display for OscContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::InvalidUtf8(error) => {
                write!(f, "OSC context sequence is not valid UTF-8: {error}")
            }
        }
    }
}

impl std::error::Error for OscContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidUtf8(error) => Some(error),
        }
    }
}

impl From<io::Error> for OscContextError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<std::string::FromUtf8Error> for OscContextError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::InvalidUtf8(value)
    }
}

// SAFETY: These declarations match `src/shared/osc-context.h`. `Id128` is
// `SdId128`, whose `repr(C)`, size, and alignment are verified by
// `systemd-basic-rs` against C's `sd_id128_t`. Every pointer passed below is
// either null where the C API documents an optional argument or points to
// live, correctly typed storage for the duration of the call.
// SAFETY: The declaration block itself introduces no call; each invocation
// below repeats the pointer-lifetime conditions specific to that call.
unsafe extern "C" {
    #[link_name = "osc_context_open_boot"]
    fn c_osc_context_open_boot(ret_seq: *mut *mut c_char) -> libc::c_int;
    #[link_name = "osc_context_open_container"]
    fn c_osc_context_open_container(
        name: *const c_char,
        ret_seq: *mut *mut c_char,
        ret_context_id: *mut Id128,
    ) -> libc::c_int;
    #[link_name = "osc_context_open_vm"]
    fn c_osc_context_open_vm(
        name: *const c_char,
        ret_seq: *mut *mut c_char,
        ret_context_id: *mut Id128,
    ) -> libc::c_int;
    #[link_name = "osc_context_open_chpriv"]
    fn c_osc_context_open_chpriv(
        target_user: *const c_char,
        ret_seq: *mut *mut c_char,
        ret_context_id: *mut Id128,
    ) -> libc::c_int;
    #[link_name = "osc_context_open_session"]
    fn c_osc_context_open_session(
        user: *const c_char,
        session_id: *const c_char,
        ret_seq: *mut *mut c_char,
        ret_context_id: *mut Id128,
    ) -> libc::c_int;
    #[link_name = "osc_context_open_service"]
    fn c_osc_context_open_service(
        unit: *const c_char,
        invocation_id: Id128,
        ret_seq: *mut *mut c_char,
    ) -> libc::c_int;
    #[link_name = "osc_context_close"]
    fn c_osc_context_close(id: Id128, ret_seq: *mut *mut c_char) -> libc::c_int;
    #[link_name = "osc_context_id_from_invocation_id"]
    fn c_osc_context_id_from_invocation_id(id: Id128, ret: *mut Id128) -> libc::c_int;
}

/// An allocated sequence returned by the C API.
///
/// `osc-context.c` creates these with `asprintf()`, so `free()` is the exact
/// allocator-compatible destructor. The guard releases a sequence on both
/// UTF-8 conversion errors and normal return paths.
struct CSequence(NonNull<c_char>);

impl Drop for CSequence {
    fn drop(&mut self) {
        // SAFETY: `CSequence` is constructed only from a non-null sequence
        // allocated by `osc-context.c`; that C code documents `free()` as the
        // matching destructor, and this guard owns it exactly once.
        unsafe_ffi!(libc::free(self.0.as_ptr().cast()));
    }
}

fn invalid_argument() -> OscContextError {
    io::Error::from_raw_os_error(libc::EINVAL).into()
}

fn c_string(value: &str) -> Result<CString, OscContextError> {
    CString::new(value).map_err(|_| invalid_argument())
}

fn sequence_from_c_result(
    result: libc::c_int,
    sequence: *mut c_char,
) -> Result<Option<String>, OscContextError> {
    let sequence = NonNull::new(sequence).map(CSequence);

    if result < 0 {
        // Drop a defensively returned allocation on errors as well. Current C
        // implementations leave the output null on error, but this keeps the
        // Rust ownership boundary sound if that implementation changes.
        drop(sequence);
        return Err(io::Error::from_raw_os_error(-result).into());
    }

    let Some(sequence) = sequence else {
        return Ok(None);
    };

    // SAFETY: on success a non-null `ret_seq` is an `asprintf()`-allocated,
    // NUL-terminated C string owned by `sequence`; it remains alive until the
    // guard drops after this conversion copies its bytes.
    let bytes = unsafe_ffi!(CStr::from_ptr(sequence.0.as_ptr())).to_bytes();
    Ok(Some(String::from_utf8(bytes.to_vec())?))
}

fn required_sequence(
    result: libc::c_int,
    sequence: *mut c_char,
) -> Result<String, OscContextError> {
    sequence_from_c_result(result, sequence)?
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EPROTO).into())
}

/// Generate a boot-context opening sequence using C's configured identity and
/// process-stable default context ID.
pub fn osc_context_open_boot() -> Result<String, OscContextError> {
    let mut sequence = std::ptr::null_mut();
    // SAFETY: `sequence` is a live output slot for the duration of this call;
    // `osc_context_open_boot()` retains neither its address nor its contents.
    let result = unsafe_ffi!(c_osc_context_open_boot(&mut sequence));
    required_sequence(result, sequence)
}

/// Generate a container-context sequence and return the C-generated ID needed
/// to close it later. `None` maps directly to C's optional `name == NULL`.
pub fn osc_context_open_container(name: Option<&str>) -> Result<(String, Id128), OscContextError> {
    let name = name.map(c_string).transpose()?;
    let mut sequence = std::ptr::null_mut();
    let mut id = Id128::NULL;
    // SAFETY: optional `name` is either null or a NUL-terminated `CString`;
    // both output slots are live `osc-context.h`-compatible storage and C
    // retains none of the pointers after returning.
    let result = unsafe_ffi!({
        c_osc_context_open_container(
            name.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            &mut sequence,
            &mut id,
        )
    });
    Ok((required_sequence(result, sequence)?, id))
}

/// Generate a VM-context sequence and return the C-generated closing ID.
pub fn osc_context_open_vm(name: &str) -> Result<(String, Id128), OscContextError> {
    let name = c_string(name)?;
    let mut sequence = std::ptr::null_mut();
    let mut id = Id128::NULL;
    // SAFETY: `name` is a non-null NUL-terminated string as required by C;
    // output slots have the exact C ABI layout and outlive the call.
    let result = unsafe_ffi!(c_osc_context_open_vm(name.as_ptr(), &mut sequence, &mut id));
    Ok((required_sequence(result, sequence)?, id))
}

/// Generate a privilege-change context sequence and its C-generated closing
/// ID. C decides whether the target is a subcontext, elevation, or chpriv.
pub fn osc_context_open_chpriv(target_user: &str) -> Result<(String, Id128), OscContextError> {
    let target_user = c_string(target_user)?;
    let mut sequence = std::ptr::null_mut();
    let mut id = Id128::NULL;
    // SAFETY: `target_user` is non-null and NUL-terminated; output slots are
    // valid writable C ABI storage and are not retained by C.
    let result = unsafe_ffi!(c_osc_context_open_chpriv(
        target_user.as_ptr(),
        &mut sequence,
        &mut id
    ));
    Ok((required_sequence(result, sequence)?, id))
}

/// Generate a session-context sequence and return the C-generated closing ID.
/// Optional strings map directly to the nullable C arguments.
pub fn osc_context_open_session(
    user: Option<&str>,
    session_id: Option<&str>,
) -> Result<(String, Id128), OscContextError> {
    let user = user.map(c_string).transpose()?;
    let session_id = session_id.map(c_string).transpose()?;
    let mut sequence = std::ptr::null_mut();
    let mut id = Id128::NULL;
    // SAFETY: optional inputs are null or owned NUL-terminated C strings;
    // output slots are valid through the call and C does not retain them.
    let result = unsafe_ffi!({
        c_osc_context_open_session(
            user.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            session_id
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            &mut sequence,
            &mut id,
        )
    });
    Ok((required_sequence(result, sequence)?, id))
}

/// Generate a service-context sequence. The returned ID is calculated through
/// the same C helper used by the service sequence, so it is safe to pass to
/// [`osc_context_close`].
pub fn osc_context_open_service(
    unit: Option<&str>,
    invocation_id: Id128,
) -> Result<(String, Id128), OscContextError> {
    let unit = unit.map(c_string).transpose()?;
    let id = osc_context_id_from_invocation_id(invocation_id)?;
    let mut sequence = std::ptr::null_mut();
    // SAFETY: `unit` is null or a NUL-terminated string; `invocation_id` is a
    // by-value ABI-compatible `sd_id128_t`, and `sequence` is a live output
    // slot which C does not retain.
    let result = unsafe_ffi!({
        c_osc_context_open_service(
            unit.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            invocation_id,
            &mut sequence,
        )
    });
    Ok((required_sequence(result, sequence)?, id))
}

/// Generate the matching OSC closing sequence. A null ID intentionally maps
/// to `Ok(None)`, exactly as `osc_context_close()` documents.
pub fn osc_context_close(id: Id128) -> Result<Option<String>, OscContextError> {
    let mut sequence = std::ptr::null_mut();
    // SAFETY: `id` has the C ABI layout and `sequence` is a live output slot;
    // C retains neither and returns an owned sequence when it is non-null.
    let result = unsafe_ffi!(c_osc_context_close(id, &mut sequence));
    sequence_from_c_result(result, sequence)
}

/// Derive the opaque service context ID using the C implementation's
/// application-specific ID helper.
pub fn osc_context_id_from_invocation_id(invocation_id: Id128) -> Result<Id128, OscContextError> {
    let mut id = Id128::NULL;
    // SAFETY: `id` is writable `sd_id128_t`-layout storage for the duration of
    // the call, and C retains neither it nor the by-value invocation ID.
    let result = unsafe_ffi!(c_osc_context_id_from_invocation_id(invocation_id, &mut id));
    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result).into());
    }
    Ok(id)
}
