//! Production driver for the PAM conversation: prompt the user for the
//! smart-card PIN through the live `pam_conv` callback.
//!
//! The safe parts of the API (the [`PamConvError`] enum and the
//! callback-based `prompt_pin_via_callback`) live in
//! [`pam_certauth_core::pam_conv`].  This module hosts the unsafe FFI glue
//! that talks to `libpam` via `pam-sys`, and is only compiled on Linux.
//!
//! The helper [`closure_from_pamh`] adapts a live PAM handle into a
//! `FnMut(&str) -> Result<SecretString, PamConvError>` closure suitable for
//! `pam_certauth_core::pkcs12::acquire_p12_material_with_prompter`.

#![cfg(target_os = "linux")]
#![allow(unsafe_code, clippy::similar_names)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

use pam_certauth_core::pam_conv::PamConvError;
use secrecy::SecretString;

// ----- Constants pulled from <security/pam_appl.h> ----------------------------
//
// pam-sys generates these via bindgen, but the constant names come out as
// `PAM_*` directly because of the `allowlist_var("PAM_.*")` rule in its
// build.rs.  We pull them in by name and pin them at the integer types the
// PAM ABI uses.  If the underlying header changes (e.g. on a new Astra
// release), this will surface as a build break rather than a silent skew.

const PAM_SUCCESS: c_int = pam_sys::PAM_SUCCESS as c_int;
const PAM_CONV: c_int = pam_sys::PAM_CONV as c_int;
const PAM_PROMPT_ECHO_OFF: c_int = pam_sys::PAM_PROMPT_ECHO_OFF as c_int;

// ----- ABI-compatible struct shapes ------------------------------------------
//
// We re-declare these locally because `pam-sys` exposes them under
// bindgen-generated names that vary across libpam versions
// (`pam_message`/`pam_response`/`pam_conv`).  The shapes below match the
// stable ABI defined in `pam_appl.h` on every Linux distribution we care
// about.

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            num_msg: c_int,
            msg: *mut *const PamMessage,
            resp: *mut *mut PamResponse,
            appdata_ptr: *mut c_void,
        ) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

extern "C" {
    /// `pam_get_item` is exposed by pam-sys but with a varying signature; we
    /// re-declare it to a known-stable shape.
    fn pam_get_item(
        pamh: *mut pam_sys::pam_handle_t,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;
}

extern "C" {
    /// libc `free` — used to release the `pam_response` allocations the conv
    /// callback hands back, per the PAM contract.
    fn free(ptr: *mut c_void);
}

/// Drive the live PAM conversation handle to ask for a PIN.
///
/// # Safety
///
/// `pamh` must be the live PAM handle handed to a `pam_sm_*` callback.  After
/// this call returns, the PAM-allocated response buffer is overwritten with
/// zeros and freed; callers MUST NOT retain any pointer derived from it.
///
/// # Errors
///
/// * [`PamConvError::NoConv`] — PAM did not return a `pam_conv` item.
/// * [`PamConvError::ConvFailed`] — the conv callback returned non-success
///   or produced a NULL response.
/// * [`PamConvError::NonUtf8`] — the response is not valid UTF-8.
pub unsafe fn prompt_pin(
    pamh: *mut pam_sys::pam_handle_t,
    prompt: &str,
) -> Result<SecretString, PamConvError> {
    let mut conv_ptr: *const c_void = std::ptr::null();
    // SAFETY: `pamh` is the live PAM handle (function safety contract);
    // `conv_ptr` is a stack-local out-pointer that libpam writes to.
    let rc = unsafe { pam_get_item(pamh, PAM_CONV, &raw mut conv_ptr) };
    if rc != PAM_SUCCESS || conv_ptr.is_null() {
        return Err(PamConvError::NoConv);
    }
    // SAFETY: pam_get_item returned PAM_SUCCESS and conv_ptr is non-null;
    // libpam guarantees it points to a `struct pam_conv` owned by the
    // PAM application for the lifetime of `pamh`.
    let conv: &PamConv = unsafe { &*(conv_ptr.cast::<PamConv>()) };
    let Some(conv_fn) = conv.conv else {
        return Err(PamConvError::NoConv);
    };

    // Build the prompt; CString::new fails only if there's an interior NUL,
    // which would be a programmer error.
    let c_prompt = CString::new(prompt).map_err(|_| PamConvError::ConvFailed)?;
    let msg = PamMessage {
        msg_style: PAM_PROMPT_ECHO_OFF,
        msg: c_prompt.as_ptr(),
    };
    // PAM expects an array-of-pointers.  Use a stack-allocated 1-elem array.
    let msg_ptr: *const PamMessage = &raw const msg;
    let mut msg_arr: [*const PamMessage; 1] = [msg_ptr];
    let mut resp_ptr: *mut PamResponse = std::ptr::null_mut();

    // SAFETY: `msg_arr` and `resp_ptr` are valid for the duration of this
    // call; `conv_fn` is the application-supplied callback obtained from
    // pam_get_item(PAM_CONV) and `conv.appdata_ptr` is opaque app state
    // owned by libpam. On success libpam allocates *resp_ptr and we
    // assume ownership of freeing it via libc::free.
    let rc = unsafe { conv_fn(1, msg_arr.as_mut_ptr(), &raw mut resp_ptr, conv.appdata_ptr) };
    if rc != PAM_SUCCESS || resp_ptr.is_null() {
        return Err(PamConvError::ConvFailed);
    }

    // SAFETY: conv_fn returned PAM_SUCCESS and resp_ptr is non-null; it
    // points to a heap-allocated `pam_response` owned by libpam that we
    // are now responsible for freeing.
    let resp = unsafe { &*resp_ptr };
    if resp.resp.is_null() {
        // SAFETY: resp_ptr is a non-null pointer to a libpam allocation
        // (libpam allocates pam_response with malloc); we did not retain
        // any other pointer derived from it.
        unsafe { free(resp_ptr.cast::<c_void>()) };
        return Err(PamConvError::ConvFailed);
    }

    // SAFETY: resp.resp is non-null (checked above) and libpam guarantees
    // it is a NUL-terminated C string holding the PIN reply.
    let pin_cstr = unsafe { CStr::from_ptr(resp.resp) };
    let pin_result = pin_cstr.to_str().map(str::to_string);

    // Always overwrite the PAM-allocated buffer before freeing — even on the
    // UTF-8-error path — to keep the PIN out of process memory longer than
    // strictly necessary.  The buffer is always at least one byte (the NUL
    // terminator).
    let len = pin_cstr.to_bytes().len();
    if len > 0 {
        // SAFETY: resp.resp points to `len` bytes of writable libpam-owned
        // memory (we just read exactly that many via CStr::from_ptr above);
        // zeroing in place before free does not extend its lifetime.
        unsafe { std::ptr::write_bytes(resp.resp.cast::<u8>(), 0_u8, len) };
    }
    // SAFETY: resp.resp is a non-null libpam-owned allocation (malloc'd
    // by the conv callback per the PAM contract); no other pointers
    // derived from it are retained past this call.
    unsafe { free(resp.resp.cast::<c_void>()) };
    // SAFETY: resp_ptr is a non-null libpam-owned allocation (malloc'd
    // by the conv callback per the PAM contract); no other pointers
    // derived from it are retained past this call.
    unsafe { free(resp_ptr.cast::<c_void>()) };

    let pin_str = pin_result.map_err(|_| PamConvError::NonUtf8)?;
    Ok(SecretString::from(pin_str))
}

/// Build a closure that drives `prompt_pin` against a captured PAM handle.
///
/// This is the production-side adapter consumed by
/// `pam_certauth_core::pkcs12::acquire_p12_material_with_prompter`.
///
/// # Safety
///
/// The returned closure captures `pamh` by value (as a raw pointer).  The
/// caller MUST ensure the closure does not outlive the PAM stack frame that
/// owns `pamh` (i.e. do not store the closure across `pam_sm_*` boundaries).
pub unsafe fn closure_from_pamh(
    pamh: *mut pam_sys::pam_handle_t,
) -> impl FnMut(&str) -> Result<SecretString, PamConvError> {
    move |prompt: &str| {
        // SAFETY: `pamh` was provided by PAM and is valid for the duration
        // captured above.  See the function-level safety contract.
        unsafe { prompt_pin(pamh, prompt) }
    }
}
