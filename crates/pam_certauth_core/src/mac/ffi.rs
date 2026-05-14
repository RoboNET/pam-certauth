//! Raw FFI bindings to Astra Linux's `libpdp` (МКЦ — mandatory integrity
//! control) text-API.  Only compiled when the `astra-mac` cargo feature is
//! enabled (the linker directive lives in `build.rs`).
//!
//! Verified symbols (Astra SE 1.8.4, `nm -D /usr/lib/libpdp.so.3`):
//! `pdp_set_pid`, `pdp_get_pid`, `pdp_get_fd`, `pdp_set_fd`, `pdp_set_path`,
//! `pdp_get_lpath`, `pdpl_get_from_text`, `pdpl_get_text`, `pdpl_put`,
//! `parsec_strict_mode`, `parsec_enabled`, `parsec_astramode`,
//! `pdp_get_current_ilev`.  All `pdp_get_*` and `pdpl_get_*` are
//! return-pointer style per `pdp.h` (NULL on failure); `pdp_set_*` returns
//! `int` (0 on success).
//!
//! NB: `pdp_set_current` is an inline wrapper around `pdp_set_pid(0, l)` in
//! `pdp.h` — there is no `pdp_set_current` symbol in the `.so`.  We always
//! call `pdp_set_pid(0, ...)` directly.
//!
//! `parsec_capget` exact link location is TBD-runtime-verified: if the first
//! Astra deb build fails to resolve it, switch the extern block link name to
//! `parsec-base` AND emit `cargo:rustc-link-lib=parsec-base` from
//! `build.rs`.
//!
//! Real semantics are exercised on the Astra VM via `test-mac.sh` (Phase 10
//! E2E).  Dev-host CI only `cargo check`s this module under `astra-mac`.

#![allow(unsafe_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::io::RawFd;
use std::path::Path;
use std::ptr;

use crate::mac::backend::MacRuntime;
use crate::mac::text_codec::{decode_label_text, encode_label_text, McFlag};
use crate::mac::{IntegrityLabel, MacError};

// ---------------------------------------------------------------------------
// extern declarations
// ---------------------------------------------------------------------------

#[link(name = "pdp")]
unsafe extern "C" {
    fn pdp_set_pid(pid: libc::pid_t, label: *const c_void) -> c_int;
    fn pdp_get_pid(pid: libc::pid_t) -> *mut c_void;
    fn pdp_set_fd(fd: c_int, label: *const c_void) -> c_int;
    fn pdp_get_fd(fd: c_int) -> *mut c_void;
    fn pdp_set_path(path: *const c_char, label: *const c_void) -> c_int;
    fn pdp_get_lpath(path: *const c_char) -> *mut c_void;
    fn pdp_get_peer_label(sockfd: c_int) -> *mut c_void;

    fn pdpl_get_from_text(text: *const c_char) -> *mut c_void;
    fn pdpl_get_text(label: *const c_void, flags: c_int) -> *mut c_char;
    fn pdpl_put(label: *mut c_void);

    fn parsec_strict_mode() -> c_int;

    fn getmicnam(name: *const c_char) -> *mut MicUser;
    fn freemicent_r(ent: *mut MicUser);
}

// `parsec_capget` lives in libpdp on Astra 1.8.4 according to current
// best-guess.  If linking on the deb build fails, move this block to
// `#[link(name = "parsec-base")]` and add the matching directive in
// `build.rs`.
#[link(name = "pdp")]
unsafe extern "C" {
    fn parsec_capget(pid: libc::pid_t, caps: *mut ParsecCaps) -> c_int;
}

// ---------------------------------------------------------------------------
// FFI record layouts
// ---------------------------------------------------------------------------

/// `struct mic_user` per `mic.h` (best-guess layout).
///
/// NB: the actual width of `mic_t` (here modelled as `u32`) is not verified
/// against runtime headers.  If Task 4.0 on the Astra VM reveals a wider
/// type, broaden this field and saturate the cast in [`get_user_mnkc`].
#[repr(C)]
struct MicUser {
    il: u32,
    name: *mut c_char,
}

/// `parsec_caps_t` per `parsec.h` (best-guess layout).
///
/// NB: exact field widths are TBD until runtime-verified on the Astra deb
/// build.  Bit 3 (`PARSEC_CAP_CHMAC`) is what we test in
/// [`check_chmac_capability`]; if the struct turns out narrower (e.g. `u32`
/// per field), the bit-3 mask still works but layout must be re-checked.
#[repr(C)]
#[allow(clippy::struct_field_names)]
struct ParsecCaps {
    cap_effective: u64,
    cap_inheritable: u64,
    cap_permitted: u64,
}

/// PARSEC capability bit for CHMAC (modify file labels).
pub const PARSEC_CAP_CHMAC: u32 = 3;

// ---------------------------------------------------------------------------
// Pdpl: opaque label handle with RAII
// ---------------------------------------------------------------------------

/// Owned wrapper around an opaque `pdpl_t` heap allocation.  `pdpl_put` is
/// invoked on drop so we never leak.
struct Pdpl(*mut c_void);

impl Pdpl {
    /// Build a `Pdpl` from a [`IntegrityLabel`] + optional flag set by going
    /// through `pdpl_get_from_text`.
    fn from_label(label: IntegrityLabel, flags: &[McFlag]) -> Result<Self, MacError> {
        let text = encode_label_text(label, flags);
        let c = CString::new(text)
            .map_err(|e| MacError::TextFormat(format!("interior NUL in label text: {e}")))?;
        // SAFETY: `c.as_ptr()` is a valid NUL-terminated C string owned by
        // `c` for the duration of the call; libpdp returns a fresh
        // allocation or NULL on error per pdp.h.
        let raw = unsafe { pdpl_get_from_text(c.as_ptr()) };
        if raw.is_null() {
            return Err(MacError::Parsec {
                op: "pdpl_get_from_text",
                rc: -1,
            });
        }
        Ok(Self(raw))
    }

    /// Decode this label into an [`IntegrityLabel`] via `pdpl_get_text` +
    /// the pure-Rust [`decode_label_text`] codec.
    fn to_label(&self) -> Result<IntegrityLabel, MacError> {
        // SAFETY: `self.0` is a valid `pdpl_t` (constructed via
        // `pdpl_get_from_text` and not yet freed); libpdp returns either a
        // freshly malloc'd C string or NULL on failure (pdp.h).
        let raw = unsafe { pdpl_get_text(self.0, 0) };
        if raw.is_null() {
            return Err(MacError::Parsec {
                op: "pdpl_get_text",
                rc: -1,
            });
        }
        // SAFETY: libpdp guarantees `raw` is a valid NUL-terminated C
        // string that we must free with `libc::free`.
        let s = unsafe { CStr::from_ptr(raw) }
            .to_str()
            .map_err(|e| MacError::TextFormat(format!("non-UTF8 label text: {e}")))?
            .to_owned();
        // SAFETY: `raw` came from libpdp which allocates with libc malloc.
        unsafe { libc::free(raw.cast()) };
        decode_label_text(&s)
    }

    fn as_ptr(&self) -> *const c_void {
        self.0
    }
}

impl Drop for Pdpl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was produced by `pdpl_get_from_text` (or an
            // equivalent libpdp ctor) and is freed exactly once here.
            unsafe { pdpl_put(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

fn path_to_cstring(p: &Path) -> Result<CString, MacError> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes())
        .map_err(|e| MacError::TextFormat(format!("interior NUL in path: {e}")))
}

/// Probe the running kernel/userspace for MAC support.  Returns
/// [`MacRuntime::Active`] iff PARSEC is enabled (any non-zero from
/// `parsec_enabled`).
#[must_use]
pub fn probe_runtime() -> MacRuntime {
    // SAFETY: parameterless libpdp call; safe in all states.
    let strict = unsafe { parsec_strict_mode() };
    match strict {
        1 => MacRuntime::Active,
        0 => MacRuntime::Disabled,
        _ => MacRuntime::Unavailable,
    }
}

/// Apply `label` to the current process via `pdp_set_pid(0, l)`.
///
/// # Errors
/// Returns [`MacError::Parsec`] if the kernel rejects the label (e.g.
/// exceeds the process's MNKC bound).
pub fn set_proc(label: IntegrityLabel) -> Result<(), MacError> {
    let p = Pdpl::from_label(label, &[])?;
    // SAFETY: `p.as_ptr()` is a valid `pdpl_t` for the duration of this
    // call; `0` selects the current pid per the `pdp_set_current` inline
    // wrapper convention in `pdp.h`.
    let rc = unsafe { pdp_set_pid(0, p.as_ptr()) };
    if rc != 0 {
        return Err(MacError::Parsec {
            op: "pdp_set_pid",
            rc,
        });
    }
    Ok(())
}

/// Check whether the current process holds `PARSEC_CAP_CHMAC`.
///
/// Returns `false` on any FFI error — callers should treat this as a soft
/// warning (we still attempt the operation; the kernel will reject if the
/// capability is truly missing).
#[must_use]
pub fn check_chmac_capability() -> bool {
    use std::mem::MaybeUninit;
    let mut caps: MaybeUninit<ParsecCaps> = MaybeUninit::zeroed();
    // SAFETY: `parsec_capget` accepts an out-pointer to a `parsec_caps_t`
    // and writes the effective/inheritable/permitted bitsets on success.
    // `pid=0` selects the calling process per libparsec convention.
    let rc = unsafe { parsec_capget(0, caps.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    // SAFETY: rc==0 ⇒ libpdp has fully initialised the struct.
    let caps = unsafe { caps.assume_init() };
    (caps.cap_effective & (1u64 << PARSEC_CAP_CHMAC)) != 0
}

/// Resolve the maximum МКЦ label allowed for `user` (the `MNKC` value from
/// `mic.db`).  Categories are reported as zero — mic-cat is not modelled in
/// v1.
///
/// # Errors
/// [`MacError::UserUnknown`] if `getmicnam` returns NULL.
pub fn get_user_mnkc(user: &str) -> Result<IntegrityLabel, MacError> {
    let c = CString::new(user)
        .map_err(|e| MacError::TextFormat(format!("interior NUL in user: {e}")))?;
    // SAFETY: `c.as_ptr()` is a valid NUL-terminated C string for the call;
    // libpdp returns either NULL or a heap pointer we must free with
    // `freemicent_r`.
    let ent = unsafe { getmicnam(c.as_ptr()) };
    if ent.is_null() {
        return Err(MacError::UserUnknown {
            user: user.to_owned(),
        });
    }
    // SAFETY: `ent` is non-NULL libpdp-allocated `mic_user`.
    let il = unsafe { (*ent).il };
    // SAFETY: matched against the libpdp allocation; freed exactly once.
    unsafe { freemicent_r(ent) };
    // Saturate to i8::MAX — `mic_t` width on Astra may exceed our wrapper's
    // representation.  v1 does not model mic-cat → categories = 0.
    let level = i8::try_from(il).unwrap_or(i8::MAX);
    Ok(IntegrityLabel {
        level,
        categories: 0,
    })
}

/// Read the МКЦ label currently attached to `path`.
///
/// # Errors
/// Returns [`MacError::Parsec`] on libpdp failure.
pub fn get_file_label(path: &Path) -> Result<IntegrityLabel, MacError> {
    let c = path_to_cstring(path)?;
    // SAFETY: `c.as_ptr()` is valid for the duration of the call; libpdp
    // returns either a fresh `pdpl_t` allocation or NULL on failure.
    let raw = unsafe { pdp_get_lpath(c.as_ptr()) };
    if raw.is_null() {
        return Err(MacError::Parsec {
            op: "pdp_get_lpath",
            rc: -1,
        });
    }
    let p = Pdpl(raw);
    p.to_label()
}

/// Set the МКЦ label on `path`.  When `irelax` is true, the encoded text
/// label includes the `irelax` flag so libpdp performs a write-down where
/// supported.
///
/// # Errors
/// Returns [`MacError::Parsec`] on libpdp failure.
pub fn set_file_label(path: &Path, label: IntegrityLabel, irelax: bool) -> Result<(), MacError> {
    let flags: &[McFlag] = if irelax { &[McFlag::Irelax] } else { &[] };
    let p = Pdpl::from_label(label, flags)?;
    let c = path_to_cstring(path)?;
    // SAFETY: `c.as_ptr()` and `p.as_ptr()` are valid for the call.
    let rc = unsafe { pdp_set_path(c.as_ptr(), p.as_ptr()) };
    if rc != 0 {
        return Err(MacError::Parsec {
            op: "pdp_set_path",
            rc,
        });
    }
    Ok(())
}

/// Set the МКЦ label on the open file descriptor `fd`.  Used by the
/// sessions.json writer to close the path-based TOCTOU window.
///
/// # Errors
/// Returns [`MacError::Parsec`] on libpdp failure.
pub fn set_fd_label(fd: RawFd, label: IntegrityLabel, irelax: bool) -> Result<(), MacError> {
    let flags: &[McFlag] = if irelax { &[McFlag::Irelax] } else { &[] };
    let p = Pdpl::from_label(label, flags)?;
    // SAFETY: `fd` is owned by the caller for the duration of this call;
    // `p.as_ptr()` is a valid `pdpl_t`.
    let rc = unsafe { pdp_set_fd(fd as c_int, p.as_ptr()) };
    if rc != 0 {
        return Err(MacError::Parsec {
            op: "pdp_set_fd",
            rc,
        });
    }
    Ok(())
}

// Reference-only forwards so the linker keeps the otherwise-unused symbols
// in test builds and so `cargo check --features astra-mac` flags missing
// declarations early.  These do not get called.
#[allow(dead_code)]
fn _unused_link_anchor() {
    // SAFETY: never called; references kept solely to anchor symbols for
    // the linker and surface missing declarations early during
    // `cargo check --features astra-mac`.
    let _ = pdp_get_pid as unsafe extern "C" fn(_) -> _;
    let _ = pdp_get_fd as unsafe extern "C" fn(_) -> _;
    let _ = pdp_get_peer_label as unsafe extern "C" fn(_) -> _;
    let _ = parsec_strict_mode as unsafe extern "C" fn() -> _;
}
