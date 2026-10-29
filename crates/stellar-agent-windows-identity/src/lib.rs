//! Safe wrappers for Windows-only Win32 FFI: the process-user account SID
//! lookup and DPAPI (`CryptProtectData`/`CryptUnprotectData`) CurrentUser-scope
//! protect/unprotect.
//!
//! `stellar-agent-core` forbids unsafe code. This small Windows-only crate
//! contains the Win32 FFI these two callers need and exposes safe APIs.
//!
//! - [`current_user_sid_string`] reads the current process token's user
//!   account SID. The SID binds approval attestations to the OS user that
//!   created them, so an attestation blob minted by one user cannot be
//!   replayed by another user on the same machine.
//! - `create_owner_only_directory` creates a directory whose protected DACL
//!   grants access to the current user only, inherited by everything created
//!   inside it; `path_dacl_sddl` reads a path's DACL back as SDDL, and
//!   `admits_only_current_user` checks that a path's DACL grants nothing to
//!   anyone else. The CLI writes its private browser redirect file into such
//!   a directory. All three are Windows-only and have no stub on other
//!   targets.
//! - [`dpapi_protect`] / [`dpapi_unprotect`] wrap DPAPI CurrentUser-scope
//!   protect/unprotect, and [`dpapi_protect_with_entropy`] /
//!   [`dpapi_unprotect_with_entropy`] add DPAPI's optional entropy, consumed
//!   by `stellar-agent-headless-keyring`'s `dpapi` protection mode. Both calls require access to the current user's
//!   DPAPI master key and pass `CRYPTPROTECT_UI_FORBIDDEN` to prevent UI prompts.
//!   Key-authenticated SSH sessions can lack master-key access; an interactive
//!   desktop logon may help. The wallet's `headless-env` backend avoids this
//!   dependency and requires its configured encryption key.
//!
//! Protect failures expose typed numeric Windows codes when available. The
//! wallet reports `auth.keyring_platform_error` naming `CryptProtectData`.
//! The headless keyring keeps unprotect failures detail-free, exposing no
//! decryption reason or code to the wallet.

/// Errors returned by the Windows SID lookup wrapper.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WindowsIdentityError {
    /// A Win32 API returned failure. The code is from `GetLastError()`.
    #[error("{api} failed with Windows error {code}")]
    Win32 {
        /// The Win32 API label.
        api: &'static str,
        /// The numeric `GetLastError()` value.
        code: u32,
    },
    /// Win32 returned a null pointer where a valid pointer was required.
    #[error("{api} returned a null pointer")]
    NullPointer {
        /// The Win32 API label.
        api: &'static str,
    },
    /// The returned SID string was not valid UTF-16.
    #[error("SID string was not valid UTF-16")]
    InvalidUtf16,
    /// A returned security-descriptor string was not valid UTF-16.
    #[error("security descriptor string was not valid UTF-16")]
    SddlNotUtf16,
    /// A path passed to a Win32 API contains a NUL character.
    #[error("path contains a NUL character")]
    PathContainsNul,
    /// Returned only by the non-Windows stub of [`current_user_sid_string`];
    /// unreachable when the crate is used as intended, behind a Windows cfg.
    #[error("Windows SID lookup is only available on Windows")]
    UnsupportedPlatform,
}

/// Returns the current process token user's SID string, for example
/// `S-1-5-21-...`.
///
/// # Errors
///
/// Returns [`WindowsIdentityError`] if any Win32 call fails or the returned SID
/// string cannot be decoded.
#[cfg(target_os = "windows")]
pub fn current_user_sid_string() -> Result<String, WindowsIdentityError> {
    windows::current_user_sid_string()
}

/// Non-Windows stub so the wrapper crate remains buildable on authoring hosts.
///
/// `stellar-agent-core` only calls this crate behind `#[cfg(target_os =
/// "windows")]`; this function exists for direct crate tests and docs on other
/// platforms.
///
/// # Errors
///
/// Always returns [`WindowsIdentityError::UnsupportedPlatform`] on non-Windows
/// targets.
#[cfg(not(target_os = "windows"))]
pub fn current_user_sid_string() -> Result<String, WindowsIdentityError> {
    Err(WindowsIdentityError::UnsupportedPlatform)
}

/// Creates `path` as a new directory whose DACL grants full access to the
/// current process user only.
///
/// The DACL is protected, so nothing is inherited from the parent, and its
/// single access-allowed ACE carries object and container inheritance, so
/// every file and directory later created inside receives the same
/// user-only ACE. The directory is created with that descriptor in one
/// `CreateDirectoryW` call; there is no moment at which it exists with a
/// broader DACL. An existing path, a symbolic link included, fails with
/// `ERROR_ALREADY_EXISTS` and is never reused.
///
/// # Errors
///
/// Returns [`WindowsIdentityError`] if the SID lookup, the security-descriptor
/// conversion, or the directory creation fails, or if `path` contains a NUL.
#[cfg(target_os = "windows")]
pub fn create_owner_only_directory(path: &std::path::Path) -> Result<(), WindowsIdentityError> {
    windows::create_owner_only_directory(path)
}

/// Returns the DACL of `path` in SDDL form, for example
/// `D:P(A;OICI;FA;;;S-1-5-21-...)`.
///
/// # Errors
///
/// Returns [`WindowsIdentityError`] if the security information cannot be
/// read or converted, or if `path` contains a NUL.
#[cfg(target_os = "windows")]
pub fn path_dacl_sddl(path: &std::path::Path) -> Result<String, WindowsIdentityError> {
    windows::path_dacl_sddl(path)
}

/// Returns `true` iff the DACL of `path` holds only access-allowed ACEs for
/// the current process user, at least one of them, and, when
/// `require_protected` is set, is protected from inheritance.
///
/// # Errors
///
/// Returns [`WindowsIdentityError`] if the SID lookup or the DACL read fails.
#[cfg(target_os = "windows")]
pub fn admits_only_current_user(
    path: &std::path::Path,
    require_protected: bool,
) -> Result<bool, WindowsIdentityError> {
    let sid = current_user_sid_string()?;
    let sddl = path_dacl_sddl(path)?;
    Ok(dacl_sddl_admits_only(&sddl, &sid, require_protected))
}

/// Decides [`admits_only_current_user`] on an SDDL DACL string.
///
/// The string has the form `D:<flags>(<ace>)(<ace>)...`; each ACE is
/// `type;flags;rights;object;inherit-object;sid`. Every ACE must be an allow
/// ACE (`A`) whose trustee is exactly `sid`, and there must be at least one.
/// An empty DACL (`D:` with no ACE) grants nothing to anyone and is refused
/// too, as is a NULL DACL (`D:NO_ACCESS_CONTROL`), which grants everything.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn dacl_sddl_admits_only(sddl: &str, sid: &str, require_protected: bool) -> bool {
    let Some(body) = sddl.strip_prefix("D:") else {
        return false;
    };
    let split = body.find('(').unwrap_or(body.len());
    let (flags, mut aces) = body.split_at(split);
    if flags.contains("NO_ACCESS_CONTROL") || (require_protected && !flags.contains('P')) {
        return false;
    }
    let mut count = 0usize;
    while !aces.is_empty() {
        let Some(rest) = aces.strip_prefix('(') else {
            return false;
        };
        let Some(end) = rest.find(')') else {
            return false;
        };
        let fields: Vec<&str> = rest[..end].split(';').collect();
        if fields.len() != 6 || fields[0] != "A" || fields[5] != sid {
            return false;
        }
        count += 1;
        aces = &rest[end + 1..];
    }
    count > 0
}

/// Errors returned by the DPAPI protect/unprotect wrappers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DpapiError {
    /// A DPAPI Win32 API returned failure. The code is from `GetLastError()`.
    #[error("{api} failed with Windows error {code}")]
    Win32 {
        /// The Win32 API label (`"CryptProtectData"` or `"CryptUnprotectData"`).
        api: &'static str,
        /// The numeric `GetLastError()` value.
        code: u32,
    },
    /// DPAPI returned a null output buffer despite reporting success.
    #[error("{api} reported success but returned a null buffer")]
    NullBuffer {
        /// The Win32 API label.
        api: &'static str,
    },
    /// The input exceeds DPAPI's `u32` length field. Unreachable for
    /// keyring-sized secrets; refusing is strictly safer than sealing a
    /// silently truncated prefix.
    #[error("input exceeds the DPAPI maximum length")]
    InputTooLarge,
    /// Returned only by the non-Windows stubs of [`dpapi_protect`] /
    /// [`dpapi_unprotect`]; unreachable when the crate is used as intended,
    /// behind a Windows cfg.
    #[error("DPAPI is only available on Windows")]
    UnsupportedPlatform,
}

/// Encrypts `plaintext` with DPAPI CurrentUser scope
/// (`CryptProtectData`, no optional entropy, no `LOCAL_MACHINE` flag).
///
/// Processes running as the same Windows user can decrypt with
/// [`dpapi_unprotect`] when their session can access that user's DPAPI master
/// key. Passes `CRYPTPROTECT_UI_FORBIDDEN` to prevent UI prompts.
///
/// # Errors
///
/// Returns [`DpapiError`] if the underlying `CryptProtectData` call fails.
#[cfg(target_os = "windows")]
pub fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    dpapi::protect(plaintext, None)
}

/// Decrypts `ciphertext` previously produced by [`dpapi_protect`].
///
/// # Errors
///
/// Returns [`DpapiError`] if the underlying `CryptUnprotectData` call fails
/// (including the fail-closed case of a corrupted or tampered blob — DPAPI
/// blobs carry their own integrity protection, and a modified blob fails to
/// unprotect rather than silently returning altered plaintext).
#[cfg(target_os = "windows")]
pub fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    dpapi::unprotect(ciphertext, None)
}

/// Encrypts `plaintext` as [`dpapi_protect`] does, with `entropy` as DPAPI's
/// optional entropy.
///
/// The blob opens only through [`dpapi_unprotect_with_entropy`] with the same
/// `entropy`, so a caller that passes what a value is stored under binds the
/// blob to that place.
///
/// # Errors
///
/// Returns [`DpapiError`] if the underlying `CryptProtectData` call fails, or
/// [`DpapiError::InputTooLarge`] when either input exceeds DPAPI's length
/// field.
#[cfg(target_os = "windows")]
pub fn dpapi_protect_with_entropy(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, DpapiError> {
    dpapi::protect(plaintext, Some(entropy))
}

/// Decrypts `ciphertext` produced by [`dpapi_protect_with_entropy`] with the
/// same `entropy`.
///
/// # Errors
///
/// Returns [`DpapiError`] if the underlying `CryptUnprotectData` call fails,
/// which includes an `entropy` other than the one the blob was sealed with and
/// a blob sealed with no entropy.
#[cfg(target_os = "windows")]
pub fn dpapi_unprotect_with_entropy(
    ciphertext: &[u8],
    entropy: &[u8],
) -> Result<Vec<u8>, DpapiError> {
    dpapi::unprotect(ciphertext, Some(entropy))
}

/// Non-Windows stub; see [`current_user_sid_string`]'s stub doc for the
/// rationale (this crate must stay buildable on authoring hosts).
///
/// # Errors
///
/// Always returns [`DpapiError::UnsupportedPlatform`] on non-Windows targets.
#[cfg(not(target_os = "windows"))]
pub fn dpapi_protect(_plaintext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    Err(DpapiError::UnsupportedPlatform)
}

/// Non-Windows stub; see [`dpapi_protect`]'s stub doc for the rationale.
///
/// # Errors
///
/// Always returns [`DpapiError::UnsupportedPlatform`] on non-Windows targets.
#[cfg(not(target_os = "windows"))]
pub fn dpapi_unprotect(_ciphertext: &[u8]) -> Result<Vec<u8>, DpapiError> {
    Err(DpapiError::UnsupportedPlatform)
}

/// Non-Windows stub; see [`dpapi_protect`]'s stub doc for the rationale.
///
/// # Errors
///
/// Always returns [`DpapiError::UnsupportedPlatform`] on non-Windows targets.
#[cfg(not(target_os = "windows"))]
pub fn dpapi_protect_with_entropy(
    _plaintext: &[u8],
    _entropy: &[u8],
) -> Result<Vec<u8>, DpapiError> {
    Err(DpapiError::UnsupportedPlatform)
}

/// Non-Windows stub; see [`dpapi_protect`]'s stub doc for the rationale.
///
/// # Errors
///
/// Always returns [`DpapiError::UnsupportedPlatform`] on non-Windows targets.
#[cfg(not(target_os = "windows"))]
pub fn dpapi_unprotect_with_entropy(
    _ciphertext: &[u8],
    _entropy: &[u8],
) -> Result<Vec<u8>, DpapiError> {
    Err(DpapiError::UnsupportedPlatform)
}

// The Win32 FFI is the only place in the crate that needs unsafe; the workspace
// `unsafe_code = "deny"` lint stays in force everywhere else.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod windows {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::WindowsIdentityError;

    /// Owns a `LocalAlloc`-backed allocation returned by a Win32 API and
    /// releases it with `LocalFree` exactly once, on drop.
    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by the Win32 API that
                // returned it, which documents `LocalFree` as its release;
                // it is released exactly once, here.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    /// `path` as a NUL-terminated UTF-16 string.
    fn wide_path(path: &Path) -> Result<Vec<u16>, WindowsIdentityError> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(WindowsIdentityError::PathContainsNul);
        }
        wide.push(0);
        Ok(wide)
    }

    pub(super) fn create_owner_only_directory(path: &Path) -> Result<(), WindowsIdentityError> {
        let sid = current_user_sid_string()?;
        // A protected DACL (`P`) with one ACE: allow (`A`) full file access
        // (`FA`) to the current user, inherited by files (`OI`) and
        // subdirectories (`CI`) created inside.
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{sid})")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `sddl` is a NUL-terminated UTF-16 string live for the call;
        // `descriptor` is a valid out-pointer and the size out-pointer may be
        // null. On success the descriptor is a LocalAlloc allocation, owned
        // below by `LocalAllocation`.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(last_error(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }
        if descriptor.is_null() {
            return Err(WindowsIdentityError::NullPointer {
                api: "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            });
        }
        let descriptor = LocalAllocation(descriptor);

        let wide = wide_path(path)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // SAFETY: `wide` is a NUL-terminated UTF-16 path and `attributes`
        // points to the live self-relative descriptor; both outlive the call.
        let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
        if created == 0 {
            return Err(last_error("CreateDirectoryW"));
        }
        Ok(())
    }

    pub(super) fn path_dacl_sddl(path: &Path) -> Result<String, WindowsIdentityError> {
        let wide = wide_path(path)?;
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `wide` is a NUL-terminated UTF-16 path live for the call.
        // Only the descriptor out-pointer is requested; the owner, group,
        // DACL and SACL out-pointers may be null. On success the descriptor
        // is a LocalAlloc allocation, owned below by `LocalAllocation`.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(WindowsIdentityError::Win32 {
                api: "GetNamedSecurityInfoW",
                code: status,
            });
        }
        if descriptor.is_null() {
            return Err(WindowsIdentityError::NullPointer {
                api: "GetNamedSecurityInfoW",
            });
        }
        let descriptor = LocalAllocation(descriptor);

        let mut sddl: *mut u16 = null_mut();
        // SAFETY: `descriptor.0` is the live descriptor returned above and
        // `sddl` is a valid out-pointer; the length out-pointer may be null.
        // On success the string is a LocalAlloc allocation, owned below.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(last_error(
                "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            ));
        }
        if sddl.is_null() {
            return Err(WindowsIdentityError::NullPointer {
                api: "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            });
        }
        let allocation = LocalAllocation(sddl.cast::<c_void>());
        // SAFETY: `sddl` is non-null (checked above) and points to the
        // NUL-terminated UTF-16 string the conversion produced, live until
        // `allocation` drops at the end of this function.
        let decoded = unsafe { wide_null_terminated_to_string(sddl) }
            .map_err(|_| WindowsIdentityError::SddlNotUtf16);
        drop(allocation);
        decoded
    }

    struct TokenHandle(HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is a token handle returned by
                // `OpenProcessToken`; closing it exactly once is required by the
                // Win32 ownership contract.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub(super) fn current_user_sid_string() -> Result<String, WindowsIdentityError> {
        let mut token: HANDLE = null_mut();
        // SAFETY: `GetCurrentProcess` returns the current pseudo-handle and
        // `token` is a valid out-pointer for `OpenProcessToken`.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(last_error("OpenProcessToken"));
        }
        if token.is_null() {
            return Err(WindowsIdentityError::NullPointer {
                api: "OpenProcessToken",
            });
        }
        let token = TokenHandle(token);

        let mut needed_len = 0_u32;
        // SAFETY: The null buffer + zero length pattern is the documented size
        // query for `GetTokenInformation`; `needed_len` is a valid out-pointer.
        // The BOOL result is intentionally ignored: the size probe is expected
        // to return FALSE (ERROR_INSUFFICIENT_BUFFER) while still writing the
        // required length, so success is judged by a non-zero `needed_len`.
        unsafe {
            GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed_len);
        }
        if needed_len == 0 {
            return Err(last_error("GetTokenInformation(size)"));
        }

        // `TOKEN_USER` begins with a pointer field (`SID_AND_ATTRIBUTES.Sid`),
        // so on 64-bit targets it requires 8-byte alignment. A `Vec<u8>`
        // guarantees only alignment 1, so back the buffer with `u64`
        // (alignment 8) and round the element count up; `GetTokenInformation`
        // still receives the size in bytes.
        let word_len = (needed_len as usize).div_ceil(size_of::<u64>());
        let mut buffer = vec![0_u64; word_len];
        // SAFETY: `buffer` holds `word_len * 8 >= needed_len` writable bytes and
        // `needed_len` is passed as the length, so the call never writes out of
        // bounds; the token handle remains valid for the duration of the call.
        let read = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast::<c_void>(),
                needed_len,
                &mut needed_len,
            )
        };
        if read == 0 {
            return Err(last_error("GetTokenInformation(TokenUser)"));
        }

        // SAFETY: A successful `GetTokenInformation(TokenUser)` writes a
        // `TOKEN_USER` at the start of the buffer. The buffer is `u64`-backed, so
        // its base address is 8-byte aligned, satisfying `TOKEN_USER`'s alignment
        // requirement (its first field is a pointer).
        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let sid = token_user.User.Sid;
        if sid.is_null() {
            return Err(WindowsIdentityError::NullPointer {
                api: "GetTokenInformation(TokenUser).Sid",
            });
        }

        let mut sid_string_ptr: *mut u16 = null_mut();
        // SAFETY: `sid` points into the live TOKEN_USER buffer and
        // `sid_string_ptr` is a valid out-pointer. Win32 allocates the returned
        // string with LocalAlloc; this function frees it with LocalFree.
        let converted = unsafe { ConvertSidToStringSidW(sid, &mut sid_string_ptr) };
        if converted == 0 {
            return Err(last_error("ConvertSidToStringSidW"));
        }
        if sid_string_ptr.is_null() {
            return Err(WindowsIdentityError::NullPointer {
                api: "ConvertSidToStringSidW",
            });
        }

        // Decode first, then free unconditionally: the SID string allocation
        // must be released on both the success and the decode-failure path.
        // SAFETY: `sid_string_ptr` is non-null (checked above) and points to the
        // NUL-terminated UTF-16 string produced by `ConvertSidToStringSidW`,
        // which stays live until the `LocalFree` below.
        let decoded = unsafe { wide_null_terminated_to_string(sid_string_ptr) };
        // SAFETY: `sid_string_ptr` was allocated by `ConvertSidToStringSidW` and
        // must be released exactly once with `LocalFree`. `LocalFree` returns
        // null on success; the handle is not used afterward.
        let _ = unsafe { LocalFree(sid_string_ptr.cast::<c_void>()) };
        decoded
    }

    /// Decodes a NUL-terminated UTF-16 string into an owned `String`.
    ///
    /// # Safety
    ///
    /// `ptr` must be non-null and point to a valid NUL-terminated UTF-16 string
    /// that stays live for the duration of the call.
    unsafe fn wide_null_terminated_to_string(
        ptr: *const u16,
    ) -> Result<String, WindowsIdentityError> {
        let mut len = 0_usize;
        // SAFETY: the caller guarantees `ptr` is non-null and NUL-terminated, so
        // the scan reads only up to and not past the terminating NUL.
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(ptr, len))
                .map_err(|_| WindowsIdentityError::InvalidUtf16)
        }
    }

    fn last_error(api: &'static str) -> WindowsIdentityError {
        // SAFETY: `GetLastError` has no preconditions.
        let code = unsafe { GetLastError() };
        WindowsIdentityError::Win32 { api, code }
    }
}

/// DPAPI CurrentUser-scope protect/unprotect. The Win32 FFI is the only place
/// in this module that needs unsafe; the workspace `unsafe_code = "deny"`
/// lint stays in force everywhere else.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod dpapi {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };

    use super::DpapiError;

    /// Wraps a `LocalAlloc`-backed `CRYPT_INTEGER_BLOB` output buffer, freeing
    /// it with `LocalFree` on drop.
    struct OutBlob(CRYPT_INTEGER_BLOB);

    impl Default for OutBlob {
        fn default() -> Self {
            Self(CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: null_mut(),
            })
        }
    }

    impl Drop for OutBlob {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // SAFETY: `pbData` was allocated by DPAPI (via LocalAlloc) on
                // the success path that sets it non-null; the buffer may hold
                // recovered PLAINTEXT (the unprotect path), so it is wiped
                // before release — a freed-but-unwiped LocalAlloc block would
                // retain a plaintext copy. Freeing exactly once on drop
                // matches the Win32 ownership contract.
                unsafe {
                    std::ptr::write_bytes(self.0.pbData, 0, self.0.cbData as usize);
                    LocalFree(self.0.pbData.cast::<c_void>());
                }
            }
        }
    }

    /// Copies a `CRYPT_INTEGER_BLOB`'s bytes into an owned `Vec<u8>`.
    ///
    /// # Safety
    ///
    /// `blob.pbData` must be non-null and point to at least `blob.cbData`
    /// readable bytes.
    unsafe fn blob_to_vec(blob: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: caller guarantees `pbData` is valid for `cbData` bytes.
        unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }.to_vec()
    }

    /// Borrows `bytes` as a DPAPI input blob.
    ///
    /// DPAPI does not mutate an input blob despite the non-const pointer in
    /// its type; casting away const matches the documented Win32 contract.
    fn input_blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB, DpapiError> {
        Ok(CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len()).map_err(|_| DpapiError::InputTooLarge)?,
            pbData: bytes.as_ptr().cast_mut(),
        })
    }

    /// The optional-entropy pointer DPAPI takes: null for no entropy.
    fn entropy_ptr(entropy: Option<&CRYPT_INTEGER_BLOB>) -> *const CRYPT_INTEGER_BLOB {
        entropy.map_or(null(), std::ptr::from_ref)
    }

    pub(super) fn protect(plaintext: &[u8], entropy: Option<&[u8]>) -> Result<Vec<u8>, DpapiError> {
        let entropy = entropy.map(input_blob).transpose()?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(plaintext.len()).map_err(|_| DpapiError::InputTooLarge)?,
            // CryptProtectData does not mutate the input blob despite the
            // non-const pointer in its signature; casting away const here
            // matches the documented (if awkwardly typed) Win32 contract.
            pbData: plaintext.as_ptr().cast_mut(),
        };
        let mut out = OutBlob::default();

        // SAFETY: `input` points to `plaintext` for `plaintext.len()` bytes,
        // live for the duration of the call. The entropy pointer is null or
        // points to `entropy`, a blob over the caller's entropy slice; both
        // outlive the call. `out.0` is a valid out-pointer; DPAPI allocates
        // its `pbData` via LocalAlloc on success, freed by `OutBlob::drop`. No
        // prompt struct (forbidden by the flag below), no description string.
        let ok = unsafe {
            CryptProtectData(
                &input,
                null_mut(),
                entropy_ptr(entropy.as_ref()),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out.0,
            )
        };
        if ok == 0 {
            // SAFETY: `GetLastError` has no preconditions.
            let code = unsafe { GetLastError() };
            return Err(DpapiError::Win32 {
                api: "CryptProtectData",
                code,
            });
        }
        if out.0.pbData.is_null() {
            return Err(DpapiError::NullBuffer {
                api: "CryptProtectData",
            });
        }
        // SAFETY: `out.0.pbData` was just checked non-null and DPAPI reported
        // `cbData` valid bytes on success.
        Ok(unsafe { blob_to_vec(&out.0) })
    }

    pub(super) fn unprotect(
        ciphertext: &[u8],
        entropy: Option<&[u8]>,
    ) -> Result<Vec<u8>, DpapiError> {
        let entropy = entropy.map(input_blob).transpose()?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(ciphertext.len()).map_err(|_| DpapiError::InputTooLarge)?,
            pbData: ciphertext.as_ptr().cast_mut(),
        };
        let mut out = OutBlob::default();

        // SAFETY: same discipline as `protect` above, the entropy pointer
        // included; `ppszDataDescr` is null (the description string is not
        // used by this wrapper).
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                null_mut(),
                entropy_ptr(entropy.as_ref()),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out.0,
            )
        };
        if ok == 0 {
            // A tampered/corrupted blob surfaces here as an ordinary Win32
            // failure (DPAPI blobs are self-authenticating) — the fail-closed
            // path callers rely on.
            // SAFETY: `GetLastError` has no preconditions.
            let code = unsafe { GetLastError() };
            return Err(DpapiError::Win32 {
                api: "CryptUnprotectData",
                code,
            });
        }
        if out.0.pbData.is_null() {
            return Err(DpapiError::NullBuffer {
                api: "CryptUnprotectData",
            });
        }
        // SAFETY: `out.0.pbData` was just checked non-null and DPAPI reported
        // `cbData` valid bytes on success.
        Ok(unsafe { blob_to_vec(&out.0) })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    #[test]
    #[cfg(target_os = "windows")]
    fn current_user_sid_string_returns_sid() {
        let sid = current_user_sid_string().expect("Windows SID must be available");
        assert!(
            sid.starts_with("S-1-"),
            "Windows SID should start with S-1-, got {sid:?}"
        );
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn current_user_sid_string_is_windows_only() {
        assert!(matches!(
            current_user_sid_string(),
            Err(WindowsIdentityError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn error_display_is_stable_for_every_variant() {
        assert_eq!(
            WindowsIdentityError::Win32 {
                api: "OpenProcessToken",
                code: 5,
            }
            .to_string(),
            "OpenProcessToken failed with Windows error 5"
        );
        assert_eq!(
            WindowsIdentityError::NullPointer {
                api: "ConvertSidToStringSidW",
            }
            .to_string(),
            "ConvertSidToStringSidW returned a null pointer"
        );
        assert_eq!(
            WindowsIdentityError::InvalidUtf16.to_string(),
            "SID string was not valid UTF-16"
        );
        assert_eq!(
            WindowsIdentityError::UnsupportedPlatform.to_string(),
            "Windows SID lookup is only available on Windows"
        );
        assert_eq!(
            WindowsIdentityError::SddlNotUtf16.to_string(),
            "security descriptor string was not valid UTF-16"
        );
        assert_eq!(
            WindowsIdentityError::PathContainsNul.to_string(),
            "path contains a NUL character"
        );
    }

    #[test]
    fn dacl_sddl_admits_only_the_named_user() {
        let sid = "S-1-5-21-1-2-3-1001";
        assert!(dacl_sddl_admits_only(
            "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)",
            sid,
            true
        ));
        assert!(dacl_sddl_admits_only(
            "D:AI(A;ID;FA;;;S-1-5-21-1-2-3-1001)",
            sid,
            false
        ));
        assert!(dacl_sddl_admits_only(
            "D:PAI(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;ID;0x1200a9;;;S-1-5-21-1-2-3-1001)",
            sid,
            true
        ));
        for refused in [
            "D:AI(A;ID;FA;;;S-1-5-21-1-2-3-1001)",
            "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;OICI;FA;;;SY)",
            "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;OICI;FR;;;WD)",
            "D:P(D;OICI;FA;;;S-1-5-21-1-2-3-1001)",
            "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-10010)",
            "D:P",
            "D:NO_ACCESS_CONTROL",
            "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001",
            "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)",
            "",
        ] {
            assert!(!dacl_sddl_admits_only(refused, sid, true), "{refused}");
        }
    }

    /// The directory carries exactly one protected, inheritable ACE for the
    /// current user, a file created inside inherits exactly that ACE, and an
    /// existing path is refused.
    #[test]
    #[cfg(target_os = "windows")]
    fn owner_only_directory_admits_only_the_current_user() {
        let sid = current_user_sid_string().expect("Windows SID must be available");
        let parent = std::env::temp_dir().join(format!(
            "stellar-agent-owner-only-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir(&parent).expect("parent directory");
        let dir = parent.join("private");

        create_owner_only_directory(&dir).expect("CreateDirectoryW must succeed");
        // SDDL `D:<flags>(ace)(ace)...`: split the control flags from the ACEs.
        let split = |sddl: String| {
            let body = sddl.strip_prefix("D:").expect("a DACL string").to_owned();
            let at = body.find('(').unwrap_or(body.len());
            (body[..at].to_owned(), body[at..].to_owned())
        };
        let (flags, aces) = split(path_dacl_sddl(&dir).expect("directory DACL"));
        assert!(flags.contains('P'), "the DACL must be protected: {flags}");
        assert_eq!(aces, format!("(A;OICI;FA;;;{sid})"));

        let file = dir.join("redirect.html");
        std::fs::write(&file, b"x").expect("file inside the directory");
        let (_flags, aces) = split(path_dacl_sddl(&file).expect("file DACL"));
        assert_eq!(aces, format!("(A;ID;FA;;;{sid})"));
        assert!(admits_only_current_user(&dir, true).expect("directory DACL"));
        assert!(admits_only_current_user(&file, false).expect("file DACL"));
        assert!(!admits_only_current_user(&parent, true).expect("parent DACL"));

        assert!(matches!(
            create_owner_only_directory(&dir),
            Err(WindowsIdentityError::Win32 {
                api: "CreateDirectoryW",
                ..
            })
        ));
        std::fs::remove_dir_all(&parent).expect("cleanup");
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn dpapi_protect_unprotect_round_trips() {
        let plaintext = b"stellar-agent headless-keyring DPAPI round-trip test";
        let ciphertext = dpapi_protect(plaintext).expect("CryptProtectData must succeed");
        assert_ne!(
            ciphertext, plaintext,
            "DPAPI output must not equal the plaintext"
        );
        let decrypted = dpapi_unprotect(&ciphertext).expect("CryptUnprotectData must succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn dpapi_unprotect_rejects_tampered_ciphertext() {
        let plaintext = b"tamper-detection fixture";
        let mut ciphertext = dpapi_protect(plaintext).expect("CryptProtectData must succeed");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        assert!(
            dpapi_unprotect(&ciphertext).is_err(),
            "a tampered DPAPI blob must fail to unprotect (fail-closed)"
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn dpapi_entropy_binds_the_blob_to_its_entropy() {
        let plaintext = b"entropy-binding fixture";
        let bound = dpapi_protect_with_entropy(plaintext, b"service\0account")
            .expect("CryptProtectData must succeed");
        assert_eq!(
            dpapi_unprotect_with_entropy(&bound, b"service\0account")
                .expect("the same entropy opens the blob"),
            plaintext
        );
        assert!(
            dpapi_unprotect_with_entropy(&bound, b"service\0other").is_err(),
            "another entropy must not open the blob"
        );
        assert!(
            dpapi_unprotect(&bound).is_err(),
            "no entropy must not open a blob sealed with entropy"
        );
        let unbound = dpapi_protect(plaintext).expect("CryptProtectData must succeed");
        assert!(
            dpapi_unprotect_with_entropy(&unbound, b"service\0account").is_err(),
            "entropy must not open a blob sealed without it"
        );
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn dpapi_functions_are_windows_only() {
        assert!(matches!(
            dpapi_protect(b"x"),
            Err(DpapiError::UnsupportedPlatform)
        ));
        assert!(matches!(
            dpapi_unprotect(b"x"),
            Err(DpapiError::UnsupportedPlatform)
        ));
        assert!(matches!(
            dpapi_protect_with_entropy(b"x", b"e"),
            Err(DpapiError::UnsupportedPlatform)
        ));
        assert!(matches!(
            dpapi_unprotect_with_entropy(b"x", b"e"),
            Err(DpapiError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn dpapi_error_display_is_stable_for_every_variant() {
        assert_eq!(
            DpapiError::Win32 {
                api: "CryptProtectData",
                code: 5,
            }
            .to_string(),
            "CryptProtectData failed with Windows error 5"
        );
        assert_eq!(
            DpapiError::NullBuffer {
                api: "CryptUnprotectData",
            }
            .to_string(),
            "CryptUnprotectData reported success but returned a null buffer"
        );
        assert_eq!(
            DpapiError::InputTooLarge.to_string(),
            "input exceeds the DPAPI maximum length"
        );
        assert_eq!(
            DpapiError::UnsupportedPlatform.to_string(),
            "DPAPI is only available on Windows"
        );
    }
}
