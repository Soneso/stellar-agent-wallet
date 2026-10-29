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
//!   inside it, and `admits_only_current_user` checks that a path's DACL
//!   grants nothing to anyone else. The CLI writes its private browser
//!   redirect file into such a directory. Both are Windows-only and have no
//!   stub on other targets.
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
    /// A Win32 API returned a SID that is not valid or does not fit in the
    /// data it returned.
    #[error("{api} returned an invalid SID")]
    InvalidSid {
        /// The Win32 API label.
        api: &'static str,
    },
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

/// Returns `true` iff the DACL of `path` holds only access-allowed ACEs for
/// the current process user, at least one of them, and, when
/// `require_protected` is set, is protected from inheritance.
///
/// Trustees are compared as binary SIDs with `EqualSid`, so the result does
/// not depend on how a SID renders as text. A NULL or absent DACL, which
/// grants everyone full access, and an empty DACL, which grants nothing, are
/// refused, as is a DACL holding any ACE type other than access-allowed.
///
/// # Errors
///
/// Returns [`WindowsIdentityError`] if the SID lookup or the DACL read fails,
/// or if `path` contains a NUL.
#[cfg(target_os = "windows")]
pub fn admits_only_current_user(
    path: &std::path::Path,
    require_protected: bool,
) -> Result<bool, WindowsIdentityError> {
    windows::admits_only_current_user(path, require_protected)
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
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetTokenInformation,
        IsValidSid, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
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

    /// Converts `sddl` into a self-relative security descriptor.
    fn security_descriptor_from_sddl(sddl: &str) -> Result<LocalAllocation, WindowsIdentityError> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string live for the call;
        // `descriptor` is a valid out-pointer and the size out-pointer may be
        // null. On success the descriptor is a LocalAlloc allocation, owned
        // below by `LocalAllocation`.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
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
        Ok(LocalAllocation(descriptor))
    }

    pub(super) fn create_owner_only_directory(path: &Path) -> Result<(), WindowsIdentityError> {
        let sid = current_user_sid_string()?;
        // A protected DACL (`P`) with one ACE: allow (`A`) full file access
        // (`FA`) to the current user, inherited by files (`OI`) and
        // subdirectories (`CI`) created inside.
        let descriptor = security_descriptor_from_sddl(&format!("D:P(A;OICI;FA;;;{sid})"))?;

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

    /// Reads the DACL part of the security descriptor of `path`.
    fn path_security_descriptor(path: &Path) -> Result<LocalAllocation, WindowsIdentityError> {
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
        Ok(LocalAllocation(descriptor))
    }

    pub(super) fn admits_only_current_user(
        path: &Path,
        require_protected: bool,
    ) -> Result<bool, WindowsIdentityError> {
        let user = current_user_sid()?;
        let descriptor = path_security_descriptor(path)?;
        // SAFETY: `descriptor.0` is the descriptor `GetNamedSecurityInfoW`
        // returned, live until `descriptor` drops after the call.
        unsafe { descriptor_admits_only(descriptor.0, &user, require_protected) }
    }

    /// Decides whether the DACL of `descriptor` admits `user` and nobody
    /// else; see [`Dacl::admits_only`].
    ///
    /// # Safety
    ///
    /// `descriptor` must point to a valid security descriptor that stays live
    /// for the call.
    unsafe fn descriptor_admits_only(
        descriptor: PSECURITY_DESCRIPTOR,
        user: &Sid,
        require_protected: bool,
    ) -> Result<bool, WindowsIdentityError> {
        // SAFETY: forwarded from this function's contract.
        let dacl = unsafe { read_dacl(descriptor) }?;
        Ok(dacl.admits_only(user, require_protected))
    }

    /// The smallest SID: revision, sub-authority count and the six-byte
    /// identifier authority, without a sub-authority.
    const MIN_SID_LEN: usize = 8;

    /// A SID copied into an owned buffer.
    ///
    /// [`Sid::copy_from`] is the only constructor and validates the SID, so
    /// the buffer always starts with a valid SID. The buffer is `u32`-backed
    /// because the SID's sub-authorities are DWORDs.
    pub(super) struct Sid(Vec<u32>);

    impl Sid {
        /// Copies the SID at `sid`, or returns `None` when the bytes there are
        /// not a valid SID that fits in `available` bytes.
        ///
        /// # Safety
        ///
        /// `sid` must be non-null and point to `available` readable bytes.
        unsafe fn copy_from(sid: PSID, available: usize) -> Option<Self> {
            if available < MIN_SID_LEN {
                return None;
            }
            // SAFETY: `sid` points to at least `MIN_SID_LEN` readable bytes,
            // the fixed header that `IsValidSid` checks.
            if unsafe { IsValidSid(sid) } == 0 {
                return None;
            }
            // SAFETY: `sid` is a valid SID (checked above), the precondition
            // of `GetLengthSid`.
            let len = usize::try_from(unsafe { GetLengthSid(sid) }).ok()?;
            if len > available {
                return None;
            }
            let mut words = vec![0_u32; len.div_ceil(size_of::<u32>())];
            // SAFETY: `sid` has `len <= available` readable bytes and `words`
            // holds at least `len` writable bytes in a separate allocation.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    sid.cast::<u8>().cast_const(),
                    words.as_mut_ptr().cast::<u8>(),
                    len,
                );
            }
            Some(Self(words))
        }

        fn as_psid(&self) -> PSID {
            self.0.as_ptr().cast_mut().cast::<c_void>()
        }

        /// Returns `true` iff `self` and `other` are the same SID, as
        /// `EqualSid` decides.
        pub(super) fn equals(&self, other: &Self) -> bool {
            // SAFETY: both buffers hold a valid SID (the `Sid` invariant) and
            // live for the call; `EqualSid` only reads them.
            unsafe { EqualSid(self.as_psid(), other.as_psid()) != 0 }
        }

        /// Parses a SID string such as `S-1-5-18`.
        #[cfg(test)]
        pub(super) fn parse(text: &str) -> Result<Self, WindowsIdentityError> {
            let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sid: PSID = null_mut();
            // SAFETY: `wide` is a NUL-terminated UTF-16 string live for the
            // call and `sid` is a valid out-pointer. On success the SID is a
            // LocalAlloc allocation, owned below by `LocalAllocation`.
            let converted = unsafe {
                windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW(
                    wide.as_ptr(),
                    &mut sid,
                )
            };
            if converted == 0 {
                return Err(last_error("ConvertStringSidToSidW"));
            }
            if sid.is_null() {
                return Err(WindowsIdentityError::NullPointer {
                    api: "ConvertStringSidToSidW",
                });
            }
            let allocation = LocalAllocation(sid);
            // SAFETY: the conversion produced a valid SID, the precondition of
            // `GetLengthSid`, in an allocation of that length.
            let len = usize::try_from(unsafe { GetLengthSid(sid) }).unwrap_or(0);
            // SAFETY: `sid` is non-null and its allocation holds `len` bytes.
            let copied = unsafe { Self::copy_from(sid, len) };
            drop(allocation);
            copied.ok_or(WindowsIdentityError::InvalidSid {
                api: "ConvertStringSidToSidW",
            })
        }
    }

    /// A DACL as the access check judges it.
    pub(super) struct Dacl {
        /// The descriptor's `SE_DACL_PROTECTED` control bit: the DACL
        /// inherits no ACE from the parent.
        pub(super) protected: bool,
        /// The ACEs in order; `None` for a NULL or absent DACL, which grants
        /// everyone full access.
        pub(super) entries: Option<Vec<AceEntry>>,
    }

    /// One ACE of a [`Dacl`].
    pub(super) struct AceEntry {
        /// The ACE type, for example `ACCESS_ALLOWED_ACE_TYPE`.
        pub(super) ace_type: u8,
        /// The inheritance flags, for example `OBJECT_INHERIT_ACE` or
        /// `INHERITED_ACE`.
        #[cfg_attr(not(test), allow(dead_code, reason = "read by the DACL shape tests"))]
        pub(super) flags: u8,
        /// The access mask of an access-allowed ACE; zero for other types.
        #[cfg_attr(not(test), allow(dead_code, reason = "read by the DACL shape tests"))]
        pub(super) mask: u32,
        /// The trustee of an access-allowed ACE; `None` for other types and
        /// for an ACE whose trustee is not a valid SID.
        pub(super) trustee: Option<Sid>,
    }

    impl Dacl {
        /// Returns `true` iff the DACL holds at least one ACE, every ACE is
        /// an access-allowed ACE whose trustee is `user`, and, when
        /// `require_protected` is set, the DACL is protected.
        ///
        /// A NULL or absent DACL grants everyone full access and an empty
        /// DACL grants nothing; both are refused.
        pub(super) fn admits_only(&self, user: &Sid, require_protected: bool) -> bool {
            if require_protected && !self.protected {
                return false;
            }
            let Some(entries) = &self.entries else {
                return false;
            };
            !entries.is_empty()
                && entries.iter().all(|entry| {
                    u32::from(entry.ace_type) == ACCESS_ALLOWED_ACE_TYPE
                        && entry
                            .trustee
                            .as_ref()
                            .is_some_and(|trustee| trustee.equals(user))
                })
        }
    }

    /// Reads the DACL of `descriptor` together with its protected bit.
    ///
    /// # Safety
    ///
    /// `descriptor` must point to a valid security descriptor that stays live
    /// for the call.
    unsafe fn read_dacl(descriptor: PSECURITY_DESCRIPTOR) -> Result<Dacl, WindowsIdentityError> {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: `descriptor` is valid (caller contract) and both
        // out-pointers are valid for writes.
        let read = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
        if read == 0 {
            return Err(last_error("GetSecurityDescriptorControl"));
        }
        let protected = control & SE_DACL_PROTECTED != 0;

        let mut present = 0;
        let mut acl: *mut ACL = null_mut();
        let mut defaulted = 0;
        // SAFETY: `descriptor` is valid (caller contract) and the three
        // out-pointers are valid for writes. On success `acl` is null or
        // points to the ACL inside `descriptor`.
        let read = unsafe {
            GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted)
        };
        if read == 0 {
            return Err(last_error("GetSecurityDescriptorDacl"));
        }
        if present == 0 || acl.is_null() {
            return Ok(Dacl {
                protected,
                entries: None,
            });
        }

        // SAFETY: `acl` is non-null and points to the ACL header inside the
        // live descriptor.
        let count = unsafe { acl.read_unaligned() }.AceCount;
        let mut entries = Vec::with_capacity(usize::from(count));
        for index in 0..u32::from(count) {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: `acl` is the live ACL, `index` is below its ACE count,
            // and `ace` is a valid out-pointer. On success `ace` points to
            // the ACE inside the ACL.
            if unsafe { GetAce(acl, index, &mut ace) } == 0 {
                return Err(last_error("GetAce"));
            }
            if ace.is_null() {
                return Err(WindowsIdentityError::NullPointer { api: "GetAce" });
            }
            // SAFETY: `ace` points to an ACE, which starts with an
            // `ACE_HEADER`.
            let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
            let (mask, trustee) = if u32::from(header.AceType) == ACCESS_ALLOWED_ACE_TYPE {
                // SAFETY: `ace` points to an access-allowed ACE whose header
                // gives its size in bytes.
                unsafe { allowed_ace_body(ace, header.AceSize) }
            } else {
                (0, None)
            };
            entries.push(AceEntry {
                ace_type: header.AceType,
                flags: header.AceFlags,
                mask,
                trustee,
            });
        }
        Ok(Dacl {
            protected,
            entries: Some(entries),
        })
    }

    /// The access mask and trustee of the access-allowed ACE at `ace`. The
    /// trustee is `None` when the ACE is too short for a valid SID.
    ///
    /// # Safety
    ///
    /// `ace` must point to an access-allowed ACE of `size` readable bytes.
    unsafe fn allowed_ace_body(ace: *const c_void, size: u16) -> (u32, Option<Sid>) {
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let Some(available) = usize::from(size).checked_sub(sid_offset) else {
            return (0, None);
        };
        let base = ace.cast::<u8>();
        // SAFETY: the ACE holds at least `sid_offset` bytes (checked above),
        // and the mask lies before the SID.
        let mask = unsafe {
            base.add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, Mask))
                .cast::<u32>()
                .read_unaligned()
        };
        // SAFETY: the trustee starts `sid_offset` bytes into the ACE and the
        // `available` bytes after it lie within the ACE.
        let trustee = unsafe { Sid::copy_from(base.add(sid_offset).cast_mut().cast(), available) };
        (mask, trustee)
    }

    /// Reads the DACL of `path`.
    #[cfg(test)]
    pub(super) fn path_dacl(path: &Path) -> Result<Dacl, WindowsIdentityError> {
        let descriptor = path_security_descriptor(path)?;
        // SAFETY: `descriptor.0` is the descriptor `GetNamedSecurityInfoW`
        // returned, live until `descriptor` drops after the call.
        unsafe { read_dacl(descriptor.0) }
    }

    /// Decides the DACL that `sddl` describes against the SID that `sid`
    /// spells, through the same check [`admits_only_current_user`] applies to
    /// a path.
    #[cfg(test)]
    pub(super) fn sddl_admits_only(
        sddl: &str,
        sid: &str,
        require_protected: bool,
    ) -> Result<bool, WindowsIdentityError> {
        let descriptor = security_descriptor_from_sddl(sddl)?;
        let user = Sid::parse(sid)?;
        // SAFETY: `descriptor.0` is the converted descriptor, live until
        // `descriptor` drops after the call.
        unsafe { descriptor_admits_only(descriptor.0, &user, require_protected) }
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

    /// Reads the current process token's user SID.
    pub(super) fn current_user_sid() -> Result<Sid, WindowsIdentityError> {
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
        // The SID is stored in the buffer after the `TOKEN_USER` header; the
        // bytes from it to the end of the written data bound its length.
        let available = sid
            .addr()
            .checked_sub(buffer.as_ptr().addr())
            .and_then(|offset| (needed_len as usize).checked_sub(offset))
            .ok_or(WindowsIdentityError::InvalidSid {
                api: "GetTokenInformation(TokenUser)",
            })?;
        // SAFETY: `sid` is non-null and points into `buffer`, which holds the
        // `available` bytes after it and stays live for the call.
        unsafe { Sid::copy_from(sid, available) }.ok_or(WindowsIdentityError::InvalidSid {
            api: "GetTokenInformation(TokenUser)",
        })
    }

    pub(super) fn current_user_sid_string() -> Result<String, WindowsIdentityError> {
        let sid = current_user_sid()?;
        let mut sid_string_ptr: *mut u16 = null_mut();
        // SAFETY: `sid` holds a valid SID live for the call and
        // `sid_string_ptr` is a valid out-pointer. Win32 allocates the returned
        // string with LocalAlloc; this function frees it with LocalFree.
        let converted = unsafe { ConvertSidToStringSidW(sid.as_psid(), &mut sid_string_ptr) };
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
            WindowsIdentityError::InvalidSid {
                api: "GetTokenInformation(TokenUser)",
            }
            .to_string(),
            "GetTokenInformation(TokenUser) returned an invalid SID"
        );
        assert_eq!(
            WindowsIdentityError::PathContainsNul.to_string(),
            "path contains a NUL character"
        );
    }

    /// The access check compares binary SIDs: an ACE written with an SDDL
    /// alias matches the SID the alias stands for, and every DACL that grants
    /// anything to another trustee, grants nothing, or is not protected when
    /// protection is required, is refused.
    #[test]
    #[cfg(target_os = "windows")]
    fn dacl_check_compares_binary_sids() {
        const SYSTEM: &str = "S-1-5-18";
        const ADMINISTRATORS: &str = "S-1-5-32-544";
        const USER: &str = "S-1-5-21-1-2-3-1001";

        for (sddl, sid, require_protected) in [
            ("D:P(A;OICI;FA;;;SY)", SYSTEM, true),
            ("D:P(A;OICI;FA;;;BA)", ADMINISTRATORS, true),
            ("D:P(A;OICI;FA;;;S-1-5-18)", SYSTEM, true),
            ("D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)", USER, true),
            (
                "D:PAI(A;OICI;FA;;;SY)(A;ID;0x1200a9;;;S-1-5-18)",
                SYSTEM,
                true,
            ),
            ("D:(A;OICI;FA;;;SY)", SYSTEM, false),
            ("D:AI(A;ID;FA;;;SY)", SYSTEM, false),
        ] {
            let decided = windows::sddl_admits_only(sddl, sid, require_protected);
            assert!(
                matches!(decided, Ok(true)),
                "{sddl} must admit {sid}: {decided:?}"
            );
        }

        for (sddl, sid, require_protected) in [
            // The only trustee is a different SID.
            ("D:P(A;OICI;FA;;;SY)", ADMINISTRATORS, true),
            ("D:P(A;OICI;FA;;;S-1-5-21-1-2-3-10010)", USER, true),
            // A second ACE grants another trustee.
            ("D:P(A;OICI;FA;;;SY)(A;OICI;FR;;;WD)", SYSTEM, true),
            ("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SYSTEM, true),
            // A deny ACE, alone or beside the user's allow ACE.
            ("D:P(D;OICI;FA;;;SY)", SYSTEM, true),
            ("D:P(D;OICI;FA;;;WD)(A;OICI;FA;;;SY)", SYSTEM, true),
            // Protection is required but the DACL is not protected.
            ("D:(A;OICI;FA;;;SY)", SYSTEM, true),
            ("D:AI(A;ID;FA;;;SY)", SYSTEM, true),
            // An empty DACL grants nothing.
            ("D:P", SYSTEM, true),
            ("D:P", SYSTEM, false),
            // A NULL DACL and an absent DACL grant everyone full access.
            ("D:NO_ACCESS_CONTROL", SYSTEM, false),
            ("O:SY", SYSTEM, false),
        ] {
            let decided = windows::sddl_admits_only(sddl, sid, require_protected);
            assert!(
                matches!(decided, Ok(false)),
                "{sddl} must not admit {sid} (require_protected {require_protected}): {decided:?}"
            );
        }
    }

    /// The directory carries exactly one protected, inheritable allow ACE for
    /// the current user, a file created inside inherits exactly that ACE,
    /// and an existing path is refused.
    #[test]
    #[cfg(target_os = "windows")]
    fn owner_only_directory_admits_only_the_current_user() {
        use windows_sys::Win32::Security::{
            CONTAINER_INHERIT_ACE, INHERITED_ACE, OBJECT_INHERIT_ACE,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

        let user = windows::current_user_sid().expect("Windows SID must be available");
        let parent = std::env::temp_dir().join(format!(
            "stellar-agent-owner-only-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir(&parent).expect("parent directory");
        let dir = parent.join("private");

        create_owner_only_directory(&dir).expect("CreateDirectoryW must succeed");
        let single_user_ace = |path: &std::path::Path, flags: u32| {
            let dacl = windows::path_dacl(path).expect("a readable DACL");
            let entries = dacl.entries.expect("a DACL is present");
            assert_eq!(entries.len(), 1, "exactly one ACE on {}", path.display());
            let ace = &entries[0];
            assert_eq!(u32::from(ace.ace_type), ACCESS_ALLOWED_ACE_TYPE);
            assert_eq!(u32::from(ace.flags), flags);
            assert_eq!(ace.mask, FILE_ALL_ACCESS);
            assert!(
                ace.trustee.as_ref().is_some_and(|t| t.equals(&user)),
                "the ACE trustee must be the current user"
            );
            dacl.protected
        };
        assert!(
            single_user_ace(&dir, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE),
            "the directory DACL must be protected"
        );

        let file = dir.join("redirect.html");
        std::fs::write(&file, b"x").expect("file inside the directory");
        single_user_ace(&file, INHERITED_ACE);
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
