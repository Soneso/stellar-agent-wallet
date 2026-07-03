//! Safe wrapper for the Windows process-user account SID lookup.
//!
//! `stellar-agent-core` forbids unsafe code. This small Windows-only helper
//! contains the Win32 FFI required to read the current process token's user
//! account SID and exposes a safe, string-returning API. The SID binds approval
//! attestations to the OS user that created them, so an attestation blob minted
//! by one user cannot be replayed by another user on the same machine.

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

// The Win32 FFI is the only place in the crate that needs unsafe; the workspace
// `unsafe_code = "deny"` lint stays in force everywhere else.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod windows {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::WindowsIdentityError;

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
    }
}
