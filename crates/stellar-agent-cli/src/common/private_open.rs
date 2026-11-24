//! Opens a bearer URL in the browser without placing the URL in any child
//! process's arguments.
//!
//! The approval inbox, the interactive operator enrollment and the passkey
//! registration each hand the browser a loopback URL that carries a
//! single-use secret. A platform launcher passes its argument to a child
//! process (on Linux and the BSDs, `xdg-open` or the browser itself), whose
//! argument vector other local users can read. [`open_private`] therefore
//! never gives the launcher the bearer URL:
//!
//! 1. It accepts only the wallet's loopback HTTP destinations
//!    (`http://127.0.0.1:<port>`, `http://localhost:<port>`,
//!    `http://[::1]:<port>`).
//! 2. It creates a fresh directory that only the current user can open: mode
//!    `0700` on Unix; on Windows a protected DACL whose single ACE grants the
//!    current user access and is inherited by the file inside. A path that
//!    already exists, a symbolic link included, is refused.
//! 3. It creates the redirect file inside it, mode `0600` on Unix, verifies
//!    both are private, and only then writes a minimal HTML page that
//!    redirects to the bearer URL, with a `no-referrer` policy and no external
//!    resource.
//! 4. It flushes and closes the file, then gives the launcher only the file's
//!    `file://` URL.
//!
//! The returned [`PrivateOpen`] keeps the file for as long as the browser may
//! still need it; the caller holds it until the ceremony or the server ends.
//! [`PrivateOpen::close`] and its `Drop` remove the file and the directory.
//! Every failure removes whatever was created and returns an error whose text
//! never contains the URL; the caller then falls back to its printed manual
//! handoff. There is no retry that passes the bearer URL to the launcher.
//!
//! A platform without a private-directory implementation refuses, so the
//! manual handoff is the only path there.

use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore as _};
use url::{Host, Url};

/// Name of the redirect file inside the private directory.
const REDIRECT_FILE_NAME: &str = "open.html";

/// Prefix of the private directory's name; a random suffix follows.
const DIRECTORY_PREFIX: &str = "stellar-agent-open-";

/// Owns a private redirect file and its directory.
///
/// Dropping it, or calling [`PrivateOpen::close`], removes both. `Debug`
/// shows nothing: the file holds a bearer URL.
pub(crate) struct PrivateOpen {
    directory: PathBuf,
    file: PathBuf,
    removed: bool,
}

impl std::fmt::Debug for PrivateOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateOpen").finish_non_exhaustive()
    }
}

impl PrivateOpen {
    /// Removes the redirect file and its directory.
    ///
    /// # Errors
    ///
    /// Returns the first removal error other than an already absent path.
    pub(crate) fn close(mut self) -> io::Result<()> {
        self.remove()
    }

    fn remove(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        self.removed = true;
        let file = remove_if_present(std::fs::remove_file(&self.file));
        let directory = remove_if_present(std::fs::remove_dir(&self.directory));
        file.and(directory)
    }

    /// The redirect file's path.
    #[cfg(test)]
    pub(crate) fn file_path(&self) -> &Path {
        &self.file
    }
}

impl Drop for PrivateOpen {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            tracing::debug!(
                error.kind = ?error.kind(),
                "private browser handoff: redirect file cleanup failed"
            );
        }
    }
}

fn remove_if_present(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Opens `url` through a private redirect file in the system temporary
/// directory, giving `opener` only the file's `file://` URL.
///
/// # Errors
///
/// Returns an error, after removing everything it created, when `url` is not
/// a wallet loopback destination, when the private directory or file cannot
/// be created and verified, or when `opener` fails. No error text contains
/// `url`.
pub(crate) fn open_private(
    url: &str,
    opener: impl FnOnce(&str) -> io::Result<()>,
) -> io::Result<PrivateOpen> {
    open_private_in(&std::env::temp_dir(), url, opener, |_, _| {})
}

/// Opens `url` through [`open_private`] and returns the guard, or, when the
/// open fails, tells the operator on stderr to use `handoff`, the place the
/// command printed the URL, and returns `None`.
///
/// The notice names only the error kind, never the URL; the manual handoff is
/// the only fallback.
pub(crate) fn open_or_point_to_handoff(
    url: &str,
    opener: impl FnOnce(&str) -> io::Result<()>,
    handoff: &str,
) -> Option<PrivateOpen> {
    match open_private(url, opener) {
        Ok(guard) => Some(guard),
        Err(error) => {
            #[allow(
                clippy::print_stderr,
                reason = "CLI binary intentional user output: manual handoff notice"
            )]
            {
                eprintln!(
                    "stellar-agent: could not open the browser ({}); open {handoff}.",
                    error.kind()
                );
            }
            None
        }
    }
}

/// The launcher [`open_private`] uses outside tests: the system default
/// browser.
pub(crate) fn browser_opener(file_url: &str) -> io::Result<()> {
    webbrowser::open(file_url)
}

/// [`open_private`] under `base`, with `before_write` called after the
/// directory and the file exist and are verified private, and before any byte
/// is written.
fn open_private_in(
    base: &Path,
    url: &str,
    opener: impl FnOnce(&str) -> io::Result<()>,
    before_write: impl FnOnce(&Path, &Path),
) -> io::Result<PrivateOpen> {
    let mut suffix = [0u8; 16];
    OsRng.fill_bytes(&mut suffix);
    let directory = base.join(format!("{DIRECTORY_PREFIX}{}", hex::encode(suffix)));
    open_private_at(&directory, url, opener, before_write)
}

/// [`open_private_in`] with an explicit directory path, which must not exist.
fn open_private_at(
    directory: &Path,
    url: &str,
    opener: impl FnOnce(&str) -> io::Result<()>,
    before_write: impl FnOnce(&Path, &Path),
) -> io::Result<PrivateOpen> {
    let target = loopback_destination(url)?;
    create_private_directory(directory)?;
    // From here on the guard owns cleanup: every early return removes the
    // directory and whatever is inside it.
    let guard = PrivateOpen {
        directory: directory.to_path_buf(),
        file: directory.join(REDIRECT_FILE_NAME),
        removed: false,
    };
    let mut file = create_private_file(&guard.file)?;
    verify_private(&guard.directory, &guard.file)?;
    before_write(&guard.directory, &guard.file);
    file.write_all(redirect_page(&target).as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    drop(file);

    let file_url = Url::from_file_path(&guard.file).map_err(|()| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the redirect file path has no file URL form",
        )
    })?;
    opener(file_url.as_str())?;
    Ok(guard)
}

/// Parses `url` and accepts only a wallet loopback HTTP destination: scheme
/// `http`, host `127.0.0.1`, `localhost` or `::1`, an explicit port, no
/// credentials, and a serialization free of characters that would need
/// quoting in the redirect page.
fn loopback_destination(url: &str) -> io::Result<Url> {
    let refuse = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the browser handoff accepts only a wallet loopback http URL",
        )
    };
    let parsed = Url::parse(url).map_err(|_| refuse())?;
    let loopback_host = match parsed.host() {
        Some(Host::Domain(domain)) => domain == "localhost",
        Some(Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        None => false,
    };
    let plain = parsed
        .as_str()
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&()*+,=%".contains(&b));
    if parsed.scheme() != "http"
        || !loopback_host
        || parsed.port().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !plain
    {
        return Err(refuse());
    }
    Ok(parsed)
}

/// The redirect page: a meta refresh to `target`, a `no-referrer` policy, and
/// a content security policy that loads nothing.
fn redirect_page(target: &Url) -> String {
    let target = stellar_agent_loopback_http::escape::html_escape(target.as_str());
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'">
<meta name="referrer" content="no-referrer">
<meta http-equiv="refresh" content="0;url={target}">
<title>Opening the wallet page</title>
</head>
<body>
<p>Opening the wallet page. If it does not open, use the address the command printed in the terminal.</p>
</body>
</html>
"#
    )
}

#[cfg(unix)]
fn create_private_directory(directory: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    // mkdir(2) fails on any existing path, a symbolic link included, so a
    // pre-placed path is never followed or reused.
    std::fs::DirBuilder::new().mode(0o700).create(directory)
}

#[cfg(unix)]
fn create_private_file(file: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    // O_CREAT | O_EXCL: fails on any existing path, a symbolic link included.
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file)
}

#[cfg(unix)]
fn verify_private(directory: &Path, file: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let directory_meta = std::fs::symlink_metadata(directory)?;
    let file_meta = std::fs::symlink_metadata(file)?;
    let private = directory_meta.is_dir()
        && directory_meta.permissions().mode() & 0o077 == 0
        && file_meta.is_file()
        && file_meta.permissions().mode() & 0o077 == 0
        && file_meta.len() == 0;
    if private { Ok(()) } else { Err(not_private()) }
}

#[cfg(windows)]
fn create_private_directory(directory: &Path) -> io::Result<()> {
    stellar_agent_windows_identity::create_owner_only_directory(directory).map_err(io::Error::other)
}

#[cfg(windows)]
fn create_private_file(file: &Path) -> io::Result<File> {
    // CREATE_NEW: fails on any existing path. The file inherits the
    // directory's user-only ACE.
    OpenOptions::new().write(true).create_new(true).open(file)
}

#[cfg(windows)]
fn verify_private(directory: &Path, file: &Path) -> io::Result<()> {
    use stellar_agent_windows_identity::admits_only_current_user;
    let private = admits_only_current_user(directory, true).map_err(io::Error::other)?
        && admits_only_current_user(file, false).map_err(io::Error::other)?
        && std::fs::symlink_metadata(file)?.len() == 0;
    if private { Ok(()) } else { Err(not_private()) }
}

#[cfg(not(any(unix, windows)))]
fn create_private_directory(_directory: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "a private browser handoff is not available on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
fn create_private_file(_file: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "a private browser handoff is not available on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
fn verify_private(_directory: &Path, _file: &Path) -> io::Result<()> {
    Err(not_private())
}

fn not_private() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "the redirect file is not private to the current user",
    )
}

/// Test probe for the command sites' handoff phases.
///
/// A phase takes its opener and its interrupt as parameters. The probe's
/// opener records every URL it receives; the probe's interrupt future, polled
/// only while the phase waits, records whether the redirect file is present
/// at that moment and what it holds, then ends the wait.
#[cfg(test)]
pub(crate) mod handoff_probe {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::cell::RefCell;

    use std::io;
    use std::path::PathBuf;

    /// Records what a phase's opener receives and what the redirect file held
    /// while the phase waited.
    #[derive(Default)]
    pub(crate) struct HandoffProbe {
        launched: RefCell<Vec<String>>,
        during_wait: RefCell<Option<Option<String>>>,
    }

    impl HandoffProbe {
        /// An opener that records its argument and returns `result`.
        pub(crate) fn opener(
            &self,
            result: io::Result<()>,
        ) -> impl FnOnce(&str) -> io::Result<()> + '_ {
            move |url| {
                self.launched.borrow_mut().push(url.to_owned());
                result
            }
        }

        /// An interrupt that, once the phase waits on it, records the redirect
        /// file's content (`None` when the file is absent) and resolves.
        pub(crate) async fn interrupt(&self) -> io::Result<()> {
            let page = self
                .launched
                .borrow()
                .first()
                .and_then(|launched| url::Url::parse(launched).ok())
                .and_then(|launched| launched.to_file_path().ok())
                .and_then(|file| std::fs::read_to_string(file).ok());
            *self.during_wait.borrow_mut() = Some(page);
            Ok(())
        }

        /// Every URL the opener received.
        pub(crate) fn launched(&self) -> Vec<String> {
            self.launched.borrow().clone()
        }

        /// The redirect file named by the single URL the opener received.
        pub(crate) fn redirect_file(&self) -> PathBuf {
            let launched = self.launched();
            assert_eq!(launched.len(), 1, "{launched:?}");
            url::Url::parse(&launched[0])
                .unwrap()
                .to_file_path()
                .unwrap()
        }

        /// Asserts the private handoff of `bearer_url`, whose secret part is
        /// `secret`: the opener received exactly one `file://` URL free of the
        /// secret; the file was present and redirected to `bearer_url` while
        /// the phase waited; the file and its directory are gone now.
        pub(crate) fn assert_private_handoff(&self, bearer_url: &str, secret: &str) {
            let launched = self.launched();
            assert_eq!(launched.len(), 1, "{launched:?}");
            assert!(launched[0].starts_with("file://"), "{}", launched[0]);
            assert!(!launched[0].contains(secret), "{}", launched[0]);
            let page = self
                .during_wait
                .borrow()
                .clone()
                .expect("the phase waited on the interrupt");
            let page = page.expect("the redirect file existed while the phase waited");
            assert!(page.contains(bearer_url), "{page}");
            let file = self.redirect_file();
            assert!(!file.exists(), "{}", file.display());
            assert!(!file.parent().unwrap().exists(), "{}", file.display());
        }

        /// Asserts that a failed open made exactly one attempt, with a
        /// `file://` URL free of `secret`, and left no file behind.
        pub(crate) fn assert_failed_open_left_nothing(&self, secret: &str) {
            let launched = self.launched();
            assert_eq!(launched.len(), 1, "{launched:?}");
            assert!(launched[0].starts_with("file://"), "{}", launched[0]);
            assert!(!launched[0].contains(secret), "{}", launched[0]);
            let file = self.redirect_file();
            assert!(!file.parent().unwrap().exists(), "{}", file.display());
        }

        /// Whether the phase waited on the interrupt.
        pub(crate) fn waited(&self) -> bool {
            self.during_wait.borrow().is_some()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::cell::RefCell;

    use super::*;

    const TOKEN: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn bearer_url() -> String {
        format!("http://127.0.0.1:41234/bootstrap/{TOKEN}")
    }

    fn entries(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect()
    }

    /// The launcher sees only a `file://` URL without the bearer secret; the
    /// file it names still holds the redirect when the browser reads it later,
    /// and closing the guard removes it.
    #[test]
    fn private_open_hides_bearer_and_keeps_file_alive() {
        let base = tempfile::tempdir().unwrap();
        let seen = RefCell::new(Vec::<String>::new());
        let guard = open_private_in(
            base.path(),
            &bearer_url(),
            |arg| {
                seen.borrow_mut().push(arg.to_owned());
                Ok(())
            },
            |_, _| {},
        )
        .unwrap();

        let seen = seen.into_inner();
        assert_eq!(seen.len(), 1);
        let launched = Url::parse(&seen[0]).unwrap();
        assert_eq!(launched.scheme(), "file");
        assert!(!seen[0].contains(TOKEN));
        assert!(!seen[0].contains("bootstrap"));

        // The browser reads the file after the launcher returned.
        let path = launched.to_file_path().unwrap();
        assert_eq!(path, guard.file_path());
        let page = std::fs::read_to_string(&path).unwrap();
        assert!(
            page.contains(&format!(
                r#"<meta http-equiv="refresh" content="0;url={}">"#,
                bearer_url()
            )),
            "{page}"
        );
        assert!(page.contains(r#"<meta name="referrer" content="no-referrer">"#));
        assert!(page.contains(r#"content="default-src 'none'""#));
        assert_eq!(page.matches("http://").count(), 1);
        assert!(!page.contains("https://"));
        assert!(!page.contains("<script"));
        assert!(!page.contains("src="));

        guard.close().unwrap();
        assert!(!path.exists());
        assert!(entries(base.path()).is_empty());
    }

    /// The directory and the file are private, and the file still empty, at
    /// the moment the first byte of the secret is written.
    #[cfg(unix)]
    #[test]
    fn private_open_permissions_precede_secret_write() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = tempfile::tempdir().unwrap();
        let observed = RefCell::new(None);
        let guard = open_private_in(
            base.path(),
            &bearer_url(),
            |_| Ok(()),
            |dir, file| {
                let dir_meta = std::fs::symlink_metadata(dir).unwrap();
                let file_meta = std::fs::symlink_metadata(file).unwrap();
                *observed.borrow_mut() = Some((
                    dir_meta.permissions().mode() & 0o777,
                    file_meta.permissions().mode() & 0o777,
                    file_meta.len(),
                    std::fs::read(file).unwrap(),
                ));
            },
        )
        .unwrap();
        let (dir_mode, file_mode, len, content) = observed.into_inner().expect("hook ran");
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        assert_eq!(len, 0);
        assert!(content.is_empty());
        drop(guard);
    }

    /// A directory path that already exists, as a directory, a symbolic link
    /// to a directory, or a dangling symbolic link, is refused before anything
    /// is written or launched, and the link target is left untouched.
    #[cfg(unix)]
    #[test]
    fn private_open_refuses_unsafe_existing_paths() {
        let base = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();

        let existing = base.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        let linked = base.path().join("linked");
        std::os::unix::fs::symlink(elsewhere.path(), &linked).unwrap();
        let dangling = base.path().join("dangling");
        let dangling_target = elsewhere.path().join("created-through-link");
        std::os::unix::fs::symlink(&dangling_target, &dangling).unwrap();

        for path in [&existing, &linked, &dangling] {
            let launched = RefCell::new(false);
            let error = open_private_at(
                path,
                &bearer_url(),
                |_| {
                    *launched.borrow_mut() = true;
                    Ok(())
                },
                |_, _| panic!("nothing may be written under {}", path.display()),
            )
            .unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::AlreadyExists,
                "{}",
                path.display()
            );
            assert!(!launched.into_inner());
            assert!(!error.to_string().contains(TOKEN));
        }
        assert!(entries(&existing).is_empty());
        assert!(entries(elsewhere.path()).is_empty());
        assert!(!dangling_target.exists());
    }

    /// Every exit removes the file and the directory: an explicit close, a
    /// drop, a failing launcher, a task cancelled while it holds the guard.
    #[test]
    fn private_open_cleans_up_on_all_exits() {
        let base = tempfile::tempdir().unwrap();

        let closed = open_private_in(base.path(), &bearer_url(), |_| Ok(()), |_, _| {}).unwrap();
        assert_eq!(entries(base.path()).len(), 1);
        closed.close().unwrap();
        assert!(entries(base.path()).is_empty());

        let dropped = open_private_in(base.path(), &bearer_url(), |_| Ok(()), |_, _| {}).unwrap();
        assert_eq!(entries(base.path()).len(), 1);
        drop(dropped);
        assert!(entries(base.path()).is_empty());

        let failed = open_private_in(
            base.path(),
            &bearer_url(),
            |_| Err(io::Error::other("no browser")),
            |_, _| {},
        )
        .unwrap_err();
        assert_eq!(failed.to_string(), "no browser");
        assert!(entries(base.path()).is_empty());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let guard = open_private_in(base.path(), &bearer_url(), |_| Ok(()), |_, _| {}).unwrap();
            let task = tokio::spawn(async move {
                let _held = guard;
                std::future::pending::<()>().await;
            });
            tokio::task::yield_now().await;
            assert_eq!(entries(base.path()).len(), 1);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        });
        assert!(entries(base.path()).is_empty());
    }

    /// Only the wallet's loopback HTTP destinations are accepted, and a
    /// refusal neither launches anything nor echoes the URL.
    #[test]
    fn private_open_accepts_only_wallet_loopback_destinations() {
        for accepted in [
            format!("http://127.0.0.1:1/bootstrap/{TOKEN}"),
            format!("http://localhost:65535/bootstrap/{TOKEN}"),
            "http://localhost:8080/register/AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            format!("http://[::1]:9/bootstrap/{TOKEN}"),
        ] {
            assert!(loopback_destination(&accepted).is_ok(), "{accepted}");
        }
        let base = tempfile::tempdir().unwrap();
        for refused in [
            format!("https://127.0.0.1:1/bootstrap/{TOKEN}"),
            format!("http://127.0.0.1/bootstrap/{TOKEN}"),
            format!("http://127.0.0.2:1/bootstrap/{TOKEN}"),
            format!("http://example.com:1/bootstrap/{TOKEN}"),
            format!("http://user:pass@127.0.0.1:1/bootstrap/{TOKEN}"),
            format!("http://127.0.0.1:1/bootstrap/{TOKEN}'"),
            format!("http://127.0.0.1:1/bootstrap/{TOKEN};x"),
            format!("file:///tmp/{TOKEN}"),
            format!("javascript:{TOKEN}"),
            TOKEN.to_owned(),
        ] {
            let launched = RefCell::new(false);
            let error = open_private_in(
                base.path(),
                &refused,
                |_| {
                    *launched.borrow_mut() = true;
                    Ok(())
                },
                |_, _| {},
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{refused}");
            assert!(!error.to_string().contains(TOKEN), "{refused}");
            assert!(!launched.into_inner(), "{refused}");
        }
        assert!(entries(base.path()).is_empty());
    }

    #[test]
    fn private_open_debug_is_redacted() {
        let base = tempfile::tempdir().unwrap();
        let guard = open_private_in(base.path(), &bearer_url(), |_| Ok(()), |_, _| {}).unwrap();
        let rendered = format!("{guard:?}");
        assert_eq!(rendered, "PrivateOpen { .. }");
    }
}
