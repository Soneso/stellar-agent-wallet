//! In-memory log capture for test-time subscriber output.
//!
//! Provides [`CaptureWriter`], a `MakeWriter` implementation backed by a
//! shared `Arc<Mutex<Vec<u8>>>` buffer that collects every byte written by a
//! `tracing_subscriber` fmt layer. The buffer is cheaply `Clone`d so that the
//! same `CaptureWriter` instance can be passed to both the subscriber
//! constructor and the assertion side of a test.
//!
//! After the test runs, call [`CaptureWriter::captured`] (or
//! [`CaptureWriter::captured_str`]) and pass the result to
//! [`crate::assert_no_secret_bytes`] to assert that no secret material
//! reached the writer.

// The `expect` calls in this module are on `std::sync::Mutex::lock()` results.
// A mutex can only be poisoned if a thread panicked while holding the lock.
// In single-threaded tests (the only context this crate targets) that cannot
// happen; the `expect` is therefore provably infallible.
#![allow(clippy::expect_used)]

use std::{
    io,
    sync::{Arc, Mutex},
};

/// In-memory writer that accumulates bytes written by a `tracing_subscriber`
/// fmt layer.
///
/// Each clone shares the same underlying buffer, so the subscriber and the
/// assertion side of a test can hold independent handles that observe each
/// other's writes.
///
/// # Examples
///
/// ```rust
/// use stellar_agent_test_support::{CaptureWriter, assert_no_secret_bytes};
///
/// let capture = CaptureWriter::new();
/// let subscriber = tracing_subscriber::fmt()
///     .with_writer(capture.clone())
///     .finish();
/// tracing::subscriber::with_default(subscriber, || {
///     tracing::info!(message = "hello");
/// });
/// assert_no_secret_bytes(&capture.captured());
/// ```
#[derive(Clone)]
pub struct CaptureWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl CaptureWriter {
    /// Creates a new `CaptureWriter` with an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns a clone of the current buffer contents.
    ///
    /// Takes the mutex lock for the duration of the copy. The returned
    /// `Vec<u8>` is independent of the internal buffer.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (only possible if a previous
    /// writer thread panicked while holding the lock, which cannot happen in
    /// single-threaded tests).
    #[must_use]
    pub fn captured(&self) -> Vec<u8> {
        self.buf
            .lock()
            .expect("CaptureWriter mutex poisoned")
            .clone()
    }

    /// Returns the captured bytes interpreted as a lossy UTF-8 string.
    ///
    /// Non-UTF-8 bytes are replaced with the Unicode replacement character.
    /// In practice, the `tracing_subscriber` fmt layer always emits valid
    /// UTF-8, so replacement is a safety net.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (see [`Self::captured`]).
    #[must_use]
    pub fn captured_str(&self) -> String {
        String::from_utf8_lossy(&self.captured()).into_owned()
    }

    /// Empties the buffer.
    ///
    /// Useful in multi-phase tests where each phase should be assessed
    /// independently.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (see [`Self::captured`]).
    pub fn clear(&self) {
        self.buf
            .lock()
            .expect("CaptureWriter mutex poisoned")
            .clear();
    }
}

impl Default for CaptureWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl io::Write for CaptureWriter {
    /// Appends `buf` to the internal byte buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal mutex is poisoned. In practice this
    /// cannot happen in single-threaded tests.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf
            .lock()
            .map_err(|_| io::Error::other("CaptureWriter mutex poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Flush is a no-op; the buffer is held in memory.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;

    /// Returns a clone of this `CaptureWriter`.
    ///
    /// Because all clones share the same `Arc<Mutex<Vec<u8>>>`, bytes written
    /// through the returned clone are visible via any other clone.
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Strict tracing-capture harness for asserting that selected plaintext values
/// never reach subscriber output.
///
/// The harness combines [`CaptureWriter`] with a `tracing_subscriber` fmt
/// subscriber. Tests execute the code under test through [`Self::run`] so the
/// subscriber is mounted only for the closure body, then call
/// [`Self::assert_clean`] after capture has stopped.
pub struct RedactionStrictSubscriber {
    capture: CaptureWriter,
    forbidden: Vec<Vec<u8>>,
}

impl RedactionStrictSubscriber {
    /// Creates a strict subscriber harness that rejects the supplied forbidden
    /// plaintext needles.
    #[must_use]
    pub fn new<I, S>(forbidden: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        Self {
            capture: CaptureWriter::new(),
            forbidden: forbidden
                .into_iter()
                .map(|needle| needle.as_ref().to_vec())
                .collect(),
        }
    }

    fn subscriber_guard(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
        tracing_subscriber::fmt()
            .with_writer(self.capture.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish()
    }

    /// Executes `f` with the strict subscriber mounted as the default.
    ///
    /// The subscriber is unmounted before this method returns, so callers can
    /// run the code under test inside the closure and then call
    /// [`Self::assert_clean`] knowing that no later writes can be captured.
    pub fn run<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        tracing::subscriber::with_default(self.subscriber_guard(), f)
    }

    /// Builds a `tracing` subscriber that writes every formatted event to the
    /// harness capture buffer.
    ///
    /// Prefer [`Self::run`] for new tests so the subscriber lifetime is bounded
    /// by the code under test.
    #[doc(hidden)]
    #[deprecated(note = "use RedactionStrictSubscriber::run to bound capture lifetime")]
    #[must_use]
    pub fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
        self.subscriber_guard()
    }

    /// Returns captured subscriber output as lossy UTF-8.
    #[must_use]
    pub fn captured_str(&self) -> String {
        self.capture.captured_str()
    }

    /// Panics if captured output contains any forbidden plaintext needle or a
    /// generic secret pattern such as an S-strkey or sensitive field value.
    ///
    /// # Panics
    ///
    /// Panics on the first detected forbidden byte sequence or generic secret
    /// pattern in the captured subscriber output.
    pub fn assert_clean(&self) {
        let captured = self.capture.captured();
        for needle in &self.forbidden {
            if needle.is_empty() {
                continue;
            }
            assert!(
                memchr::memmem::find(&captured, needle.as_slice()).is_none(),
                "captured logs contain forbidden plaintext: {}",
                String::from_utf8_lossy(needle)
            );
        }
        crate::assert_no_secret_bytes(&captured);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn write_read_round_trip() {
        let mut writer = CaptureWriter::new();
        writer.write_all(b"hello world").expect("write failed");
        assert_eq!(writer.captured(), b"hello world");
    }

    #[test]
    fn captured_str_returns_utf8() {
        let mut writer = CaptureWriter::new();
        writer
            .write_all(b"structured log line\n")
            .expect("write failed");
        assert_eq!(writer.captured_str(), "structured log line\n");
    }

    #[test]
    fn make_writer_shares_buffer() {
        let capture = CaptureWriter::new();
        // Obtain a writer instance through the MakeWriter trait.
        let mut w = tracing_subscriber::fmt::MakeWriter::make_writer(&capture);
        w.write_all(b"from make_writer").expect("write failed");
        // The original capture sees the bytes.
        assert_eq!(capture.captured(), b"from make_writer");
    }

    #[test]
    fn clone_shares_buffer() {
        let a = CaptureWriter::new();
        let mut b = a.clone();
        b.write_all(b"written via b").expect("write failed");
        // `a` observes the write made through `b`.
        assert_eq!(a.captured(), b"written via b");
    }

    #[test]
    fn clear_empties_buffer() {
        let capture = CaptureWriter::new();
        let mut w = tracing_subscriber::fmt::MakeWriter::make_writer(&capture);
        w.write_all(b"phase one").expect("write failed");
        capture.clear();
        assert!(capture.captured().is_empty());
    }

    #[test]
    fn multiple_writes_accumulate() {
        let capture = CaptureWriter::new();
        {
            let mut w = tracing_subscriber::fmt::MakeWriter::make_writer(&capture);
            w.write_all(b"line one\n").expect("write failed");
        }
        {
            let mut w = tracing_subscriber::fmt::MakeWriter::make_writer(&capture);
            w.write_all(b"line two\n").expect("write failed");
        }
        assert_eq!(capture.captured(), b"line one\nline two\n");
    }

    #[test]
    fn strict_subscriber_detects_forbidden_plaintext() {
        let strict = RedactionStrictSubscriber::new(["memo-secret"]);
        strict.run(|| {
            tracing::info!("memo-secret");
        });

        let result = std::panic::catch_unwind(|| strict.assert_clean());
        assert!(result.is_err());
    }

    #[test]
    fn capture_writer_default_write_flush_roundtrip() {
        use std::io::Write as _;
        let mut w = CaptureWriter::default();
        w.write_all(b"hello ").expect("write");
        w.write_all(b"world").expect("write");
        w.flush().expect("flush is a no-op");
        assert_eq!(w.captured_str(), "hello world");
    }

    #[test]
    fn strict_subscriber_clean_output_passes_and_exposes_capture() {
        // An empty needle in the forbidden set must be skipped, not matched.
        let strict = RedactionStrictSubscriber::new([Vec::new(), b"never-logged".to_vec()]);
        strict.run(|| {
            tracing::info!("ordinary message with no secrets");
        });
        assert!(strict.captured_str().contains("ordinary message"));
        // Clean output: no forbidden needle and no secret pattern, so the
        // generic secret scan at the end of assert_clean is reached and passes.
        strict.assert_clean();
    }
}
