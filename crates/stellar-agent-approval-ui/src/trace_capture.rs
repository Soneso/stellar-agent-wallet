//! Test-only span and event capture for the loopback servers' trace tests.
//!
//! [`SpanCapture::install`] makes a collector the current thread's default
//! dispatcher and records every span's fields and every event's fields as
//! one text line each. The trace tests drive a router on that thread and
//! assert on the lines: what a request span records and what never reaches
//! any field.

#![allow(
    clippy::unwrap_used,
    reason = "test-only; a poisoned lock is a failure"
)]

use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// Records every span and event field as text, in emission order.
#[derive(Clone, Default)]
pub(crate) struct SpanCapture {
    lines: Arc<Mutex<Vec<String>>>,
    next_id: Arc<Mutex<u64>>,
}

/// Keeps a [`SpanCapture`] installed until dropped.
pub(crate) struct InstalledCapture {
    capture: SpanCapture,
    _default: tracing::subscriber::DefaultGuard,
    /// Registered before the capture's dispatcher and kept while it is
    /// installed, so `tracing` computes callsite interest from every
    /// registered dispatcher, the capture's included.
    _inert: tracing::Dispatch,
}

impl SpanCapture {
    /// Installs a fresh capture as this thread's default dispatcher.
    pub(crate) fn install() -> InstalledCapture {
        let inert = stellar_agent_test_support::inert_dispatcher();
        let capture = Self::default();
        let default = tracing::subscriber::set_default(capture.clone());
        tracing::callsite::rebuild_interest_cache();
        InstalledCapture {
            capture,
            _default: default,
            _inert: inert,
        }
    }

    fn push(&self, line: String) {
        self.lines.lock().unwrap().push(line);
    }
}

impl InstalledCapture {
    /// Every line recorded so far.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.capture.lines.lock().unwrap().clone()
    }

    /// The `path` field of every span named `span_name`, in creation order.
    pub(crate) fn span_paths(&self, span_name: &str) -> Vec<String> {
        let prefix = format!("{span_name} ");
        self.lines()
            .iter()
            .filter(|line| line.starts_with(&prefix))
            .filter_map(|line| {
                line.split(' ')
                    .find_map(|field| field.strip_prefix("path="))
                    .map(str::to_owned)
            })
            .collect()
    }
}

struct Collect<'a>(&'a mut String);

impl Visit for Collect<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={value:?}", field.name()));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push_str(&format!(" {}={value}", field.name()));
    }
}

impl Subscriber for SpanCapture {
    fn register_callsite(
        &self,
        _metadata: &'static Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }

    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn new_span(&self, span: &Attributes<'_>) -> Id {
        let mut line = span.metadata().name().to_owned();
        span.record(&mut Collect(&mut line));
        self.push(line);
        let mut next = self.next_id.lock().unwrap();
        *next += 1;
        Id::from_u64(*next)
    }

    fn record(&self, _span: &Id, values: &Record<'_>) {
        let mut line = String::from("record");
        values.record(&mut Collect(&mut line));
        self.push(line);
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut line = event.metadata().name().to_owned();
        event.record(&mut Collect(&mut line));
        self.push(line);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}
