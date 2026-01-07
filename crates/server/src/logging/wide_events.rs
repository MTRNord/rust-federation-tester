use std::fmt::Display;

/// WideEvent - improved, OTLP-friendly, ergonomic API
///
/// This module implements a compact WideEvent API that records attributes directly on the
/// underlying `tracing::Span` so OpenTelemetry exporters see attributes (not a single JSON blob).
///
/// Usage examples:
///
/// Per-request/event:
/// ```rust
/// // Create a WideEvent at the start of handling a request and attach attributes as they
/// // become available. Enter the span to make other tracing events children of it.
/// let evt = WideEvent::new("request", "rust_federation_tester::api");
/// evt.add("request_id", &request_id);
/// evt.add_opt("user_id", maybe_user_id.as_ref());
/// evt.info("request complete");
/// ```
///
/// Quick inline:
/// ```rust
/// // Use the evt-form to log quickly with an existing WideEvent
/// wide_info!(evt, "done processing item {}", id);
/// ```
///
/// Implementation notes:
/// We record values with `tracing::field::display` which maps neatly to OTLP string attributes.
/// Numeric types will still be formatted as strings. If you need strictly typed OTLP attributes
/// later, we can add typed helpers that call `span.record` with typed values.
use tracing::{Level, Span, field};

#[derive(Clone)]
pub struct WideEvent {
    // A span that represents the lifetime / scope of this event.
    span: Span,
}

impl WideEvent {
    /// Create a new wide event with the given name. The span will have the provided `target`.
    /// This is intentionally tiny so creation looks like:
    ///   let evt = WideEvent::new("request", "mycrate::module");
    ///
    /// The macro `tracing::span!` expects a literal span name; to support dynamic
    /// logical names we use a fixed span name "wide_event" and record the logical
    /// `event.name` attribute on the span. This avoids the "non-constant value"
    /// macro error while still exporting the event name to OTLP.
    pub fn new(name: &'static str, target: &'static str) -> Self {
        // Use an INFO-level span by default; the emitted events can use any level.
        // span name is a literal to satisfy macro constraints, record the logical name as attribute.
        let span = tracing::span!(Level::INFO, "wide_event", target = target, event.name = %name);
        WideEvent { span }
    }

    /// Enter the span and return a guard that keeps it entered while alive.
    /// Use `let _enter = evt.enter();` so other tracing events become children of this span.
    pub fn enter<'a>(&'a self) -> tracing::span::Entered<'a> {
        self.span.enter()
    }

    /// Add a field to the span. This records the field on the underlying span so OTLP
    /// exporters will receive it as a span attribute.
    ///
    /// Key should be a stable static string (OTLP attribute name). Value must implement
    /// `Display`. For convenience, you can pass references or primitives.
    pub fn add<V: Display>(&self, key: &'static str, value: V) {
        // Record using `field::display` so the value forwards to the OTLP exporter.
        self.span.record(key, field::display(value));
    }

    /// Add an optional field only if `Some`.
    pub fn add_opt<V: Display>(&self, key: &'static str, value: Option<V>) {
        if let Some(v) = value {
            self.add(key, v);
        }
    }

    /// Convenience typed helpers (examples) - add more as needed.
    pub fn add_u64(&self, key: &'static str, value: u64) {
        // `field::display` will stringify; if you want numeric typed attributes in OTLP
        // we can add explicit `Value` conversions later.
        self.span.record(key, field::display(value));
    }

    /// Emit an event at the given level. The span's recorded attributes will be
    /// associated with the emitted event by the subscriber/exporter.
    pub fn emit(&self, message: &str, level: Level) {
        // Use `in_scope` so the event attaches to this span.
        self.span.in_scope(|| match level {
            Level::ERROR => tracing::event!(Level::ERROR, message = %message),
            Level::WARN => tracing::event!(Level::WARN, message = %message),
            Level::INFO => tracing::event!(Level::INFO, message = %message),
            Level::DEBUG => tracing::event!(Level::DEBUG, message = %message),
            Level::TRACE => tracing::event!(Level::TRACE, message = %message),
        });
    }

    /// Convenience emission methods for common levels so callsites are compact:
    ///   evt.info("done");
    pub fn info(&self, message: &str) {
        self.emit(message, Level::INFO)
    }
    pub fn warn(&self, message: &str) {
        self.emit(message, Level::WARN)
    }
    pub fn error(&self, message: &str) {
        self.emit(message, Level::ERROR)
    }
    pub fn debug(&self, message: &str) {
        self.emit(message, Level::DEBUG)
    }
    pub fn trace(&self, message: &str) {
        self.emit(message, Level::TRACE)
    }
}

/// Small ergonomic macros so usage can look similar to `tracing::info`.
/// These macros support two forms:
/// 1) evt-form: pass an existing WideEvent instance and a format string:
/// ```rust
/// let evt = WideEvent::new("request", "mycrate::api");
/// wide_info!(evt, "handled request {}", id);
/// ```
/// 2) inline-form: create a WideEvent for a one-off event and optionally attach key/value pairs:
/// ```rust
/// wide_info!("request", "mycrate::api", "handled request", request_id = id, user_id = user);
/// ```
///
/// The inline form will create a temporary `WideEvent`, add the provided key/value pairs
/// (keys are recorded as static attribute names via `stringify!($k)`), then emit the event.
///
/// Note: the macros use `$crate::logging::wide_events::WideEvent` to create inline events so
/// they work when invoked from other crates that depend on this crate.
#[macro_export]
macro_rules! wide_info {
    // Existing evt-form: pass an existing WideEvent instance and format args
    ($evt:expr, $($arg:tt)+) => {
        $evt.emit(&format!($($arg)+), tracing::Level::INFO)
    };
    // Inline form: create a WideEvent, optionally add key=value pairs, then emit.
    // Usage: wide_info!("name", "target", "message", key1 = val1, key2 = val2);
    ($name:expr, $target:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let evt = $crate::logging::wide_events::WideEvent::new($name, $target);
            $( evt.add(stringify!($k), $v); )*
            evt.emit($msg, tracing::Level::INFO);
        }
    };
}
#[macro_export]
macro_rules! wide_debug {
    // evt-form
    ($evt:expr, $($arg:tt)+) => {
        $evt.emit(&format!($($arg)+), tracing::Level::DEBUG)
    };
    // inline form
    ($name:expr, $target:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let evt = $crate::logging::wide_events::WideEvent::new($name, $target);
            $( evt.add(stringify!($k), $v); )*
            evt.emit($msg, tracing::Level::DEBUG);
        }
    };
}
#[macro_export]
macro_rules! wide_error {
    // evt-form
    ($evt:expr, $($arg:tt)+) => {
        $evt.emit(&format!($($arg)+), tracing::Level::ERROR)
    };
    // inline form
    ($name:expr, $target:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let evt = $crate::logging::wide_events::WideEvent::new($name, $target);
            $( evt.add(stringify!($k), $v); )*
            evt.emit($msg, tracing::Level::ERROR);
        }
    };
}
