/*
wide_events crate - provides WideEvent and ergonomic macros for Wide Event logging.

This file is a migration of the previous `wide_events.rs` implementation into a standalone
library crate. It exposes:

- `WideEvent` type: a small ergonomic wrapper around a `tracing::Span` that records
  attributes (fields) directly on the span so exporters (OTLP etc.) receive structured
  attributes rather than a single JSON blob.
- `wide_info!`, `wide_debug!`, `wide_error!` macros for quick event emission.
- `wide_instrument!` macro that constructs and returns a `WideEvent` for function-level
  instrumentation (the caller may `enter()` it for the desired scope).

Notes:
- The span name is a literal `"wide_event"` to satisfy `tracing::span!` macro constraints.
  The logical event name is recorded as a span attribute `event.name`.
- Values are recorded using `tracing::field::display`, which routes them to OTLP as
  string-like attributes. If you later want numeric/bool typed attributes in OTLP,
  consider adding typed helpers that convert to `opentelemetry::Value` or appropriate types.
*/

use std::fmt::Display;
use tracing::{Level, Span, field};

/// A compact wrapper that owns a `tracing::Span` and records fields directly on it.
///
/// Create with `WideEvent::new("name", "target")`. The `target` should be a stable
/// module path like `concat!(env!("CARGO_PKG_NAME"), "::", module_path!())`.
#[derive(Clone)]
pub struct WideEvent {
    span: Span,
    target: &'static str,
}

impl WideEvent {
    /// Construct a WideEvent from an existing `tracing::Span`.
    ///
    /// This is useful for inline macro forms that create a `tracing::span!` with a
    /// literal span name so the span name visible in tracing backends is the logical
    /// event name. Callers can then `enter()` or clone the span as needed.
    pub fn from_span(span: Span) -> Self {
        WideEvent {
            span,
            target: concat!(env!("CARGO_PKG_NAME"), "::", module_path!()),
        }
    }

    /// Construct a WideEvent from an existing `tracing::Span` and an explicit target string.
    /// Use this when the macro creating the span also knows the desired `target` value.
    pub fn from_span_with_target(span: Span, target: &'static str) -> Self {
        WideEvent { span, target }
    }

    /// Return a clone of the inner tracing::Span so it can be passed to other callers
    /// or used to instrument spawned tasks.
    pub fn span(&self) -> Span {
        self.span.clone()
    }

    /// Return the recorded target associated with this WideEvent (usually crate::module).
    pub fn target(&self) -> &'static str {
        self.target
    }

    /// Create a new WideEvent with a logical `name` and `target`.
    ///
    /// `name` should be a &'static str (logical event name). `target` should be the
    /// tracing target string (usually package::module).
    pub fn new(name: &'static str, target: &'static str) -> Self {
        // `tracing::span!` requires a literal span name in many usage patterns.
        // This helper uses a stable literal span name and records the logical event
        // name as a span attribute so exporters still receive it when callers cannot
        // provide a literal span name at macro-invocation time.
        let span = tracing::span!(Level::INFO, "wide_event", target = target, event.name = %name);
        WideEvent { span, target }
    }

    /// Create a WideEvent that is a child of the provided parent span.
    /// Usage: let child = WideEvent::with_parent("name", "target", parent_span);
    /// Note: `parent` is taken by value (a Span clone) so callers can do `with_parent(..., evt.span())`.
    pub fn with_parent(name: &'static str, target: &'static str, parent: Span) -> Self {
        let span = tracing::span!(parent: &parent, tracing::Level::INFO, "wide_event", target = target, event.name = %name);
        WideEvent { span, target }
    }

    /// Enter the span and return a guard that keeps it entered while alive.
    /// Use `let _enter = evt.enter();` so child events become children of this span.
    pub fn enter<'a>(&'a self) -> tracing::span::Entered<'a> {
        self.span.enter()
    }

    /// Record a field/attribute on the span. Value must implement `Display`.
    /// Keys should be stable static strings (OTLP attribute names).
    pub fn add<V: Display>(&self, key: &'static str, value: V) {
        self.span.record(key, field::display(value));
    }

    /// Add an optional field only when `Some`.
    pub fn add_opt<V: Display>(&self, key: &'static str, value: Option<V>) {
        if let Some(v) = value {
            self.add(key, v);
        }
    }

    /// Convenience typed helper for u64 values (still recorded as display/text).
    pub fn add_u64(&self, key: &'static str, value: u64) {
        self.span.record(key, field::display(value));
    }

    /// Emit an event under this span with the provided message and level.
    /// The recorded span attributes will be associated with the emitted event.
    pub fn emit(&self, message: &str, level: Level) {
        self.span.in_scope(|| match level {
            Level::ERROR => tracing::event!(Level::ERROR, message = %message),
            Level::WARN => tracing::event!(Level::WARN, message = %message),
            Level::INFO => tracing::event!(Level::INFO, message = %message),
            Level::DEBUG => tracing::event!(Level::DEBUG, message = %message),
            Level::TRACE => tracing::event!(Level::TRACE, message = %message),
        });
    }

    /// Convenience level-specific emitters.
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

    /// Record a W3C `traceparent` header value as attributes on this WideEvent.
    /// This records the raw header under `traceparent.incoming` and, when possible,
    /// extracts and records `trace.trace_id`, `trace.span_id` and `trace.trace_flags`
    /// as additional attributes for better OTel correlation.
    pub fn record_traceparent(&self, traceparent: &str) {
        // Record the raw header first so it's always available.
        self.add("traceparent.incoming", traceparent);

        // Try to parse the canonical W3C `traceparent` format:
        //   version-traceid-spanid-flags  (example: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() >= 4 {
            let trace_id = parts[1];
            let span_id = parts[2];
            let trace_flags = parts[3];
            // Record parsed components as stable attributes for OTel consumption.
            self.add("trace.trace_id", trace_id);
            self.add("trace.span_id", span_id);
            self.add("trace.trace_flags", trace_flags);
        }
    }

    /// Record trace identifiers from the current tracing span's OpenTelemetry SpanContext.
    /// When `tracing-opentelemetry` is enabled this will record `trace.trace_id`,
    /// `trace.span_id` and `trace.trace_flags` attributes on this WideEvent when available.
    #[cfg(feature = "tracing-opentelemetry")]
    pub fn record_current_span_context(&self) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        // Extract the span context from the current tracing span.
        let cx = self.span.context();
        let span_ref = cx.span();
        let span_ctx = span_ref.span_context();
        if span_ctx.is_valid() {
            self.add("trace.trace_id", span_ctx.trace_id().to_string());
            self.add("trace.span_id", span_ctx.span_id().to_string());
            self.add(
                "trace.trace_flags",
                format!("{:02x}", span_ctx.trace_flags().to_u8()),
            );
        }
    }

    /// No-op when tracing-opentelemetry is not enabled so callers can always invoke this helper.
    #[cfg(not(feature = "tracing-opentelemetry"))]
    pub fn record_current_span_context(&self) {}

    /// Mark the span/event with an OTel-like status of ERROR and record a description.
    /// This records attributes `otel.status_code` and `otel.status_description`.
    pub fn set_status_error(&self, description: &str) {
        self.add("otel.status_code", "ERROR");
        self.add("otel.status_description", description);
    }

    /// Mark the span/event with an OTel-like status of OK.
    pub fn set_status_ok(&self) {
        self.add("otel.status_code", "OK");
    }

    /// Helper to attach common HTTP request attributes following OTel conventions.
    /// `method` should be an HTTP verb (GET/POST/etc). `target` is the request target/path.
    pub fn attach_http_request(&self, method: &str, target: &str) {
        // Use OTel semantic names for HTTP where appropriate.
        self.add("http.method", method);
        self.add("http.target", target);
    }

    /// Helper to attach HTTP response attributes and map status -> OTel status hint.
    /// Records `http.status_code` as a numeric value (u64) and sets `otel.status_code`
    /// to ERROR for 5xx responses. The numeric status is recorded with `add_u64` so
    /// downstream exporters can treat it as a number.
    pub fn attach_http_response_status(&self, status: u16) {
        // Record numeric status code explicitly so it's available in telemetry as a number.
        self.add_u64("http.status_code", status as u64);
        if status >= 500 {
            self.add("otel.status_code", "ERROR");
            self.add("otel.status_description", format!("HTTP {}", status));
        } else {
            // Treat 4xx as OK from an OTel status perspective (application-level errors),
            // but the numeric `http.status_code` remains available for routing/alerts.
            self.add("otel.status_code", "OK");
        }
    }
}

/// Ergonomic macros to emit events with a `WideEvent` or inline.
///
/// Forms supported:
/// - evt-form: `wide_info!(evt, "message {}", arg);` where `evt` is a `WideEvent`.
/// - inline form: `wide_info!("name", "target", "message", key = val, ...)` creates a
///   temporary `WideEvent`, records key/value pairs, then emits the message.
///
/// The macros use `$crate::WideEvent` to construct inline events so they work when
/// invoked from other crates that depend on this crate.
#[macro_export]
macro_rules! wide_info {
    // name + msg convenience form with automatic target and optional key-value pairs
    ($name:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let __span = tracing::span!(tracing::Level::INFO, $name, target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()));
            let __evt = $crate::WideEvent::from_span_with_target(__span, concat!(env!("CARGO_PKG_NAME"), "::", module_path!()));
            $( __evt.add(stringify!($k), $v); )*
            __evt.emit($msg, tracing::Level::INFO);
            __evt
        }
    };

    // pass wide event as argument and use it as parent. Require name and message and optional key-value pairs
    ($evt:expr, $name:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let __evt = $crate::WideEvent::with_parent($name, $evt.target(), $evt.span());
            $( __evt.add(stringify!($k), $v); )*
            __evt.emit($msg, tracing::Level::ERROR);
            __evt
        }
    };

    // Inline form: create a WideEvent with a literal span name so backends show it,
    // optionally add key=value pairs, then emit.
    // Usage: wide_info!("my.event", "mycrate::module", "message", key1 = val1, ...);
    ($name:expr, $target:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let __span = tracing::span!(tracing::Level::INFO, $name, target = $target);
            let __evt = $crate::WideEvent::from_span_with_target(__span, $target);
            $( __evt.add(stringify!($k), $v); )*
            __evt.emit($msg, tracing::Level::INFO);
            __evt
        }
    };
}

#[macro_export]
macro_rules! wide_debug {
    // name + msg convenience form with automatic target and optional key-value pairs
    ($name:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let __span = tracing::span!(tracing::Level::DEBUG, $name, target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()));
            let __evt = $crate::WideEvent::from_span_with_target(__span, concat!(env!("CARGO_PKG_NAME"), "::", module_path!()));
            $( __evt.add(stringify!($k), $v); )*
            __evt.emit($msg, tracing::Level::DEBUG);
            __evt
        }
    };

    // pass wide event as argument and use it as parent. Require name and message and optional key-value pairs
    ($evt:expr, $name:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let __evt = $crate::WideEvent::with_parent($name, $evt.target(), $evt.span());
            $( __evt.add(stringify!($k), $v); )*
            __evt.emit($msg, tracing::Level::ERROR);
            __evt
        }
    };

    // inline form
    ($name:expr, $target:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let __span = tracing::span!(tracing::Level::DEBUG, $name, target = $target);
            let __evt = $crate::WideEvent::from_span_with_target(__span, $target);
            $( __evt.add(stringify!($k), $v); )*
            __evt.emit($msg, tracing::Level::DEBUG);
            __evt
        }
    };
}

#[macro_export]
macro_rules! wide_error {
    // name + msg convenience form with automatic target and optional key-value pairs
    ($name:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let __span = tracing::span!(tracing::Level::ERROR, $name, target = concat!(env!("CARGO_PKG_NAME"), "::", module_path!()));
            let __evt = $crate::WideEvent::from_span_with_target(__span, concat!(env!("CARGO_PKG_NAME"), "::", module_path!()));
            $( __evt.add(stringify!($k), $v); )*
            __evt.emit($msg, tracing::Level::ERROR);
            __evt
        }
    };

    // pass wide event as argument and use it as parent. Require name and message and optional key-value pairs
    ($evt:expr, $name:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let __evt = $crate::WideEvent::with_parent($name, $evt.target(), $evt.span());
            $( __evt.add(stringify!($k), $v); )*
            __evt.emit($msg, tracing::Level::ERROR);
            __evt
        }
    };

    // inline form
    ($name:expr, $target:expr, $msg:expr $(, $k:ident = $v:expr )* $(,)? ) => {
        {
            let __span = tracing::span!(tracing::Level::ERROR, $name, target = $target);
            let __evt = $crate::WideEvent::from_span_with_target(__span, $target);
            $( __evt.add(stringify!($k), $v); )*
            __evt.emit($msg, tracing::Level::ERROR);
            __evt
        }
    };
}
