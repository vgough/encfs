//! Export filesystem operation traces to an OpenTelemetry collector over
//! OTLP/HTTP (`encfs --otel-endpoint <URL>`, built with `--features telemetry`).
//!
//! Only spans are exported: the DEBUG span every [`crate::fs::EncFs`]
//! operation runs in, which names entries by backing path alone, with the
//! events logged inside it as span events. Events outside any span stay local.
//!
//! The exporter runs threads of its own (the batch span processor and the
//! HTTP client), and threads don't survive a fork. So logging starts with an
//! empty slot for the exporting layer ([`deferred_layer`]), and the layer is
//! put in it by [`Pending::start`] once `encfs` has daemonized.

use anyhow::{Context, Result};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{Key, KeyValue};
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use rust_i18n::t;
use tracing::warn;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::{Layer, Registry, reload};

/// Where OTLP/HTTP receives traces, relative to the collector's base URL.
const TRACES_PATH: &str = "/v1/traces";

/// The name traces are reported under unless `OTEL_SERVICE_NAME` or
/// `OTEL_RESOURCE_ATTRIBUTES` gives one.
const SERVICE_NAME: &str = "encfs";

type OtelLayer = tracing_opentelemetry::OpenTelemetryLayer<Registry, SdkTracer>;

/// Parses `--otel-endpoint`: the collector's base URL, as in
/// `OTEL_EXPORTER_OTLP_ENDPOINT`, to which the traces path is appended
/// (`http://host:4318` becomes `http://host:4318/v1/traces`). A URL that
/// already ends in that path is used as given.
pub fn parse_endpoint(value: &str) -> Result<String, String> {
    let invalid =
        |error: &dyn std::fmt::Display| t!("telemetry.invalid_endpoint", error = error).to_string();
    let uri: http::Uri = value.parse().map_err(|e| invalid(&e))?;
    let scheme = match uri.scheme_str() {
        Some(scheme @ ("http" | "https")) => scheme,
        _ => return Err(invalid(&t!("telemetry.endpoint_scheme"))),
    };
    let authority = match uri.authority() {
        Some(authority) if !authority.host().is_empty() => authority,
        _ => return Err(invalid(&t!("telemetry.endpoint_host"))),
    };
    if uri.query().is_some() {
        return Err(invalid(&t!("telemetry.endpoint_query")));
    }
    let path = uri.path().trim_end_matches('/');
    let path = if path.ends_with(TRACES_PATH) {
        path.to_string()
    } else {
        format!("{path}{TRACES_PATH}")
    };
    Ok(format!("{scheme}://{authority}{path}"))
}

/// The layer that will export spans to `endpoint`, and the means to start it.
/// The layer goes directly on the [`Registry`]; until [`Pending::start`] it
/// does nothing.
///
/// Its filter is fixed, independent of `RUST_LOG` and `-v`: DEBUG for this
/// crate, which is where the operation spans are, and nothing else. That
/// also leaves out the exporter's own events (and those of its HTTP client),
/// so exporting never produces more to export. The filter sits outside the
/// reloadable layer so it is registered once, when logging is installed.
pub(crate) fn deferred_layer(endpoint: String) -> (impl Layer<Registry> + Send + Sync, Pending) {
    let (layer, handle) = reload::Layer::new(None::<OtelLayer>);
    let layer =
        layer.with_filter(Targets::new().with_target(env!("CARGO_CRATE_NAME"), LevelFilter::DEBUG));
    (layer, Pending { handle, endpoint })
}

/// Trace export that has been set up in the subscriber but not started.
pub struct Pending {
    handle: reload::Handle<Option<OtelLayer>, Registry>,
    endpoint: String,
}

impl Pending {
    /// Starts exporting. Call it after daemonizing: it starts threads.
    /// Spans are sent in batches; the returned guard sends the last one when
    /// it is dropped.
    pub fn start(&self) -> Result<Telemetry> {
        let exporter = SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(self.endpoint.clone())
            .build()
            .context(t!("telemetry.exporter_failed"))?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource())
            .build();
        self.install(provider)
    }

    /// Exports spans through `provider` from now on.
    pub(crate) fn install(&self, provider: SdkTracerProvider) -> Result<Telemetry> {
        let tracer = provider.tracer(SERVICE_NAME);
        self.handle
            .reload(Some(tracing_opentelemetry::layer().with_tracer(tracer)))
            .context(t!("telemetry.exporter_failed"))?;
        Ok(Telemetry {
            provider,
            handle: self.handle.clone(),
        })
    }
}

/// Running trace export. Dropping it stops exporting and flushes the spans
/// not yet sent.
pub struct Telemetry {
    provider: SdkTracerProvider,
    handle: reload::Handle<Option<OtelLayer>, Registry>,
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        // Spans that close from here on have nowhere to go.
        let _ = self.handle.reload(None);
        if let Err(error) = self.provider.shutdown() {
            warn!("{}", t!("telemetry.shutdown_failed", error = error));
        }
    }
}

/// The resource traces are reported with: what the SDK detects from the
/// environment, named `encfs` unless the environment names it, with this
/// build's version. Nothing about the volume or mount point.
fn resource() -> Resource {
    let named = Resource::builder()
        .build()
        .get(&Key::from_static_str("service.name"))
        .is_some_and(|name| !name.as_str().starts_with("unknown_service"));
    let builder = Resource::builder()
        .with_attribute(KeyValue::new("service.version", crate::build_info::VERSION));
    if named {
        builder.build()
    } else {
        builder.with_service_name(SERVICE_NAME).build()
    }
}

#[cfg(test)]
mod tests {
    use super::parse_endpoint;

    #[test]
    fn endpoint_is_a_base_url_for_the_traces_path() {
        for (given, expected) in [
            ("http://localhost:4318", "http://localhost:4318/v1/traces"),
            ("http://localhost:4318/", "http://localhost:4318/v1/traces"),
            ("https://otel.example", "https://otel.example/v1/traces"),
            (
                "https://otel.example/otlp/",
                "https://otel.example/otlp/v1/traces",
            ),
            (
                "http://127.0.0.1:4318/v1/traces",
                "http://127.0.0.1:4318/v1/traces",
            ),
            (
                "http://[::1]:4318/v1/traces/",
                "http://[::1]:4318/v1/traces",
            ),
        ] {
            assert_eq!(parse_endpoint(given).as_deref(), Ok(expected), "{given}");
        }
    }

    #[test]
    fn endpoint_must_be_an_http_url_with_a_host() {
        for given in [
            "",
            "localhost:4318",
            "/v1/traces",
            "ftp://localhost:4318",
            "grpc://localhost:4317",
            "http://localhost:4318/?token=1",
            "http://local host",
        ] {
            assert!(parse_endpoint(given).is_err(), "{given}");
        }
    }
}
