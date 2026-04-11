use anyhow::{Context, Result};
use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::{ObservabilityOptions, TelemetryOptions};

pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

impl TelemetryGuard {
    pub fn shutdown(self) -> Result<()> {
        if let Some(provider) = self.provider {
            provider
                .shutdown()
                .context("failed to shutdown OpenTelemetry tracer provider")?;
        }

        Ok(())
    }
}

pub fn init_tracing(observability: &ObservabilityOptions) -> Result<TelemetryGuard> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "anymirror=debug,tower_http=debug".into());
    let fmt_layer = tracing_subscriber::fmt::layer();

    if !observability.enabled {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();

        return Ok(TelemetryGuard { provider: None });
    }

    let telemetry = &observability.telemetry;
    let provider = build_tracer_provider(telemetry)?;
    let tracer = provider.tracer(telemetry.service_name.clone());
    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(telemetry_layer)
        .init();

    Ok(TelemetryGuard {
        provider: Some(provider),
    })
}

fn build_tracer_provider(telemetry: &TelemetryOptions) -> Result<SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(telemetry.otlp_endpoint.clone())
        .build()
        .context("failed to build OTLP span exporter")?;

    let resource = Resource::builder()
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .with_service_name(telemetry.service_name.clone())
        .build();

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build())
}
