use std::time::Duration;

use axol::cors::{Any, Cors};
use axol::{trace::Trace, Router};
use axol::{Logger, RealIp};
use axol_http::response::Response;
use config::{CONFIG, PUBLIC_URL_BASE};
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::{error, info, span, Instrument};
use tracing_subscriber::layer::SubscriberExt;

mod config;
mod jwt;
mod jwtc;
mod oidc;

mod auth;
mod login;
mod validate;

async fn health() {}

async fn cache_control(mut response: Response) -> Response {
    response
        .headers
        .insert("cache-control", "no-store, must-revalidate, max-age=0");
    response
}

fn route() -> Router {
    Router::default()
        .nest(
            &*PUBLIC_URL_BASE,
            Router::new()
                .get("/validate", validate::validate)
                .get("/login", login::login)
                .get("/auth", auth::auth)
                .get("/health", health),
        )
        .request_hook_direct("/", RealIp("x-original-forwarded-for".to_string()))
        .late_response_hook("/", cache_control)
        // allow origin * is justified in that each route does not perform stateful action.
        // the /login endpoint could be used a redirect loop, but in practice is this avoided from redirect whitelists on the side of the OIDC provider
        .plugin("/", Cors::default().allow_methods(Any).allow_origin("*"))
        .plugin("/", Trace::default())
        .plugin("/", Logger::default())
}

async fn run() {
    info!("initializing OIDC...");
    oidc::init().await;
    info!("OIDC initialized");

    let server = axol::Server::bind(CONFIG.bind, route())
        .await
        .expect("bind failed")
        .serve();
    info!("listening on {}", CONFIG.bind);

    if let Err(e) = server.await {
        error!("server error: {}", e);
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::new()
        .parse_env(env_logger::Env::default().default_filter_or("info"))
        .init();
    lazy_static::initialize(&CONFIG);

    let tracer_provider = if let Some(config) = &CONFIG.opentelemetry {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(config.endpoint.to_string())
            .with_timeout(Duration::from_secs_f64(config.timeout_sec))
            .build()
            .expect("tracer init failed");
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .build();

        let telemetry =
            tracing_opentelemetry::layer().with_tracer(provider.tracer(env!("CARGO_PKG_NAME")));

        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(telemetry))
            .unwrap();
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::default());
        info!("otel tracing initialized");
        Some(provider)
    } else {
        None
    };

    if let Some(prometheus_bind) = CONFIG.prometheus_bind {
        prometheus_exporter::start(prometheus_bind).expect("failed to bind prometheus exporter");
    }

    let root = span!(tracing::Level::INFO, "app_start");

    run().instrument(root).await;

    if let Some(provider) = tracer_provider {
        if let Err(e) = provider.shutdown() {
            error!("failed to flush traces: {e}");
        }
    }
}
