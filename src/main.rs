use std::time::Duration;

use axol::cors::{Any, Cors};
use axol::trace::RegistryWrapper;
use axol::{trace::Trace, Router};
use axol::{Logger, RealIp};
use axol_http::response::Response;
use config::{CONFIG, PUBLIC_URL_BASE};
use opentelemetry::runtime::Tokio;
use opentelemetry::sdk::propagation::TraceContextPropagator;
use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
use tracing::{error, info, span, Instrument};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

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

fn route(registry: Option<RegistryWrapper>) -> Router {
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
        .plugin(
            "/",
            registry
                .map(|x| Trace::default().registry(x))
                .unwrap_or_default(),
        )
        .plugin("/", Logger::default())
}

async fn run(registry: Option<RegistryWrapper>) {
    info!("initializing OIDC...");
    oidc::init().await;
    info!("OIDC initialized");

    let server = axol::Server::bind(CONFIG.bind)
        .expect("bind failed")
        .router(route(registry))
        .serve();
    info!("listening on {}", CONFIG.bind);

    if let Err(e) = server.await {
        error!("server error: {}", e);
    }
}

lazy_static::lazy_static! {
    pub(crate) static ref REGISTRY: RegistryWrapper = {
        RegistryWrapper::from(Registry::default())
    };
}

#[tokio::main]
async fn main() {
    env_logger::Builder::new()
        .parse_env(env_logger::Env::default().default_filter_or("info"))
        .init();
    lazy_static::initialize(&CONFIG);

    let registry = if let Some(config) = &CONFIG.opentelemetry {
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_export_config(ExportConfig {
                        endpoint: config.endpoint.to_string(),
                        protocol: Protocol::Grpc,
                        timeout: Duration::from_secs_f64(config.timeout_sec),
                    }),
            )
            .install_batch(Tokio)
            .expect("tracer init failed");

        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing::subscriber::set_global_default(REGISTRY.clone().with(telemetry)).unwrap();
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::default());
        info!("otel tracing initialized");
        Some(REGISTRY.clone())
    } else {
        None
    };

    if let Some(prometheus_bind) = CONFIG.prometheus_bind {
        prometheus_exporter::start(prometheus_bind).expect("failed to bind prometheus exporter");
    }

    let root = span!(tracing::Level::INFO, "app_start");

    run(registry).instrument(root).await;
}
