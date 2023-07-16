use std::{convert::Infallible, net::SocketAddr, time::Instant};

use anyhow::Result;
use config::{CONFIG, PUBLIC_URL_BASE};
use http::{Method, Request, Response, StatusCode};
use hyper::{
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Server,
};
use log::info;

mod config;
mod jwt;
mod jwtc;
mod oidc;

mod auth;
mod login;
mod validate;

pub fn status(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

pub fn unauthorized() -> Response<Body> {
    status(StatusCode::UNAUTHORIZED)
}

async fn handle(request: Request<Body>) -> Response<Body> {
    let Some(path) = request.uri().path().strip_prefix(&*PUBLIC_URL_BASE) else {
        return status(StatusCode::NOT_FOUND);
    };
    if request.method() != Method::GET {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }
    match path {
        "validate" => validate::validate(request).await,
        "login" => login::login(request).await,
        "auth" => auth::auth(request).await,
        "health" => status(StatusCode::OK),
        _ => status(StatusCode::NOT_FOUND),
    }
}

async fn do_handle(addr: SocketAddr, request: Request<Body>) -> Result<Response<Body>, Infallible> {
    let method = request.method().clone();
    let path = request.uri().clone();
    let start = Instant::now();
    let response = handle(request).await;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    info!(
        "[{}] {} {} -> {} [{:.02} ms]",
        addr.ip(),
        method,
        path,
        response.status(),
        elapsed
    );
    Ok(response)
}

#[tokio::main]
async fn main() {
    env_logger::Builder::new()
        .parse_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    lazy_static::initialize(&CONFIG);
    if let Some(prometheus_bind) = CONFIG.prometheus_bind {
        prometheus_exporter::start(prometheus_bind).expect("failed to bind prometheus exporter");
    }

    info!("initializing OIDC...");
    oidc::init().await;
    info!("OIDC initialized");

    let make_service = make_service_fn(|conn: &AddrStream| {
        let addr = conn.remote_addr();
        let service = service_fn(move |req| do_handle(addr, req));
        async move { Ok::<_, Infallible>(service) }
    });

    info!("listening on {}", CONFIG.bind);
    let server = Server::bind(&CONFIG.bind).serve(make_service);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
