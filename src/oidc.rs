use always_cell::AlwaysCell;
use anyhow::{bail, Context, Result};
use axol::trace::{default_request_header_filter, http_flavor};
use axol_http::typed_headers::HeaderMap;
use chrono::{DateTime, Utc};
use openid::{
    Bearer, Client, CompactJson, CustomClaims, Discovered, Options, StandardClaims, Token,
};
use opentelemetry::{Key, StringValue, Value};
use reqwest_maybe_middleware::Extensions;
use reqwest_tracing::{ReqwestOtelSpanBackend, TracingMiddleware};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::{field::Empty, warn, Instrument};
use tracing_opentelemetry::OtelData;
use tracing_subscriber::registry::{LookupSpan, SpanData};
use url::Url;

use crate::{
    config::{CONFIG, REDIRECT_URL},
    REGISTRY,
};

#[derive(Clone)]
pub struct OidcHandler {
    client: Arc<RwLock<(DateTime<Utc>, Client<Discovered, Claims>)>>,
}

lazy_static::lazy_static! {
    static ref OIDC_OPTIONS: Options = Options {
        scope: Some(CONFIG.scopes.clone()),
        state: None,
        ..Default::default()
    };
}
pub static OIDC: AlwaysCell<OidcHandler> = AlwaysCell::new();

pub async fn init() {
    AlwaysCell::set(&OIDC, OidcHandler::new().await);
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Claims {
    pub realm_access: Option<RealmAccess>,
    #[serde(flatten)]
    pub standard: StandardClaims,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RealmAccess {
    #[serde(default)]
    pub roles: Vec<String>,
}

impl CustomClaims for Claims {
    fn standard_claims(&self) -> &StandardClaims {
        &self.standard
    }
}

impl CompactJson for Claims {}

lazy_static::lazy_static! {
    static ref HTTP_CLIENT: reqwest_maybe_middleware::Client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
        .with(TracingMiddleware::<Tracer>::new()).build().into();
}

struct Tracer;

fn grouped_headers(headers: &HeaderMap) -> Vec<(&str, Vec<&str>)> {
    let mut names = headers
        .iter()
        .filter_map(|(name, value)| Some((name.as_str(), value.to_str().ok()?)))
        .collect::<Vec<_>>();
    names.sort_by_key(|x| x.0);
    let mut out: Vec<(&str, Vec<&str>)> = vec![];
    for (name, value) in names {
        if out.last().map(|x| x.0) == Some(name) {
            out.last_mut().unwrap().1.push(value);
        } else {
            out.push((name, vec![value]))
        }
    }
    out
}

impl ReqwestOtelSpanBackend for Tracer {
    fn on_request_start(req: &reqwest::Request, _extension: &mut Extensions) -> tracing::Span {
        let host = req
            .headers()
            .get("host")
            .and_then(|x| x.to_str().ok())
            .or(req.url().host_str())
            .unwrap_or_default();
        let port = req.url().port().map(|x| x);
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|x| x.to_str().ok());
        let name = format!("OIDC {} {}", req.method(), req.url().path());
        let span = tracing::info_span!(
            "OIDC Request",
            http.request.method = %req.method(),
            network.protocol.version = %http_flavor(req.version()),
            server.address = %host,
            server.port = port,
            url.full = %req.url(),
            user_agent.original = user_agent,
            otel.name = name,
            otel.kind = ?opentelemetry_api::trace::SpanKind::Client,
            http.response.status_code = Empty, // to set on response
            otel.status_code = Empty, // to set on response
            trace_id = Empty, // to set on response
            request_id = Empty, // to set
            exception.message = Empty, // to set on response
        );
        if let Some(span_id) = span.id() {
            let span = REGISTRY.span_data(&span_id).expect("missing span");
            let mut extensions = span.extensions_mut();
            if let Some(data) = extensions.get_mut::<OtelData>() {
                let target = data.builder.attributes.as_mut().unwrap();
                for (name, values) in grouped_headers(req.headers()) {
                    let values: Vec<StringValue> = values
                        .into_iter()
                        .filter_map(|value| (default_request_header_filter)(name, value))
                        .map(|x| StringValue::from(x.to_string()))
                        .collect::<Vec<_>>();
                    if values.is_empty() {
                        continue;
                    }
                    //todo: use static header values?
                    target.insert(
                        Key::new(format!("http.request.header.{}", name.replace('-', "_"))),
                        Value::Array(values.into()),
                    );
                }
            }
        }
        span
    }

    fn on_request_end(
        span: &tracing::Span,
        outcome: &reqwest_middleware::Result<reqwest::Response>,
        _extension: &mut Extensions,
    ) {
        match outcome {
            Ok(response) => {
                span.record(
                    "http.response.status_code",
                    &tracing::field::display(response.status().as_u16()),
                );
                if response.status().is_server_error() {
                    span.record("otel.status_code", "ERROR");
                } else {
                    span.record("otel.status_code", "OK");
                }

                if let Some(span_id) = span.id() {
                    let span = REGISTRY.span_data(&span_id).expect("missing span");
                    let mut extensions = span.extensions_mut();
                    if let Some(data) = extensions.get_mut::<OtelData>() {
                        let target = data.builder.attributes.as_mut().unwrap();
                        for (name, values) in grouped_headers(response.headers()) {
                            let values: Vec<StringValue> = values
                                .into_iter()
                                .filter_map(|value| (default_request_header_filter)(name, value))
                                .map(|x| StringValue::from(x.to_string()))
                                .collect::<Vec<_>>();
                            if values.is_empty() {
                                continue;
                            }
                            //todo: use static header values?
                            target.insert(
                                Key::new(format!(
                                    "http.response.header.{}",
                                    name.replace('-', "_")
                                )),
                                Value::Array(values.into()),
                            );
                        }
                    }
                }
            }
            Err(e) => {
                span.record("otel.status_code", "ERROR");
                span.record("exception.message", e.to_string());
            }
        }
    }
}

impl OidcHandler {
    async fn new() -> Self {
        let client = Self::recreate().await;
        Self {
            client: Arc::new(RwLock::new((
                Utc::now() + chrono::Duration::seconds(CONFIG.oidc_refresh_time_sec as i64),
                client,
            ))),
        }
    }

    async fn recreate() -> Client<Discovered, Claims> {
        loop {
            match Client::<Discovered, Claims>::discover_with_client(
                HTTP_CLIENT.clone(),
                CONFIG.client_id.to_string(),
                CONFIG.client_secret.to_string(),
                Some(REDIRECT_URL.to_string()),
                CONFIG.issuer.clone(),
            )
            .await
            {
                Ok(x) => break x,
                Err(e) => {
                    warn!("failed to discover OIDC: {e:?}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    pub async fn auth_url(&self, redirect_uri: Url) -> Url {
        let client = self.client.read().await;
        let mut client = client.1.clone();
        client.redirect_uri = Some(redirect_uri.to_string());
        client.auth_url(&OIDC_OPTIONS)
    }

    pub async fn renew(&self, token: Bearer) -> Result<(Bearer, Claims)> {
        let client = self.client.read().await;
        let mut token: Token<Claims> = client.1.refresh_token(token, None).await?.into();
        if let Some(id_token) = &mut token.id_token {
            client
                .1
                .decode_token(id_token)
                .context("failed to decode token")?;
            client
                .1
                .validate_token(id_token, None, None)
                .context("failed to validate token")?;
        } else {
            bail!("no id token");
        };

        Ok((token.bearer, token.id_token.unwrap().unwrap_decoded().1))
    }

    pub async fn validate_code(&self, redirect_uri: &Url, code: &str) -> Result<(Bearer, Claims)> {
        let mut client = self.client.read().await;
        let now = Utc::now();
        if client.0 < now {
            drop(client);
            let span = tracing::debug_span!("OIDC reconnect");
            let mut old_client = self.client.write().instrument(span.clone()).await;
            if old_client.0 < now {
                let new_client = Self::recreate().instrument(span).await;
                *old_client = (
                    now + chrono::Duration::seconds(CONFIG.oidc_refresh_time_sec as i64),
                    new_client,
                )
            }
            drop(old_client);
            client = self.client.read().await;
        }
        let mut client = client.1.clone();
        client.redirect_uri = Some(redirect_uri.to_string());
        let mut token: Token<Claims> = client
            .request_token(code)
            .await
            .context("failed to resolve token")?
            .into();

        if let Some(id_token) = &mut token.id_token {
            client
                .decode_token(id_token)
                .context("failed to decode token")?;
            client
                .validate_token(id_token, None, None)
                .context("failed to validate token")?;
        } else {
            bail!("no id token");
        };

        Ok((token.bearer, token.id_token.unwrap().unwrap_decoded().1))
    }
}
