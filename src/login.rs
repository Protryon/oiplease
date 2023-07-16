use anyhow::{Context, Result};
use http::{Request, Response, StatusCode};
use hyper::Body;
use log::warn;
use serde::Deserialize;
use url::Url;

use crate::{config::REDIRECT_URL, oidc::OIDC};

#[derive(Deserialize)]
struct LoginParameters {
    url: Url,
}

async fn redirect_uri(request: &Request<Body>) -> Result<Url> {
    let query = request.uri().query().context("missing query")?;
    let parameters: LoginParameters =
        serde_urlencoded::from_str(query).context("failed to parse query")?;

    let mut redirect_uri = REDIRECT_URL.clone();
    redirect_uri
        .query_pairs_mut()
        .append_pair("url", parameters.url.as_str());
    Ok(OIDC.auth_url(redirect_uri).await)
}

pub async fn login(request: Request<Body>) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    let location = match redirect_uri(&request).await {
        Ok(x) => x,
        Err(e) => {
            warn!("failed to calculate redirect uri: {e:#}");
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return response;
        }
    };

    *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    response
        .headers_mut()
        .insert("location", location.as_str().parse().unwrap());
    response
}
