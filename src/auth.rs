use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::Utc;
use cookie::{Cookie, CookieBuilder};
use http::{Request, Response, StatusCode};
use hyper::Body;
use log::warn;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::{
    config::{CONFIG, REDIRECT_URL},
    jwt::JwtClaims,
    jwtc::compress,
    oidc::OIDC,
    unauthorized,
};

#[derive(Deserialize)]
struct OauthParameters {
    code: String,
    url: Url,
}

async fn validate_oauth(request: &Request<Body>) -> Result<(Url, Cookie)> {
    let query = request.uri().query().context("missing query")?;
    let parameters: OauthParameters =
        serde_urlencoded::from_str(query).context("failed to parse query")?;
    let mut redirect_uri = REDIRECT_URL.clone();
    redirect_uri
        .query_pairs_mut()
        .append_pair("url", parameters.url.as_str());

    let (mut bearer, claims) = OIDC.validate_code(&redirect_uri, &parameters.code).await?;
    let roles = claims
        .realm_access
        .as_ref()
        .map(|x| &x.roles[..])
        .unwrap_or_default()
        .to_vec();

    let raw_userinfo = serde_json::to_value(claims.standard.userinfo)?;
    let now = Utc::now().timestamp();
    let mut max_age = CONFIG.login_cache_minutes * 60;
    if CONFIG.honor_token_expiry {
        if let Some(expires) = bearer.expires {
            if let Some(new_age) = expires.timestamp().checked_sub(Utc::now().timestamp()) {
                max_age = max_age.min(new_age)
            }
        }
    }

    bearer.id_token.take();
    bearer.access_token = "".to_string();
    if !CONFIG.refresh_tokens {
        bearer.refresh_token.take();
    }
    let mut out = JwtClaims {
        issuer: CONFIG.public.clone(),
        claims: HashMap::new(),
        iss: now,
        exp: now + max_age,
        roles,
        bearer,
    };
    // if !out.has_required_roles(&CONFIG.required_roles) {
    //     bail!("missing required roles: {:?}", CONFIG.required_roles);
    // }
    for claim in CONFIG.header_claims.values() {
        if let Some(value) = raw_userinfo.get(claim) {
            let value = match value {
                Value::Null => continue,
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.clone(),
                _ => {
                    warn!("unserializable userinfo field: {claim}");
                    continue;
                }
            };
            out.claims.insert(claim.clone(), value);
        }
    }
    Ok((parameters.url, build_cookie(&out, max_age)?))
}

pub fn build_cookie(claims: &JwtClaims, max_age: i64) -> Result<Cookie<'static>> {
    let signed = claims.sign()?;
    let value = compress(&signed)?;
    let cookie = CookieBuilder::new(&CONFIG.cookie_name, value)
        .http_only(true)
        .secure(CONFIG.cookie_secure)
        .max_age(cookie::time::Duration::seconds(max_age))
        .domain(&CONFIG.cookie_domain)
        .path("/")
        .finish();
    Ok(cookie)
}

pub async fn auth(request: Request<Body>) -> Response<Body> {
    let (url, cookie) = match validate_oauth(&request).await {
        Ok(c) => c,
        Err(e) => {
            warn!("failed to validate claims: {e:#}");
            return unauthorized();
        }
    };

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    response
        .headers_mut()
        .insert("location", url.as_str().parse().unwrap());
    response
        .headers_mut()
        .insert("set-cookie", cookie.encoded().to_string().parse().unwrap());
    response
}
