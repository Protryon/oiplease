use std::collections::HashMap;

use axol::{Error, IntoResponse, Query, Result, Typed};
use axol_http::{header::TypedHeader, typed_headers::SetCookie};
use chrono::Utc;
use cookie::{Cookie, CookieBuilder};
use serde::Deserialize;
use serde_json::Value;
use tracing::warn;
use url::Url;

use crate::{
    config::{CONFIG, REDIRECT_URL},
    jwt::JwtClaims,
    jwtc::compress,
    oidc::OIDC,
};

#[derive(Deserialize)]
pub struct OauthParameters {
    code: String,
    url: Url,
}

pub fn build_cookie(claims: &JwtClaims, max_age: i64) -> anyhow::Result<Cookie<'static>> {
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

pub async fn auth(Query(query): Query<OauthParameters>) -> Result<impl IntoResponse> {
    let mut redirect_uri = REDIRECT_URL.clone();
    redirect_uri
        .query_pairs_mut()
        .append_pair("url", query.url.as_str());

    let (mut bearer, claims) = OIDC
        .validate_code(&redirect_uri, &query.code)
        .await
        .map_err(|e| {
            warn!("failed to validate claims: {e:#}");
            Error::unauthorized("bad oauth code")
        })?;
    let roles = claims
        .realm_access
        .as_ref()
        .map(|x| &x.roles[..])
        .unwrap_or_default()
        .to_vec();

    let raw_userinfo = serde_json::to_value(claims.standard.userinfo).map_err(Error::internal)?;
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
    let mut claims = JwtClaims {
        issuer: CONFIG.public.clone(),
        claims: HashMap::new(),
        iss: now,
        exp: now + max_age,
        roles,
        bearer,
    };
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
            claims.claims.insert(claim.clone(), value);
        }
    }

    let cookie = build_cookie(&claims, max_age).map_err(Error::internal)?;

    Ok((
        Typed(SetCookie::decode(&cookie.encoded().to_string()).unwrap()),
        query.url,
    ))
}
