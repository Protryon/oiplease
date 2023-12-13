use axol::{Error, Result, Typed};
use axol_http::{header::HeaderMap, typed_headers::Cookie as CookieHeader};
use chrono::Utc;
use cookie::Cookie;
use tracing::{error, info};
use url::Url;

use crate::{
    auth::build_cookie,
    config::{Customized, CONFIG},
    jwt::JwtClaims,
    jwtc::decompress,
    oidc::OIDC,
};

enum PostValidation {
    Expired,
    Forbidden,
    Renewed(Cookie<'static>, JwtClaims),
    Pass(JwtClaims),
}

async fn postvalidate_jwt(
    mut claims: JwtClaims,
    customized: &Customized<'_>,
) -> Result<PostValidation> {
    let now = Utc::now().timestamp();
    if claims.exp < now || claims.iss + CONFIG.login_cache_minutes * 60 < now {
        return Ok(PostValidation::Expired);
    }
    if !claims.has_required_roles(&customized.required_roles[..]) {
        return Ok(PostValidation::Forbidden);
    }
    if CONFIG.refresh_tokens
        && claims.bearer.refresh_token.is_some()
        && claims.iss + CONFIG.login_renew_seconds < now
    {
        info!("renewing token");
        let (bearer, new_claims) = OIDC.renew(claims.bearer).await?;
        claims.bearer = bearer;
        claims.bearer.id_token.take();
        claims.bearer.access_token = "".to_string();
        claims.roles = new_claims
            .realm_access
            .as_ref()
            .map(|x| &x.roles[..])
            .unwrap_or_default()
            .to_vec();

        let now = Utc::now().timestamp();
        let mut max_age = CONFIG.login_cache_minutes * 60;
        if CONFIG.honor_token_expiry {
            if let Some(expires) = claims.bearer.expires {
                if let Some(new_age) = expires.timestamp().checked_sub(Utc::now().timestamp()) {
                    max_age = max_age.min(new_age)
                }
            }
        }

        claims.iss = now;
        claims.exp = claims.iss + max_age;
        return Ok(PostValidation::Renewed(
            build_cookie(&claims, max_age)?,
            claims,
        ));
    }
    Ok(PostValidation::Pass(claims))
}

pub async fn validate(
    cookies: Option<Typed<CookieHeader>>,
    headers_in: HeaderMap,
) -> Result<HeaderMap> {
    let original_url = headers_in
        .get("x-original-url")
        .and_then(|x| Url::parse(x).ok());

    let customized = if let Some(original_url) = original_url {
        CONFIG.customized(
            original_url.host_str().unwrap_or_default(),
            original_url.path(),
        )
    } else {
        CONFIG.uncustomized()
    };

    if customized.bypass {
        return Ok(HeaderMap::new());
    }

    let claims = match &cookies {
        None => return Err(Error::unauthorized("missing cookies")),
        Some(header) => header
            .0
            .get(&CONFIG.cookie_name)
            .ok_or_else(|| Error::unauthorized("no cookie set"))?,
    };
    let decompressed = decompress(claims).map_err(|_| Error::bad_request("malformed jwt"))?;
    let claims =
        JwtClaims::validate(&decompressed).map_err(|_| Error::bad_request("invalid jwt"))?;

    if claims.issuer != CONFIG.public {
        return Err(Error::unauthorized("bad issuer"));
    }

    let mut headers = HeaderMap::new();

    let claims = match postvalidate_jwt(claims, &customized).await {
        Err(e) => {
            error!("postvalidation error: {e:#}");
            return Err(Error::unauthorized("token invalid"));
        }
        Ok(PostValidation::Expired) => return Err(Error::unauthorized("expired token")),
        Ok(PostValidation::Forbidden) => return Err(Error::Forbidden),
        Ok(PostValidation::Renewed(new_cookie, claims)) => {
            headers.insert("set-cookie", new_cookie.encoded().to_string());
            claims
        }
        Ok(PostValidation::Pass(claims)) => claims,
    };

    headers.insert(&*CONFIG.success_header, "true");
    for (header, claim) in &CONFIG.header_claims {
        if let Some(value) = claims.claims.get(claim) {
            headers.insert(&**header, value);
        }
    }

    Ok(headers)
}
