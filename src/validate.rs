use anyhow::Result;
use chrono::Utc;
use cookie::Cookie;
use http::{Request, Response, StatusCode};
use hyper::Body;
use log::{error, info, warn};

use crate::{
    auth::build_cookie, config::CONFIG, jwt::JwtClaims, jwtc::decompress, oidc::OIDC, status,
    unauthorized,
};

fn get_cookie(request: &Request<Body>) -> Result<Option<JwtClaims>> {
    let Some(cookie) = request.headers().get("cookie") else {
        return Ok(None);
    };
    let cookie = cookie.to_str()?;
    for cookie in Cookie::split_parse_encoded(cookie) {
        let cookie = cookie?;
        if cookie.name() == CONFIG.cookie_name {
            let decompressed = decompress(cookie.value())?;
            return Ok(Some(JwtClaims::validate(&decompressed)?));
        }
    }
    Ok(None)
}

enum PostValidation {
    Expired,
    Forbidden,
    Renewed(Cookie<'static>, JwtClaims),
    Pass(JwtClaims),
}

async fn postvalidate_jwt(mut claims: JwtClaims) -> Result<PostValidation> {
    let now = Utc::now().timestamp();
    if claims.exp < now || claims.iss + CONFIG.login_cache_minutes * 60 < now {
        return Ok(PostValidation::Expired);
    }
    if !claims.has_required_roles(&CONFIG.required_roles) {
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

pub async fn validate(request: Request<Body>) -> Response<Body> {
    let claims = match get_cookie(&request) {
        Ok(Some(x)) => x,
        Ok(None) => {
            return unauthorized();
        }
        Err(e) => {
            warn!("failed to decode jwt: {e:#}");
            return unauthorized();
        }
    };

    if claims.issuer != CONFIG.public {
        return unauthorized();
    }

    let mut response = Response::new(Body::empty());

    let claims = match postvalidate_jwt(claims).await {
        Err(e) => {
            error!("postvalidation error: {e:#}");
            return unauthorized();
        }
        Ok(PostValidation::Expired) => return unauthorized(),
        Ok(PostValidation::Forbidden) => return status(StatusCode::FORBIDDEN),
        Ok(PostValidation::Renewed(new_cookie, claims)) => {
            response.headers_mut().insert(
                "set-cookie",
                new_cookie.encoded().to_string().parse().unwrap(),
            );
            claims
        }
        Ok(PostValidation::Pass(claims)) => claims,
    };

    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(&*CONFIG.success_header, "true".parse().unwrap());
    for (header, claim) in &CONFIG.header_claims {
        if let Some(value) = claims.claims.get(claim) {
            response
                .headers_mut()
                .insert(&**header, value.parse().unwrap());
        }
    }

    response
}
