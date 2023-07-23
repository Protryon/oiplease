use axol::Query;
use serde::Deserialize;
use url::Url;

use crate::{config::REDIRECT_URL, oidc::OIDC};

#[derive(Deserialize)]
pub struct LoginParameters {
    url: Url,
}

pub async fn login(Query(query): Query<LoginParameters>) -> Url {
    let mut redirect_uri = REDIRECT_URL.clone();
    redirect_uri
        .query_pairs_mut()
        .append_pair("url", query.url.as_str());
    OIDC.auth_url(redirect_uri).await
}
