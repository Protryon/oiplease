use always_cell::AlwaysCell;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use log::warn;
use openid::{
    Bearer, Client, CompactJson, CustomClaims, Discovered, Options, StandardClaims, Token,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use url::Url;

use crate::config::{CONFIG, REDIRECT_URL};

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

impl OidcHandler {
    async fn new() -> Self {
        let client = loop {
            match Client::<Discovered, Claims>::discover(
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
        };
        Self {
            client: Arc::new(RwLock::new((
                Utc::now() + chrono::Duration::seconds(CONFIG.oidc_refresh_time_sec as i64),
                client,
            ))),
        }
    }

    async fn recreate(&self) -> Client<Discovered, Claims> {
        loop {
            match Client::<Discovered, Claims>::discover(
                CONFIG.client_id.to_string(),
                CONFIG.client_secret.to_string(),
                Some(REDIRECT_URL.to_string()),
                CONFIG.issuer.clone(),
            )
            .await
            {
                Ok(x) => break x,
                Err(e) => {
                    warn!("failed to rediscover OIDC: {e:?}");
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
            let mut old_client = self.client.write().await;
            if old_client.0 < now {
                let new_client = self.recreate().await;
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

        // let info = client.request_userinfo(&token).await?;

        Ok((token.bearer, token.id_token.unwrap().unwrap_decoded().1))
    }
}
