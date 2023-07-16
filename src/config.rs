use std::{collections::HashMap, net::SocketAddr};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub bind: SocketAddr,
    pub prometheus_bind: Option<SocketAddr>,
    pub public: Url,
    pub client_id: String,
    pub client_secret: String,
    pub issuer: Url,
    #[serde(default = "default_refresh_time_sec")]
    pub oidc_refresh_time_sec: u64,
    #[serde(default = "default_scopes")]
    pub scopes: String,
    pub jwt_key: String,
    pub cookie_name: String,
    pub success_header: String,
    #[serde(default = "default_login_renew_seconds")]
    pub login_renew_seconds: i64,
    #[serde(default = "default_login_cache_minutes")]
    pub login_cache_minutes: i64,
    #[serde(default)]
    pub refresh_tokens: bool,
    /// If true, when the access token expires, so does the login JWT.
    #[serde(default)]
    pub honor_token_expiry: bool,
    #[serde(default = "default_true")]
    pub cookie_secure: bool,
    pub cookie_domain: String,
    #[serde(default)]
    pub required_roles: Vec<String>,
    // header -> claim
    #[serde(default)]
    pub header_claims: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

fn default_refresh_time_sec() -> u64 {
    3600
}

fn default_login_renew_seconds() -> i64 {
    1800
}

fn default_login_cache_minutes() -> i64 {
    240
}

fn default_scopes() -> String {
    "openid email profile roles".to_string()
}

lazy_static::lazy_static! {
    static ref CONFIG_FILE: String = {
        let base = std::env::var("OIPLEASE_CONF").unwrap_or_default();
        if base.is_empty() {
            "./config.yaml".to_string()
        } else {
            base
        }
    };
    pub static ref CONFIG: Config = {
        serde_yaml::from_str(&std::fs::read_to_string(&*CONFIG_FILE).expect("failed to read config")).expect("failed to parse config")
    };
    pub static ref REDIRECT_URL: Url = {
        let mut base = CONFIG.public.clone();
        base.path_segments_mut().unwrap().push("auth");
        base
    };
    pub static ref JWT_KEY: Hmac<Sha256> = {
        Hmac::new_from_slice(CONFIG.jwt_key.as_bytes()).unwrap()
    };
    /// with trailing slash
    pub static ref PUBLIC_URL_BASE: String = {
        let mut out = CONFIG.public.path().to_string();
        if !out.ends_with('/') {
            out.push('/');
        }
        out
    };
}
