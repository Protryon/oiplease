use std::{collections::HashMap, net::SocketAddr};

use hmac::{Hmac, Mac};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
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
    #[serde(default)]
    pub header_claims: HashMap<String, String>,
    #[serde(default)]
    pub customizations: Vec<Customization>,
    pub opentelemetry: Option<OtelConfig>,
}

pub struct Customized<'a> {
    pub required_roles: Vec<&'a str>,
    pub bypass: bool,
}

impl Config {
    pub fn uncustomized(&self) -> Customized<'_> {
        let required_roles: Vec<&str> = self.required_roles.iter().map(|x| &**x).collect();

        Customized {
            required_roles,
            bypass: false,
        }
    }

    pub fn customized(&self, host: &str, path: &str) -> Customized<'_> {
        let mut required_roles: Vec<&str> = self.required_roles.iter().map(|x| &**x).collect();
        let mut bypass = false;

        for custom in &self.customizations {
            if custom.filter.matches(host, path) {
                required_roles.extend(custom.config.required_roles.iter().map(|x| &**x));
                if custom.config.bypass {
                    bypass = true;
                }
            }
        }
        required_roles.sort();
        required_roles.dedup();

        Customized {
            required_roles,
            bypass,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Customization {
    pub filter: EndpointFilter,
    pub config: EndpointConfig,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct EndpointFilter {
    pub hostname: Option<String>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub hostname_regex: Option<Regex>,
    pub path: Option<String>,
    pub path_prefix: Option<String>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub path_regex: Option<Regex>,
}

impl EndpointFilter {
    pub fn matches(&self, host: &str, path: &str) -> bool {
        if let Some(hostname) = &self.hostname {
            if host != hostname {
                return false;
            }
        }
        if let Some(hostname_regex) = &self.hostname_regex {
            if !hostname_regex.is_match(host) {
                return false;
            }
        }
        if let Some(check_path) = &self.path {
            if check_path != path {
                return false;
            }
        }
        if let Some(path_prefix) = &self.path_prefix {
            if !path.starts_with(path_prefix) {
                return false;
            }
        }
        if let Some(path_regex) = &self.path_regex {
            if !path_regex.is_match(path) {
                return false;
            }
        }
        true
    }
}

#[derive(Serialize, Deserialize)]
pub struct EndpointConfig {
    #[serde(default)]
    pub required_roles: Vec<String>,
    #[serde(default)]
    pub bypass: bool,
}

#[derive(Serialize, Deserialize)]
pub struct OtelConfig {
    pub endpoint: Url,
    pub timeout_sec: f64,
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
        base.path_segments_mut().unwrap().pop_if_empty();
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
