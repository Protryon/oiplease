use std::collections::HashMap;

use anyhow::Result;
use jwt::{SignWithKey, VerifyWithKey};
use openid::Bearer;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::JWT_KEY;

#[derive(Serialize, Deserialize)]
pub struct JwtClaims {
    pub issuer: Url,
    pub claims: HashMap<String, String>,
    pub iss: i64,
    pub exp: i64,
    pub roles: Vec<String>,
    #[serde(flatten)]
    pub bearer: Bearer,
}

impl JwtClaims {
    pub fn sign(&self) -> Result<String> {
        Ok(self.sign_with_key(&*JWT_KEY)?)
    }

    pub fn validate(value: &str) -> Result<Self> {
        Ok(value.verify_with_key(&*JWT_KEY)?)
    }

    pub fn has_required_roles(&self, roles: &[String]) -> bool {
        roles.iter().all(|x| self.roles.contains(x))
    }
}
