//! Shared application state: created once per process / Lambda container.

use std::{ops::Deref, sync::Arc};

use anyhow::{Context, Result};
use chrono::Utc;
use clang_auth_core::{
    keys::{AccessClaims, SigningKeys},
    model::User,
    secret::random_token,
    store::Store,
};

use crate::config::{Config, SigningKeySource};

pub struct Inner {
    pub config: Config,
    pub store: Store,
    pub keys: SigningKeys,
}

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(config: Config, store: Store, keys: SigningKeys) -> Self {
        Self(Arc::new(Inner {
            config,
            store,
            keys,
        }))
    }

    /// Load signing keys and connect to MongoDB according to `config`.
    pub async fn from_config(config: Config) -> Result<Self> {
        let keys = load_keys(&config)?;
        let store = Store::connect(&config.mongodb_uri, &config.mongodb_db)
            .await
            .context("connecting to MongoDB")?;
        Ok(Self::new(config, store, keys))
    }

    /// Build the claims for `user`, valid for `ttl` from now.
    pub fn claims_for(&self, user: &User, ttl: std::time::Duration) -> AccessClaims {
        let iat = Utc::now().timestamp();
        AccessClaims {
            iss: self.config.base_url.clone(),
            sub: user.id.to_hex(),
            email: user.email.clone(),
            name: user.name.clone(),
            apps: user
                .grants
                .iter()
                .map(|g| (g.app.clone(), g.roles.clone()))
                .collect(),
            iat,
            exp: iat + ttl.as_secs() as i64,
            jti: random_token(16),
        }
    }

    /// Sign a fresh access token for `user` with the configured TTL.
    pub fn issue_access_token(
        &self,
        user: &User,
    ) -> Result<(String, AccessClaims), clang_auth_core::Error> {
        let claims = self.claims_for(user, self.config.access_token_ttl);
        Ok((self.keys.sign(&claims)?, claims))
    }

    /// Is `origin` (already normalised) the auth host or a registered app?
    pub async fn is_trusted_origin(&self, origin: &str) -> clang_auth_core::Result<bool> {
        if origin == self.config.auth_origin {
            return Ok(true);
        }
        self.is_app_origin(origin).await
    }

    pub async fn is_app_origin(&self, origin: &str) -> clang_auth_core::Result<bool> {
        Ok(self.store.app_for_origin(origin).await?.is_some())
    }
}

pub fn load_keys(config: &Config) -> Result<SigningKeys> {
    let retired = &config.signing_keys_retired;
    let keys = match &config.signing_key {
        SigningKeySource::Pem(pem) => SigningKeys::from_pem(pem, retired)?,
        SigningKeySource::Path(path) => {
            let pem = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            SigningKeys::from_pem(&pem, retired)?
        }
        SigningKeySource::DevAutoGenerate(path) => SigningKeys::load_or_generate(path, retired)?,
    };
    Ok(keys)
}
