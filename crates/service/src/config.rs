//! Service configuration from environment variables (spec §9).

use std::{collections::HashMap, path::PathBuf, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clang_auth_core::{duration, origin, password::HashParams};

/// Variables that may instead be fetched from SSM Parameter Store by setting
/// `<NAME>_SSM_PARAM` to the parameter name (used in Lambda).
pub const SSM_BACKED: &[&str] = &[
    "MONGODB_URI",
    "ADMIN_API_KEY_HASH",
    "SIGNING_KEY",
    "SIGNING_KEYS_RETIRED",
];

/// SSM-backed variables whose parameter may not exist (treated as empty).
/// Retired keys only exist during a rotation.
pub const SSM_OPTIONAL: &[&str] = &["SIGNING_KEYS_RETIRED"];

#[derive(Clone, Debug)]
pub enum SigningKeySource {
    /// PEM text (prod: fetched from SSM).
    Pem(String),
    /// A file that must exist.
    Path(PathBuf),
    /// Local dev: use this file, generating it on first run.
    DevAutoGenerate(PathBuf),
}

#[derive(Clone)]
pub struct Config {
    /// e.g. `https://auth.example.com`; also the JWT `iss`. No trailing slash.
    pub base_url: String,
    /// Origin of `base_url`, used for CSRF checks.
    pub auth_origin: String,
    pub cookie_domain: String,
    pub cookie_secure: bool,
    pub allow_insecure_origins: bool,
    pub allow_token_mint: bool,
    pub mongodb_uri: String,
    pub mongodb_db: String,
    pub admin_key_hash: String,
    pub signing_key: SigningKeySource,
    pub signing_keys_retired: String,
    pub session_ttl: Duration,
    pub session_max_ttl: Duration,
    pub access_token_ttl: Duration,
    pub invite_ttl: Duration,
    pub port: u16,
    pub log_level: String,
    pub argon2: HashParams,
    /// Rate limits (spec §11): failures allowed per window before blocking.
    pub rate_limit_email: i64,
    pub rate_limit_ip: i64,
    pub rate_limit_window: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets (MongoDB URI with credentials, key material) are omitted.
        f.debug_struct("Config")
            .field("base_url", &self.base_url)
            .field("cookie_domain", &self.cookie_domain)
            .field("cookie_secure", &self.cookie_secure)
            .field("allow_insecure_origins", &self.allow_insecure_origins)
            .field("allow_token_mint", &self.allow_token_mint)
            .field("mongodb_db", &self.mongodb_db)
            .field("session_ttl", &self.session_ttl)
            .field("session_max_ttl", &self.session_max_ttl)
            .field("access_token_ttl", &self.access_token_ttl)
            .field("invite_ttl", &self.invite_ttl)
            .finish_non_exhaustive()
    }
}

fn parse_bool(name: &str, v: &str) -> Result<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        _ => bail!("{name} must be true or false, got {v:?}"),
    }
}

impl Config {
    /// Read configuration from the process environment.
    pub fn from_env() -> Result<Self> {
        let vars: HashMap<String, String> = std::env::vars().collect();
        Self::from_map(&vars, in_lambda())
    }

    /// Build configuration from a map of variables. `lambda` disables the
    /// dev-only signing-key auto-generation.
    pub fn from_map(vars: &HashMap<String, String>, lambda: bool) -> Result<Self> {
        let get = |k: &str| vars.get(k).map(|v| v.trim()).filter(|v| !v.is_empty());
        let req = |k: &str| {
            get(k)
                .map(str::to_string)
                .ok_or_else(|| anyhow!("{k} is required"))
        };
        let flag = |k: &str, default: bool| get(k).map_or(Ok(default), |v| parse_bool(k, v));
        let dur = |k: &str, default: &str| {
            duration::parse(get(k).unwrap_or(default)).map_err(|e| anyhow!("{k}: {e}"))
        };
        let num = |k: &str, default: u32| -> Result<u32> {
            get(k).map_or(Ok(default), |v| {
                v.parse().with_context(|| format!("{k} must be an integer"))
            })
        };

        let allow_insecure_origins = flag("ALLOW_INSECURE_ORIGINS", false)?;
        let base_url = req("AUTH_BASE_URL")?.trim_end_matches('/').to_string();
        let auth_origin = origin::normalize_origin(&base_url, allow_insecure_origins)
            .map_err(|e| anyhow!("AUTH_BASE_URL: {e}"))?;

        let cookie_domain = req("COOKIE_DOMAIN")?;
        let auth_host = url::Url::parse(&base_url)?
            .host_str()
            .unwrap_or_default()
            .to_string();
        let bare = cookie_domain.trim_start_matches('.');
        if !(auth_host == bare || auth_host.ends_with(&format!(".{bare}"))) {
            bail!("COOKIE_DOMAIN {cookie_domain:?} must be a parent domain of the AUTH_BASE_URL host {auth_host:?}");
        }

        let admin_key_hash = req("ADMIN_API_KEY_HASH")?.to_ascii_lowercase();
        if admin_key_hash.len() != 64 || !admin_key_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("ADMIN_API_KEY_HASH must be the 64-character sha256 hex of the admin key");
        }

        let signing_key = match (get("SIGNING_KEY"), get("SIGNING_KEY_PATH")) {
            (Some(pem), _) => SigningKeySource::Pem(pem.to_string()),
            (None, Some(path)) if lambda => SigningKeySource::Path(path.into()),
            (None, Some(path)) => SigningKeySource::DevAutoGenerate(path.into()),
            (None, None) if lambda => {
                bail!("SIGNING_KEY (or SIGNING_KEY_SSM_PARAM) is required in Lambda")
            }
            (None, None) => SigningKeySource::DevAutoGenerate(".dev-keys/signing-key.pem".into()),
        };

        let session_ttl = dur("SESSION_TTL", "30d")?;
        let session_max_ttl = dur("SESSION_MAX_TTL", "90d")?;
        if session_max_ttl < session_ttl {
            bail!("SESSION_MAX_TTL must be >= SESSION_TTL");
        }

        let argon2 = HashParams::new(
            num("ARGON2_M_KIB", clang_auth_core::password::MIN_M_KIB)?,
            num("ARGON2_T", clang_auth_core::password::MIN_T)?,
            num("ARGON2_P", clang_auth_core::password::MIN_P)?,
        )?;

        Ok(Self {
            base_url,
            auth_origin,
            cookie_domain,
            cookie_secure: flag("COOKIE_SECURE", true)?,
            allow_insecure_origins,
            allow_token_mint: flag("ALLOW_TOKEN_MINT", false)?,
            mongodb_uri: req("MONGODB_URI")?,
            mongodb_db: get("MONGODB_DB").unwrap_or("clang_auth").to_string(),
            admin_key_hash,
            signing_key,
            signing_keys_retired: get("SIGNING_KEYS_RETIRED").unwrap_or_default().to_string(),
            session_ttl,
            session_max_ttl,
            access_token_ttl: dur("ACCESS_TOKEN_TTL", "15m")?,
            invite_ttl: dur("INVITE_TTL", "72h")?,
            port: get("PORT").map_or(Ok(4000), |v| {
                v.parse().context("PORT must be a port number")
            })?,
            log_level: get("LOG_LEVEL").unwrap_or("info").to_string(),
            argon2,
            rate_limit_email: 5,
            rate_limit_ip: 20,
            rate_limit_window: Duration::from_secs(15 * 60),
        })
    }
}

/// True when running inside AWS Lambda.
pub fn in_lambda() -> bool {
    std::env::var_os("AWS_LAMBDA_RUNTIME_API").is_some()
}

/// For every `X` in [`SSM_BACKED`] that is unset but has `X_SSM_PARAM`, fetch
/// the parameter (decrypted) from SSM and insert it into `vars`. One
/// `GetParameters` call per cold start.
pub async fn resolve_ssm(vars: &mut HashMap<String, String>) -> Result<()> {
    let wanted: Vec<(String, String)> = SSM_BACKED
        .iter()
        .filter(|k| vars.get(**k).is_none_or(|v| v.trim().is_empty()))
        .filter_map(|k| {
            vars.get(&format!("{k}_SSM_PARAM"))
                .filter(|p| !p.is_empty())
                .map(|p| (k.to_string(), p.clone()))
        })
        .collect();
    if wanted.is_empty() {
        return Ok(());
    }
    let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = aws_sdk_ssm::Client::new(&sdk);
    let out = client
        .get_parameters()
        .set_names(Some(wanted.iter().map(|(_, p)| p.clone()).collect()))
        .with_decryption(true)
        .send()
        .await
        .context("fetching parameters from SSM")?;
    for bad in out.invalid_parameters() {
        let optional = wanted
            .iter()
            .any(|(var, param)| param == bad && SSM_OPTIONAL.contains(&var.as_str()));
        if !optional {
            bail!("SSM parameter not found: {bad}");
        }
    }
    for p in out.parameters() {
        let (Some(name), Some(value)) = (p.name(), p.value()) else {
            continue;
        };
        for (var, param) in &wanted {
            if param == name {
                vars.insert(var.clone(), value.to_string());
            }
        }
    }
    Ok(())
}
