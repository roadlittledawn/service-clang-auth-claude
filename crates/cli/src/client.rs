//! Thin HTTP client for the admin API.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::{Method, StatusCode, Url};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize, Default)]
struct FileConfig {
    url: Option<String>,
    admin_key: Option<String>,
}

fn config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CLANG_AUTH_CONFIG") {
        return Some(p.into());
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("clang-auth").join("config.toml"))
}

fn load_file_config() -> Result<FileConfig> {
    let Some(path) = config_path() else {
        return Ok(FileConfig::default());
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileConfig::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub struct Client {
    http: reqwest::Client,
    base: Url,
    key: String,
}

impl Client {
    pub fn from_config(url: Option<String>, key: Option<String>) -> Result<Self> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let file = load_file_config()?;
        let url = url
            .or_else(|| env("CLANG_AUTH_URL"))
            .or(file.url)
            .ok_or_else(|| anyhow!("no service URL: set CLANG_AUTH_URL, pass --url, or add url to ~/.config/clang-auth/config.toml"))?;
        let key = key
            .or_else(|| env("CLANG_AUTH_ADMIN_KEY"))
            .or(file.admin_key)
            .ok_or_else(|| anyhow!("no admin key: set CLANG_AUTH_ADMIN_KEY, pass --key, or add admin_key to ~/.config/clang-auth/config.toml"))?;
        let base = Url::parse(url.trim_end_matches('/'))
            .with_context(|| format!("invalid URL {url:?}"))?;
        let http = reqwest::Client::builder()
            .user_agent(concat!("clang-auth-cli/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http,
            base,
            key: key.trim().to_string(),
        })
    }

    /// Build a URL from path segments, percent-encoding each (emails etc.).
    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .expect("base URL can have path")
            .pop_if_empty()
            .extend(segments);
        url
    }

    async fn send(&self, method: Method, url: Url, body: Option<Value>) -> Result<Value> {
        let mut req = self
            .http
            .request(method, url.clone())
            .bearer_auth(&self.key);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let res = req
            .send()
            .await
            .with_context(|| format!("could not reach {}", self.base))?;
        let status = res.status();
        let text = res.text().await?;
        let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(json);
        }
        let msg = json["error"]["message"].as_str().unwrap_or(text.as_str());
        match status {
            StatusCode::UNAUTHORIZED => bail!("401 unauthorized: check CLANG_AUTH_ADMIN_KEY"),
            _ => bail!(
                "{} {}: {msg}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("")
            ),
        }
    }

    /// GET a path that may contain a query string (already encoded).
    pub async fn get(&self, path_and_query: &str) -> Result<Value> {
        let url = self.base.join(path_and_query)?;
        self.send(Method::GET, url, None).await
    }

    pub async fn get_path(&self, segments: &[&str]) -> Result<Value> {
        self.send(Method::GET, self.url(segments), None).await
    }

    pub async fn post(&self, segments: &[&str], body: Value) -> Result<Value> {
        self.send(Method::POST, self.url(segments), Some(body))
            .await
    }

    pub async fn put(&self, segments: &[&str], body: Value) -> Result<Value> {
        self.send(Method::PUT, self.url(segments), Some(body)).await
    }

    pub async fn patch(&self, segments: &[&str], body: Value) -> Result<Value> {
        self.send(Method::PATCH, self.url(segments), Some(body))
            .await
    }

    pub async fn delete(&self, segments: &[&str]) -> Result<Value> {
        self.send(Method::DELETE, self.url(segments), None).await
    }
}
