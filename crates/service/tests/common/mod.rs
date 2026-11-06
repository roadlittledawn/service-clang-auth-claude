//! Test harness: a router backed by a fresh MongoDB database per test.
//!
//! Requires MongoDB at `MONGODB_URI` (default `mongodb://localhost:27017`),
//! e.g. from `docker compose up -d`.

#![allow(dead_code)]

use std::{collections::HashMap, net::SocketAddr};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use clang_auth_core::{
    keys::{generate_private_pem, SigningKeys},
    model::User,
    origin::normalize_origin,
    password::{self, HashParams},
    secret::{random_token, sha256_hex},
    store::Store,
};
use clang_auth_service::{config::Config, router, state::AppState};
use http_body_util::BodyExt;
use tower::ServiceExt;

pub const AUTH: &str = "http://auth.localtest.me:4000";
pub const APP_ORIGIN: &str = "http://demo.localtest.me:3000";
pub const OTHER_ORIGIN: &str = "http://other.localtest.me:3001";
pub const ADMIN_KEY: &str = "test-admin-key";
pub const PASSWORD: &str = "correct horse battery";

pub fn mongo_uri() -> String {
    std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".into())
}

pub fn base_vars() -> HashMap<String, String> {
    [
        ("AUTH_BASE_URL", AUTH),
        ("COOKIE_DOMAIN", ".localtest.me"),
        ("COOKIE_SECURE", "true"),
        ("ALLOW_INSECURE_ORIGINS", "true"),
        ("ALLOW_TOKEN_MINT", "true"),
        ("MONGODB_URI", &mongo_uri()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .chain([
        ("ADMIN_API_KEY_HASH".to_string(), sha256_hex(ADMIN_KEY)),
        (
            "MONGODB_DB".to_string(),
            format!(
                "clang_auth_test_{}",
                random_token(6).to_lowercase().replace(['-', '_'], "x")
            ),
        ),
        ("SIGNING_KEY".to_string(), generate_private_pem()),
    ])
    .collect()
}

pub struct TestApp {
    pub state: AppState,
    pub router: Router,
    pub db_name: String,
}

pub struct Res {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Res {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }
    /// All `Set-Cookie` headers, parsed.
    pub fn cookies(&self) -> Vec<SetCookie> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| SetCookie::parse(v.to_str().unwrap()))
            .collect()
    }
    pub fn cookie(&self, name: &str) -> Option<SetCookie> {
        self.cookies().into_iter().find(|c| c.name == name)
    }
}

#[derive(Debug, Clone)]
pub struct SetCookie {
    pub name: String,
    pub value: String,
    pub attrs: HashMap<String, String>,
}

impl SetCookie {
    fn parse(s: &str) -> Self {
        let mut parts = s.split(';').map(str::trim);
        let (name, value) = parts.next().unwrap().split_once('=').unwrap();
        let attrs = parts
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (k.to_ascii_lowercase(), v.to_string()),
                None => (p.to_ascii_lowercase(), String::new()),
            })
            .collect();
        Self {
            name: name.into(),
            value: value.into(),
            attrs,
        }
    }
    pub fn has(&self, attr: &str) -> bool {
        self.attrs.contains_key(attr)
    }
    pub fn attr(&self, attr: &str) -> Option<&str> {
        self.attrs.get(attr).map(String::as_str)
    }
    pub fn is_clear(&self) -> bool {
        self.attr("max-age") == Some("0")
    }
}

/// Builder for requests against the router.
pub struct Req {
    method: Method,
    path: String,
    headers: Vec<(String, String)>,
    body: Body,
    ip: String,
}

impl Req {
    pub fn new(method: Method, path: &str) -> Self {
        Self {
            method,
            path: path.into(),
            headers: vec![],
            body: Body::empty(),
            ip: "10.0.0.1".into(),
        }
    }
    pub fn get(path: &str) -> Self {
        Self::new(Method::GET, path)
    }
    pub fn post(path: &str) -> Self {
        Self::new(Method::POST, path)
    }
    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
    pub fn origin(self, o: &str) -> Self {
        self.header("origin", o)
    }
    pub fn cookie(self, name: &str, value: &str) -> Self {
        self.header("cookie", &format!("{name}={value}"))
    }
    pub fn session(self, token: &str) -> Self {
        self.cookie("ca_session", token)
    }
    pub fn admin(self) -> Self {
        self.header("authorization", &format!("Bearer {ADMIN_KEY}"))
    }
    pub fn ip(mut self, ip: &str) -> Self {
        self.ip = ip.into();
        self
    }
    pub fn form(mut self, pairs: &[(&str, &str)]) -> Self {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        self.headers.push((
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        self.body = Body::from(body);
        self
    }
    pub fn json(mut self, v: serde_json::Value) -> Self {
        self.headers
            .push(("content-type".into(), "application/json".into()));
        self.body = Body::from(v.to_string());
        self
    }
}

impl TestApp {
    pub async fn new() -> Self {
        Self::with(|_| {}).await
    }

    /// Build with modified environment variables.
    pub async fn with(f: impl FnOnce(&mut HashMap<String, String>)) -> Self {
        let mut vars = base_vars();
        f(&mut vars);
        let config = Config::from_map(&vars, false).expect("config");
        let keys =
            SigningKeys::from_pem(vars["SIGNING_KEY"].as_str(), &config.signing_keys_retired)
                .unwrap();
        let store = Store::connect(&config.mongodb_uri, &config.mongodb_db)
            .await
            .unwrap();
        store
            .ensure_indexes()
            .await
            .expect("MongoDB must be running (docker compose up -d)");
        let db_name = config.mongodb_db.clone();
        let state = AppState::new(config, store, keys);
        let router = router(state.clone());
        let app = Self {
            state,
            router,
            db_name,
        };
        app.state
            .store
            .create_app(
                "demo",
                "Demo",
                vec![normalize_origin(APP_ORIGIN, true).unwrap()],
            )
            .await
            .unwrap();
        app.state
            .store
            .create_app(
                "other",
                "Other",
                vec![normalize_origin(OTHER_ORIGIN, true).unwrap()],
            )
            .await
            .unwrap();
        app
    }

    pub fn store(&self) -> &Store {
        &self.state.store
    }

    pub async fn send(&self, req: Req) -> Res {
        let mut builder = Request::builder().method(req.method).uri(&req.path);
        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }
        let mut request = builder.body(req.body).unwrap();
        let addr: SocketAddr = format!("{}:5555", req.ip).parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(addr));
        let res = self.router.clone().oneshot(request).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        Res {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    /// Create an active user with `PASSWORD` and the given grants.
    pub async fn user(&self, email: &str, grants: &[(&str, &[&str])]) -> User {
        let grants = grants
            .iter()
            .map(|(a, r)| (a.to_string(), r.iter().map(|s| s.to_string()).collect()))
            .collect();
        let user = self
            .store()
            .create_user(email, Some("Test User"), grants)
            .await
            .unwrap();
        let phc = password::hash(PASSWORD, HashParams::default()).unwrap();
        self.store().set_password_hash(user.id, &phc).await.unwrap();
        self.store().get_user(user.id).await.unwrap().unwrap()
    }

    pub async fn login(&self, email: &str, password: &str, redirect_uri: &str) -> Res {
        self.send(Req::post("/login").origin(AUTH).form(&[
            ("email", email),
            ("password", password),
            ("redirect_uri", redirect_uri),
        ]))
        .await
    }

    /// Log in and return the raw session token.
    pub async fn session_for(&self, email: &str) -> String {
        let res = self.login(email, PASSWORD, "").await;
        assert_eq!(res.status, StatusCode::FOUND, "login failed: {}", res.body);
        res.cookie("ca_session").expect("session cookie").value
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let name = self.db_name.clone();
        // Drop the per-test database on a fresh runtime (Drop can't be async).
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                if let Ok(client) = mongodb::Client::with_uri_str(mongo_uri()).await {
                    let _ = client.database(&name).drop().await;
                }
            });
        })
        .join();
    }
}

/// Extract the token from a setup/reset link.
pub fn token_from_link(link: &str) -> String {
    let url = url::Url::parse(link).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == "token")
        .unwrap()
        .1
        .into_owned()
}
