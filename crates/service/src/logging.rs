//! Structured logging and per-request log lines.
//!
//! Rules (spec §11): never log passwords, tokens, invite links, session IDs
//! or the admin key; never log request/response bodies. The request logger
//! therefore records only the method, the *path without query string* (the
//! setup link carries its token in the query), the status and the latency.

use std::time::Instant;

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use tracing::Instrument;
use tracing_subscriber::{fmt::MakeWriter, EnvFilter};

/// Initialise the global subscriber. `json` is used in Lambda (CloudWatch).
pub fn init(level: &str, json: bool) {
    let filter = EnvFilter::try_new(format!(
        "{level},h2=warn,hyper=warn,rustls=warn,mongodb=warn,aws=warn"
    ))
    .unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if json {
        // `without_time`: Lambda/CloudWatch timestamps every line already.
        builder
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .init();
    } else {
        builder.compact().init();
    }
}

/// Build a JSON subscriber writing to `writer`; used by tests to capture logs.
pub fn json_subscriber<W>(writer: W) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("debug,mongodb=warn,h2=warn,hyper=warn"))
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_writer(writer)
        .finish()
}

fn request_id(req: &Request) -> String {
    use lambda_http::RequestExt;
    match req.lambda_context_ref() {
        Some(ctx) if !ctx.request_id.is_empty() => ctx.request_id.clone(),
        _ => clang_auth_core::secret::random_token(12),
    }
}

/// Middleware: one span per request with a request ID, plus one summary line.
pub async fn request_logger(req: Request, next: Next) -> Response {
    let id = request_id(&req);
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let span = tracing::info_span!("request", request_id = %id);
    let start = Instant::now();
    let mut res = next.run(req).instrument(span.clone()).await;
    let status = res.status().as_u16();
    span.in_scope(|| {
        tracing::info!(
            event = "http_request",
            method = %method,
            path = %path,
            status,
            latency_ms = start.elapsed().as_millis() as u64,
        );
    });
    if let Ok(v) = HeaderValue::from_str(&id) {
        res.headers_mut().insert("x-request-id", v);
    }
    res
}
