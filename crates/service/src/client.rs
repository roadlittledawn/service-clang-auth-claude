//! Who is calling: client IP and user agent.

use std::{convert::Infallible, net::SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{header, request::Parts},
};
use lambda_http::request::RequestContext;

#[derive(Debug, Clone, Default)]
pub struct ClientInfo {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for ClientInfo {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        // In Lambda, API Gateway reports the real peer address. We do not
        // trust `X-Forwarded-For`, which any client can forge.
        let ip = match parts.extensions.get::<RequestContext>() {
            Some(RequestContext::ApiGatewayV2(ctx)) => ctx.http.source_ip.clone(),
            _ => parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip().to_string()),
        };
        let user_agent = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Ok(Self { ip, user_agent })
    }
}
