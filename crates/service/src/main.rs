//! Entrypoint. Runs as a Lambda function when `AWS_LAMBDA_RUNTIME_API` is
//! set, otherwise as a local HTTP server. Extra local subcommands:
//!
//! ```text
//! clang-auth-service                  # serve (default)
//! clang-auth-service migrate          # create MongoDB indexes
//! clang-auth-service seed             # idempotent dev data (§10.1)
//! clang-auth-service gen-signing-key  # print a new ES256 private key (PEM)
//! clang-auth-service public-key       # print the public key for SIGNING_KEY[_PATH]
//! clang-auth-service hash-admin-key K # print sha256(K) for ADMIN_API_KEY_HASH
//! ```

use std::{collections::HashMap, future::IntoFuture, net::SocketAddr};

use anyhow::{bail, Context, Result};
use clang_auth_core::{keys, secret};
use clang_auth_service::{
    config::{self, Config},
    logging, router, seed,
    state::AppState,
};

#[tokio::main]
async fn main() -> Result<()> {
    if config::in_lambda() {
        return run_lambda().await;
    }
    // Local only: load `.env` if present. Never in Lambda.
    let _ = dotenvy::dotenv();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("serve") => serve_local().await,
        Some("migrate") => {
            let state = AppState::from_config(Config::from_env()?).await?;
            state.store.ensure_indexes().await?;
            println!("indexes are up to date");
            Ok(())
        }
        Some("seed") => {
            let state = AppState::from_config(Config::from_env()?).await?;
            seed::run(&state).await
        }
        Some("gen-signing-key") => {
            print!("{}", keys::generate_private_pem());
            Ok(())
        }
        Some("public-key") => {
            let pem = match (std::env::var("SIGNING_KEY"), std::env::var("SIGNING_KEY_PATH")) {
                (Ok(pem), _) if !pem.trim().is_empty() => pem,
                (_, Ok(path)) => std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?,
                _ => std::fs::read_to_string(".dev-keys/signing-key.pem").context("set SIGNING_KEY or SIGNING_KEY_PATH")?,
            };
            print!("{}", keys::public_pem_from_private(&pem)?);
            Ok(())
        }
        Some("hash-admin-key") => match args.get(1) {
            Some(k) => {
                println!("{}", secret::sha256_hex(k));
                Ok(())
            }
            None => bail!("usage: hash-admin-key <key>"),
        },
        Some("gen-admin-key") => {
            let key = secret::random_token(32);
            println!("ADMIN KEY (give to the CLI as CLANG_AUTH_ADMIN_KEY): {key}");
            println!("ADMIN_API_KEY_HASH (give to the service):           {}", secret::sha256_hex(&key));
            Ok(())
        }
        Some(other) => bail!("unknown command {other:?} (expected serve, migrate, seed, gen-signing-key, public-key, gen-admin-key, hash-admin-key)"),
    }
}

async fn serve_local() -> Result<()> {
    let config = Config::from_env()?;
    let json = std::env::var("LOG_FORMAT").is_ok_and(|v| v == "json");
    logging::init(&config.log_level, json);
    let state = AppState::from_config(config).await?;
    state
        .store
        .ensure_indexes()
        .await
        .context("creating indexes (is MongoDB running? try `docker compose up -d`)")?;
    // `*.localtest.me` resolves to both 127.0.0.1 and ::1, and browsers may
    // pick either, so listen on both loopback addresses.
    let port = state.config.port;
    let v4 = SocketAddr::from(([127, 0, 0, 1], port));
    let v6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port));
    let listener4 = tokio::net::TcpListener::bind(v4)
        .await
        .with_context(|| format!("binding {v4}"))?;
    let listener6 = match tokio::net::TcpListener::bind(v6).await {
        Ok(l) => Some(l),
        Err(e) => {
            tracing::warn!(addr = %v6, error = %e, "could not listen on IPv6 loopback; browsers resolving ::1 may hit another process");
            None
        }
    };
    tracing::info!(event = "listening", port, ipv6 = listener6.is_some(), base_url = %state.config.base_url);
    let app = router(state);
    let shutdown = || async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let s4 = axum::serve(
        listener4,
        app.clone()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown());
    match listener6 {
        Some(l6) => {
            let s6 = axum::serve(l6, app.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(shutdown());
            tokio::try_join!(s4.into_future(), s6.into_future())?;
        }
        None => s4.await?,
    }
    Ok(())
}

async fn run_lambda() -> Result<()> {
    let mut vars: HashMap<String, String> = std::env::vars().collect();
    let level = vars
        .get("LOG_LEVEL")
        .cloned()
        .unwrap_or_else(|| "info".into());
    logging::init(&level, true);
    // Cold start: fetch secrets from SSM once, then connect once. The client
    // and keys live for the lifetime of this container.
    config::resolve_ssm(&mut vars).await?;
    let config = Config::from_map(&vars, true)?;
    let state = AppState::from_config(config).await?;
    // Index creation is idempotent; run it without blocking the first request.
    let store = state.store.clone();
    tokio::spawn(async move {
        if let Err(e) = store.ensure_indexes().await {
            tracing::error!(error = %e, "ensure_indexes failed");
        }
    });
    lambda_http::run(router(state))
        .await
        .map_err(|e| anyhow::anyhow!(e))
}
