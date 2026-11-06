//! Idempotent local-dev seed data (spec §10.1).

use anyhow::Result;
use clang_auth_core::{origin::normalize_origin, password, secret::sha256_hex, Error};

use crate::state::AppState;

pub const DEV_APP: &str = "demo";
pub const DEV_APP_ORIGIN: &str = "http://demo.localtest.me:3000";
pub const DEV_EMAIL: &str = "dev@localtest.me";
pub const DEV_PASSWORD: &str = "devpassword123";
pub const DEV_ADMIN_KEY: &str = "dev-admin-key-change-me";

/// Create (or restore) the `demo` app and the dev user. Safe to run often.
pub async fn run(state: &AppState) -> Result<()> {
    let store = &state.store;
    store.ensure_indexes().await?;
    let origin = normalize_origin(DEV_APP_ORIGIN, true)?;

    match store.get_app(DEV_APP).await? {
        None => {
            store.create_app(DEV_APP, "Demo app", vec![origin]).await?;
            println!("created app {DEV_APP} ({DEV_APP_ORIGIN})");
        }
        Some(app) if !app.origins.contains(&origin) => {
            let mut origins = app.origins;
            origins.push(origin);
            store.update_app(DEV_APP, None, Some(origins)).await?;
            println!("added {DEV_APP_ORIGIN} to app {DEV_APP}");
        }
        Some(_) => println!("app {DEV_APP} already exists"),
    }

    let user = match store.find_user_by_email(DEV_EMAIL).await? {
        Some(u) => {
            println!("user {DEV_EMAIL} already exists");
            u
        }
        None => match store.create_user(DEV_EMAIL, Some("Dev User"), vec![]).await {
            Ok(u) => {
                println!("created user {DEV_EMAIL}");
                u
            }
            Err(Error::Conflict(_)) => store
                .find_user_by_email(DEV_EMAIL)
                .await?
                .expect("user exists"),
            Err(e) => return Err(e.into()),
        },
    };
    if !user.is_active() {
        store
            .update_user(
                user.id,
                None,
                Some(clang_auth_core::model::UserStatus::Active),
            )
            .await?;
    }
    let phc = password::hash(DEV_PASSWORD, state.config.argon2)?;
    store.set_password_hash(user.id, &phc).await?;
    store
        .set_grant(user.id, DEV_APP, &["admin".to_string()])
        .await?;
    println!("user {DEV_EMAIL} password is {DEV_PASSWORD:?} with grant {DEV_APP}: [\"admin\"]");

    if state.config.admin_key_hash == sha256_hex(DEV_ADMIN_KEY) {
        println!("admin API key is {DEV_ADMIN_KEY:?} (from .env.example)");
    } else {
        println!(
            "note: ADMIN_API_KEY_HASH is not the dev key; use your own admin key with the CLI"
        );
    }
    Ok(())
}
