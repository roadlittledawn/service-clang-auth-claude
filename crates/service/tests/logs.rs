//! §15: no sensitive values in logs. Captures every log line emitted during
//! the login, invite, reset and admin flows and checks that no password,
//! token, invite link, session ID or admin key appears, while the audit
//! events (§11 Observability) do.

mod common;

use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use clang_auth_core::secret::sha256_hex;
use common::*;
use serde_json::json;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// `#[tokio::test]` uses a current-thread runtime, so a thread-local default
// subscriber sees every log line from the handlers.
#[tokio::test]
async fn logs_contain_no_secrets_but_do_contain_audit_events() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(clang_auth_service::logging::json_subscriber(
        capture.clone(),
    ));

    let app = TestApp::new().await;
    let pw = "my secret passphrase 123";
    let wrong = "a wrong passphrase 456";
    let mut secrets: Vec<String> = vec![ADMIN_KEY.into(), pw.into(), wrong.into()];

    // Invite + setup.
    let res = app
        .send(
            Req::post("/admin/users")
                .admin()
                .json(json!({ "email": "log@example.com", "grants": { "demo": ["member"] } })),
        )
        .await;
    let link = res.json()["setup_link"].as_str().unwrap().to_string();
    let token = token_from_link(&link);
    secrets.extend([link.clone(), token.clone()]);
    let form = app.send(Req::get(&format!("/setup?token={token}"))).await;
    assert_eq!(form.status, StatusCode::OK);
    let res = app
        .send(Req::post("/setup").origin(AUTH).form(&[
            ("token", &token),
            ("password", pw),
            ("password_confirm", pw),
        ]))
        .await;
    assert_eq!(res.status, StatusCode::FOUND);
    secrets.push(res.cookie("ca_session").unwrap().value);
    secrets.push(res.cookie("ca_access").unwrap().value);

    // Logins: failure, success, refresh, logout.
    assert_eq!(
        app.login("log@example.com", wrong, "").await.status,
        StatusCode::UNAUTHORIZED
    );
    let res = app.login("log@example.com", pw, APP_ORIGIN).await;
    let session = res.cookie("ca_session").unwrap().value;
    secrets.push(session.clone());
    secrets.push(res.cookie("ca_access").unwrap().value);
    let res = app
        .send(
            Req::post("/api/session/refresh")
                .origin(APP_ORIGIN)
                .session(&session),
        )
        .await;
    secrets.push(res.cookie("ca_access").unwrap().value);
    app.send(Req::post("/logout").origin(AUTH).session(&session))
        .await;

    // Reset flow.
    let res = app
        .send(Req::post("/admin/users/log@example.com/reset").admin())
        .await;
    let reset = res.json()["reset_link"].as_str().unwrap().to_string();
    let reset_token = token_from_link(&reset);
    secrets.extend([reset.clone(), reset_token.clone()]);
    app.send(
        Req::post("/setup")
            .origin(AUTH)
            .form(&[("token", &reset_token), ("password", "short")]),
    )
    .await;
    app.send(Req::post("/setup").origin(AUTH).form(&[
        ("token", &reset_token),
        ("password", "reset passphrase 789"),
    ]))
    .await;
    secrets.push("reset passphrase 789".into());

    // Admin mutations + mint + failed admin auth.
    app.send(
        Req::new(Method::PUT, "/admin/users/log@example.com/grants/other")
            .admin()
            .json(json!({ "roles": ["x"] })),
    )
    .await;
    let minted = app
        .send(
            Req::post("/admin/tokens")
                .admin()
                .json(json!({ "email": "log@example.com" })),
        )
        .await;
    secrets.push(minted.json()["token"].as_str().unwrap().to_string());
    app.send(Req::get("/admin/apps").header("authorization", "Bearer guessed-admin-key"))
        .await;
    secrets.push("guessed-admin-key".into());
    app.send(
        Req::new(Method::PATCH, "/admin/users/log@example.com")
            .admin()
            .json(json!({ "status": "disabled" })),
    )
    .await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.lines().count() > 20,
        "expected plenty of log lines, got:\n{logs}"
    );
    for s in &secrets {
        assert!(!logs.contains(s.as_str()), "secret {s:?} leaked into logs");
        // Hashes of session tokens are database keys; keep those out too.
        assert!(
            !logs.contains(&sha256_hex(s)),
            "hash of {s:?} leaked into logs"
        );
    }
    assert!(!logs.contains("token="), "query strings must not be logged");
    assert!(!logs.contains("password"), "no password fields");

    for event in [
        "login_success",
        "login_failure",
        "logout",
        "invite_created",
        "invite_used",
        "user_created",
        "grant_set",
        "user_updated",
        "token_minted",
        "admin_auth_failed",
        "http_request",
    ] {
        assert!(
            logs.contains(&format!("\"event\":\"{event}\"")),
            "missing audit event {event}"
        );
    }
    // Every line is JSON and request lines carry a request ID.
    for line in logs.lines() {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}"));
        if v["event"] == "http_request" {
            assert!(v["span"]["request_id"].is_string(), "{line}");
        }
    }
}
