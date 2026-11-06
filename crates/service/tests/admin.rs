//! §15 "Admin" items (HTTP level). CLI end-to-end lives in the cli crate.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;

#[tokio::test]
async fn admin_requires_the_key() {
    let app = TestApp::new().await;
    let routes = [
        (Method::GET, "/admin/apps"),
        (Method::POST, "/admin/apps"),
        (Method::GET, "/admin/apps/demo"),
        (Method::PATCH, "/admin/apps/demo"),
        (Method::DELETE, "/admin/apps/demo"),
        (Method::GET, "/admin/users"),
        (Method::POST, "/admin/users"),
        (Method::GET, "/admin/users/x@example.com"),
        (Method::PATCH, "/admin/users/x@example.com"),
        (Method::DELETE, "/admin/users/x@example.com"),
        (Method::POST, "/admin/users/x@example.com/reset"),
        (Method::PUT, "/admin/users/x@example.com/grants/demo"),
        (Method::DELETE, "/admin/users/x@example.com/grants/demo"),
        (Method::DELETE, "/admin/users/x@example.com/sessions"),
        (Method::POST, "/admin/tokens"),
    ];
    for (m, path) in routes {
        for auth in [
            None,
            Some("Bearer wrong-key"),
            Some("Bearer "),
            Some(ADMIN_KEY),
            Some("Basic dGVzdA=="),
        ] {
            let mut req = Req::new(m.clone(), path).json(json!({}));
            if let Some(a) = auth {
                req = req.header("authorization", a);
            }
            let res = app.send(req).await;
            assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{m} {path} {auth:?}");
            assert_eq!(res.json()["error"]["code"], "unauthorized");
        }
    }
    // The demo app is untouched.
    assert_eq!(
        app.send(Req::get("/admin/apps/demo").admin()).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn app_crud_and_validation() {
    let app = TestApp::new().await;
    let res = app
        .send(Req::post("/admin/apps").admin().json(json!({ "slug": "recipes", "name": "Recipes", "origins": ["http://Recipes.localtest.me:5000/"] })))
        .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.body);
    assert_eq!(
        res.json()["origins"],
        json!(["http://recipes.localtest.me:5000"]),
        "normalised"
    );

    let dup = app
        .send(
            Req::post("/admin/apps").admin().json(
                json!({ "slug": "recipes", "name": "R", "origins": ["http://r.localtest.me"] }),
            ),
        )
        .await;
    assert_eq!(dup.status, StatusCode::CONFLICT);
    assert_eq!(dup.json()["error"]["code"], "conflict");

    for bad in [
        json!({ "slug": "Bad Slug", "name": "x", "origins": ["http://a.localtest.me"] }),
        json!({ "slug": "ok", "name": "x", "origins": [] }),
        json!({ "slug": "ok", "name": "x", "origins": ["http://a.localtest.me/path"] }),
        json!({ "slug": "ok", "name": "x" }),
    ] {
        let res = app
            .send(Req::post("/admin/apps").admin().json(bad.clone()))
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
        assert!(res.json()["error"]["message"].is_string());
    }

    let res = app
        .send(
            Req::new(Method::PATCH, "/admin/apps/recipes")
                .admin()
                .json(json!({ "name": "Recipes 2", "origins": ["http://r2.localtest.me"] })),
        )
        .await;
    assert_eq!(res.json()["name"], "Recipes 2");
    assert_eq!(res.json()["origins"], json!(["http://r2.localtest.me"]));

    let list = app.send(Req::get("/admin/apps").admin()).await.json();
    assert_eq!(list.as_array().unwrap().len(), 3);
    assert_eq!(
        app.send(Req::new(Method::DELETE, "/admin/apps/recipes").admin())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        app.send(Req::get("/admin/apps/recipes").admin())
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn user_crud_and_grants() {
    let app = TestApp::new().await;
    let res = app
        .send(
            Req::post("/admin/users")
                .admin()
                .json(json!({ "email": "Ann@Example.com", "grants": { "demo": ["member"] } })),
        )
        .await;
    assert_eq!(res.status, StatusCode::CREATED);
    let id = res.json()["user"]["id"].as_str().unwrap().to_string();
    assert_eq!(res.json()["user"]["email"], "ann@example.com");

    let unknown_app = app
        .send(
            Req::post("/admin/users")
                .admin()
                .json(json!({ "email": "b@example.com", "grants": { "nope": [] } })),
        )
        .await;
    assert_eq!(unknown_app.status, StatusCode::BAD_REQUEST);
    let dup = app
        .send(
            Req::post("/admin/users")
                .admin()
                .json(json!({ "email": "ANN@example.com" })),
        )
        .await;
    assert_eq!(
        dup.status,
        StatusCode::CONFLICT,
        "emails are case-insensitive"
    );

    // :id accepts the ObjectId or the email.
    for r in [id.as_str(), "ann@example.com"] {
        let u = app
            .send(Req::get(&format!("/admin/users/{r}")).admin())
            .await
            .json();
        assert_eq!(u["id"], id.as_str());
        assert_eq!(u["active_sessions"], 0);
    }

    let res = app
        .send(
            Req::new(Method::PUT, "/admin/users/ann@example.com/grants/other")
                .admin()
                .json(json!({ "roles": ["admin", "admin"] })),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let res = app
        .send(
            Req::new(Method::PUT, "/admin/users/ann@example.com/grants/demo")
                .admin()
                .json(json!({ "roles": ["owner"] })),
        )
        .await;
    let grants = res.json()["grants"].clone();
    assert_eq!(grants.as_array().unwrap().len(), 2);
    assert_eq!(
        grants[0],
        json!({ "app": "demo", "roles": ["owner"], "granted_at": grants[0]["granted_at"] })
    );
    assert_eq!(grants[1]["roles"], json!(["admin"]), "deduplicated");

    let res = app
        .send(
            Req::new(Method::PUT, "/admin/users/ann@example.com/grants/nope")
                .admin()
                .json(json!({ "roles": [] })),
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);

    let filtered = app
        .send(Req::get("/admin/users?app=other").admin())
        .await
        .json();
    assert_eq!(filtered.as_array().unwrap().len(), 1);
    let res = app
        .send(Req::new(Method::DELETE, "/admin/users/ann@example.com/grants/other").admin())
        .await;
    assert_eq!(res.json()["grants"].as_array().unwrap().len(), 1);
    assert_eq!(
        app.send(Req::get("/admin/users?app=other").admin())
            .await
            .json(),
        json!([])
    );
    let res = app
        .send(Req::new(Method::DELETE, "/admin/users/ann@example.com/grants/other").admin())
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);

    let res = app
        .send(
            Req::new(Method::PATCH, &format!("/admin/users/{id}"))
                .admin()
                .json(json!({ "name": "Ann" })),
        )
        .await;
    assert_eq!(res.json()["name"], "Ann");
    let res = app
        .send(
            Req::new(Method::PATCH, &format!("/admin/users/{id}"))
                .admin()
                .json(json!({ "name": null })),
        )
        .await;
    assert_eq!(res.json()["name"], serde_json::Value::Null);
    let res = app
        .send(
            Req::new(Method::PATCH, &format!("/admin/users/{id}"))
                .admin()
                .json(json!({ "status": "bogus" })),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);

    assert_eq!(
        app.send(Req::new(Method::DELETE, &format!("/admin/users/{id}")).admin())
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        app.send(Req::get(&format!("/admin/users/{id}")).admin())
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn disabling_a_user_revokes_sessions() {
    let app = TestApp::new().await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let s = app.session_for("me@example.com").await;
    assert_eq!(
        app.send(Req::get("/admin/users/me@example.com").admin())
            .await
            .json()["active_sessions"],
        1
    );

    let res = app
        .send(
            Req::new(Method::PATCH, "/admin/users/me@example.com")
                .admin()
                .json(json!({ "status": "disabled" })),
        )
        .await;
    assert_eq!(res.json()["status"], "disabled");
    let user = app
        .send(Req::get("/admin/users/me@example.com").admin())
        .await
        .json();
    assert_eq!(user["active_sessions"], 0);
    assert_eq!(
        app.send(
            Req::post("/api/session/refresh")
                .origin(APP_ORIGIN)
                .session(&s)
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.login("me@example.com", PASSWORD, "").await.status,
        StatusCode::UNAUTHORIZED
    );

    app.send(
        Req::new(Method::PATCH, "/admin/users/me@example.com")
            .admin()
            .json(json!({ "status": "active" })),
    )
    .await;
    assert_eq!(
        app.login("me@example.com", PASSWORD, "").await.status,
        StatusCode::FOUND
    );
}

#[tokio::test]
async fn deleting_an_app_removes_its_grants() {
    let app = TestApp::new().await;
    app.user(
        "a@example.com",
        &[("demo", &["admin"]), ("other", &["member"])],
    )
    .await;
    app.user("b@example.com", &[("demo", &["member"])]).await;
    app.user("c@example.com", &[("other", &[])]).await;

    let res = app
        .send(Req::new(Method::DELETE, "/admin/apps/demo").admin())
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json()["grants_removed"], 2);

    for (email, expected) in [
        ("a@example.com", vec!["other"]),
        ("b@example.com", vec![]),
        ("c@example.com", vec!["other"]),
    ] {
        let u = app
            .send(Req::get(&format!("/admin/users/{email}")).admin())
            .await
            .json();
        let apps: Vec<&str> = u["grants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["app"].as_str().unwrap())
            .collect();
        assert_eq!(apps, expected, "{email}");
    }
    // And the next token no longer mentions it.
    let jwt = app
        .login("a@example.com", PASSWORD, "")
        .await
        .cookie("ca_access")
        .unwrap()
        .value;
    let res = app
        .send(
            Req::post("/admin/tokens")
                .admin()
                .json(json!({ "email": "a@example.com" })),
        )
        .await;
    assert!(res.json()["claims"]["apps"].get("demo").is_none());
    assert!(!jwt.is_empty());
}

#[tokio::test]
async fn token_mint_is_404_unless_enabled() {
    let off = TestApp::with(|v| {
        v.insert("ALLOW_TOKEN_MINT".into(), "false".into());
    })
    .await;
    off.user("me@example.com", &[("demo", &[])]).await;
    let res = off
        .send(
            Req::post("/admin/tokens")
                .admin()
                .json(json!({ "email": "me@example.com" })),
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let res = off
        .send(Req::post("/admin/tokens").json(json!({ "email": "me@example.com" })))
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND, "even without a key");

    let on = TestApp::new().await;
    let user = on.user("me@example.com", &[("demo", &["admin"])]).await;
    for (body, ttl) in [
        (json!({ "email": "me@example.com" }), 900),
        (json!({ "user_id": user.id.to_hex(), "ttl": "1h" }), 3600),
        (json!({ "email": "me@example.com", "ttl": 60 }), 60),
    ] {
        let res = on.send(Req::post("/admin/tokens").admin().json(body)).await;
        assert_eq!(res.status, StatusCode::OK);
        let c = &res.json()["claims"];
        assert_eq!(c["exp"].as_i64().unwrap() - c["iat"].as_i64().unwrap(), ttl);
        assert_eq!(c["apps"]["demo"], json!(["admin"]));
    }
    let res = on
        .send(
            Req::post("/admin/tokens")
                .admin()
                .json(json!({ "email": "me@example.com", "ttl": "forever" })),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_json_uses_error_shape() {
    let app = TestApp::new().await;
    let res = app
        .send(
            Req::post("/admin/apps")
                .admin()
                .header("content-type", "application/json"),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.json()["error"]["code"].is_string());
    let res = app.send(Req::post("/admin/apps").admin()).await;
    assert_eq!(res.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(res.json()["error"]["code"], "unsupported_media_type");
}
