//! §15 "Tokens": JWTs verify against the published JWKS with a standard
//! library (`jsonwebtoken`), the claims match §5.3, and key rotation works.

mod common;

use axum::http::StatusCode;
use clang_auth_core::keys::{
    generate_private_pem, public_pem_from_private, AccessClaims, SigningKeys,
};
use common::*;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use std::collections::BTreeMap;

/// Verify like an app would: find the JWK by `kid`, check signature, `iss`,
/// `exp`, and that the app's slug is present.
fn verify(jwks: &JwkSet, token: &str, slug: &str) -> Result<AccessClaims, String> {
    let header = decode_header(token).map_err(|e| e.to_string())?;
    let kid = header.kid.ok_or("no kid")?;
    let jwk = jwks.find(&kid).ok_or("unknown kid")?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| e.to_string())?;
    let mut v = Validation::new(Algorithm::ES256);
    v.set_issuer(&[AUTH]);
    v.set_required_spec_claims(&["exp", "iss", "sub"]);
    let claims = decode::<AccessClaims>(token, &key, &v)
        .map_err(|e| e.to_string())?
        .claims;
    if !claims.apps.contains_key(slug) {
        return Err("app not granted".into());
    }
    Ok(claims)
}

async fn fetch_jwks(app: &TestApp) -> JwkSet {
    let res = app.send(Req::get("/.well-known/jwks.json")).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.header("cache-control"), Some("public, max-age=3600"));
    serde_json::from_str(&res.body).unwrap()
}

#[tokio::test]
async fn login_jwt_verifies_against_jwks_and_matches_spec_claims() {
    let app = TestApp::new().await;
    let user = app
        .user(
            "me@example.com",
            &[("demo", &["admin"]), ("other", &["member", "viewer"])],
        )
        .await;
    let res = app.login("me@example.com", PASSWORD, APP_ORIGIN).await;
    let jwt = res.cookie("ca_access").unwrap().value;

    let header = decode_header(&jwt).unwrap();
    assert_eq!(header.alg, Algorithm::ES256);
    assert!(header.kid.is_some(), "kid present");

    let jwks = fetch_jwks(&app).await;
    let claims = verify(&jwks, &jwt, "demo").expect("verifies");
    assert_eq!(claims.iss, AUTH);
    assert_eq!(claims.sub, user.id.to_hex());
    assert_eq!(claims.email, "me@example.com");
    assert_eq!(claims.name.as_deref(), Some("Test User"));
    assert_eq!(
        claims.apps,
        BTreeMap::from([
            ("demo".to_string(), vec!["admin".to_string()]),
            (
                "other".to_string(),
                vec!["member".to_string(), "viewer".to_string()]
            ),
        ])
    );
    assert_eq!(
        claims.exp - claims.iat,
        900,
        "exp - iat == ACCESS_TOKEN_TTL"
    );
    assert!(!claims.jti.is_empty());
    assert!(verify(&jwks, &jwt, "recipes").is_err(), "slug not in apps");

    // Exactly the §5.3 claim set, nothing more.
    let payload = jwt.split('.').nth(1).unwrap();
    use base64::Engine;
    let raw: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    let mut keys: Vec<_> = raw.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["apps", "email", "exp", "iat", "iss", "jti", "name", "sub"]
    );

    // Every JWKS entry is a P-256 signing key with a kid.
    let raw_jwks: serde_json::Value =
        serde_json::from_str(&app.send(Req::get("/.well-known/jwks.json")).await.body).unwrap();
    for k in raw_jwks["keys"].as_array().unwrap() {
        assert_eq!(k["kty"], "EC");
        assert_eq!(k["crv"], "P-256");
        assert_eq!(k["alg"], "ES256");
        assert_eq!(k["use"], "sig");
        assert!(k["kid"].is_string());
        assert!(k.get("d").is_none(), "no private material");
    }
}

#[tokio::test]
async fn access_token_ttl_is_configurable() {
    let app = TestApp::with(|v| {
        v.insert("ACCESS_TOKEN_TTL".into(), "5m".into());
    })
    .await;
    app.user("me@example.com", &[("demo", &[])]).await;
    let res = app.login("me@example.com", PASSWORD, APP_ORIGIN).await;
    assert_eq!(
        res.cookie("ca_access").unwrap().attr("max-age"),
        Some("300")
    );
    let claims = verify(
        &fetch_jwks(&app).await,
        &res.cookie("ca_access").unwrap().value,
        "demo",
    )
    .unwrap();
    assert_eq!(claims.exp - claims.iat, 300);
}

fn sample_claims() -> AccessClaims {
    let now = chrono::Utc::now().timestamp();
    AccessClaims {
        iss: AUTH.into(),
        sub: "abc".into(),
        email: "me@example.com".into(),
        name: None,
        apps: BTreeMap::from([("demo".to_string(), vec![])]),
        iat: now,
        exp: now + 600,
        jti: "x".into(),
    }
}

#[tokio::test]
async fn retired_keys_verify_while_listed_and_unknown_keys_fail() {
    let old_pem = generate_private_pem();
    let old_keys = SigningKeys::from_pem(&old_pem, "").unwrap();
    let old_token = old_keys.sign(&sample_claims()).unwrap();

    // Rotated: new active key, old public key retired.
    let retired = public_pem_from_private(&old_pem).unwrap();
    let app = TestApp::with(|v| {
        v.insert("SIGNING_KEYS_RETIRED".into(), retired.clone());
    })
    .await;
    let jwks = fetch_jwks(&app).await;
    assert_eq!(jwks.keys.len(), 2);
    assert_eq!(
        jwks.keys[0].common.key_id.as_deref(),
        Some(app.state.keys.active_kid()),
        "active key first"
    );
    verify(&jwks, &old_token, "demo").expect("retired key still verifies");

    // New tokens are signed with the new key.
    app.user("me@example.com", &[("demo", &[])]).await;
    let new_jwt = app
        .login("me@example.com", PASSWORD, "")
        .await
        .cookie("ca_access")
        .unwrap()
        .value;
    assert_eq!(
        decode_header(&new_jwt).unwrap().kid.as_deref(),
        Some(app.state.keys.active_kid())
    );
    verify(&jwks, &new_jwt, "demo").unwrap();

    // Once the retired key is removed, old tokens stop verifying.
    let app2 = TestApp::new().await;
    let jwks2 = fetch_jwks(&app2).await;
    assert_eq!(jwks2.keys.len(), 1);
    assert_eq!(
        verify(&jwks2, &old_token, "demo").unwrap_err(),
        "unknown kid"
    );

    // A token from a key we never published fails.
    let stranger = SigningKeys::from_pem(&generate_private_pem(), "").unwrap();
    let forged = stranger.sign(&sample_claims()).unwrap();
    assert!(verify(&jwks, &forged, "demo").is_err());

    // Forged with a published kid but signed by another key: bad signature.
    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.kid = Some(app.state.keys.active_kid().to_string());
    let der = {
        use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
        p256::SecretKey::from_pkcs8_pem(&generate_private_pem())
            .unwrap()
            .to_pkcs8_der()
            .unwrap()
    };
    let lying = jsonwebtoken::encode(
        &header,
        &sample_claims(),
        &jsonwebtoken::EncodingKey::from_ec_der(der.as_bytes()),
    )
    .unwrap();
    assert!(verify(&jwks, &lying, "demo")
        .unwrap_err()
        .contains("InvalidSignature"));
}
