//! §15: full CRUD for apps, users and grants through the CLI binary against a
//! running local service (real HTTP, real MongoDB).

use std::{collections::HashMap, net::SocketAddr, process::Command, sync::mpsc};

use clang_auth_core::{keys::generate_private_pem, secret::sha256_hex};
use clang_auth_service::{config::Config, router, state::AppState};
use serde_json::Value;

const KEY: &str = "cli-e2e-admin-key";

struct Server {
    url: String,
    db: String,
}

/// Start the real service on a random port in a background thread.
fn start_server(mint: bool) -> Server {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let db = format!("clang_auth_cli_test_{}_{n}", std::process::id());
    let (tx, rx) = mpsc::channel();
    let db2 = db.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let base = format!("http://auth.localtest.me:{port}");
            let vars: HashMap<String, String> = [
                ("AUTH_BASE_URL", base.as_str()),
                ("COOKIE_DOMAIN", ".localtest.me"),
                ("COOKIE_SECURE", "false"),
                ("ALLOW_INSECURE_ORIGINS", "true"),
                ("ALLOW_TOKEN_MINT", if mint { "true" } else { "false" }),
                (
                    "MONGODB_URI",
                    &std::env::var("MONGODB_URI")
                        .unwrap_or_else(|_| "mongodb://localhost:27017".into()),
                ),
                ("MONGODB_DB", &db2),
                ("ADMIN_API_KEY_HASH", &sha256_hex(KEY)),
                ("SIGNING_KEY", &generate_private_pem()),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
            let state = AppState::from_config(Config::from_map(&vars, false).unwrap())
                .await
                .unwrap();
            state.store.database().drop().await.unwrap();
            state.store.ensure_indexes().await.unwrap();
            tx.send(format!("http://127.0.0.1:{port}")).unwrap();
            axum::serve(
                listener,
                router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
    });
    Server {
        url: rx.recv().unwrap(),
        db,
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let db = self.db.clone();
        let _ = std::thread::spawn(move || {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let uri = std::env::var("MONGODB_URI")
                    .unwrap_or_else(|_| "mongodb://localhost:27017".into());
                if let Ok(c) = mongodb::Client::with_uri_str(uri).await {
                    let _ = c.database(&db).drop().await;
                }
            })
        })
        .join();
    }
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("bad JSON ({e}): {}\n{}", self.stdout, self.stderr))
    }
}

fn cli(server: &Server, args: &[&str]) -> Out {
    let out = Command::new(env!("CARGO_BIN_EXE_clang-auth"))
        .args(args)
        .env("CLANG_AUTH_URL", &server.url)
        .env("CLANG_AUTH_ADMIN_KEY", KEY)
        .env("CLANG_AUTH_CONFIG", "/nonexistent/config.toml")
        .current_dir(std::env::temp_dir()) // don't pick up the repo's .env
        .output()
        .expect("run clang-auth");
    Out {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into(),
        stderr: String::from_utf8_lossy(&out.stderr).into(),
    }
}

fn ok(server: &Server, args: &[&str]) -> Out {
    let o = cli(server, args);
    assert!(
        o.ok,
        "clang-auth {args:?} failed:\n{}\n{}",
        o.stdout, o.stderr
    );
    o
}

#[test]
fn full_crud_through_the_cli() {
    let s = start_server(true);

    // ---- apps
    let o = ok(
        &s,
        &[
            "app",
            "create",
            "recipes",
            "--name",
            "Recipes",
            "--origin",
            "http://recipes.localtest.me:5000",
        ],
    );
    assert!(o.stdout.contains("Created app: recipes"));
    ok(
        &s,
        &[
            "app",
            "create",
            "budget",
            "--name",
            "Budget",
            "--origin",
            "http://budget.localtest.me:5001",
        ],
    );
    let o = ok(&s, &["app", "list"]);
    assert!(
        o.stdout.contains("recipes")
            && o.stdout.contains("budget")
            && o.stdout.contains("http://recipes.localtest.me:5000")
    );
    let apps = ok(&s, &["--json", "app", "list"]).json();
    assert_eq!(apps.as_array().unwrap().len(), 2);

    ok(
        &s,
        &[
            "app",
            "update",
            "recipes",
            "--name",
            "Recipe Box",
            "--add-origin",
            "http://recipes2.localtest.me:5000",
        ],
    );
    let a = ok(&s, &["--json", "app", "show", "recipes"]).json();
    assert_eq!(a["name"], "Recipe Box");
    assert_eq!(a["origins"].as_array().unwrap().len(), 2);
    ok(
        &s,
        &[
            "app",
            "update",
            "recipes",
            "--remove-origin",
            "http://recipes.localtest.me:5000/",
        ],
    );
    let a = ok(&s, &["--json", "app", "show", "recipes"]).json();
    assert_eq!(
        a["origins"],
        serde_json::json!(["http://recipes2.localtest.me:5000"])
    );

    let dup = cli(
        &s,
        &[
            "app",
            "create",
            "recipes",
            "--name",
            "X",
            "--origin",
            "http://x.localtest.me",
        ],
    );
    assert!(!dup.ok && dup.stderr.contains("409"), "{}", dup.stderr);

    // ---- users
    let o = ok(
        &s,
        &[
            "user",
            "create",
            "ann@example.com",
            "--name",
            "Ann",
            "--grant",
            "recipes:admin,member",
            "--grant",
            "budget",
        ],
    );
    assert!(
        o.stdout.contains("/setup?token="),
        "prints setup link: {}",
        o.stdout
    );
    let created = ok(&s, &["--json", "user", "create", "bob@example.com"]).json();
    assert!(created["setup_link"]
        .as_str()
        .unwrap()
        .contains("/setup?token="));
    let bob_id = created["user"]["id"].as_str().unwrap().to_string();

    let o = ok(&s, &["user", "list"]);
    assert!(o.stdout.contains("ann@example.com") && o.stdout.contains("bob@example.com"));
    let filtered = ok(&s, &["--json", "user", "list", "--app", "recipes"]).json();
    assert_eq!(filtered.as_array().unwrap().len(), 1);

    let o = ok(&s, &["user", "show", "ann@example.com"]);
    assert!(o.stdout.contains("recipes → admin, member"), "{}", o.stdout);
    assert!(o.stdout.contains("sessions: 0 active"));
    let by_id = ok(&s, &["--json", "user", "show", &bob_id]).json();
    assert_eq!(by_id["email"], "bob@example.com");

    ok(&s, &["user", "disable", "bob@example.com"]);
    assert_eq!(
        ok(&s, &["--json", "user", "show", &bob_id]).json()["status"],
        "disabled"
    );
    ok(&s, &["user", "enable", &bob_id]);
    assert_eq!(
        ok(&s, &["--json", "user", "show", &bob_id]).json()["status"],
        "active"
    );

    let o = ok(&s, &["user", "reset", "ann@example.com"]);
    assert!(o.stdout.contains("/setup?token="));

    // ---- grants
    let u = ok(
        &s,
        &[
            "--json",
            "grant",
            "set",
            "bob@example.com",
            "recipes",
            "--role",
            "viewer",
        ],
    )
    .json();
    assert_eq!(u["grants"][0]["roles"], serde_json::json!(["viewer"]));
    let u = ok(
        &s,
        &["--json", "grant", "set", "bob@example.com", "recipes"],
    )
    .json();
    assert_eq!(u["grants"][0]["roles"], serde_json::json!([]));
    let u = ok(
        &s,
        &["--json", "grant", "remove", "bob@example.com", "recipes"],
    )
    .json();
    assert_eq!(u["grants"], serde_json::json!([]));
    let missing = cli(&s, &["grant", "set", "bob@example.com", "nope"]);
    assert!(!missing.ok && missing.stderr.contains("404"));

    // ---- sessions + tokens
    let o = ok(&s, &["session", "revoke", "ann@example.com"]);
    assert!(o.stdout.contains("Revoked 0 session(s)"));
    let token = ok(&s, &["token", "mint", "ann@example.com", "--ttl", "1h"])
        .stdout
        .trim()
        .to_string();
    assert_eq!(token.split('.').count(), 3);
    let minted = ok(&s, &["--json", "token", "mint", "ann@example.com"]).json();
    assert_eq!(
        minted["claims"]["apps"]["recipes"],
        serde_json::json!(["admin", "member"])
    );

    // ---- deletes need --yes when not interactive
    let refused = cli(&s, &["user", "delete", "bob@example.com"]);
    assert!(!refused.ok && refused.stderr.contains("--yes"));
    ok(&s, &["user", "delete", "bob@example.com", "--yes"]);
    assert!(!cli(&s, &["user", "show", "bob@example.com"]).ok);

    let refused = cli(&s, &["app", "delete", "recipes"]);
    assert!(!refused.ok);
    let o = ok(&s, &["app", "delete", "recipes", "--yes"]);
    assert!(o.stdout.contains("1 grants removed"), "{}", o.stdout);
    let ann = ok(&s, &["--json", "user", "show", "ann@example.com"]).json();
    let apps: Vec<&str> = ann["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["app"].as_str().unwrap())
        .collect();
    assert_eq!(apps, ["budget"]);
    ok(&s, &["user", "delete", "ann@example.com", "-y"]);
    assert_eq!(
        ok(&s, &["--json", "user", "list"]).json(),
        serde_json::json!([])
    );
}

#[test]
fn cli_reports_auth_and_mint_errors() {
    let s = start_server(false);
    let out = Command::new(env!("CARGO_BIN_EXE_clang-auth"))
        .args(["app", "list"])
        .env("CLANG_AUTH_URL", &s.url)
        .env("CLANG_AUTH_ADMIN_KEY", "wrong")
        .env("CLANG_AUTH_CONFIG", "/nonexistent/config.toml")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("401"));

    ok(&s, &["user", "create", "c@example.com"]);
    let mint = cli(&s, &["token", "mint", "c@example.com"]);
    assert!(
        !mint.ok && mint.stderr.contains("ALLOW_TOKEN_MINT"),
        "{}",
        mint.stderr
    );
}

#[test]
fn cli_reads_config_file() {
    let s = start_server(false);
    let dir = std::env::temp_dir().join(format!("clang-auth-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        format!("url = \"{}\"\nadmin_key = \"{KEY}\"\n", s.url),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_clang-auth"))
        .args(["--json", "app", "list"])
        .env_remove("CLANG_AUTH_URL")
        .env_remove("CLANG_AUTH_ADMIN_KEY")
        .env("CLANG_AUTH_CONFIG", &cfg)
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "[]");
    let _ = std::fs::remove_dir_all(dir);
}
