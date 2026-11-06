//! `clang-auth`: admin CLI for the clang-auth service (spec §8).
//!
//! It talks only to the admin HTTP API, never to MongoDB. Configuration, in
//! order of precedence: `--url`/`--key` flags, the `CLANG_AUTH_URL` /
//! `CLANG_AUTH_ADMIN_KEY` environment variables (a `.env` file in the current
//! directory is loaded too), then `~/.config/clang-auth/config.toml`:
//!
//! ```toml
//! url = "https://auth.example.com"
//! admin_key = "..."
//! ```

mod client;
mod output;

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};

use client::Client;

#[derive(Parser)]
#[command(
    name = "clang-auth",
    version,
    about = "Admin CLI for the clang-auth service"
)]
struct Cli {
    /// Print machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,
    /// Service base URL [env: CLANG_AUTH_URL]
    #[arg(long, global = true)]
    url: Option<String>,
    /// Admin API key [env: CLANG_AUTH_ADMIN_KEY]
    #[arg(long, global = true, hide_env_values = true)]
    key: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage apps (consumers of the auth service).
    #[command(subcommand)]
    App(AppCmd),
    /// Manage users.
    #[command(subcommand)]
    User(UserCmd),
    /// Manage a user's access to an app.
    #[command(subcommand)]
    Grant(GrantCmd),
    /// Manage login sessions.
    #[command(subcommand)]
    Session(SessionCmd),
    /// Mint access tokens for testing (server needs ALLOW_TOKEN_MINT=true).
    #[command(subcommand)]
    Token(TokenCmd),
}

#[derive(Subcommand)]
enum AppCmd {
    /// List apps.
    List,
    /// Register an app.
    Create {
        /// Slug: lowercase letters, digits and dashes (2-32 chars).
        slug: String,
        #[arg(long)]
        name: String,
        /// Allowed origin, e.g. https://recipes.example.com (repeatable).
        #[arg(long = "origin", required = true)]
        origins: Vec<String>,
    },
    /// Show one app.
    Show { slug: String },
    /// Rename an app or change its origins.
    Update {
        slug: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "add-origin")]
        add_origins: Vec<String>,
        #[arg(long = "remove-origin")]
        remove_origins: Vec<String>,
    },
    /// Delete an app and remove its grants from all users.
    Delete {
        slug: String,
        #[command(flatten)]
        confirm: Confirm,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// List users.
    List {
        /// Only users with a grant for this app.
        #[arg(long)]
        app: Option<String>,
    },
    /// Create a user and print their one-time setup link.
    Create {
        email: String,
        #[arg(long)]
        name: Option<String>,
        /// Grant access: `slug` or `slug:role,role` (repeatable).
        #[arg(long = "grant")]
        grants: Vec<String>,
    },
    /// Show a user, their grants and active session count.
    Show { user: String },
    /// Disable a user (revokes all their sessions).
    Disable { user: String },
    /// Re-enable a disabled user.
    Enable { user: String },
    /// Delete a user, their sessions and invites.
    Delete {
        user: String,
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Create a password-reset link (invalidates older links).
    Reset { user: String },
}

#[derive(Subcommand)]
enum GrantCmd {
    /// Create or replace a grant.
    Set {
        user: String,
        slug: String,
        /// Role (repeatable). No roles means plain access.
        #[arg(long = "role")]
        roles: Vec<String>,
    },
    /// Remove a grant.
    Remove { user: String, slug: String },
}

#[derive(Subcommand)]
enum SessionCmd {
    /// Revoke all of a user's sessions (signs them out everywhere).
    Revoke { user: String },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Print a signed access token for a user (dev only).
    Mint {
        user: String,
        /// Lifetime, e.g. 15m, 1h, 1d.
        #[arg(long)]
        ttl: Option<String>,
    },
}

#[derive(Args)]
struct Confirm {
    /// Don't ask for confirmation.
    #[arg(long, short = 'y')]
    yes: bool,
}

impl Confirm {
    fn check(&self, what: &str) -> Result<()> {
        if self.yes {
            return Ok(());
        }
        let stdin = std::io::stdin();
        if !stdin.is_terminal() {
            bail!("refusing to {what} without confirmation; pass --yes");
        }
        eprint!("{what}? This cannot be undone. [y/N] ");
        std::io::stderr().flush()?;
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            Ok(())
        } else {
            bail!("aborted")
        }
    }
}

/// Parse `--grant slug[:role,role]`.
fn parse_grant(s: &str) -> Result<(String, Vec<String>)> {
    let (slug, roles) = match s.split_once(':') {
        Some((slug, roles)) => (
            slug,
            roles
                .split(',')
                .map(str::trim)
                .filter(|r| !r.is_empty())
                .map(String::from)
                .collect(),
        ),
        None => (s, vec![]),
    };
    if slug.is_empty() {
        bail!("invalid --grant {s:?}: expected slug or slug:role,role");
    }
    Ok((slug.to_string(), roles))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    let client = Client::from_config(cli.url.clone(), cli.key.clone())?;
    let out = output::Output { json: cli.json };

    match cli.command {
        Command::App(cmd) => match cmd {
            AppCmd::List => out.apps(&client.get("/admin/apps").await?),
            AppCmd::Create {
                slug,
                name,
                origins,
            } => {
                let app = client
                    .post(
                        &["admin", "apps"],
                        json!({ "slug": slug, "name": name, "origins": origins }),
                    )
                    .await?;
                out.app(&app, "Created app")
            }
            AppCmd::Show { slug } => {
                out.app(&client.get_path(&["admin", "apps", &slug]).await?, "App")
            }
            AppCmd::Update {
                slug,
                name,
                add_origins,
                remove_origins,
            } => {
                let mut body = serde_json::Map::new();
                if let Some(n) = name {
                    body.insert("name".into(), json!(n));
                }
                if !add_origins.is_empty() || !remove_origins.is_empty() {
                    let current = client.get_path(&["admin", "apps", &slug]).await?;
                    let mut origins: Vec<String> =
                        serde_json::from_value(current["origins"].clone())?;
                    let norm = |s: &str| s.trim().trim_end_matches('/').to_ascii_lowercase();
                    origins.retain(|o| !remove_origins.iter().any(|r| norm(r) == norm(o)));
                    origins.extend(add_origins);
                    body.insert("origins".into(), json!(origins));
                }
                if body.is_empty() {
                    bail!("nothing to update; pass --name, --add-origin or --remove-origin");
                }
                let app = client
                    .patch(&["admin", "apps", &slug], Value::Object(body))
                    .await?;
                out.app(&app, "Updated app")
            }
            AppCmd::Delete { slug, confirm } => {
                confirm.check(&format!("Delete app {slug} and all its grants"))?;
                let res = client.delete(&["admin", "apps", &slug]).await?;
                out.done(
                    &res,
                    &format!(
                        "Deleted app {slug} ({} grants removed)",
                        res["grants_removed"]
                    ),
                )
            }
        },
        Command::User(cmd) => match cmd {
            UserCmd::List { app } => {
                let path = match app {
                    Some(a) => format!(
                        "/admin/users?app={}",
                        url::form_urlencoded::byte_serialize(a.as_bytes()).collect::<String>()
                    ),
                    None => "/admin/users".into(),
                };
                out.users(&client.get(&path).await?)
            }
            UserCmd::Create {
                email,
                name,
                grants,
            } => {
                let mut map = serde_json::Map::new();
                for g in &grants {
                    let (slug, roles) = parse_grant(g)?;
                    map.insert(slug, json!(roles));
                }
                let res = client
                    .post(
                        &["admin", "users"],
                        json!({ "email": email, "name": name, "grants": map }),
                    )
                    .await?;
                out.link(
                    &res,
                    "setup_link",
                    "Created user. Send them this one-time setup link",
                )
            }
            UserCmd::Show { user } => out.user(&client.get_path(&["admin", "users", &user]).await?),
            UserCmd::Disable { user } => {
                let u = client
                    .patch(&["admin", "users", &user], json!({ "status": "disabled" }))
                    .await?;
                out.done(
                    &u,
                    &format!(
                        "Disabled {} (all sessions revoked)",
                        u["email"].as_str().unwrap_or_default()
                    ),
                )
            }
            UserCmd::Enable { user } => {
                let u = client
                    .patch(&["admin", "users", &user], json!({ "status": "active" }))
                    .await?;
                out.done(
                    &u,
                    &format!("Enabled {}", u["email"].as_str().unwrap_or_default()),
                )
            }
            UserCmd::Delete { user, confirm } => {
                confirm.check(&format!("Delete user {user}"))?;
                let res = client.delete(&["admin", "users", &user]).await?;
                out.done(&res, &format!("Deleted user {user}"))
            }
            UserCmd::Reset { user } => {
                let res = client
                    .post(&["admin", "users", &user, "reset"], json!({}))
                    .await?;
                out.link(
                    &res,
                    "reset_link",
                    "Send them this one-time password-reset link",
                )
            }
        },
        Command::Grant(cmd) => match cmd {
            GrantCmd::Set { user, slug, roles } => {
                let u = client
                    .put(
                        &["admin", "users", &user, "grants", &slug],
                        json!({ "roles": roles }),
                    )
                    .await?;
                out.user(&u)
            }
            GrantCmd::Remove { user, slug } => {
                let u = client
                    .delete(&["admin", "users", &user, "grants", &slug])
                    .await?;
                out.user(&u)
            }
        },
        Command::Session(SessionCmd::Revoke { user }) => {
            let res = client
                .delete(&["admin", "users", &user, "sessions"])
                .await?;
            out.done(
                &res,
                &format!("Revoked {} session(s) for {user}", res["revoked"]),
            )
        }
        Command::Token(TokenCmd::Mint { user, ttl }) => {
            let key = if user.contains('@') {
                "email"
            } else {
                "user_id"
            };
            let mut body = json!({ key: user });
            if let Some(t) = ttl {
                body["ttl"] = json!(t);
            }
            let res = client.post(&["admin", "tokens"], body).await.map_err(|e| {
                if e.to_string().contains("404") {
                    anyhow::anyhow!(
                        "token minting is disabled on the server (set ALLOW_TOKEN_MINT=true)"
                    )
                } else {
                    e
                }
            })?;
            out.token(&res)
        }
    }
    .context("command failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_parse() {
        assert_eq!(parse_grant("demo").unwrap(), ("demo".into(), vec![]));
        assert_eq!(
            parse_grant("demo:admin,member").unwrap(),
            ("demo".into(), vec!["admin".into(), "member".into()])
        );
        assert!(parse_grant(":admin").is_err());
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
