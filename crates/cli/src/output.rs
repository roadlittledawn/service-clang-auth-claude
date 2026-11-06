//! Human-readable and `--json` output.

use anyhow::Result;
use serde_json::Value;

pub struct Output {
    pub json: bool,
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("-")
}

fn roles(v: &Value) -> String {
    let r: Vec<&str> = v
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if r.is_empty() {
        "(no roles)".into()
    } else {
        r.join(", ")
    }
}

fn grants_summary(u: &Value) -> String {
    let g: Vec<String> = u["grants"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|g| {
                    format!(
                        "{}[{}]",
                        s(&g["app"]),
                        roles(&g["roles"]).replace("(no roles)", "")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if g.is_empty() {
        "-".into()
    } else {
        g.join(" ")
    }
}

impl Output {
    fn print_json(&self, v: &Value) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(v)?);
        Ok(())
    }

    pub fn apps(&self, v: &Value) -> Result<()> {
        if self.json {
            return self.print_json(v);
        }
        let apps = v.as_array().cloned().unwrap_or_default();
        if apps.is_empty() {
            println!("No apps.");
            return Ok(());
        }
        println!("{:<20} {:<24} ORIGINS", "SLUG", "NAME");
        for a in apps {
            let origins: Vec<&str> = a["origins"]
                .as_array()
                .map(|o| o.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            println!(
                "{:<20} {:<24} {}",
                s(&a["slug"]),
                s(&a["name"]),
                origins.join(", ")
            );
        }
        Ok(())
    }

    pub fn app(&self, a: &Value, heading: &str) -> Result<()> {
        if self.json {
            return self.print_json(a);
        }
        println!("{heading}: {}", s(&a["slug"]));
        println!("  name:    {}", s(&a["name"]));
        for o in a["origins"].as_array().into_iter().flatten() {
            println!("  origin:  {}", s(o));
        }
        Ok(())
    }

    pub fn users(&self, v: &Value) -> Result<()> {
        if self.json {
            return self.print_json(v);
        }
        let users = v.as_array().cloned().unwrap_or_default();
        if users.is_empty() {
            println!("No users.");
            return Ok(());
        }
        println!("{:<26} {:<30} {:<9} GRANTS", "ID", "EMAIL", "STATUS");
        for u in users {
            let status = if u["has_password"] == false {
                "invited"
            } else {
                s(&u["status"])
            };
            println!(
                "{:<26} {:<30} {:<9} {}",
                s(&u["id"]),
                s(&u["email"]),
                status,
                grants_summary(&u)
            );
        }
        Ok(())
    }

    pub fn user(&self, u: &Value) -> Result<()> {
        if self.json {
            return self.print_json(u);
        }
        println!("{} ({})", s(&u["email"]), s(&u["id"]));
        println!("  name:     {}", s(&u["name"]));
        println!("  status:   {}", s(&u["status"]));
        println!(
            "  password: {}",
            if u["has_password"] == true {
                "set"
            } else {
                "not set (setup pending)"
            }
        );
        if let Some(n) = u["active_sessions"].as_u64() {
            println!("  sessions: {n} active");
        }
        let grants = u["grants"].as_array().cloned().unwrap_or_default();
        if grants.is_empty() {
            println!("  grants:   none");
        }
        for g in grants {
            println!("  grant:    {} → {}", s(&g["app"]), roles(&g["roles"]));
        }
        Ok(())
    }

    pub fn link(&self, v: &Value, field: &str, msg: &str) -> Result<()> {
        if self.json {
            return self.print_json(v);
        }
        if let Some(u) = v.get("user") {
            println!("{} ({})", s(&u["email"]), s(&u["id"]));
        }
        println!("{msg} (expires {}):", s(&v["expires_at"]));
        println!("{}", s(&v[field]));
        Ok(())
    }

    pub fn token(&self, v: &Value) -> Result<()> {
        if self.json {
            return self.print_json(v);
        }
        // Just the token, so `$(clang-auth token mint ...)` works.
        println!("{}", s(&v["token"]));
        Ok(())
    }

    pub fn done(&self, v: &Value, msg: &str) -> Result<()> {
        if self.json {
            return self.print_json(v);
        }
        println!("{msg}");
        Ok(())
    }
}
