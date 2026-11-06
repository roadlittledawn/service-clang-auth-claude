//! §15: no secrets in the repo. Scans every file git would commit (tracked
//! plus untracked-but-not-ignored) for private keys, credentials and
//! files that must never be committed.

use std::process::Command;

fn repo_files() -> (std::path::PathBuf, Vec<String>) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let out = Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .current_dir(&root)
        .output()
        .expect("git available");
    assert!(out.status.success());
    let files = String::from_utf8(out.stdout)
        .unwrap()
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    (root, files)
}

#[test]
fn no_secrets_committed() {
    let (root, files) = repo_files();
    assert!(
        files.iter().any(|f| f == "SPEC.md"),
        "sanity: scanning the right repo"
    );
    let patterns: &[(&str, &str)] = &[
        ("-----BEGIN PRIVATE KEY-----", "PKCS#8 private key"),
        ("-----BEGIN EC PRIVATE KEY-----", "SEC1 private key"),
        ("-----BEGIN RSA PRIVATE KEY-----", "RSA private key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "SSH private key"),
        ("aws_secret_access_key", "AWS secret key"),
    ];
    for f in &files {
        // This file necessarily contains the patterns it looks for.
        if f.ends_with("repo_hygiene.rs") || f.contains("node_modules/") {
            continue;
        }
        let name = f.rsplit('/').next().unwrap();
        assert!(
            name != ".env" && !name.ends_with(".pem"),
            "{f} must not be committed"
        );
        assert!(
            !f.starts_with(".dev-keys/") && !f.starts_with(".aws-sam/"),
            "{f} must not be committed"
        );
        let Ok(text) = std::fs::read_to_string(root.join(f)) else {
            continue;
        };
        for (pat, what) in patterns {
            assert!(!text.contains(pat), "{f} contains a {what}");
        }
        // AWS access key IDs.
        for (i, _) in text.match_indices("AKIA") {
            let id = &text[i..text.len().min(i + 20)];
            assert!(
                !(id.len() == 20
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())),
                "{f} contains an AWS access key id"
            );
        }
        // MongoDB URIs with embedded passwords (user:pass@). Placeholders OK.
        for (i, _) in text.match_indices("mongodb+srv://") {
            let rest: String = text[i + 14..]
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '`')
                .collect();
            if let Some((cred, _)) = rest.split_once('@') {
                let pw = cred.split_once(':').map(|(_, p)| p).unwrap_or("");
                assert!(
                    pw.is_empty()
                        || pw.starts_with('<')
                        || pw.contains("PASSWORD")
                        || pw.contains("REPLACE"),
                    "{f} has a MongoDB password: {cred}"
                );
            }
        }
    }
}

#[test]
fn gitignore_covers_local_secrets() {
    let (root, _) = repo_files();
    let gi = std::fs::read_to_string(root.join(".gitignore")).unwrap();
    for entry in [".env", ".dev-keys/", ".aws-sam/"] {
        assert!(
            gi.lines().any(|l| l.trim() == entry),
            ".gitignore must list {entry}"
        );
    }
}
