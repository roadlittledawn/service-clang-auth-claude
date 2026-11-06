//! §15 "Documentation": every §12 file exists, how-it-works.md has the six
//! required sections, and each listed flow has a Mermaid sequence diagram.

fn read(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("{rel} must exist"))
}

#[test]
fn all_section_12_files_exist() {
    for f in [
        "README.md",
        "docs/how-it-works.md",
        "docs/integration-guide.md",
        "docs/operations.md",
        "docs/cli.md",
        "DECISIONS.md",
    ] {
        assert!(read(f).len() > 500, "{f} looks empty");
    }
}

#[test]
fn how_it_works_has_required_sections_and_diagrams() {
    let doc = read("docs/how-it-works.md");
    for h in [
        "## 1. Concepts glossary",
        "## 2. Architecture overview",
        "## 3. Flow walkthroughs",
        "## 4. Security decisions and threat model",
        "## 5. Known limitations",
        "## 6. Code map",
    ] {
        assert!(doc.contains(h), "missing section {h:?}");
    }
    for term in [
        "Authentication vs. authorization",
        "Session",
        "JWT",
        "Signing vs. encryption",
        "JWKS",
        "Public/private keys",
        "HttpOnly",
        "Secure",
        "SameSite",
        "Domain",
        "CORS",
        "CSRF",
        "Open redirect",
        "Password hashing vs. encryption",
        "Argon2id",
        "Rate limiting",
        "Token revocation",
    ] {
        let glossary = &doc[doc.find("## 1.").unwrap()..doc.find("## 2.").unwrap()];
        assert!(
            glossary.contains(&format!("**{term}")) || glossary.contains(&format!("**`{term}")),
            "glossary missing {term}"
        );
    }
    // The architecture diagram plus one sequence diagram per flow.
    assert!(
        doc.contains("```mermaid\nflowchart"),
        "architecture diagram"
    );
    let flows = [
        "First login",
        "Login when already signed in to another app",
        "Access-token refresh",
        "Logout",
        "Invite and first-time setup",
        "Password reset",
        "An admin granting access",
    ];
    let sections: Vec<&str> = doc.split("\n### ").collect();
    for flow in flows {
        let section = sections
            .iter()
            .find(|s| s.split_once('\n').is_some_and(|(h, _)| h.contains(flow)))
            .unwrap_or_else(|| panic!("no section for {flow}"));
        assert!(
            section.contains("```mermaid\nsequenceDiagram"),
            "{flow} needs a Mermaid sequence diagram"
        );
    }
    // Refresh covers both navigation and XHR.
    let refresh = sections.iter().find(|s| s.starts_with("3.3")).unwrap();
    assert!(refresh.contains("navigation") && refresh.contains("XHR"));
}

#[test]
fn integration_guide_covers_troubleshooting() {
    let g = read("docs/integration-guide.md");
    for t in [
        "cookie isn't sent",
        "CORS errors",
        "clock skew",
        "localtest.me",
    ] {
        assert!(g.contains(t), "troubleshooting missing {t}");
    }
}

#[test]
fn operations_covers_required_topics() {
    let o = read("docs/operations.md");
    for t in [
        "AWS Budget",
        "Cost Anomaly Detection",
        "Kill switch",
        "Rotating the signing key",
        "Rotating the admin API key",
        "If a credential leaks",
        "Atlas",
        "put-parameter",
        "sam deploy",
    ] {
        assert!(o.contains(t), "operations.md missing {t}");
    }
    for budget in ["Threshold\\\":5", "Threshold\\\":10", "Threshold\\\":20"] {
        assert!(o.contains(budget), "budget alert {budget}");
    }
}
