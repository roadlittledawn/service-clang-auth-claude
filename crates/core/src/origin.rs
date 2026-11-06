//! Origin normalisation and `redirect_uri` validation (spec §4.2).
//!
//! An *origin* is `scheme://host[:port]`. Browsers enforce security
//! boundaries by origin, so we compare redirect targets and CORS requests
//! against registered app origins by exact origin equality, never by
//! substring or suffix (which is how `example.com.evil.com` style attacks
//! sneak through).

use url::Url;

use crate::{Error, Result};

fn check_scheme(url: &Url, allow_insecure: bool) -> Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_insecure => Ok(()),
        "http" => Err(Error::Invalid(
            "http:// origins are only allowed when ALLOW_INSECURE_ORIGINS=true".into(),
        )),
        other => Err(Error::Invalid(format!("unsupported scheme {other:?}"))),
    }
}

/// Normalise an origin given by an admin (e.g. `https://Recipes.Example.com/`)
/// into its canonical serialisation (`https://recipes.example.com`).
///
/// Paths other than `/`, queries, fragments and credentials are rejected so
/// that registered origins are unambiguous.
pub fn normalize_origin(input: &str, allow_insecure: bool) -> Result<String> {
    let url = Url::parse(input.trim())
        .map_err(|e| Error::Invalid(format!("invalid origin {input:?}: {e}")))?;
    check_scheme(&url, allow_insecure)?;
    if url.host_str().is_none_or(str::is_empty) {
        return Err(Error::Invalid(format!("origin {input:?} has no host")));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Invalid(format!(
            "origin {input:?} must not contain credentials"
        )));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(Error::Invalid(format!(
            "origin {input:?} must not have a path, query or fragment"
        )));
    }
    Ok(url.origin().ascii_serialization())
}

/// A redirect target that has been parsed and whose origin is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectTarget {
    /// Canonical re-serialisation of the URL. We redirect to this, never to
    /// the raw user input.
    pub url: String,
    /// The URL's origin, to be matched against registered app origins.
    pub origin: String,
}

/// Parse a `redirect_uri`. Returns `None` for anything that is not an absolute
/// http(s) URL with a host: relative paths, scheme-relative `//evil.com`,
/// `javascript:`/`data:` URLs, URLs with embedded credentials, and so on.
///
/// The caller must still check that `origin` is registered to an app.
pub fn parse_redirect(input: &str, allow_insecure: bool) -> Option<RedirectTarget> {
    // Reject anything with control characters or surrounding whitespace
    // outright, rather than relying on the URL parser stripping them.
    if input.is_empty()
        || input.len() > 2048
        || input.trim() != input
        || input.chars().any(char::is_control)
    {
        return None;
    }
    let url = Url::parse(input).ok()?;
    check_scheme(&url, allow_insecure).ok()?;
    url.host_str().filter(|h| !h.is_empty())?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    Some(RedirectTarget {
        origin: url.origin().ascii_serialization(),
        url: url.to_string(),
    })
}

/// Extract the origin from a header value such as `Origin` or `Referer`.
pub fn origin_of(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    match url.scheme() {
        "http" | "https" => {}
        _ => return None,
    }
    url.host_str()?;
    Some(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_origins() {
        assert_eq!(
            normalize_origin("https://Recipes.Example.com/", false).unwrap(),
            "https://recipes.example.com"
        );
        assert_eq!(
            normalize_origin("https://a.example.com:443", false).unwrap(),
            "https://a.example.com"
        );
        assert_eq!(
            normalize_origin("https://a.example.com:8443", false).unwrap(),
            "https://a.example.com:8443"
        );
        assert_eq!(
            normalize_origin("http://demo.localtest.me:3000", true).unwrap(),
            "http://demo.localtest.me:3000"
        );
    }

    #[test]
    fn rejects_bad_origins() {
        assert!(normalize_origin("http://demo.localtest.me:3000", false).is_err());
        assert!(normalize_origin("https://a.example.com/path", false).is_err());
        assert!(normalize_origin("https://a.example.com/?q=1", false).is_err());
        assert!(normalize_origin("https://user:pw@a.example.com", false).is_err());
        assert!(normalize_origin("ftp://a.example.com", false).is_err());
        assert!(normalize_origin("a.example.com", false).is_err());
        assert!(normalize_origin("javascript:alert(1)", false).is_err());
    }

    #[test]
    fn parses_redirects() {
        let t = parse_redirect("https://recipes.example.com/dash?x=1#y", false).unwrap();
        assert_eq!(t.origin, "https://recipes.example.com");
        assert_eq!(t.url, "https://recipes.example.com/dash?x=1#y");

        let t = parse_redirect("https://recipes.example.com.evil.com/", false).unwrap();
        assert_eq!(t.origin, "https://recipes.example.com.evil.com");
    }

    #[test]
    fn rejects_dangerous_redirects() {
        for bad in [
            "",
            "/relative",
            "//evil.com",
            "//evil.com/path",
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "data:text/html,hi",
            "https://good.example.com@evil.com/",
            " https://recipes.example.com/",
            "https://recipes.example.com/\n",
            "http://insecure.example.com/",
        ] {
            assert!(
                parse_redirect(bad, false).is_none(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn origin_header_parsing() {
        assert_eq!(
            origin_of("https://a.example.com").as_deref(),
            Some("https://a.example.com")
        );
        assert_eq!(
            origin_of("https://a.example.com/page?x").as_deref(),
            Some("https://a.example.com")
        );
        assert_eq!(origin_of("null"), None);
    }
}
