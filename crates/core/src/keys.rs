//! ES256 signing keys, access-token issuing, and the JWKS document.
//!
//! The auth service holds one *active* private key and signs every access
//! token with it. Apps never see the private key: they fetch the matching
//! public key from `/.well-known/jwks.json` and verify signatures locally.
//! Old public keys listed in `SIGNING_KEYS_RETIRED` stay in the JWKS so tokens
//! signed before a rotation keep verifying until they expire.

use std::collections::BTreeMap;
use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::{
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    PublicKey, SecretKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// The claims inside every access token (spec §5.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessClaims {
    pub iss: String,
    pub sub: String,
    pub email: String,
    pub name: Option<String>,
    /// App slug → roles. Only apps the user has a grant for appear here.
    pub apps: BTreeMap<String, Vec<String>>,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

/// A public key as published in JWKS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
}

impl Jwk {
    fn from_public(pk: &PublicKey) -> Self {
        let point = pk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y"));
        // RFC 7638 JWK thumbprint: SHA-256 over the required members in
        // lexicographic order, no whitespace. Stable across restarts and
        // unique per key, which is exactly what a `kid` needs.
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        Self {
            kty: "EC".into(),
            crv: "P-256".into(),
            x,
            y,
            kid,
            use_: "sig".into(),
            alg: "ES256".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// The active signing key plus retired public keys.
#[derive(Clone)]
pub struct SigningKeys {
    encoding: EncodingKey,
    active: Jwk,
    retired: Vec<Jwk>,
}

impl std::fmt::Debug for SigningKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("SigningKeys")
            .field("active_kid", &self.active.kid)
            .field(
                "retired",
                &self.retired.iter().map(|k| &k.kid).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Normalise PEM text that came through an environment variable, where
/// newlines are sometimes written as a literal `\n`.
fn unescape_pem(pem: &str) -> String {
    pem.replace("\\n", "\n").trim().to_string()
}

/// Generate a new P-256 private key as PKCS#8 PEM.
pub fn generate_private_pem() -> String {
    let sk = SecretKey::random(&mut rand::rngs::OsRng);
    sk.to_pkcs8_pem(LineEnding::LF)
        .expect("encode pkcs8")
        .to_string()
}

/// Derive the SPKI public-key PEM from a private-key PEM.
pub fn public_pem_from_private(private_pem: &str) -> Result<String> {
    let sk = parse_private(private_pem)?;
    sk.public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| Error::Key(format!("encode public key: {e}")))
}

fn parse_private(pem: &str) -> Result<SecretKey> {
    let pem = unescape_pem(pem);
    // Accept PKCS#8 ("BEGIN PRIVATE KEY") and SEC1 ("BEGIN EC PRIVATE KEY",
    // which is what `openssl ecparam -genkey` prints).
    SecretKey::from_pkcs8_pem(&pem)
        .or_else(|_| SecretKey::from_sec1_pem(&pem))
        .map_err(|_| {
            Error::Key("SIGNING_KEY is not a valid P-256 private key (PKCS#8 or SEC1 PEM)".into())
        })
}

/// Parse zero or more concatenated SPKI public-key PEM blocks.
pub fn parse_public_keys(pems: &str) -> Result<Vec<Jwk>> {
    let text = unescape_pem(pems);
    const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
    let mut out = Vec::new();
    for chunk in text.split(BEGIN).map(str::trim).filter(|c| !c.is_empty()) {
        let block = format!("{BEGIN}\n{chunk}");
        let pk = PublicKey::from_public_key_pem(&block).map_err(|_| {
            Error::Key("SIGNING_KEYS_RETIRED contains an invalid P-256 public key PEM".into())
        })?;
        out.push(Jwk::from_public(&pk));
    }
    Ok(out)
}

impl SigningKeys {
    /// Build from a private-key PEM and (possibly empty) retired public keys.
    pub fn from_pem(private_pem: &str, retired_public_pems: &str) -> Result<Self> {
        let sk = parse_private(private_pem)?;
        let der = sk
            .to_pkcs8_der()
            .map_err(|e| Error::Key(format!("encode pkcs8: {e}")))?;
        let encoding = EncodingKey::from_ec_der(der.as_bytes());
        let active = Jwk::from_public(&sk.public_key());
        let retired = parse_public_keys(retired_public_pems)?
            .into_iter()
            .filter(|k| k.kid != active.kid)
            .collect();
        Ok(Self {
            encoding,
            active,
            retired,
        })
    }

    /// Load the key at `path`, generating and saving a new one if the file
    /// does not exist. For local development only.
    pub fn load_or_generate(path: &Path, retired_public_pems: &str) -> Result<Self> {
        let pem = match std::fs::read_to_string(path) {
            Ok(pem) => pem,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let pem = generate_private_pem();
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)
                        .map_err(|e| Error::Key(format!("create {}: {e}", dir.display())))?;
                }
                write_private(path, &pem)?;
                tracing::info!(event = "signing_key_generated", path = %path.display(), "generated dev signing key");
                pem
            }
            Err(e) => return Err(Error::Key(format!("read {}: {e}", path.display()))),
        };
        Self::from_pem(&pem, retired_public_pems)
    }

    pub fn active_kid(&self) -> &str {
        &self.active.kid
    }

    /// The JWKS document: active key first, then retired keys.
    pub fn jwks(&self) -> JwkSet {
        let mut keys = vec![self.active.clone()];
        keys.extend(self.retired.iter().cloned());
        JwkSet { keys }
    }

    /// Sign claims as a compact JWS with `alg=ES256` and the active `kid`.
    pub fn sign(&self, claims: &AccessClaims) -> Result<String> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.active.kid.clone());
        Ok(jsonwebtoken::encode(&header, claims, &self.encoding)?)
    }
}

fn write_private(path: &Path, pem: &str) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| Error::Key(format!("write {}: {e}", path.display())))?;
    f.write_all(pem.as_bytes())
        .map_err(|e| Error::Key(format!("write {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation};

    fn claims() -> AccessClaims {
        AccessClaims {
            iss: "https://auth.example.com".into(),
            sub: "u1".into(),
            email: "me@example.com".into(),
            name: None,
            apps: BTreeMap::from([("recipes".into(), vec!["admin".into()])]),
            iat: 1_730_000_000,
            exp: 4_000_000_000,
            jti: "j".into(),
        }
    }

    fn decoding_key(jwk: &Jwk) -> DecodingKey {
        DecodingKey::from_ec_components(&jwk.x, &jwk.y).unwrap()
    }

    #[test]
    fn sign_and_verify_with_jwks() {
        let keys = SigningKeys::from_pem(&generate_private_pem(), "").unwrap();
        let token = keys.sign(&claims()).unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some(keys.active_kid()));
        assert_eq!(header.alg, Algorithm::ES256);

        let jwks = keys.jwks();
        let jwk = jwks
            .keys
            .iter()
            .find(|k| Some(&k.kid) == header.kid.as_ref())
            .unwrap();
        let mut v = Validation::new(Algorithm::ES256);
        v.set_issuer(&["https://auth.example.com"]);
        let data = jsonwebtoken::decode::<AccessClaims>(&token, &decoding_key(jwk), &v).unwrap();
        assert_eq!(data.claims, claims());
    }

    #[test]
    fn kid_is_stable_and_retired_keys_published() {
        let old = generate_private_pem();
        let new = generate_private_pem();
        let old_keys = SigningKeys::from_pem(&old, "").unwrap();
        let again = SigningKeys::from_pem(&old, "").unwrap();
        assert_eq!(old_keys.active_kid(), again.active_kid());

        let retired = public_pem_from_private(&old).unwrap();
        let rotated = SigningKeys::from_pem(&new, &retired).unwrap();
        let kids: Vec<_> = rotated.jwks().keys.into_iter().map(|k| k.kid).collect();
        assert_eq!(
            kids,
            vec![
                rotated.active_kid().to_string(),
                old_keys.active_kid().to_string()
            ]
        );
    }

    #[test]
    fn accepts_escaped_newlines_and_multiple_retired() {
        let a = public_pem_from_private(&generate_private_pem()).unwrap();
        let b = public_pem_from_private(&generate_private_pem()).unwrap();
        let joined = format!("{a}{b}").replace('\n', "\\n");
        assert_eq!(parse_public_keys(&joined).unwrap().len(), 2);
        assert!(parse_public_keys("").unwrap().is_empty());
        assert!(
            parse_public_keys("-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----")
                .is_err()
        );
    }

    #[test]
    fn debug_hides_key_material() {
        let pem = generate_private_pem();
        let keys = SigningKeys::from_pem(&pem, "").unwrap();
        let dbg = format!("{keys:?}");
        assert!(!dbg.contains("PRIVATE"));
    }
}
