//! MongoDB document shapes (spec §7).

use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub type Timestamp = DateTime<Utc>;

/// Serialise chrono timestamps as BSON dates so TTL indexes work.
pub mod bson_dt {
    pub use bson::serde_helpers::chrono_datetime_as_bson_datetime as required;

    pub mod optional {
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(
            v: &Option<DateTime<Utc>>,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            v.map(bson::DateTime::from_chrono).serialize(s)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Option<DateTime<Utc>>, D::Error> {
            Ok(Option::<bson::DateTime>::deserialize(d)?.map(|v| v.to_chrono()))
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Grant {
    pub app: String,
    pub roles: Vec<String>,
    #[serde(with = "bson_dt::required")]
    pub granted_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub email: String,
    pub name: Option<String>,
    pub password_hash: Option<String>,
    pub status: UserStatus,
    #[serde(default)]
    pub grants: Vec<Grant>,
    #[serde(with = "bson_dt::required")]
    pub created_at: Timestamp,
    #[serde(with = "bson_dt::required")]
    pub updated_at: Timestamp,
}

impl User {
    pub fn grant(&self, app: &str) -> Option<&Grant> {
        self.grants.iter().find(|g| g.app == app)
    }

    pub fn is_active(&self) -> bool {
        self.status == UserStatus::Active
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct App {
    /// The slug, `^[a-z0-9-]{2,32}$`.
    #[serde(rename = "_id")]
    pub slug: String,
    pub name: String,
    pub origins: Vec<String>,
    #[serde(with = "bson_dt::required")]
    pub created_at: Timestamp,
    #[serde(with = "bson_dt::required")]
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// `sha256(token)` as hex. The raw token only ever lives in the cookie.
    #[serde(rename = "_id")]
    pub id: String,
    pub user_id: ObjectId,
    #[serde(with = "bson_dt::required")]
    pub created_at: Timestamp,
    /// Sliding expiry; MongoDB's TTL monitor deletes the document after this.
    #[serde(with = "bson_dt::required")]
    pub expires_at: Timestamp,
    /// Hard cap: sliding never extends beyond this.
    #[serde(with = "bson_dt::required")]
    pub absolute_expires_at: Timestamp,
    #[serde(with = "bson_dt::required")]
    pub last_used_at: Timestamp,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InvitePurpose {
    Setup,
    Reset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// `sha256(token)` as hex.
    #[serde(rename = "_id")]
    pub id: String,
    pub user_id: ObjectId,
    pub purpose: InvitePurpose,
    #[serde(with = "bson_dt::required")]
    pub expires_at: Timestamp,
    #[serde(with = "bson_dt::optional", default)]
    pub used_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempts {
    /// `email:<email>` or `ip:<ip>`.
    #[serde(rename = "_id")]
    pub id: String,
    pub count: i64,
    #[serde(with = "bson_dt::required")]
    pub expires_at: Timestamp,
}

/// Validate an app slug: `^[a-z0-9-]{2,32}$`.
pub fn valid_slug(slug: &str) -> bool {
    (2..=32).contains(&slug.len())
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Canonical form of an email for storage and lookup.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Minimal sanity check; the admin is trusted, this only catches typos.
pub fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && email.len() <= 254
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert!(valid_slug("recipes"));
        assert!(valid_slug("my-app-2"));
        assert!(!valid_slug("a"));
        assert!(!valid_slug("Recipes"));
        assert!(!valid_slug("re_cipes"));
        assert!(!valid_slug(&"a".repeat(33)));
    }

    #[test]
    fn emails() {
        assert_eq!(normalize_email("  Me@Example.COM "), "me@example.com");
        assert!(valid_email("dev@localtest.me"));
        assert!(!valid_email("nope"));
        assert!(!valid_email("a@b"));
        assert!(!valid_email("a b@c.com"));
    }
}
