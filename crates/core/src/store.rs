//! MongoDB persistence.
//!
//! One `Store` is created per process (per Lambda container) and shared by
//! all requests; the driver keeps a connection pool inside it.

use std::time::Duration;

use bson::{doc, oid::ObjectId, DateTime as BsonDateTime, Document};
use chrono::Utc;
use futures::TryStreamExt;
use mongodb::{
    options::{ClientOptions, IndexOptions, ReturnDocument},
    Client, Collection, Database, IndexModel,
};

use crate::{
    duration::to_chrono,
    model::*,
    secret::{new_token, sha256_hex},
    Error, Result,
};

#[derive(Clone, Debug)]
pub struct Store {
    db: Database,
    pub users: Collection<User>,
    pub apps: Collection<App>,
    pub sessions: Collection<Session>,
    pub invites: Collection<Invite>,
    pub attempts: Collection<LoginAttempts>,
}

fn now_bson() -> BsonDateTime {
    BsonDateTime::from_chrono(Utc::now())
}

/// Clean up a role list: trim, drop duplicates, reject empty strings.
pub fn normalize_roles(roles: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::with_capacity(roles.len());
    for r in roles {
        let r = r.trim();
        if r.is_empty() || r.len() > 64 {
            return Err(Error::Invalid(
                "roles must be non-empty strings of at most 64 characters".into(),
            ));
        }
        if !out.iter().any(|x| x == r) {
            out.push(r.to_string());
        }
    }
    Ok(out)
}

/// How a caller refers to a user: by ObjectId hex or by email.
pub fn parse_user_ref(r: &str) -> Document {
    match ObjectId::parse_str(r) {
        Ok(id) => doc! { "_id": id },
        Err(_) => doc! { "email": normalize_email(r) },
    }
}

impl Store {
    /// Connect and return a store. Does not perform any network I/O until the
    /// first operation (the driver connects lazily).
    pub async fn connect(uri: &str, db_name: &str) -> Result<Self> {
        let mut opts = ClientOptions::parse(uri).await?;
        opts.app_name.get_or_insert_with(|| "clang-auth".into());
        // Lambda reserved concurrency is 5 and each container handles one
        // request at a time, so a small pool is plenty and keeps us well
        // under Atlas M0's connection limit.
        opts.max_pool_size.get_or_insert(5);
        opts.server_selection_timeout
            .get_or_insert(Duration::from_secs(5));
        opts.connect_timeout.get_or_insert(Duration::from_secs(5));
        let client = Client::with_options(opts)?;
        Ok(Self::from_db(client.database(db_name)))
    }

    pub fn from_db(db: Database) -> Self {
        Self {
            users: db.collection("users"),
            apps: db.collection("apps"),
            sessions: db.collection("sessions"),
            invites: db.collection("invites"),
            attempts: db.collection("login_attempts"),
            db,
        }
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    pub async fn ping(&self) -> Result<()> {
        self.db.run_command(doc! { "ping": 1 }).await?;
        Ok(())
    }

    /// Create all indexes. Idempotent: MongoDB ignores identical existing
    /// index definitions.
    pub async fn ensure_indexes(&self) -> Result<()> {
        let unique = IndexOptions::builder().unique(true).build();
        let ttl = || {
            IndexOptions::builder()
                .expire_after(Duration::from_secs(0))
                .build()
        };
        self.users
            .create_indexes([
                IndexModel::builder()
                    .keys(doc! { "email": 1 })
                    .options(unique)
                    .build(),
                IndexModel::builder().keys(doc! { "grants.app": 1 }).build(),
            ])
            .await?;
        self.apps
            .create_index(IndexModel::builder().keys(doc! { "origins": 1 }).build())
            .await?;
        self.sessions
            .create_indexes([
                IndexModel::builder().keys(doc! { "user_id": 1 }).build(),
                IndexModel::builder()
                    .keys(doc! { "expires_at": 1 })
                    .options(ttl())
                    .build(),
            ])
            .await?;
        self.invites
            .create_indexes([
                IndexModel::builder().keys(doc! { "user_id": 1 }).build(),
                IndexModel::builder()
                    .keys(doc! { "expires_at": 1 })
                    .options(ttl())
                    .build(),
            ])
            .await?;
        self.attempts
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "expires_at": 1 })
                    .options(ttl())
                    .build(),
            )
            .await?;
        Ok(())
    }

    // ----------------------------------------------------------------- apps

    pub async fn list_apps(&self) -> Result<Vec<App>> {
        Ok(self
            .apps
            .find(doc! {})
            .sort(doc! { "_id": 1 })
            .await?
            .try_collect()
            .await?)
    }

    pub async fn get_app(&self, slug: &str) -> Result<Option<App>> {
        Ok(self.apps.find_one(doc! { "_id": slug }).await?)
    }

    /// `origins` must already be normalised (see `origin::normalize_origin`).
    pub async fn create_app(&self, slug: &str, name: &str, origins: Vec<String>) -> Result<App> {
        if !valid_slug(slug) {
            return Err(Error::Invalid("slug must match ^[a-z0-9-]{2,32}$".into()));
        }
        if name.trim().is_empty() {
            return Err(Error::Invalid("name is required".into()));
        }
        if origins.is_empty() {
            return Err(Error::Invalid("at least one origin is required".into()));
        }
        let now = Utc::now();
        let app = App {
            slug: slug.into(),
            name: name.trim().into(),
            origins: dedupe(origins),
            created_at: now,
            updated_at: now,
        };
        match self.apps.insert_one(&app).await {
            Ok(_) => Ok(app),
            Err(e) if Error::is_duplicate_key(&e) => {
                Err(Error::Conflict(format!("app {slug:?} already exists")))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn update_app(
        &self,
        slug: &str,
        name: Option<&str>,
        origins: Option<Vec<String>>,
    ) -> Result<App> {
        let mut set = doc! { "updated_at": now_bson() };
        if let Some(name) = name {
            if name.trim().is_empty() {
                return Err(Error::Invalid("name must not be empty".into()));
            }
            set.insert("name", name.trim());
        }
        if let Some(origins) = origins {
            if origins.is_empty() {
                return Err(Error::Invalid("at least one origin is required".into()));
            }
            set.insert("origins", dedupe(origins));
        }
        self.apps
            .find_one_and_update(doc! { "_id": slug }, doc! { "$set": set })
            .return_document(ReturnDocument::After)
            .await?
            .ok_or(Error::NotFound("app"))
    }

    /// Delete an app and strip its grants from every user.
    pub async fn delete_app(&self, slug: &str) -> Result<u64> {
        let res = self.apps.delete_one(doc! { "_id": slug }).await?;
        if res.deleted_count == 0 {
            return Err(Error::NotFound("app"));
        }
        let pulled = self
            .users
            .update_many(
                doc! { "grants.app": slug },
                doc! { "$pull": { "grants": { "app": slug } }, "$set": { "updated_at": now_bson() } },
            )
            .await?;
        Ok(pulled.modified_count)
    }

    /// The app that owns a normalised origin, if any.
    pub async fn app_for_origin(&self, origin: &str) -> Result<Option<App>> {
        Ok(self.apps.find_one(doc! { "origins": origin }).await?)
    }

    // ---------------------------------------------------------------- users

    pub async fn list_users(&self, app: Option<&str>) -> Result<Vec<User>> {
        let filter = match app {
            Some(slug) => doc! { "grants.app": slug },
            None => doc! {},
        };
        Ok(self
            .users
            .find(filter)
            .sort(doc! { "email": 1 })
            .await?
            .try_collect()
            .await?)
    }

    /// Look a user up by ObjectId hex or email.
    pub async fn find_user(&self, user_ref: &str) -> Result<Option<User>> {
        Ok(self.users.find_one(parse_user_ref(user_ref)).await?)
    }

    pub async fn get_user(&self, id: ObjectId) -> Result<Option<User>> {
        Ok(self.users.find_one(doc! { "_id": id }).await?)
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>> {
        Ok(self
            .users
            .find_one(doc! { "email": normalize_email(email) })
            .await?)
    }

    async fn require_apps(&self, slugs: impl Iterator<Item = &String>) -> Result<()> {
        for slug in slugs {
            if self.get_app(slug).await?.is_none() {
                return Err(Error::Invalid(format!("unknown app {slug:?}")));
            }
        }
        Ok(())
    }

    pub async fn create_user(
        &self,
        email: &str,
        name: Option<&str>,
        grants: Vec<(String, Vec<String>)>,
    ) -> Result<User> {
        let email = normalize_email(email);
        if !valid_email(&email) {
            return Err(Error::Invalid(format!("invalid email {email:?}")));
        }
        self.require_apps(grants.iter().map(|(s, _)| s)).await?;
        let now = Utc::now();
        let mut out: Vec<Grant> = Vec::new();
        for (app, roles) in grants {
            let roles = normalize_roles(&roles)?;
            out.retain(|g| g.app != app);
            out.push(Grant {
                app,
                roles,
                granted_at: now,
            });
        }
        let user = User {
            id: ObjectId::new(),
            email: email.clone(),
            name: name
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(Into::into),
            password_hash: None,
            status: UserStatus::Active,
            grants: out,
            created_at: now,
            updated_at: now,
        };
        match self.users.insert_one(&user).await {
            Ok(_) => Ok(user),
            Err(e) if Error::is_duplicate_key(&e) => {
                Err(Error::Conflict(format!("user {email:?} already exists")))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Update name and/or status. Disabling a user revokes all their sessions.
    pub async fn update_user(
        &self,
        id: ObjectId,
        name: Option<Option<&str>>,
        status: Option<UserStatus>,
    ) -> Result<User> {
        let mut set = doc! { "updated_at": now_bson() };
        if let Some(name) = name {
            match name.map(str::trim).filter(|n| !n.is_empty()) {
                Some(n) => set.insert("name", n),
                None => set.insert("name", bson::Bson::Null),
            };
        }
        if let Some(status) = status {
            set.insert("status", bson::to_bson(&status).expect("status to bson"));
        }
        let user = self
            .users
            .find_one_and_update(doc! { "_id": id }, doc! { "$set": set })
            .return_document(ReturnDocument::After)
            .await?
            .ok_or(Error::NotFound("user"))?;
        if status == Some(UserStatus::Disabled) {
            self.revoke_user_sessions(id).await?;
        }
        Ok(user)
    }

    /// Delete a user along with their sessions and invites.
    pub async fn delete_user(&self, id: ObjectId) -> Result<()> {
        let res = self.users.delete_one(doc! { "_id": id }).await?;
        if res.deleted_count == 0 {
            return Err(Error::NotFound("user"));
        }
        self.sessions.delete_many(doc! { "user_id": id }).await?;
        self.invites.delete_many(doc! { "user_id": id }).await?;
        Ok(())
    }

    /// Create or replace a user's grant for `slug`.
    pub async fn set_grant(&self, id: ObjectId, slug: &str, roles: &[String]) -> Result<User> {
        let roles = normalize_roles(roles)?;
        if self.get_app(slug).await?.is_none() {
            return Err(Error::NotFound("app"));
        }
        let now = now_bson();
        let replaced = self
            .users
            .find_one_and_update(
                doc! { "_id": id, "grants.app": slug },
                doc! { "$set": { "grants.$.roles": &roles, "updated_at": now } },
            )
            .return_document(ReturnDocument::After)
            .await?;
        if let Some(user) = replaced {
            return Ok(user);
        }
        self.users
            .find_one_and_update(
                doc! { "_id": id, "grants.app": { "$ne": slug } },
                doc! {
                    "$push": { "grants": { "app": slug, "roles": &roles, "granted_at": now } },
                    "$set": { "updated_at": now },
                },
            )
            .return_document(ReturnDocument::After)
            .await?
            .ok_or(Error::NotFound("user"))
    }

    pub async fn remove_grant(&self, id: ObjectId, slug: &str) -> Result<User> {
        let user = self
            .users
            .find_one_and_update(
                doc! { "_id": id, "grants.app": slug },
                doc! { "$pull": { "grants": { "app": slug } }, "$set": { "updated_at": now_bson() } },
            )
            .return_document(ReturnDocument::After)
            .await?;
        match user {
            Some(u) => Ok(u),
            None => match self.get_user(id).await? {
                Some(_) => Err(Error::NotFound("grant")),
                None => Err(Error::NotFound("user")),
            },
        }
    }

    pub async fn set_password_hash(&self, id: ObjectId, phc: &str) -> Result<()> {
        self.users
            .update_one(
                doc! { "_id": id },
                doc! { "$set": { "password_hash": phc, "updated_at": now_bson() } },
            )
            .await?;
        Ok(())
    }

    // ------------------------------------------------------------- sessions

    /// Create a session. Returns the raw token (for the cookie) and the record.
    pub async fn create_session(
        &self,
        user_id: ObjectId,
        ttl: Duration,
        max_ttl: Duration,
        user_agent: Option<String>,
        ip: Option<String>,
    ) -> Result<(String, Session)> {
        let token = new_token();
        let now = Utc::now();
        let absolute = now + to_chrono(max_ttl);
        let session = Session {
            id: sha256_hex(&token),
            user_id,
            created_at: now,
            expires_at: (now + to_chrono(ttl)).min(absolute),
            absolute_expires_at: absolute,
            last_used_at: now,
            user_agent: user_agent.map(|ua| ua.chars().take(256).collect()),
            ip,
        };
        self.sessions.insert_one(&session).await?;
        Ok((token, session))
    }

    /// Validate a session token and slide its expiry. Returns `None` if the
    /// session is unknown, expired, or its user is missing or disabled (in
    /// which case the session is deleted).
    pub async fn use_session(&self, token: &str, ttl: Duration) -> Result<Option<(Session, User)>> {
        let id = sha256_hex(token);
        let now = Utc::now();
        let Some(session) = self.sessions.find_one(doc! { "_id": &id }).await? else {
            return Ok(None);
        };
        // The TTL monitor only runs once a minute, so check expiry ourselves.
        if session.expires_at <= now || session.absolute_expires_at <= now {
            self.sessions.delete_one(doc! { "_id": &id }).await?;
            return Ok(None);
        }
        let user = match self.get_user(session.user_id).await? {
            Some(u) if u.is_active() => u,
            _ => {
                self.sessions.delete_one(doc! { "_id": &id }).await?;
                return Ok(None);
            }
        };
        let expires_at = (now + to_chrono(ttl)).min(session.absolute_expires_at);
        let session = self
            .sessions
            .find_one_and_update(
                doc! { "_id": &id },
                doc! { "$set": {
                    "expires_at": BsonDateTime::from_chrono(expires_at),
                    "last_used_at": BsonDateTime::from_chrono(now),
                } },
            )
            .return_document(ReturnDocument::After)
            .await?;
        Ok(session.map(|s| (s, user)))
    }

    pub async fn delete_session(&self, token: &str) -> Result<bool> {
        let res = self
            .sessions
            .delete_one(doc! { "_id": sha256_hex(token) })
            .await?;
        Ok(res.deleted_count > 0)
    }

    pub async fn revoke_user_sessions(&self, user_id: ObjectId) -> Result<u64> {
        Ok(self
            .sessions
            .delete_many(doc! { "user_id": user_id })
            .await?
            .deleted_count)
    }

    pub async fn count_active_sessions(&self, user_id: ObjectId) -> Result<u64> {
        Ok(self
            .sessions
            .count_documents(doc! {
                "user_id": user_id,
                "expires_at": { "$gt": now_bson() },
                "absolute_expires_at": { "$gt": now_bson() },
            })
            .await?)
    }

    // -------------------------------------------------------------- invites

    /// Create an invite and invalidate the user's earlier unused invites.
    /// Returns the raw token for the link.
    pub async fn create_invite(
        &self,
        user_id: ObjectId,
        purpose: InvitePurpose,
        ttl: Duration,
    ) -> Result<(String, Invite)> {
        self.invites
            .delete_many(doc! { "user_id": user_id, "used_at": bson::Bson::Null })
            .await?;
        let token = new_token();
        let invite = Invite {
            id: sha256_hex(&token),
            user_id,
            purpose,
            expires_at: Utc::now() + to_chrono(ttl),
            used_at: None,
        };
        self.invites.insert_one(&invite).await?;
        Ok((token, invite))
    }

    fn live_invite_filter(token: &str) -> Document {
        doc! { "_id": sha256_hex(token), "used_at": bson::Bson::Null, "expires_at": { "$gt": now_bson() } }
    }

    /// Look up a usable invite without consuming it.
    pub async fn peek_invite(&self, token: &str) -> Result<Option<Invite>> {
        Ok(self
            .invites
            .find_one(Self::live_invite_filter(token))
            .await?)
    }

    /// Atomically mark an invite used. Returns `None` if it was already used,
    /// expired, superseded, or never existed. Two concurrent submissions of
    /// the same link cannot both succeed.
    pub async fn consume_invite(&self, token: &str) -> Result<Option<Invite>> {
        Ok(self
            .invites
            .find_one_and_update(
                Self::live_invite_filter(token),
                doc! { "$set": { "used_at": now_bson() } },
            )
            .return_document(ReturnDocument::After)
            .await?)
    }

    // ------------------------------------------------------- rate limiting

    /// Number of recorded failures for `key` in the current window.
    pub async fn failure_count(&self, key: &str) -> Result<i64> {
        let doc = self
            .attempts
            .find_one(doc! { "_id": key, "expires_at": { "$gt": now_bson() } })
            .await?;
        Ok(doc.map_or(0, |d| d.count))
    }

    /// Record a failed login for `key`. The first failure opens a fixed
    /// window of length `window`; later failures increment the counter.
    pub async fn record_failure(&self, key: &str, window: Duration) -> Result<()> {
        // A stale document (window over, TTL monitor not yet run) restarts.
        self.attempts
            .delete_one(doc! { "_id": key, "expires_at": { "$lte": now_bson() } })
            .await?;
        let expires = BsonDateTime::from_chrono(Utc::now() + to_chrono(window));
        let res = self
            .attempts
            .update_one(
                doc! { "_id": key },
                doc! { "$inc": { "count": 1_i64 }, "$setOnInsert": { "expires_at": expires } },
            )
            .upsert(true)
            .await;
        match res {
            Ok(_) => Ok(()),
            // Two concurrent upserts can race on insert; retry once as update.
            Err(e) if Error::is_duplicate_key(&e) => {
                self.attempts
                    .update_one(doc! { "_id": key }, doc! { "$inc": { "count": 1_i64 } })
                    .await?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

fn dedupe(v: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(v.len());
    for s in v {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}
