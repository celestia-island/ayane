//! Account sessions for the webmail surface.
//!
//! A session is a random bearer token minted after the mailbox password
//! verifies against the store's hash — or after a provider proved the
//! visitor's identity and that identity is linked to a mailbox. A
//! provider-minted session for an own-domain account starts **locked**
//! ([`Session::needs_mailbox_password`]): the provider said nothing about
//! the mailbox, so the password is proven once on the verify card before
//! any mail is read — and before any admin method runs: it is the
//! account's second factor for every privileged surface
//! ([`SessionStore::is_admin`]).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ayane_proto::Address;
use ayane_store::{password, StateStore};

/// How long a login stays valid.
pub const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

/// Why a login failed.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The address does not exist or is disabled.
    #[error("unknown account")]
    UnknownAccount,
    /// The password did not verify.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// The session's mailbox is not locked, so there is nothing to unlock.
    #[error("the mailbox is not locked")]
    NotLocked,
}

/// One live session.
#[derive(Debug, Clone)]
pub struct Session {
    /// The mailbox the token unlocks.
    pub address: Address,
    /// Display name from the desired state.
    pub display_name: String,
    /// The administrator flag as it stood when the session was minted
    /// (`true` for the admin-token override). A record, not the decision:
    /// authority is read live by [`SessionStore::is_admin`], which follows
    /// the account table and answers `false` while the session is locked.
    pub admin: bool,
    /// The mailbox password for the IMAP leg of this session (`None` for
    /// admin sessions). Lives in memory and in the 0600 sessions file
    /// only — never logged, never sent back to any client.
    pub password: Option<String>,
    /// Set while a provider-minted session still owes the mailbox password
    /// (an own-domain account without a cached credential): `password` is
    /// `None` and every mail method AND every admin method refuses with
    /// `Session.MailboxLocked` until [`SessionStore::unlock_mailbox`]
    /// verifies it once.
    pub needs_mailbox_password: bool,
    /// When the session expires.
    pub expires: Instant,
}

impl Session {
    /// Whether mail must refuse this session until the mailbox is unlocked.
    #[must_use]
    pub fn mailbox_locked(&self) -> bool {
        self.needs_mailbox_password
    }
}

/// The on-disk mirror of one live session (sessions.json, 0600).
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedSession {
    address: Address,
    display_name: String,
    admin: bool,
    #[serde(default)]
    password: Option<String>,
    /// Absent on files written before provider sign-in: never locked.
    #[serde(default)]
    needs_mailbox_password: bool,
    /// Seconds remaining at save time; re-armed as an absolute instant
    /// on load.
    expires_in: u64,
}

/// In-memory token → session map, mirrored to a 0600 JSON file so a
/// control-plane restart does not log every browser out (the file carries
/// the mailbox password for the IMAP leg — same sensitivity tier as the
/// session itself, never leaves the state dir).
#[derive(Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
    persistence: Option<PathBuf>,
}

impl SessionStore {
    /// An in-memory-only store (tests).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that mirrors sessions to `path` (created 0600).
    #[must_use]
    pub fn with_persistence(path: PathBuf) -> Self {
        let store = Self {
            persistence: Some(path),
            ..Self::default()
        };
        store.load_persisted();
        store
    }

    fn load_persisted(&self) {
        let Some(path) = &self.persistence else {
            return;
        };
        let Ok(raw) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(map) = serde_json::from_str::<HashMap<String, PersistedSession>>(&raw) else {
            return;
        };
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("sessions mutex");
        for (token, record) in map {
            let Some(expires) = now.checked_add(Duration::from_secs(record.expires_in)) else {
                continue;
            };
            if expires <= now {
                continue;
            }
            inner.insert(
                token,
                Session {
                    address: record.address,
                    display_name: record.display_name,
                    admin: record.admin,
                    password: record.password,
                    needs_mailbox_password: record.needs_mailbox_password,
                    expires,
                },
            );
        }
    }

    fn persist(&self) {
        let Some(path) = &self.persistence else {
            return;
        };
        let inner = self.inner.lock().expect("sessions mutex");
        let now = Instant::now();
        let map: HashMap<String, PersistedSession> = inner
            .iter()
            .filter(|(_, s)| s.expires > now)
            .map(|(token, s)| {
                (
                    token.clone(),
                    PersistedSession {
                        address: s.address.clone(),
                        display_name: s.display_name.clone(),
                        admin: s.admin,
                        password: s.password.clone(),
                        needs_mailbox_password: s.needs_mailbox_password,
                        expires_in: s.expires.duration_since(now).as_secs(),
                    },
                )
            })
            .collect();
        if let Ok(json) = serde_json::to_string(&map) {
            let _ = std::fs::write(path, json);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }

    /// Verify mailbox credentials and mint a session token.
    ///
    /// # Errors
    ///
    /// [`LoginError::UnknownAccount`] when the address has no account,
    /// [`LoginError::InvalidCredentials`] when the password does not match.
    pub fn login(
        &self,
        store: &dyn StateStore,
        address_raw: &str,
        password_raw: &str,
    ) -> Result<(String, Session), LoginError> {
        // A bare local part ("test") resolves against the hosted domains
        // when exactly one account matches — the common single-domain case
        // users naturally type.
        let address = match Address::parse(address_raw) {
            Ok(address) => address,
            Err(_) => resolve_bare_local(store, address_raw).ok_or(LoginError::UnknownAccount)?,
        };
        let stored = store.load().map_err(|_| LoginError::UnknownAccount)?;
        let hash = stored
            .password_hash(&address)
            .ok_or(LoginError::UnknownAccount)?;
        password::verify_password(password_raw, hash)
            .map_err(|_| LoginError::InvalidCredentials)?;
        let account = stored
            .desired
            .accounts
            .iter()
            .find(|account| account.address == address);
        let display_name = account
            .map(|account| account.display_name.clone())
            .unwrap_or_default();
        // Admin authority is an ACCOUNT property (the admin-token escape
        // hatch aside): an admin account's ordinary login already carries
        // the admin session, so the webmail never asks for a second
        // credential.
        let admin = account.is_some_and(|account| account.admin);
        self.mint(
            address,
            display_name,
            admin,
            Some(password_raw.to_owned()),
            false,
        )
    }

    /// Mint a session after a provider proved the visitor's identity.
    ///
    /// `cached_credential` is what the account opens its mailbox with when
    /// the server holds one (a forwarding-node account, see
    /// [`ayane_store::StoredState::cached_credential`]): such a session is
    /// complete at once — a user never re-enters the password of an
    /// already-registered foreign mailbox. `None` means an own-domain
    /// account: the session starts locked and the SPA asks for the mailbox
    /// password once ([`Self::unlock_mailbox`]).
    ///
    /// # Errors
    ///
    /// [`LoginError::InvalidCredentials`] when the token entropy fails.
    pub fn mint_provider(
        &self,
        address: Address,
        display_name: String,
        admin: bool,
        cached_credential: Option<String>,
    ) -> Result<(String, Session), LoginError> {
        let locked = cached_credential.is_none();
        self.mint(address, display_name, admin, cached_credential, locked)
    }

    /// Prove the mailbox password of a locked session and unlock it.
    ///
    /// The password is verified against the hash of the SESSION's own
    /// address — the one mailbox this method can be asked about, since it
    /// is given no address (the server never keeps the plaintext) — then
    /// sets the session's password and clears the lock for the rest of
    /// the session's lifetime. A password that belongs to any other
    /// mailbox fails that verification exactly as a wrong one does.
    ///
    /// # Errors
    ///
    /// [`LoginError::NotLocked`] when the session owes no password,
    /// [`LoginError::InvalidCredentials`] when the token is unknown,
    /// expired, or the password does not match.
    pub fn unlock_mailbox(
        &self,
        store: &dyn StateStore,
        token: &str,
        password_raw: &str,
    ) -> Result<Session, LoginError> {
        let session = {
            let mut inner = self.inner.lock().expect("sessions mutex");
            inner.retain(|_, session| session.expires > Instant::now());
            inner
                .get(token)
                .cloned()
                .ok_or(LoginError::InvalidCredentials)?
        };
        if !session.needs_mailbox_password {
            return Err(LoginError::NotLocked);
        }
        let stored = store.load().map_err(|_| LoginError::UnknownAccount)?;
        let hash = stored
            .password_hash(&session.address)
            .ok_or(LoginError::UnknownAccount)?;
        password::verify_password(password_raw, hash)
            .map_err(|_| LoginError::InvalidCredentials)?;
        // MUT:unlock-verify-then-clear — the lock clears only after the
        // hash verified; a wrong password leaves the session locked.
        let mut inner = self.inner.lock().expect("sessions mutex");
        let session = inner.get_mut(token).ok_or(LoginError::InvalidCredentials)?;
        session.password = Some(password_raw.to_owned());
        session.needs_mailbox_password = false;
        let unlocked = session.clone();
        drop(inner);
        self.persist();
        Ok(unlocked)
    }

    /// Mint an admin session after the admin token matched.
    ///
    /// # Errors
    ///
    /// [`LoginError::InvalidCredentials`] when the token does not match.
    pub fn admin_login(
        &self,
        expected_admin_token: Option<&str>,
        presented: &str,
    ) -> Result<(String, Session), LoginError> {
        let expected = expected_admin_token.ok_or(LoginError::InvalidCredentials)?;
        if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
            return Err(LoginError::InvalidCredentials);
        }
        self.mint(
            Address::parse("admin@localhost").map_err(|_| LoginError::UnknownAccount)?,
            "Administrator".to_owned(),
            true,
            None,
            false,
        )
    }

    /// Resolve a token to a live session (re-arming nothing).
    ///
    /// # Errors
    ///
    /// [`LoginError::InvalidCredentials`] when the token is unknown or
    /// expired.
    pub fn resolve(&self, token: &str) -> Result<Session, LoginError> {
        let mut inner = self.inner.lock().expect("sessions mutex");
        inner.retain(|_, session| session.expires > Instant::now());
        inner
            .get(token)
            .cloned()
            .ok_or(LoginError::InvalidCredentials)
    }

    /// Whether the session holds admin authority RIGHT NOW.
    ///
    /// Admin is an account property, not a login-time snapshot: flipping an
    /// account's flag must take effect for sessions already open (and
    /// revoking it must bite immediately). Sessions minted by the admin
    /// token override keep their grant (there is no account behind them).
    ///
    /// A locked session holds none of it. The mailbox password is the
    /// account's second factor for every privileged surface, exactly as it
    /// is for the mailbox: until [`Self::unlock_mailbox`] proves it, the
    /// provider's word settles who the visitor is and nothing about what
    /// they may administer. The gate that needs to say WHY answers
    /// `Session.MailboxLocked` itself (`rpc::require_admin`); this
    /// predicate is the one every other reader of the flag shares.
    #[must_use]
    pub fn is_admin(&self, store: &dyn StateStore, session: &Session) -> bool {
        // MUT:locked-no-admin — checked first, before the token-override
        // shortcut and before the live table: a locked session is never an
        // admin, whatever either would say.
        if session.needs_mailbox_password {
            return false;
        }
        // The no-password marker of a token-override session.
        if session.admin && session.password.is_none() {
            return true;
        }
        store.load().is_ok_and(|stored| {
            stored
                .desired
                .accounts
                .iter()
                .any(|account| account.address == session.address && account.admin)
        })
    }

    /// Drop a session.
    pub fn logout(&self, token: &str) {
        self.inner.lock().expect("sessions mutex").remove(token);
    }

    fn mint(
        &self,
        address: Address,
        display_name: String,
        admin: bool,
        password: Option<String>,
        needs_mailbox_password: bool,
    ) -> Result<(String, Session), LoginError> {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).map_err(|_| LoginError::InvalidCredentials)?;
        let token = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let session = Session {
            address,
            display_name,
            admin,
            password,
            needs_mailbox_password,
            expires: Instant::now() + SESSION_TTL,
        };
        self.inner
            .lock()
            .expect("sessions mutex")
            .insert(token.clone(), session.clone());
        drop(self.inner.lock().expect("sessions mutex"));
        self.persist();
        Ok((token, session))
    }
}

/// Length-leaking-but-content-constant comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Resolve a bare local part ("test") to the single hosted account with
/// that local part; ambiguous (multiple domains) or unknown → `None`.
#[must_use]
fn resolve_bare_local(store: &dyn StateStore, raw: &str) -> Option<Address> {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.is_empty() || lower.contains('@') {
        return None;
    }
    let stored = store.load().ok()?;
    let mut matches: Vec<Address> = stored
        .desired
        .accounts
        .iter()
        .map(|account| account.address.clone())
        .filter(|address| address.local() == lower)
        .collect();
    matches.sort();
    matches.dedup();
    if matches.len() == 1 {
        matches.pop()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ayane_proto::{Account, DesiredState, MailDomain};
    use ayane_store::{RedbStateStore, StoredState};
    use std::collections::HashMap;

    fn store_with(addresses: &[&str]) -> RedbStateStore {
        let dir = std::env::temp_dir().join(format!("ayane-session-{}", uuid::Uuid::new_v4()));
        let store = RedbStateStore::open(dir.join("state.redb")).expect("open");
        let mut hashes = HashMap::new();
        let accounts: Vec<Account> = addresses
            .iter()
            .map(|raw| {
                let address = Address::parse(raw).expect("addr");
                hashes.insert(address.to_string(), "{SHA512-CRYPT}x".to_owned());
                Account {
                    id: uuid::Uuid::new_v4(),
                    address,
                    display_name: "T".to_owned(),
                    quota_bytes: 0,
                    admin: false,
                }
            })
            .collect();
        let stored = StoredState {
            desired: DesiredState {
                domains: vec![MailDomain {
                    name: "example.test".to_owned(),
                    catch_all: None,
                    enabled: true,
                }],
                accounts,
                ..Default::default()
            },
            password_hashes: hashes,
            external_identities: Vec::new(),
        };
        store.save(&stored).expect("save");
        store
    }

    /// A store whose one account has a REAL hash, so a password verifies.
    fn store_with_password(address: &str, password: &str) -> RedbStateStore {
        let dir = std::env::temp_dir().join(format!("ayane-session-{}", uuid::Uuid::new_v4()));
        let store = RedbStateStore::open(dir.join("state.redb")).expect("open");
        let address = Address::parse(address).expect("addr");
        let stored = StoredState {
            desired: DesiredState {
                domains: vec![MailDomain {
                    name: "example.test".to_owned(),
                    catch_all: None,
                    enabled: true,
                }],
                accounts: vec![Account {
                    id: uuid::Uuid::new_v4(),
                    address: address.clone(),
                    display_name: "Test".to_owned(),
                    quota_bytes: 0,
                    admin: false,
                }],
                ..Default::default()
            },
            password_hashes: HashMap::from([(
                address.to_string(),
                password::hash_password(password).expect("hash"),
            )]),
            external_identities: Vec::new(),
        };
        store.save(&stored).expect("save");
        store
    }

    #[test]
    fn bare_local_resolves_to_the_single_match() {
        let store = store_with(&["test@example.test", "ops@example.test"]);
        let sessions = SessionStore::new();
        let resolved = resolve_bare_local(&store, "test");
        assert_eq!(
            resolved.map(|a| a.to_string()),
            Some("test@example.test".to_owned())
        );
        let _ = sessions;
    }

    #[test]
    fn bare_local_across_two_domains_is_ambiguous() {
        use ayane_proto::MailDomain as Domain;
        let dir = std::env::temp_dir().join(format!("ayane-session-{}", uuid::Uuid::new_v4()));
        let store = RedbStateStore::open(dir.join("state.redb")).expect("open");
        let mk = |raw: &str| Account {
            id: uuid::Uuid::new_v4(),
            address: Address::parse(raw).expect("addr"),
            display_name: "T".to_owned(),
            quota_bytes: 0,
            admin: false,
        };
        let stored = StoredState {
            desired: DesiredState {
                domains: vec![
                    Domain {
                        name: "a.test".to_owned(),
                        catch_all: None,
                        enabled: true,
                    },
                    Domain {
                        name: "b.test".to_owned(),
                        catch_all: None,
                        enabled: true,
                    },
                ],
                accounts: vec![mk("test@a.test"), mk("test@b.test")],
                ..Default::default()
            },
            password_hashes: HashMap::new(),
            external_identities: Vec::new(),
        };
        store.save(&stored).expect("save");
        assert!(resolve_bare_local(&store, "test").is_none());
    }

    #[test]
    fn full_addresses_never_hit_the_resolution_path() {
        let store = store_with(&["test@example.test"]);
        assert!(resolve_bare_local(&store, "test@example.test").is_none());
        assert!(resolve_bare_local(&store, "").is_none());
    }

    #[test]
    fn a_provider_session_without_a_credential_starts_locked() {
        let _store = store_with_password("test@example.test", "correct-horse-battery");
        let sessions = SessionStore::new();
        let (token, session) = sessions
            .mint_provider(
                Address::parse("test@example.test").expect("addr"),
                "Test".to_owned(),
                false,
                None,
            )
            .expect("mint");
        // MUT:provider-session-locked — the provider proved the identity,
        // not the mailbox: the password is owed and mail must refuse.
        assert!(session.needs_mailbox_password);
        assert!(session.mailbox_locked());
        assert!(session.password.is_none());
        let _ = token;
    }

    #[test]
    fn a_cached_credential_mints_an_unlocked_session() {
        // The forwarding-node shape: the server holds the credential, so
        // the user is never asked for the password again.
        let sessions = SessionStore::new();
        let (_, session) = sessions
            .mint_provider(
                Address::parse("node@example.test").expect("addr"),
                "Node".to_owned(),
                false,
                Some("cached-credential".to_owned()),
            )
            .expect("mint");
        assert!(!session.needs_mailbox_password);
        assert_eq!(session.password.as_deref(), Some("cached-credential"));
    }

    #[test]
    fn unlock_refuses_a_wrong_password_and_clears_the_lock_on_the_right_one() {
        let store = store_with_password("test@example.test", "correct-horse-battery");
        let sessions = SessionStore::new();
        let (token, _) = sessions
            .mint_provider(
                Address::parse("test@example.test").expect("addr"),
                "Test".to_owned(),
                false,
                None,
            )
            .expect("mint");
        // MUT:unlock-wrong-password — a wrong password never unlocks.
        assert!(matches!(
            sessions.unlock_mailbox(&store, &token, "wrong"),
            Err(LoginError::InvalidCredentials)
        ));
        let still = sessions.resolve(&token).expect("live");
        assert!(still.needs_mailbox_password);
        assert!(still.password.is_none());
        // An unknown token is refused the same way.
        assert!(matches!(
            sessions.unlock_mailbox(&store, "no-such-token", "correct-horse-battery"),
            Err(LoginError::InvalidCredentials)
        ));
        sessions
            .unlock_mailbox(&store, &token, "correct-horse-battery")
            .expect("unlock");
        let unlocked = sessions.resolve(&token).expect("live");
        assert!(!unlocked.needs_mailbox_password);
        assert_eq!(unlocked.password.as_deref(), Some("correct-horse-battery"));
        // Unlocked, there is nothing left to unlock.
        assert!(matches!(
            sessions.unlock_mailbox(&store, &token, "correct-horse-battery"),
            Err(LoginError::NotLocked)
        ));
    }

    #[test]
    fn the_lock_survives_the_persisted_file() {
        let dir = std::env::temp_dir().join(format!("ayane-session-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("sessions.json");
        let (token, _) = SessionStore::with_persistence(path.clone())
            .mint_provider(
                Address::parse("test@example.test").expect("addr"),
                "Test".to_owned(),
                false,
                None,
            )
            .expect("mint");
        let reloaded = SessionStore::with_persistence(path.clone());
        let session = reloaded.resolve(&token).expect("restored");
        assert!(session.needs_mailbox_password);
        // A file written before the flag existed reads as unlocked.
        std::fs::write(
            &path,
            serde_json::json!({
                "t": { "address": "test@example.test", "display_name": "T", "admin": false,
                       "password": "p", "expires_in": 600 }
            })
            .to_string(),
        )
        .expect("legacy file");
        let legacy = SessionStore::with_persistence(path);
        assert!(!legacy.resolve("t").expect("legacy").needs_mailbox_password);
    }

    #[test]
    fn a_locked_provider_session_earns_admin_only_through_the_live_table() {
        let store = store_with_password("boss@example.test", "correct-horse-battery");
        let mut stored = store.load().expect("load");
        stored.desired.accounts[0].admin = true;
        store.save(&stored).expect("save");
        let sessions = SessionStore::new();
        let (token, locked) = sessions
            .mint_provider(
                Address::parse("boss@example.test").expect("addr"),
                "Boss".to_owned(),
                true,
                None,
            )
            .expect("mint");
        // MUT:locked-no-admin — the account is an admin and the mint was
        // told so, and it settles nothing: while the mailbox password is
        // owed the session holds NO admin authority.
        assert!(!sessions.is_admin(&store, &locked));
        sessions
            .unlock_mailbox(&store, &token, "correct-horse-battery")
            .expect("unlock");
        let unlocked = sessions.resolve(&token).expect("live");
        assert!(sessions.is_admin(&store, &unlocked));
        // MUT:locked-admin-live — it is not a token-override session: the
        // grant is read from the live table, so withdrawing it bites at once.
        stored.desired.accounts[0].admin = false;
        store.save(&stored).expect("save");
        assert!(!sessions.is_admin(&store, &unlocked));
        // Granting it back is read the same way.
        stored.desired.accounts[0].admin = true;
        store.save(&stored).expect("save");
        assert!(sessions.is_admin(&store, &unlocked));
    }
}
