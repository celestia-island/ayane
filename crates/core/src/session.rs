//! Account sessions for the webmail surface.
//!
//! A session is a random bearer token minted after the mailbox password
//! verifies against the store's hash. Tokens live in memory only: a service
//! restart logs everyone out, which is the right trade for a test-stage
//! deployment (nothing persistent to leak, nothing to revoke out-of-band).

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
}

/// One live session.
#[derive(Debug, Clone)]
pub struct Session {
    /// The mailbox the token unlocks.
    pub address: Address,
    /// Display name from the desired state.
    pub display_name: String,
    /// Whether this session may call `admin.*` (set by admin login only).
    pub admin: bool,
    /// The mailbox password for the IMAP leg of this session (`None` for
    /// admin sessions). Lives in memory and in the 0600 sessions file
    /// only — never logged, never sent back to any client.
    pub password: Option<String>,
    /// When the session expires.
    pub expires: Instant,
}

/// The on-disk mirror of one live session (sessions.json, 0600).
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedSession {
    address: Address,
    display_name: String,
    admin: bool,
    password: Option<String>,
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
        self.mint(address, display_name, admin, Some(password_raw.to_owned()))
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

    /// Drop a session.
    pub fn logout(&self, token: &str) {
        self.inner.lock().expect("sessions mutex").remove(token);
    }

    #[allow(clippy::too_many_arguments)]
    fn mint(
        &self,
        address: Address,
        display_name: String,
        admin: bool,
        password: Option<String>,
    ) -> Result<(String, Session), LoginError> {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).map_err(|_| LoginError::InvalidCredentials)?;
        let token = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let session = Session {
            address,
            display_name,
            admin,
            password,
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
}
