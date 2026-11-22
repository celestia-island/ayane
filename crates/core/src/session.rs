//! Account sessions for the webmail surface.
//!
//! A session is a random bearer token minted after the mailbox password
//! verifies against the store's hash. Tokens live in memory only: a service
//! restart logs everyone out, which is the right trade for a test-stage
//! deployment (nothing persistent to leak, nothing to revoke out-of-band).

use std::collections::HashMap;
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
    /// The mailbox password, in memory only, for the IMAP leg of this
    /// session (`None` for admin sessions). Never persisted, never logged.
    pub password: Option<String>,
    /// When the session expires.
    pub expires: Instant,
}

/// In-memory token → session map.
#[derive(Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        let address = Address::parse(address_raw).map_err(|_| LoginError::UnknownAccount)?;
        let stored = store.load().map_err(|_| LoginError::UnknownAccount)?;
        let hash = stored
            .password_hash(&address)
            .ok_or(LoginError::UnknownAccount)?;
        password::verify_password(password_raw, hash)
            .map_err(|_| LoginError::InvalidCredentials)?;
        let display_name = stored
            .desired
            .accounts
            .iter()
            .find(|account| account.address == address)
            .map(|account| account.display_name.clone())
            .unwrap_or_default();
        self.mint(address, display_name, false, Some(password_raw.to_owned()))
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
