//! Shared application state handed to every handler.

use std::sync::Arc;

use crate::auth::AuthState;
use crate::config::Config;
use crate::driver::EngineDriver;
use crate::MailHealth;
use ayane_store::StateStore;

/// Everything a handler needs: the store, the engine driver, the config
/// and the federated sign-in state.
#[derive(Clone)]
pub struct AppState {
    /// Persistent desired-state store.
    pub store: Arc<dyn StateStore>,
    /// How rendered configuration is pushed into the engine.
    pub driver: Arc<dyn EngineDriver>,
    /// Process configuration.
    pub config: Arc<Config>,
    /// The provider catalog, the in-flight sign-ins and the transport.
    pub auth: Arc<AuthState>,
    /// The mail service's health, when this process runs one.
    ///
    /// Set by the entry point after [`crate::engine::start`] returns; `None`
    /// for a process whose mail section is disabled, which is what makes the
    /// disabled shape byte-for-byte the old `/api/health` payload.
    pub mail_health: Option<Arc<MailHealth>>,
}

impl AppState {
    /// The payload `/api/health` answers with.
    #[must_use]
    pub fn health(&self) -> crate::Health {
        crate::Health::with_mail(self.mail_health.as_deref().cloned())
    }
}
