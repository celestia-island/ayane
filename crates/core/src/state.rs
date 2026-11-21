//! Shared application state handed to every handler.

use std::sync::Arc;

use crate::config::Config;
use crate::driver::EngineDriver;
use ayane_store::StateStore;

/// Everything a handler needs: the store, the engine driver and the config.
#[derive(Clone)]
pub struct AppState {
    /// Persistent desired-state store.
    pub store: Arc<dyn StateStore>,
    /// How rendered configuration is pushed into the engine.
    pub driver: Arc<dyn EngineDriver>,
    /// Process configuration.
    pub config: Arc<Config>,
}
