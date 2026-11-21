//! Process entry point for the ayane control plane.

use std::sync::Arc;

use ayane::config::Config;
use ayane::driver::ComposeDriver;
use ayane::state::AppState;
use ayane_store::RedbStateStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&config.log_filter))
        .init();

    if let Some(parent) = config.store_path().parent() {
        std::fs::create_dir_all(parent)?;
    }
    let store = RedbStateStore::open(config.store_path())?;
    let state = AppState {
        store: Arc::new(store),
        driver: Arc::new(ComposeDriver {
            compose_file: config.compose_file.clone(),
        }),
        config: Arc::new(config.clone()),
    };

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(
        listen = %config.listen,
        state_dir = %config.state_dir.display(),
        version = env!("CARGO_PKG_VERSION"),
        admin_api = if config.admin_token.is_some() { "enabled" } else { "disabled" },
        "ayane control plane starting"
    );
    axum::serve(listener, ayane::app(state)).await?;
    Ok(())
}
