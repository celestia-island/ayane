//! Process entry point for the ayane control plane.

use std::sync::Arc;

use kirino::auth::passport::oauth::HttpFetcher;

use ayane::auth::{AuthState, NoFetcher, ProviderCatalog, ReqwestFetcher};
use ayane::config::Config;
use ayane::driver::ComposeDriver;
use ayane::state::AppState;
use ayane::transport::RpcSurface;
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
    // Provider sign-in is read fail-closed: a provider variable that is
    // present but incomplete, or a policy that disagrees with itself,
    // refuses to start rather than quietly serve a password-only panel.
    let catalog = ProviderCatalog::from_env()?;
    let policy = catalog.validated_login_policy()?;
    let http: Arc<dyn HttpFetcher> = if catalog.has_providers() {
        Arc::new(ReqwestFetcher::new()?)
    } else {
        Arc::new(NoFetcher)
    };
    let auth = Arc::new(AuthState::new(catalog, http));
    let state = AppState {
        store: Arc::new(store),
        driver: Arc::new(ComposeDriver {
            compose_file: config.compose_file.clone(),
        }),
        config: Arc::new(config.clone()),
        auth,
    };
    let sessions_path = config.state_dir.join("sessions.json");
    let surface = RpcSurface {
        app: state.clone(),
        sessions: Arc::new(ayane::session::SessionStore::with_persistence(
            sessions_path,
        )),
    };

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(
        listen = %config.listen,
        state_dir = %config.state_dir.display(),
        version = env!("CARGO_PKG_VERSION"),
        admin_api = if config.admin_token.is_some() { "enabled" } else { "disabled" },
        auth_mode = policy.mode.as_str(),
        "ayane control plane starting"
    );
    axum::serve(listener, ayane::api::full_router(surface)).await?;
    Ok(())
}
